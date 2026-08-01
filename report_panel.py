# report_panel.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import datetime
import logging
import queue
import threading
import webbrowser
from PIL import Image, ImageTk

from database import DB
from path_policy import local_file_uri, managed_path, safe_path_component
from report_export import export_offline_report
from utils import load_and_resize_image, parse_date, decode_if_bytes, calculate_time_difference,is_potential_follow 


class ReportPanel:
    """
    Панель для отображения отчетов:
    - Список номеров (с возможностью фильтрации и поиска)
    - Детальная информация и изображения
    - История обнаружений с временными метками
    - Похожие номера
    - Статистика и экспорт обезличенного offline-отчета
    """
    def __init__(self, master):
        self.master = master
        self.db = DB()
        self.current_sort = {'column': None, 'reverse': False}
        self._report_export_active = False
        self.setup_ui()
        self.load_data()

    def setup_ui(self):
        self.pw = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)
        self.pw.pack(fill=tk.BOTH, expand=True)

        self.setup_left_panel()
        self.setup_right_panel()

    def setup_left_panel(self):
        lf = ttk.Frame(self.pw)

        sf = ttk.LabelFrame(lf, text="Search")
        sf.pack(fill=tk.X, padx=5, pady=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.load_data())
        search_entry = ttk.Entry(sf, textvariable=self.search_var)
        search_entry.pack(fill=tk.X, padx=5, pady=5)

        ff = ttk.LabelFrame(lf, text="Filters")
        ff.pack(fill=tk.X, padx=5, pady=5)

        pf = ttk.Frame(ff)
        pf.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(pf, text="Profile:").pack(side=tk.LEFT)
        self.profile_var = tk.StringVar(value="All")
        # Ensure profiles are strings
        profile_values = ["All"] + [decode_if_bytes(p) for p in self.db.get_profiles()]
        profile_cb = ttk.Combobox(pf, textvariable=self.profile_var,
                                  values=profile_values)
        profile_cb.pack(side=tk.LEFT, padx=5)
        profile_cb.bind('<<ComboboxSelected>>', lambda e: self.load_data())

        df = ttk.Frame(ff)
        df.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(df, text="Date:").pack(side=tk.LEFT)
        self.date_var = tk.StringVar(value="All")
        date_cb = ttk.Combobox(df, textvariable=self.date_var,
                               values=["All", "Today", "Last 7 Days", "Last 30 Days"])
        date_cb.pack(side=tk.LEFT, padx=5)
        date_cb.bind('<<ComboboxSelected>>', lambda e: self.load_data())

        bf = ttk.Frame(ff)
        bf.pack(fill=tk.X, padx=5, pady=2)
        self.blacklist_var = tk.BooleanVar()
        ttk.Checkbutton(bf, text="Show only blacklisted",
                        variable=self.blacklist_var,
                        command=self.load_data).pack(side=tk.LEFT)

        # Добавляем фильтр для номеров, "следующих за камерой"
        self.follow_var = tk.BooleanVar()
        ttk.Checkbutton(bf, text="Show potential tracking",
                        variable=self.follow_var,
                        command=self.load_data).pack(side=tk.LEFT, padx=10)

        self.similar_var = tk.BooleanVar()
        ttk.Checkbutton(bf, text="Show plates with similar variants",
                        variable=self.similar_var,
                        command=self.load_data).pack(side=tk.LEFT, padx=10)

        self.setup_results_tree(lf)
        self.pw.add(lf)

    def setup_results_tree(self, parent):
        columns = ('plate', 'conf', 'country', 'appearances', 'videos', 'status')
        self.tree = ttk.Treeview(parent, columns=columns, show='headings')

        # Включаем сортировку по клику на заголовок
        for col in columns:
            self.tree.heading(col, text=col.capitalize(), command=lambda c=col: self.sort_column(c))

        self.tree.column('plate', width=100)
        self.tree.column('conf', width=80)
        self.tree.column('country', width=70)
        self.tree.column('appearances', width=90)
        self.tree.column('videos', width=70)
        self.tree.column('status', width=100)

        self.tree.tag_configure('blacklisted', foreground='red')
        self.tree.tag_configure('following', foreground='blue')
        self.tree.tag_configure('similar', foreground='purple')

        scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind('<<TreeviewSelect>>', self.on_select)

    def setup_right_panel(self):
        rf = ttk.Frame(self.pw)

        # Notebook для разных вкладок информации
        self.notebook = ttk.Notebook(rf)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Вкладка "Детали"
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text="Details")

        self.images_frame = ttk.Frame(self.details_frame)
        self.images_frame.pack(fill=tk.X, padx=5, pady=5)

        self.plate_image_label = ttk.Label(self.images_frame)
        self.plate_image_label.pack(side=tk.LEFT, padx=5)

        self.frame_image_label = ttk.Label(self.images_frame)
        self.frame_image_label.pack(side=tk.LEFT, padx=5)

        self.info_text = tk.Text(self.details_frame, wrap=tk.WORD, height=10, state=tk.DISABLED) # Start disabled
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Вкладка "История обнаружений"
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="Detection History")

        # Верхний фрейм со списком обнаружений
        self.history_list_frame = ttk.Frame(self.history_frame)
        self.history_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Создаем Treeview для истории обнаружений
        columns = ('time', 'real_time', 'source_file', 'confidence')
        self.history_tree = ttk.Treeview(self.history_list_frame, columns=columns, show='headings')

        self.history_tree.heading('time', text='Detection Time')
        self.history_tree.heading('real_time', text='Real Timestamp')
        self.history_tree.heading('source_file', text='Source File')
        self.history_tree.heading('confidence', text='Confidence')

        self.history_tree.column('time', width=150)
        self.history_tree.column('real_time', width=150)
        self.history_tree.column('source_file', width=200)
        self.history_tree.column('confidence', width=80)

        scroll_h = ttk.Scrollbar(self.history_list_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scroll_h.set)

        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_h.pack(side=tk.RIGHT, fill=tk.Y)

        self.history_tree.bind('<<TreeviewSelect>>', self.on_history_select)

        # Нижний фрейм для отображения изображений выбранного обнаружения
        self.history_images_frame = ttk.Frame(self.history_frame)
        self.history_images_frame.pack(fill=tk.X, padx=5, pady=5)

        self.history_plate_image = ttk.Label(self.history_images_frame)
        self.history_plate_image.pack(side=tk.LEFT, padx=5)

        self.history_frame_image = ttk.Label(self.history_images_frame)
        self.history_frame_image.pack(side=tk.LEFT, padx=5)

        # Вкладка "Похожие номера"
        self.similar_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.similar_frame, text="Similar Plates")

        # Фрейм для кнопки анализа
        analyze_frame = ttk.Frame(self.similar_frame)
        analyze_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(analyze_frame, text="Analyze Similar Plates",
                   command=self.analyze_similar_plates).pack(pady=5)

        # Создаем Treeview для похожих номеров
        columns = ('plate1', 'plate2', 'similarity', 'time_diff', 'note')
        self.similar_tree = ttk.Treeview(self.similar_frame, columns=columns, show='headings')

        self.similar_tree.heading('plate1', text='Plate 1')
        self.similar_tree.heading('plate2', text='Plate 2')
        self.similar_tree.heading('similarity', text='Similarity')
        self.similar_tree.heading('time_diff', text='Time Difference')
        self.similar_tree.heading('note', text='Note')

        self.similar_tree.column('plate1', width=100)
        self.similar_tree.column('plate2', width=100)
        self.similar_tree.column('similarity', width=70)
        self.similar_tree.column('time_diff', width=120)
        self.similar_tree.column('note', width=200)

        scroll_s = ttk.Scrollbar(self.similar_frame, orient=tk.VERTICAL, command=self.similar_tree.yview)
        self.similar_tree.configure(yscrollcommand=scroll_s.set)

        self.similar_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        scroll_s.pack(side=tk.RIGHT, fill=tk.Y)

        # Рамка с анализом потенциального слежения
        self.tracking_frame = ttk.LabelFrame(self.similar_frame, text="Tracking Analysis")
        self.tracking_frame.pack(fill=tk.X, padx=5, pady=5)

        self.tracking_text = scrolledtext.ScrolledText(self.tracking_frame, wrap=tk.WORD, height=5, state=tk.DISABLED) # Start disabled
        self.tracking_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Вкладка статистики
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        self.update_statistics() # Initial population

        bf = ttk.Frame(rf)
        bf.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(bf, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Add to Blacklist", command=self.add_selected_to_blacklist).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Open Detection Folder", command=self.open_detection_folder).pack(side=tk.LEFT, padx=5)

        self.pw.add(rf)

    def open_detection_folder(self):
        """
        Открывает папку с историей обнаружений для выбранного номера.
        """
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a plate first")
            return

        plate_text = self.tree.item(selection[0])['values'][0]
        try:
            plate_component = safe_path_component(str(plate_text))
            folder_path = managed_path("detection_history", plate_component)
            if folder_path.is_dir():
                webbrowser.open(local_file_uri(folder_path))
            else:
                messagebox.showinfo(
                    "Info",
                    f"Detection history folder for plate {plate_text} "
                    f"does not exist ({folder_path})",
                )
        except Exception as e:
            logging.error(f"Failed to open managed detection folder: {str(e)}")
            messagebox.showerror("Error", f"Failed to open folder: {str(e)}")

    def analyze_similar_plates(self):
        """
        Запускает анализ похожих номеров и обновляет интерфейс.
        """
        self.similar_tree.delete(*self.similar_tree.get_children())

        try:
            # Показываем сообщение о процессе
            progress_window = tk.Toplevel(self.master)
            progress_window.title("Analysis in progress")
            progress_window.geometry("300x100")
            progress_window.transient(self.master)
            progress_window.grab_set()

            ttk.Label(progress_window, text="Analyzing similar plates...").pack(pady=10)
            progress = ttk.Progressbar(progress_window, mode='indeterminate')
            progress.pack(fill=tk.X, padx=20, pady=10)
            progress.start()

            # Обновляем UI перед длительной операцией
            self.master.update_idletasks() # Use update_idletasks

            # Проводим анализ
            similar_plates = self.db.analyze_similar_plates()

            # Закрываем окно прогресса
            progress_window.destroy()

            # Заполняем дерево похожих номеров
            for plate1, plate2, ratio, distance, time_diff, note in similar_plates:
                plate_text1 = decode_if_bytes(plate1['plate_text'])
                plate_text2 = decode_if_bytes(plate2['plate_text'])

                # Форматируем время
                time1 = parse_date(decode_if_bytes(plate1['first_appearance']))
                time2 = parse_date(decode_if_bytes(plate2['first_appearance']))
                if time1 and time2:
                    _, time_diff_str = calculate_time_difference(time1, time2)
                else:
                    time_diff_str = "N/A"


                self.similar_tree.insert('', tk.END, values=(
                    plate_text1,
                    plate_text2,
                    f"{ratio:.2f}",
                    time_diff_str,
                    decode_if_bytes(note) # Decode note as well
                ))

            messagebox.showinfo("Analysis Complete", f"Found {len(similar_plates)} similar plate pairs")

        except Exception as e:
            # Ensure progress window is destroyed on error
            if 'progress_window' in locals() and progress_window.winfo_exists():
                progress_window.destroy()
            messagebox.showerror("Error", f"Failed to analyze similar plates: {str(e)}")
            logging.error(f"Error analyzing similar plates: {e}", exc_info=True)

    def update_statistics(self):
        """
        Обновляет/перерисовывает сводку статистики.
        """
        try:
            stats = self.db.get_plate_stats()
            # Если в базе пока нет номеров, средняя уверенность (avg_confidence) может быть None
            avg_confidence = stats.get('avg_confidence', None) # Use .get for safety
            if avg_confidence is None:
                avg_confidence_str = "N/A"
            else:
                avg_confidence_str = f"{avg_confidence:.2f}%" # Add %

            stats_text = (
                f"Total Unique Plates: {stats.get('total_plates', 0)}\n"
                f"Total Detections (main): {stats.get('total_detections', 0)}\n"
                f"Total All Detections (history): {stats.get('total_all_detections', 0)}\n"
                f"Blacklisted Plates Detected: {stats.get('blacklisted_detected', 0)}\n"
                f"Average Confidence: {avg_confidence_str}\n"
                f"Similar Plates Pairs: {stats.get('similar_plates_count', 0)}\n"
                f"Potential Tracking Cases: {stats.get('potential_follow_count', 0)}"
            )

            for widget in self.stats_frame.winfo_children():
                widget.destroy()

            # Use a LabelFrame for better visual structure
            stats_lf = ttk.LabelFrame(self.stats_frame, text="Summary")
            stats_lf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            ttk.Label(stats_lf, text=stats_text.strip(), justify=tk.LEFT).pack(padx=10, pady=10, anchor='nw')

        except Exception as e:
            logging.error(f"Error updating statistics: {e}", exc_info=True)
            for widget in self.stats_frame.winfo_children():
                widget.destroy()
            ttk.Label(self.stats_frame, text="Error loading statistics.", foreground="red").pack(padx=5, pady=5)


    def sort_column(self, col):
        """
        Сортирует данные в self.tree по выбранному столбцу col.
        """
        if self.current_sort['column'] == col:
            self.current_sort['reverse'] = not self.current_sort['reverse']
        else:
            self.current_sort['column'] = col
            self.current_sort['reverse'] = False

        # Add visual indicator (optional)
        for c in self.tree['columns']:
            self.tree.heading(c, text=c.capitalize()) # Reset text
        arrow = ' ▲' if not self.current_sort['reverse'] else ' ▼'
        self.tree.heading(col, text=col.capitalize() + arrow)


        self.load_data()

    def load_data(self):
        """
        Загружает данные из БД, применяет фильтрацию и сортировку, отображает в self.tree.
        """
        self.tree.delete(*self.tree.get_children())

        try:
            search_text = self.search_var.get().lower()
            profile_filter = self.profile_var.get()
            date_filter = self.date_var.get()
            blacklist_only = self.blacklist_var.get()
            follow_only = self.follow_var.get()
            similar_only = self.similar_var.get()

            plates = self.db.get_all_plates()

            # Pre-fetch follow and similar plate IDs for efficiency
            follow_plate_ids = set()
            if follow_only:
                follow_plates_data = self.db.find_potential_follow_plates()
                follow_plate_ids = {p['plate']['id'] for p in follow_plates_data}

            similar_plates_ids = set()
            if similar_only:
                similar_pairs = self.db.exec('SELECT plate_id1, plate_id2 FROM similar_plates').fetchall()
                for pair in similar_pairs:
                    similar_plates_ids.add(pair['plate_id1'])
                    similar_plates_ids.add(pair['plate_id2'])

            filtered_plates = []

            for plate in plates:
                plate_text_decoded = decode_if_bytes(plate['plate_text'])
                profile_decoded = decode_if_bytes(plate['profile'])

                # Filter by search text
                if search_text and search_text not in plate_text_decoded.lower():
                    continue
                # Filter by profile
                if profile_filter != "All" and profile_decoded != profile_filter:
                    continue
                # Filter by date
                if date_filter != "All":
                    last_appearance_str = decode_if_bytes(plate['last_appearance'])
                    plate_date = parse_date(last_appearance_str) # Use robust parse_date

                    if not plate_date:
                        logging.warning(f"Could not parse date for plate {plate_text_decoded}: {last_appearance_str}")
                        continue # Skip if date is invalid

                    now = datetime.datetime.now()
                    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

                    if date_filter == "Today":
                        if plate_date < today_start:
                            continue
                    elif date_filter == "Last 7 Days":
                        if plate_date < now - datetime.timedelta(days=7):
                            continue
                    elif date_filter == "Last 30 Days":
                        if plate_date < now - datetime.timedelta(days=30):
                            continue

                # Filter "only blacklisted"
                if blacklist_only and not plate['is_blacklisted']:
                    continue

                # Filter "potential tracking"
                if follow_only and plate['id'] not in follow_plate_ids:
                    continue

                # Filter "similar plates"
                if similar_only and plate['id'] not in similar_plates_ids:
                    continue

                filtered_plates.append(plate)

            # --- Sorting ---
            if self.current_sort['column']:
                key_func = None
                col_to_sort = self.current_sort['column']

                if col_to_sort == 'plate':
                    key_func = lambda x: decode_if_bytes(x['plate_text'])
                elif col_to_sort == 'conf':
                    key_func = lambda x: float(x['confidence'])
                elif col_to_sort == 'country':
                    key_func = lambda x: decode_if_bytes(x['country_code'])
                elif col_to_sort == 'appearances':
                    key_func = lambda x: int(x['total_appearances'])
                elif col_to_sort == 'videos':
                    # This can be slow if called repeatedly; consider pre-calculating or caching
                    key_func = lambda x: len(set(decode_if_bytes(d['source_file']) for d in self.db.get_plate_detections(x['id']) if d.get('source_file')))
                elif col_to_sort == 'status':
                    # Define a sort order for status
                    def get_status_sort_key(plate):
                        if plate['is_blacklisted']: return 3
                        if follow_only and plate['id'] in follow_plate_ids: return 2 # Check follow_only flag
                        if similar_only and plate['id'] in similar_plates_ids: return 1 # Check similar_only flag
                        # Need to check general similar status if similar_only is False but want to sort by it
                        if plate['id'] in similar_plates_ids: return 1
                        return 0 # Normal
                    key_func = get_status_sort_key

                if key_func:
                    try:
                        filtered_plates.sort(key=key_func, reverse=self.current_sort['reverse'])
                    except Exception as e:
                         logging.error(f"Sorting error on column '{col_to_sort}': {e}", exc_info=True)
                         # Reset sort if it fails
                         self.current_sort = {'column': None, 'reverse': False}


            # --- Populate Treeview ---
            # Pre-fetch all detections if needed for 'videos' count to avoid DB calls in loop
            all_detections_map = {}
            if self.current_sort['column'] != 'videos': # Only fetch if not already done during sort
                plate_ids_to_fetch = [p['id'] for p in filtered_plates]
                if plate_ids_to_fetch:
                     all_detections_list = self.db.get_detections_for_plates(plate_ids_to_fetch)
                     for det in all_detections_list:
                         p_id = det['plate_id']
                         if p_id not in all_detections_map:
                             all_detections_map[p_id] = []
                         all_detections_map[p_id].append(det)

            for plate in filtered_plates:
                plate_id = plate['id']
                # Get detections from pre-fetched map or query individually if map is empty
                detections = all_detections_map.get(plate_id, [])
                if not detections and not all_detections_map: # Fallback if pre-fetch failed or wasn't done
                    detections = self.db.get_plate_detections(plate_id)

                unique_videos = len(set(decode_if_bytes(d['source_file']) for d in detections if 'source_file' in d.keys() and d['source_file'] is not None))


                status = "Normal"
                tags = ()

                # Determine status and tags, prioritize blacklist, then follow, then similar
                if plate['is_blacklisted']:
                    status = "⚠️ Blacklisted"
                    tags = ('blacklisted',)
                elif plate_id in follow_plate_ids: # Check pre-fetched set
                     status = "👀 Tracking Potential" # Simplified status
                     tags = ('following',)
                elif plate_id in similar_plates_ids: # Check pre-fetched set
                     status = "🔄 Has Similar Variants"
                     tags = ('similar',)


                values = (
                    decode_if_bytes(plate['plate_text']),
                    f"{plate['confidence']:.1f}%",
                    decode_if_bytes(plate['country_code']),
                    plate['total_appearances'],
                    unique_videos,
                    status
                )

                self.tree.insert('', tk.END, values=values, tags=tags)

            self.update_statistics()

        except Exception as e:
            logging.error(f"Error loading data: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to load data: {str(e)}")


    def on_select(self, event):
        """
        При выборе записи в списке загружаем подробные данные и показываем в правой части.
        """
        selection = self.tree.selection()
        if selection:
            selected_item = self.tree.item(selection[0])
            plate_text = selected_item['values'][0]
            # Find plate data efficiently
            plate_data = self.db.get_plate_by_text(plate_text) # Assumes DB method exists

            if not plate_data:
                 # Fallback if get_plate_by_text doesn't exist or fails
                 all_plates = self.db.get_all_plates()
                 plate_data = next((p for p in all_plates if decode_if_bytes(p['plate_text']) == plate_text), None)

            if plate_data:
                self.update_details(plate_data)
                self.update_history(plate_data['id'])
                self.update_similar_plates(plate_data['id'])
                # Update images on detail tab
                plate_img_path = plate_data['plate_image_path'] if 'plate_image_path' in plate_data.keys() else None
                frame_img_path = plate_data['frame_image_path'] if 'frame_image_path' in plate_data.keys() else None

                self.update_images(plate_img_path, frame_img_path,
                                self.plate_image_label, self.frame_image_label)
                # Clear history images initially
                self.history_plate_image.configure(image=None)
                self.history_plate_image.image = None
                self.history_frame_image.configure(image=None)
                self.history_frame_image.image = None
            else:
                 logging.warning(f"Could not find data for selected plate: {plate_text}")
                 # Clear details if plate not found
                 self.clear_details()


    def clear_details(self):
        """Clears the right panel details."""
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete('1.0', tk.END)
        self.info_text.config(state=tk.DISABLED)

        self.plate_image_label.configure(image=None)
        self.plate_image_label.image = None
        self.frame_image_label.configure(image=None)
        self.frame_image_label.image = None

        self.history_tree.delete(*self.history_tree.get_children())
        self.history_plate_image.configure(image=None)
        self.history_plate_image.image = None
        self.history_frame_image.configure(image=None)
        self.history_frame_image.image = None

        self.similar_tree.delete(*self.similar_tree.get_children())
        self.tracking_text.config(state=tk.NORMAL)
        self.tracking_text.delete('1.0', tk.END)
        self.tracking_text.insert('1.0', "Select a plate to view details.")
        self.tracking_text.config(state=tk.DISABLED)

    def on_history_select(self, event):
        """
        При выборе записи в дереве истории обнаружений показываем соответствующие изображения.
        """
        selection = self.history_tree.selection()
        if selection:
            selected_item = self.history_tree.item(selection[0])
            tags = selected_item.get('tags')

            if tags and len(tags) >= 2:
                plate_image_path = tags[0]
                frame_image_path = tags[1]

                # Загружаем и отображаем изображения в панели истории
                self.update_images(plate_image_path, frame_image_path,
                                   self.history_plate_image, self.history_frame_image,
                                   plate_size=(150, 75), frame_size=(300, 150)) # Smaller history images
            else:
                logging.warning(f"Missing image paths in history item tags: {selected_item}")
                self.history_plate_image.configure(image=None)
                self.history_plate_image.image = None
                self.history_frame_image.configure(image=None)
                self.history_frame_image.image = None

    def update_details(self, plate_data):
        """
        Показывает детальную информацию о номере (plate_data) в text-widget + изображения.
        Отображает изображения с максимальной уверенностью распознавания.
        """
        self.info_text.config(state=tk.NORMAL) # Enable editing
        self.info_text.delete('1.0', tk.END)
        self.info_text.tag_remove('blacklisted', '1.0', 'end') # Remove old tags

        try:
            # Получаем историю обнаружений
            plate_id = plate_data['id']
            detections = self.db.get_plate_detections(plate_id)
            
            # Find detection with highest confidence
            best_detection = None
            highest_confidence = -1
            
            for d in detections:
                if 'confidence' in d.keys() and d['confidence'] > highest_confidence:
                    highest_confidence = d['confidence']
                    best_detection = d
            
            # Get unique videos
            unique_videos = set(decode_if_bytes(d['source_file']) for d in detections if 'source_file' in d.keys() and d['source_file'] is not None)

            # Format timestamps
            first_app_str = decode_if_bytes(plate_data['first_appearance'])
            last_app_str = decode_if_bytes(plate_data['last_appearance'])
            first_app = parse_date(first_app_str)
            last_app = parse_date(last_app_str)
            first_app_formatted = first_app.strftime('%Y-%m-%d %H:%M:%S') if first_app else first_app_str or 'N/A'
            last_app_formatted = last_app.strftime('%Y-%m-%d %H:%M:%S') if last_app else last_app_str or 'N/A'

            # If we found a best detection, use its images and add detection date
            best_detection_date = ""
            if best_detection:
                # Get best detection timestamp (prioritize real_timestamp)
                ts_str = decode_if_bytes(best_detection['real_timestamp']) if 'real_timestamp' in best_detection.keys() and best_detection['real_timestamp'] else None
                if not ts_str:
                    ts_str = decode_if_bytes(best_detection['detection_time']) if 'detection_time' in best_detection.keys() else None
                
                dt = parse_date(ts_str)
                if dt:
                    best_detection_date = f"\nBest Detection Date: {dt.strftime('%Y-%m-%d %H:%M:%S')}"
                
                # Update images with best detection images
                plate_img_path = best_detection['plate_image_path'] if 'plate_image_path' in best_detection.keys() else None
                frame_img_path = best_detection['frame_image_path'] if 'frame_image_path' in best_detection.keys() else None
                self.update_images(plate_img_path, frame_img_path, self.plate_image_label, self.frame_image_label)

            info_text = (
                f"Plate Number: {decode_if_bytes(plate_data['plate_text'])}\n"
                f"Confidence: {plate_data['confidence']:.1f}%\n"
                f"Country: {decode_if_bytes(plate_data['country_code'])}\n"
                f"First Seen: {first_app_formatted}\n"
                f"Last Seen: {last_app_formatted}{best_detection_date}\n"
                f"Total Appearances: {plate_data['total_appearances']}\n"
                f"Unique Videos: {len(unique_videos)}\n"
                f"Profile: {decode_if_bytes(plate_data['profile'])}\n"
            )




            # Handle blacklist information
            is_blacklisted = plate_data['is_blacklisted'] if 'is_blacklisted' in plate_data.keys() else False
            if is_blacklisted:
                reason = decode_if_bytes(plate_data['blacklist_reason'] if 'blacklist_reason' in plate_data.keys() else 'N/A')
                danger = decode_if_bytes(plate_data['danger_level'] if 'danger_level' in plate_data.keys() else 'N/A')
                info_text += (
                    f"\n⚠️ BLACKLISTED\n"
                    f"Reason: {reason}\n"
                    f"Danger Level: {danger}"
                )


            # Check for potential follow based on detections
            valid_detections_for_follow = []
            if detections:
                for d in detections:
                    # Prioritize real_timestamp
                    ts_str = decode_if_bytes(d['real_timestamp'] if 'real_timestamp' in d.keys() and d['real_timestamp'] else d['detection_time'])
                    dt = parse_date(ts_str) # Use robust parsing
                    if dt:
                        valid_detections_for_follow.append({
                            'detection_time': dt,
                            'confidence': d['confidence'] if 'confidence' in d.keys() else 0.0,
                            'image_path': d['frame_image_path'] if 'frame_image_path' in d.keys() else ''
                        })

            if len(valid_detections_for_follow) >= 3:
                # Sort by time before checking
                valid_detections_for_follow.sort(key=lambda x: x['detection_time'])
                from utils import is_potential_follow # Import here if not globally needed
                # Use settings for threshold, or a default
                follow_threshold = self.db.get_setting('tracking_time_threshold', 300)
                is_follow, reason = is_potential_follow(valid_detections_for_follow, threshold_seconds=follow_threshold)
                if is_follow:
                    info_text += f"\n\n👀 POTENTIAL TRACKING DETECTED\n{reason}"

            self.info_text.insert('1.0', info_text)

            if is_blacklisted:
                # Find the start of the blacklist section
                bl_start_index = self.info_text.search("⚠️ BLACKLISTED", '1.0', tk.END)
                if bl_start_index:
                    self.info_text.tag_add('blacklisted', bl_start_index, tk.END)
                    self.info_text.tag_config('blacklisted', foreground='red', font=('Helvetica', 10, 'bold'))

        except Exception as e:
            plate_id_for_log = plate_data['id'] if plate_data and 'id' in plate_data.keys() else 'N/A'
            logging.error(f"Error updating details for plate {plate_id_for_log}: {e}", exc_info=True)
            self.info_text.insert('1.0', "Error displaying details.")
        finally:
            self.info_text.config(state=tk.DISABLED) # Disable editing again
    def update_history(self, plate_id):
        """
        Обновляет дерево истории обнаружений для выбранного номера.
        """
        # Очищаем дерево
        self.history_tree.delete(*self.history_tree.get_children())

        try:
            # Получаем историю обнаружений
            detections = self.db.get_plate_detections(plate_id)

            # Sort detections by time (most recent first, or oldest first)
            # Define the key function separately for clarity
            def get_sort_key(det): # Use 'det' to avoid confusion with the loop variable later
                ts_str = decode_if_bytes(det['real_timestamp']) if 'real_timestamp' in det.keys() and det['real_timestamp'] else None
                if not ts_str:
                    ts_str = decode_if_bytes(det['detection_time']) if 'detection_time' in det.keys() and det['detection_time'] else None
                parsed_date = parse_date(ts_str)
                return parsed_date or datetime.datetime.min

            detections.sort(key=get_sort_key, reverse=True)


            for detection in detections: # <--- Loop variable is 'detection'
                # Форматируем временные метки
                # --- FIX: Use 'detection' instead of 'd' ---
                detection_time_str = decode_if_bytes(detection['detection_time'] if 'detection_time' in detection.keys() else '')
                real_timestamp_str = decode_if_bytes(detection['real_timestamp'] if 'real_timestamp' in detection.keys() else '')
                # --- End of FIX ---

                # Parse dates for display if possible
                dt_display = parse_date(detection_time_str)
                rt_display = parse_date(real_timestamp_str)

                detection_time_formatted = dt_display.strftime('%Y-%m-%d %H:%M:%S') if dt_display else detection_time_str or "Unknown"
                real_time_formatted = rt_display.strftime('%Y-%m-%d %H:%M:%S') if rt_display else real_timestamp_str or "Unknown"

                # --- FIX: Use 'detection['key']' instead of .get() ---
                source_file = decode_if_bytes(detection['source_file'] if 'source_file' in detection.keys() else 'Unknown')
                confidence = detection['confidence'] if 'confidence' in detection.keys() else 0.0
                # --- End of FIX ---

                # Get image paths safely
                plate_img_path = detection['plate_image_path'] if 'plate_image_path' in detection.keys() else ''
                frame_img_path = detection['frame_image_path'] if 'frame_image_path' in detection.keys() else ''


                # Вставляем запись в дерево
                item_id = self.history_tree.insert('', tk.END, values=(
                    detection_time_formatted,
                    real_time_formatted,
                    source_file,
                    f"{confidence:.1f}%"
                ))

                # Сохраняем пути к изображениям в тегах
                self.history_tree.item(item_id, tags=(plate_img_path, frame_img_path))

        except Exception as e:
            logging.error(f"Error updating history for plate {plate_id}: {e}", exc_info=True)
            # Optionally display an error in the tree itself
            self.history_tree.insert('', tk.END, values=("Error loading history.", "", "", ""))

    def update_similar_plates(self, plate_id):
        """
        Обновляет информацию о похожих номерах и анализе слежения для выбранного номера.
        """
        # Очищаем дерево похожих номеров
        self.similar_tree.delete(*self.similar_tree.get_children())

        # Очищаем и подготавливаем текст анализа слежения
        self.tracking_text.config(state=tk.NORMAL)
        self.tracking_text.delete('1.0', tk.END)
        self.tracking_text.tag_remove('follow', '1.0', tk.END) # Clear previous tags

        try:
            # --- Похожие номера ---
            # get_similar_plates should return a list of sqlite3.Row objects
            similar_plates = self.db.get_similar_plates(plate_id)

            for sp in similar_plates: # sp is a sqlite3.Row object
                # Safely access data using dictionary-style access with checks
                plate_text1 = decode_if_bytes(sp['plate_text1'] if 'plate_text1' in sp.keys() else '')
                plate_text2 = decode_if_bytes(sp['plate_text2'] if 'plate_text2' in sp.keys() else '')
                time_diff_seconds = sp['time_diff_seconds'] if 'time_diff_seconds' in sp.keys() else None
                note = decode_if_bytes(sp['detection_note'] if 'detection_note' in sp.keys() else '')
                similarity_score = sp['similarity_score'] if 'similarity_score' in sp.keys() else 0.0

                # Форматируем время (разница уже посчитана в секундах)
                time_diff_str = "N/A"
                if time_diff_seconds is not None:
                     # Create dummy datetimes just to use the formatting function
                     dummy_dt = datetime.datetime.now()
                     try:
                         _, time_diff_str = calculate_time_difference(
                             dummy_dt,
                             dummy_dt + datetime.timedelta(seconds=abs(time_diff_seconds)) # Use abs for safety
                         )
                     except Exception as time_err: # Catch potential errors in timedelta calculation
                         logging.warning(f"Error calculating time difference string: {time_err}")
                         pass # Keep "N/A"

                self.similar_tree.insert('', tk.END, values=(
                    plate_text1,
                    plate_text2,
                    f"{similarity_score:.2f}",
                    time_diff_str,
                    note
                ))

            # --- Анализ слежения ---
            plate = self.db.get_plate_by_id(plate_id) # plate is also a sqlite3.Row or None
            if plate:
                detections = self.db.get_plate_detections(plate_id) # detections is a list of sqlite3.Row

                valid_detections_for_follow = []
                if detections:
                     for d in detections: # d is a sqlite3.Row here
                         # Safely get timestamp string, prioritizing real_timestamp
                         ts_str = decode_if_bytes(d['real_timestamp']) if 'real_timestamp' in d.keys() and d['real_timestamp'] else None
                         if not ts_str: # Fallback to detection_time
                             ts_str = decode_if_bytes(d['detection_time']) if 'detection_time' in d.keys() and d['detection_time'] else None

                         dt = parse_date(ts_str) # parse_date should return datetime or None
                         if dt:
                             # Safely get other detection data
                             confidence = d['confidence'] if 'confidence' in d.keys() else 0.0
                             image_path = d['frame_image_path'] if 'frame_image_path' in d.keys() else ''
                             valid_detections_for_follow.append({
                                 'detection_time': dt,
                                 'confidence': confidence,
                                 'image_path': image_path
                             })

                # Use tracking settings from DB or defaults
                min_dets_for_tracking = self.db.get_setting('min_tracking_detections', 3)
                follow_threshold = self.db.get_setting('tracking_time_threshold', 300)

                if len(valid_detections_for_follow) >= min_dets_for_tracking:
                    valid_detections_for_follow.sort(key=lambda x: x['detection_time']) # Sort by time

                    is_follow, reason = is_potential_follow(valid_detections_for_follow, threshold_seconds=follow_threshold)

                    if is_follow:
                        follow_start_index = '1.0'
                        follow_reason_text = f"POTENTIAL TRACKING DETECTED: {reason}\n\n"
                        self.tracking_text.insert(follow_start_index, follow_reason_text)
                        # Calculate end index based on inserted text length
                        follow_end_index = self.tracking_text.index(f"{follow_start_index} + {len(follow_reason_text)} chars")
                        self.tracking_text.tag_add('follow', follow_start_index, follow_end_index)
                        self.tracking_text.tag_config('follow', foreground='blue', font=('Helvetica', 10, 'bold'))

                        # Показываем историю обнаружений для слежения
                        for i in range(len(valid_detections_for_follow)):
                            curr = valid_detections_for_follow[i]
                            curr_time = curr['detection_time']
                            confidence = curr['confidence']

                            line_text = f"Detection {i+1}: {curr_time.strftime('%Y-%m-%d %H:%M:%S')} (Conf: {confidence:.1f}%)"

                            if i > 0:
                                prev_time = valid_detections_for_follow[i-1]['detection_time']
                                try:
                                    _, diff_str = calculate_time_difference(prev_time, curr_time)
                                    line_text += f" (Interval: {diff_str})"
                                except Exception as time_err:
                                     logging.warning(f"Error calculating interval for tracking display: {time_err}")

                            self.tracking_text.insert(tk.END, line_text + "\n")
                    else:
                        # Provide more context if not tracking
                        self.tracking_text.insert('1.0', "No tracking pattern detected based on current settings.\n")
                        if valid_detections_for_follow:
                             self.tracking_text.insert(tk.END, f"Number of valid detections: {len(valid_detections_for_follow)}\n")
                             if len(valid_detections_for_follow) >= 2:
                                 sorted_times = [d['detection_time'] for d in valid_detections_for_follow] # Already sorted
                                 try:
                                     _, time_span = calculate_time_difference(sorted_times[0], sorted_times[-1])
                                     self.tracking_text.insert(tk.END, f"Time span between first and last detection: {time_span}\n")
                                 except Exception as time_err:
                                      logging.warning(f"Error calculating time span: {time_err}")
                        self.tracking_text.insert(tk.END, f"(Settings: Min Detections={min_dets_for_tracking}, Time Window={follow_threshold}s)\n")

                else:
                    self.tracking_text.insert('1.0', f"Not enough valid detection data ({len(valid_detections_for_follow)} found, {min_dets_for_tracking} required) for tracking analysis.\n")
            else:
                self.tracking_text.insert('1.0', "No plate data available for tracking analysis.\n")

        except Exception as e:
            logging.error(f"Error updating similar plates/tracking for plate {plate_id}: {e}", exc_info=True)
            self.tracking_text.insert('1.0', "Error loading analysis data.")
        finally:
            self.tracking_text.config(state=tk.DISABLED) # Disable editing

    def update_images(self, plate_path, frame_path, plate_label, frame_label, plate_size=(200, 100), frame_size=(400, 200)):
        """
        Загрузка и отображение миниатюр изображений на указанных метках.
        """
        # Update Plate Image
        plate_image = load_and_resize_image(plate_path, plate_size)
        plate_label.configure(image=plate_image if plate_image else None)
        plate_label.image = plate_image # Keep reference to prevent garbage collection

        # Update Frame Image
        frame_image = load_and_resize_image(frame_path, frame_size)
        frame_label.configure(image=frame_image if frame_image else None)
        frame_label.image = frame_image # Keep reference to prevent garbage collection

    def export_report(self):
        """Export one immutable, redacted bundle from a read-only DB snapshot."""
        if self._report_export_active:
            messagebox.showinfo(
                "Report Export in Progress",
                "The current redacted report export is still running.",
            )
            return
        output_parent = filedialog.askdirectory(
            title="Select Folder for Redacted Offline Report",
            mustexist=True,
        )
        if not output_parent:
            return

        progress_window = tk.Toplevel(self.master)
        progress_window.title("Exporting Report")
        progress_window.geometry("300x100")
        progress_window.transient(self.master)
        progress_window.grab_set()
        progress_window.protocol("WM_DELETE_WINDOW", lambda: None)
        ttk.Label(
            progress_window,
            text="Building a redacted offline snapshot...",
        ).pack(pady=10)
        progress = ttk.Progressbar(progress_window, mode="indeterminate")
        progress.pack(fill=tk.X, padx=20, pady=10)
        progress.start()
        self.master.update_idletasks()

        completion_queue = queue.SimpleQueue()
        self._report_export_active = True

        def finish_export(export_result, error):
            progress.stop()
            try:
                progress_window.grab_release()
            except tk.TclError:
                pass
            if progress_window.winfo_exists():
                progress_window.destroy()
            self._report_export_active = False

            if error is not None:
                logging.error(
                    "Redacted report export failed (%s): %s",
                    type(error).__name__,
                    error,
                )
                messagebox.showerror(
                    "Report Export Refused",
                    f"The redacted report was not exported: {error}",
                )
                return

            completion_message = (
                "The immutable offline report omits raw identifiers, "
                "timestamps, source names, reasons, paths, and images.\n\n"
                f"Bundle: {export_result.bundle_root.name}"
            )
            if export_result.durability_warning is not None:
                completion_message += (
                    "\n\nDurability warning: "
                    f"{export_result.durability_warning}."
                )
                messagebox.showwarning(
                    "Redacted Report Published with Warning",
                    completion_message,
                )
            else:
                messagebox.showinfo(
                    "Redacted Report Ready",
                    completion_message,
                )
            if messagebox.askyesno(
                "Open Report",
                "Would you like to open the exported report in your browser?",
            ):
                try:
                    webbrowser.open(local_file_uri(export_result.index_path))
                except Exception as open_error:
                    logging.error("Failed to open report in browser: %s", open_error)
                    messagebox.showwarning(
                        "Browser Error",
                        f"Could not automatically open the report: {open_error}",
                    )

        def poll_completion():
            try:
                completed_result, error = completion_queue.get_nowait()
            except queue.Empty:
                self.master.after(50, poll_completion)
                return
            finish_export(completed_result, error)

        def run_export():
            try:
                export_result = export_offline_report(self.db.path, output_parent)
            except Exception as error:
                completion_queue.put((None, error))
            else:
                completion_queue.put((export_result, None))

        worker = threading.Thread(
            target=run_export,
            name="CorporateHub-report-export",
            daemon=True,
        )
        try:
            worker.start()
        except Exception as error:
            finish_export(None, error)
            return
        self.master.after(50, poll_completion)

    def add_selected_to_blacklist(self):
        """
        Добавляет выбранный номер в blacklist с указанием причины и уровня опасности.
        """
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a plate first")
            return

        plate_text = self.tree.item(selection[0])['values'][0]

        # Check if already blacklisted
        plate_data = self.db.get_plate_by_text(plate_text)
        if plate_data and plate_data.get('is_blacklisted'):
             if not messagebox.askyesno("Confirm", f"Plate {plate_text} is already blacklisted.\nDo you want to update its reason and danger level?"):
                 return
             # Pre-fill existing data if updating
             initial_reason = decode_if_bytes(plate_data.get('blacklist_reason', ''))
             initial_danger = decode_if_bytes(plate_data.get('danger_level', 'HIGH'))
        else:
            initial_reason = ""
            initial_danger = "HIGH"


        # --- Create Dialog ---
        dialog = tk.Toplevel(self.master)
        dialog.title(f"Blacklist: {plate_text}")
        dialog.geometry("400x250") # Adjusted size
        dialog.transient(self.master) # Keep on top of main window
        dialog.grab_set() # Modal behavior
        dialog.resizable(False, False)

        main_frame = ttk.Frame(dialog, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Reason
        ttk.Label(main_frame, text="Reason:").grid(row=0, column=0, sticky="w", pady=(0, 2))
        reason_entry = ttk.Entry(main_frame, width=45)
        reason_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        reason_entry.insert(0, initial_reason)

        # Danger Level
        ttk.Label(main_frame, text="Danger Level:").grid(row=2, column=0, sticky="w", pady=(0, 2))
        danger_var = tk.StringVar(value=initial_danger)
        danger_options = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        # Ensure initial_danger is valid, default if not
        if initial_danger not in danger_options: danger_var.set("HIGH")
        danger_cb = ttk.Combobox(main_frame, textvariable=danger_var, values=danger_options, state="readonly") # Readonly prevents typing invalid values
        danger_cb.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 15))

        # Buttons Frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=4, column=0, columnspan=2, sticky="e")

        def save():
            reason = reason_entry.get().strip()
            danger = danger_var.get()
            if not reason:
                messagebox.showwarning("Input Required", "Please enter a reason for blacklisting.", parent=dialog)
                reason_entry.focus()
                return

            try:
                self.db.add_to_blacklist(plate_text, reason, danger)
                messagebox.showinfo("Success", f"Plate {plate_text} added/updated in blacklist.", parent=dialog)
                self.load_data() # Refresh the main list
                dialog.destroy()
            except Exception as e:
                 logging.error(f"Failed to add {plate_text} to blacklist: {e}", exc_info=True)
                 messagebox.showerror("Database Error", f"Failed to update blacklist: {str(e)}", parent=dialog)

        def cancel():
            dialog.destroy()

        save_button = ttk.Button(buttons_frame, text="Save", command=save, style="Accent.TButton") # Style for emphasis
        save_button.pack(side=tk.LEFT, padx=(0, 5))

        cancel_button = ttk.Button(buttons_frame, text="Cancel", command=cancel)
        cancel_button.pack(side=tk.LEFT)

        # Set focus
        reason_entry.focus()
        dialog.bind('<Return>', lambda e: save()) # Allow Enter key to save
        dialog.bind('<Escape>', lambda e: cancel()) # Allow Esc key to cancel

        # Center dialog (optional)
        dialog.update_idletasks()
        x = self.master.winfo_rootx() + (self.master.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.master.winfo_rooty() + (self.master.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f'+{x}+{y}')

        dialog.wait_window() # Wait until the dialog is closed
