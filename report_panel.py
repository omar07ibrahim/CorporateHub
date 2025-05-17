# report_panel.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import datetime
import logging
import webbrowser
from PIL import Image, ImageTk
import shutil # Import shutil for copying files

from database import DB
from utils import load_and_resize_image, parse_date, decode_if_bytes, calculate_time_difference,is_potential_follow 


class ReportPanel:
    """
    Панель для отображения отчетов:
    - Список номеров (с возможностью фильтрации и поиска)
    - Детальная информация и изображения
    - История обнаружений с временными метками
    - Похожие номера
    - Статистика и экспорт отчета в HTML
    """
    def __init__(self, master):
        self.master = master
        self.db = DB()
        self.current_sort = {'column': None, 'reverse': False}
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
        # Ensure folder name is valid (replace problematic characters if needed)
        safe_plate_text = "".join(c if c.isalnum() else "_" for c in plate_text)
        folder_path = os.path.join("detection_history", safe_plate_text)

        if os.path.exists(folder_path):
            # Открываем папку в проводнике
            try:
                # Use os.path.abspath for robustness
                abs_folder_path = os.path.abspath(folder_path)
                if os.name == 'nt':  # Windows
                    os.startfile(abs_folder_path)
                elif os.name == 'posix':  # macOS, Linux
                    webbrowser.open(f"file://{abs_folder_path}") # More reliable cross-platform way
                else:
                    webbrowser.open(f"file://{abs_folder_path}") # Fallback
            except Exception as e:
                logging.error(f"Failed to open folder: {abs_folder_path} - {str(e)}")
                messagebox.showerror("Error", f"Failed to open folder: {str(e)}")
        else:
            messagebox.showinfo("Info", f"Detection history folder for plate {plate_text} does not exist ({folder_path})")

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
        """
        Экспорт всего списка plates в HTML-отчет со статистикой и копированием изображений.
        """
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML files", "*.html")],
                                            title="Save HTML Report As")
        if path:
            try:
                # Show progress/loading indicator
                progress_window = tk.Toplevel(self.master)
                progress_window.title("Exporting Report")
                progress_window.geometry("300x100")
                progress_window.transient(self.master)
                progress_window.grab_set()
                ttk.Label(progress_window, text="Gathering data and generating report...").pack(pady=10)
                progress = ttk.Progressbar(progress_window, mode='indeterminate')
                progress.pack(fill=tk.X, padx=20, pady=10)
                progress.start()
                self.master.update_idletasks()

                plates_data = self.db.get_all_plates() # Fetch all plates
                self.export_html(path, plates_data) # Generate the report

                progress_window.destroy() # Close progress window

                messagebox.showinfo("Success", "Report exported successfully!")

                # Открываем отчет в браузере
                if messagebox.askyesno("Open Report", "Would you like to open the exported report in your browser?"):
                     try:
                         abs_path = os.path.abspath(path)
                         webbrowser.open('file://' + abs_path)
                     except Exception as e_open:
                         logging.error(f"Failed to open report in browser: {e_open}")
                         messagebox.showwarning("Browser Error", f"Could not automatically open the report: {e_open}")


            except Exception as e:
                if 'progress_window' in locals() and progress_window.winfo_exists():
                    progress_window.destroy()
                logging.error(f"Failed to export report: {e}", exc_info=True)
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")

    def export_html(self, path, plates_data):
        """
        Формирует HTML-файл отчета и копирует изображения в отдельную папку report_images.
        Включает историю обнаружений и похожие номера.
        """
        report_dir = os.path.dirname(path)
        images_dir = os.path.join(report_dir, 'report_images')
        os.makedirs(images_dir, exist_ok=True)

        # Helper function to safely access sqlite3.Row objects like a dict with get behavior
        def safe_get(row, key, default=None):
            try:
                return row[key] if key in row.keys() else default
            except (IndexError, TypeError, KeyError):
                return default

        def copy_image(src_path):
            src_path = decode_if_bytes(src_path) # Ensure path is string
            if src_path and os.path.exists(src_path):
                try:
                    filename = os.path.basename(src_path)
                    # Make filename slightly more unique if needed (e.g., add timestamp prefix)
                    # timestamp_prefix = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f_")
                    # dst_filename = timestamp_prefix + filename
                    dst_path = os.path.join(images_dir, filename) # Use original filename for simplicity
                    if not os.path.exists(dst_path): # Avoid redundant copies
                        shutil.copy2(src_path, dst_path)
                    # Use relative path for HTML
                    return f'report_images/{filename}'
                except Exception as e:
                    logging.error(f"Failed to copy image {src_path} to {images_dir}: {e}")
            return None # Return None if copy fails or source doesn't exist

        report_data = []
        profiles = set()
        dates_dict = {} # For chart data {date_str: count}

        # Analyze similar and tracking plates *once* for the entire report
        try:
            all_similar_pairs_data = self.db.analyze_similar_plates()
        except Exception as e:
            logging.error(f"Error analyzing similar plates for report: {e}")
            all_similar_pairs_data = []

        try:
            all_following_plates_data = self.db.find_potential_follow_plates()
            following_plate_ids = {fp['plate']['id']: fp['reason'] for fp in all_following_plates_data}
        except Exception as e:
            logging.error(f"Error finding potential tracking plates for report: {e}")
            following_plate_ids = {}


        plate_ids_for_detections = [p['id'] for p in plates_data]
        all_detections_map = {}
        if plate_ids_for_detections:
            all_detections_list = self.db.get_detections_for_plates(plate_ids_for_detections)
            for det in all_detections_list:
                p_id = det['plate_id']
                if p_id not in all_detections_map:
                    all_detections_map[p_id] = []
                all_detections_map[p_id].append(det)


        # Process each plate
        for plate in plates_data:
            plate_id = plate['id']
            plate_dict = dict(plate) # Make a mutable copy

            # Decode byte strings and copy images
            plate_dict['plate_text'] = decode_if_bytes(plate['plate_text'])
            plate_dict['country_code'] = decode_if_bytes(safe_get(plate, 'country_code', ''))
            plate_dict['profile'] = decode_if_bytes(safe_get(plate, 'profile', ''))
            plate_dict['blacklist_reason'] = decode_if_bytes(safe_get(plate, 'blacklist_reason', ''))
            plate_dict['danger_level'] = decode_if_bytes(safe_get(plate, 'danger_level', ''))

            # Handle image paths
            plate_image_path = safe_get(plate, 'plate_image_path')
            frame_image_path = safe_get(plate, 'frame_image_path')
            plate_dict['plate_image'] = copy_image(plate_image_path)
            plate_dict['frame_image'] = copy_image(frame_image_path)

            # Format dates
            first_app = parse_date(decode_if_bytes(safe_get(plate, 'first_appearance')))
            last_app = parse_date(decode_if_bytes(safe_get(plate, 'last_appearance')))
            plate_dict['first_appearance'] = first_app.strftime('%Y-%m-%d %H:%M:%S') if first_app else 'N/A'
            plate_dict['last_appearance'] = last_app.strftime('%Y-%m-%d %H:%M:%S') if last_app else 'N/A'


            # Process detection history for this plate
            detections = all_detections_map.get(plate_id, [])
            detection_history = []
            valid_timestamps = []
            unique_video_sources = set()

            # Sort detections by time for timeline consistency
            detections.sort(key=lambda d: 
                parse_date(decode_if_bytes(safe_get(d, 'real_timestamp')) or 
                        decode_if_bytes(safe_get(d, 'detection_time'))) 
                or datetime.datetime.min)

            for d in detections:
                # Get timestamps
                detection_time_str = decode_if_bytes(safe_get(d, 'detection_time', ''))
                real_timestamp_str = decode_if_bytes(safe_get(d, 'real_timestamp', ''))
                dt_time = parse_date(detection_time_str)
                rt_time = parse_date(real_timestamp_str)

                # Get source file and track unique videos
                source_file = decode_if_bytes(safe_get(d, 'source_file', 'Unknown'))
                if source_file and source_file != 'Unknown':
                    unique_video_sources.add(source_file)

                detection_dict = {
                    'detection_time': dt_time.strftime('%Y-%m-%d %H:%M:%S') if dt_time else detection_time_str or 'Unknown',
                    'real_timestamp': rt_time.strftime('%Y-%m-%d %H:%M:%S') if rt_time else real_timestamp_str or 'Unknown',
                    'source_file': source_file,
                    'confidence': safe_get(d, 'confidence', 0.0),
                    'plate_image': copy_image(safe_get(d, 'plate_image_path')),
                    'frame_image': copy_image(safe_get(d, 'frame_image_path')),
                    'timestamp_obj': rt_time or dt_time # Store for sorting/interval calc
                }
                detection_history.append(detection_dict)
                if rt_time: valid_timestamps.append(rt_time)
                elif dt_time: valid_timestamps.append(dt_time)


            plate_dict['detection_history'] = detection_history
            unique_videos_count = len(unique_video_sources)
            plate_dict['unique_videos'] = unique_videos_count

            # Check if in identified following plates (from DB analysis)
            plate_dict['is_following'] = plate_id in following_plate_ids
            plate_dict['follow_reason'] = following_plate_ids.get(plate_id, "")

            # Additional check for tracking (appears in more than 4 video files)
            if unique_videos_count >= 4 and not plate_dict['is_following']:
                plate_dict['is_following'] = True
                plate_dict['follow_reason'] = f"Detected in {unique_videos_count} different video files"


            # Add to profile set and date dict
            profiles.add(plate_dict['profile'])
            if first_app:
                date_str = first_app.strftime('%Y-%m-%d')
                dates_dict[date_str] = dates_dict.get(date_str, 0) + 1

            report_data.append(plate_dict)

        # Calculate overall stats
        total_plates = len(report_data)
        if total_plates > 0:
            # Ensure confidence is float before summing
            valid_confs = [float(p['confidence']) for p in report_data if isinstance(p.get('confidence'), (int, float, str)) and str(p.get('confidence')).replace('.', '', 1).isdigit()]
            avg_conf = sum(valid_confs) / len(valid_confs) if valid_confs else 0
        else:
            avg_conf = 0

        # Count tracking plates including the additional 4+ videos criterion
        tracking_count = sum(1 for p in report_data if p.get('is_following'))

        stats = {
            'total_plates': total_plates,
            'total_detections': sum(int(p.get('total_appearances', 1)) for p in report_data), # Sum appearances from main table
            'total_all_detections': sum(len(p['detection_history']) for p in report_data), # Count history events
            'blacklisted': sum(1 for p in report_data if p.get('is_blacklisted')),
            'avg_confidence': avg_conf,
            'countries': len({p['country_code'] for p in report_data if p.get('country_code')}),
            'profiles': len(profiles),
            'similar_plates': len(all_similar_pairs_data), # Use pre-analyzed count
            'tracking_plates': tracking_count # Use pre-analyzed count PLUS our 4+ videos criterion
        }


        # Prepare chart data
        sorted_dates = sorted(dates_dict.keys())
        date_labels = str(sorted_dates) # Convert list to string representation for JS
        date_values = str([dates_dict[d] for d in sorted_dates]) # Convert list to string for JS

        # Correct calculation for pie chart (avoid double counting)
        normal_plates = stats['total_plates'] - stats['blacklisted'] - stats['tracking_plates']
        normal_plates = max(0, normal_plates) # Ensure it's not negative
        pie_data = str([stats['blacklisted'], stats['tracking_plates'], normal_plates])


        # --- Create HTML ---
        # (Using f-string; be careful with quotes inside expressions)
        html_content = f'''<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>LPR System Report - {datetime.datetime.now().strftime('%Y-%m-%d')}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #eee; }}
            h1, h2, h3, h4 {{ color: #333; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
            .stat-card {{ background-color: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; border: 1px solid #eee; }}
            .stat-card h3 {{ margin: 0 0 8px; font-size: 1em; color: #555; }}
            .stat-card p {{ margin: 0; font-size: 1.4em; font-weight: bold; color: #333; }}
            .chart-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }}
            .chart-box {{ background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border: 1px solid #eee; }}
            .tabs {{ display: flex; margin-bottom: 20px; border-bottom: 1px solid #ddd; }}
            .tab {{ padding: 10px 20px; cursor: pointer; background-color: #eee; border: 1px solid #ddd; border-bottom: none; margin-right: 5px; border-radius: 4px 4px 0 0; }}
            .tab.active {{ background-color: white; font-weight: bold; border-bottom: 1px solid white; position: relative; top: 1px; }}
            .tab-content {{ display: none; padding-top: 20px; }}
            .tab-content.active {{ display: block; }}
            .plates {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }}
            .plate-card {{ background-color: white; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; transition: transform .2s, box-shadow .2s; }}
            .plate-card:hover {{ transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0,0,0,0.1); }}
            .plate-card.blacklisted {{ border-left: 5px solid #dc3545; }}
            .plate-card.following {{ border-left: 5px solid #0d6efd; }}
            .warning-block {{ padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; font-weight: bold; }}
            .blacklist-warning {{ background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
            .follow-warning {{ background-color: #cce5ff; color: #004085; border: 1px solid #b8daff; }}
            .plate-images {{ display: flex; gap: 10px; padding: 10px; background-color:#f9f9f9; border-bottom: 1px solid #eee; justify-content: center; }}
            .plate-images img {{ max-width: 45%; height: auto; border-radius: 4px; cursor: pointer; border: 1px solid #ddd; object-fit: contain; }}
            .plate-info {{ padding: 15px; }}
            .plate-info h3 {{ margin: 0 0 10px; font-size: 1.2em; }}
            .blacklisted .plate-info h3 {{ color: #dc3545; }}
            .following .plate-info h3 {{ color: #0d6efd; }}
            .plate-info p {{ margin: 5px 0; color: #666; font-size: 0.9em; }}
            .plate-info strong {{ color: #333; }}
            .confidence {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: white; }}
            .detection-details {{ margin-top: 15px; padding: 15px; border-top: 1px solid #eee; background-color: #fafafa; }}
            .detection-details h4 {{ margin: 0 0 10px; font-size: 1em; color: #444; }}
            .detection-history table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 0.85em; }}
            .detection-history th, .detection-history td {{ padding: 6px 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            .detection-history th {{ background-color: #e9ecef; font-weight: bold; }}
            .detection-gallery {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
            .detection-item {{ width: 80px; margin-bottom: 8px; position: relative; border: 1px solid #ccc; border-radius: 4px; overflow:hidden; background: #eee; }}
            .detection-item img {{ display: block; width: 100%; height: 50px; object-fit: cover; cursor: pointer; }}
            .detection-item .detection-time {{ font-size: 9px; background: rgba(0,0,0,0.6); color: white; padding: 2px 3px; position: absolute; bottom: 0; left: 0; right: 0; text-align: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
            .modal {{ display: none; position: fixed; z-index: 1000; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.85); align-items: center; justify-content: center; }}
            .modal-content {{ display: block; max-width: 90%; max-height: 85vh; }}
            .modal-close {{ position: absolute; top: 20px; right: 35px; color: #f1f1f1; font-size: 40px; font-weight: bold; cursor: pointer; line-height: 1; }}
            .modal-close:hover {{ color: #bbb; }}
            #modalCaption {{ color:white; text-align:center; padding-top:15px; font-size: 1.1em; }}
            table.similar-table {{ width:100%; border-collapse:collapse; margin-bottom:20px; font-size: 0.9em; }}
            table.similar-table th, table.similar-table td {{ padding: 8px 10px; text-align: left; border: 1px solid #ddd; }}
            table.similar-table th {{ background-color: #e9ecef; font-weight: bold; }}
            @media print {{
                body {{ background-color: white; font-size: 10pt; }}
                .container {{ box-shadow: none; padding: 0; }}
                .tabs, .chart-container, .header p {{ display: none; }}
                .plates, .stats {{ grid-template-columns: 1fr; }} /* Stack cards for printing */
                .plate-card {{ page-break-inside: avoid; box-shadow: none; border: 1px solid #ccc; margin-bottom: 15px; }}
                .plate-images img {{ max-width: 30%; }}
                .modal, .modal-close {{ display: none !important; }}
            }}
        </style>
    </head>
    <body>
    <div id="imageModal" class="modal">
        <span class="modal-close" onclick="closeModal()">×</span>
        <img class="modal-content" id="modalImage">
        <div id="modalCaption"></div>
    </div>

    <div class="container">
        <div class="header">
            <h1>LPR System Report</h1>
            <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-card"><h3>Total Plates</h3><p>{stats['total_plates']}</p></div>
            <div class="stat-card"><h3>Detection Events</h3><p>{stats['total_all_detections']}</p></div>
            <div class="stat-card"><h3>Blacklisted</h3><p style="color:#dc3545">{stats['blacklisted']}</p></div>
            <div class="stat-card"><h3>Tracking Cases</h3><p style="color:#0d6efd">{stats['tracking_plates']}</p></div>
            <div class="stat-card"><h3>Avg. Confidence</h3><p>{stats['avg_confidence']:.1f}%</p></div>
            <div class="stat-card"><h3>Unique Countries</h3><p>{stats['countries']}</p></div>
            <div class="stat-card"><h3>Unique Profiles</h3><p>{stats['profiles']}</p></div>
            <div class="stat-card"><h3>Similar Pairs</h3><p>{stats['similar_plates']}</p></div>
        </div>

        <div class="chart-container">
            <div class="chart-box">
                <h4>Detections by Date</h4>
                <canvas id="detectionsByDate"></canvas>
            </div>
            <div class="chart-box">
                <h4>Plate Status Breakdown</h4>
                <canvas id="blacklistBreakdown"></canvas>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('plates', this)">All Plates ({stats['total_plates']})</div>
            <div class="tab" onclick="showTab('tracking', this)">Tracking Cases ({stats['tracking_plates']})</div>
            <div class="tab" onclick="showTab('similar', this)">Similar Plates ({stats['similar_plates']})</div>
        </div>

        <div id="plates-tab" class="tab-content active">
            <h2>Detected Plates</h2>
            <div class="plates">
    '''

        # --- Loop through plates for "All Plates" tab ---
        for plate in report_data:
            try: # Add try-except for individual plate processing
                plate_id = plate['id']
                confidence_val = float(plate.get('confidence', 0.0))
            except (ValueError, TypeError, KeyError):
                confidence_val = 0.0

            if confidence_val < 80: confidence_color = '#dc3545' # Red
            elif confidence_val < 90: confidence_color = '#ffc107' # Yellow
            else: confidence_color = '#28a745' # Green

            card_class = ""
            warning_block = ""

            if plate.get('is_blacklisted'):
                card_class = "blacklisted"
                reason_text = f"Reason: {plate.get('blacklist_reason', 'N/A')}<br>Danger: {plate.get('danger_level', 'N/A')}"
                warning_block = f'<div class="warning-block blacklist-warning">⚠️ BLACKLISTED<br>{reason_text}</div>'
            elif plate.get('is_following'):
                card_class = "following"
                warning_block = f'<div class="warning-block follow-warning">👀 POTENTIAL TRACKING<br>{plate.get("follow_reason", "")}</div>'

            # Ensure image paths are valid before creating img tags
            plate_img_tag = f'<img src="{plate.get("plate_image", "")}" alt="Plate Image" onclick=\'openModal(this, "Plate: {plate["plate_text"]}")\'>' if plate.get("plate_image") else ''
            frame_img_tag = f'<img src="{plate.get("frame_image", "")}" alt="Frame Image" onclick=\'openModal(this, "Frame: {plate["plate_text"]}")\'>' if plate.get("frame_image") else ''

            html_content += f'''
    <div class="plate-card {card_class}">
        {warning_block}
        <div class="plate-images">
            {plate_img_tag}
            {frame_img_tag}
        </div>
        <div class="plate-info">
            <h3>{plate['plate_text']}</h3>
            <p><span class="confidence" style="background-color:{confidence_color};">{confidence_val:.1f}%</span></p>
            <p><strong>Country:</strong> {plate.get('country_code', '')}</p>
            <p><strong>First Seen:</strong> {plate.get('first_appearance', 'N/A')}</p>
            <p><strong>Last Seen:</strong> {plate.get('last_appearance', 'N/A')}</p>
            <p><strong>Total Appearances:</strong> {plate.get('total_appearances', 1)}</p>
            <p><strong>Unique Videos:</strong> {plate.get('unique_videos', 0)}</p>
            <p><strong>Profile:</strong> {plate.get('profile', '')}</p>
        </div>
    '''
            # Detection History Details
            if plate.get('detection_history'):
                html_content += f'''
        <div class="detection-details">
            <h4>Detection History ({len(plate['detection_history'])} events)</h4>
            <div class="detection-history">
                <table>
                    <thead>
                        <tr><th>Det. Time</th><th>Real Time</th><th>Source</th><th>Conf.</th></tr>
                    </thead>
                    <tbody>
    '''
                for d in plate['detection_history']:
                    html_content += f'''
                    <tr>
                        <td>{d.get('detection_time','')}</td>
                        <td>{d.get('real_timestamp','')}</td>
                        <td>{d.get('source_file','')}</td>
                        <td>{d.get('confidence', 0.0):.1f}%</td>
                    </tr>'''
                html_content += '''
                    </tbody>
                </table>
            </div>
            '''
                # Detection Gallery
                html_content += '''
            <h4>Detection Gallery</h4>
            <div class="detection-gallery">
    '''
                for i, d in enumerate(plate['detection_history']):
                    frame_img = d.get('frame_image')
                    if frame_img:
                        # Use real timestamp if available, otherwise detection time for caption/tooltip
                        display_time = d.get('real_timestamp') or d.get('detection_time','')
                        # Simple time format for gallery label
                        time_label = ""
                        ts_obj = d.get('timestamp_obj')
                        if ts_obj: time_label = ts_obj.strftime('%H:%M:%S')

                        # Use double quotes inside the onclick string, single quotes for the attribute
                        onclick_attr = f'onclick=\'openModal(this, "Detection {i+1} - {plate["plate_text"]} @ {display_time}")\''
                        html_content += f'''
                <div class="detection-item">
                    <img src="{frame_img}" alt="Detection {i+1}" {onclick_attr}>
                    <div class="detection-time">{time_label}</div>
                </div>'''

                html_content += '''
            </div> <!-- end detection-gallery -->
        </div> <!-- end detection-details -->
    '''
            html_content += '</div> <!-- end plate-card -->\n'

        html_content += '''
            </div> <!-- end plates -->
        </div> <!-- end plates-tab -->

        <div id="tracking-tab" class="tab-content">
            <h2>Potential Tracking Cases</h2>
            <div class="plates">
    '''
        # --- Loop through plates for "Tracking" tab ---
        tracking_found = False
        for plate in report_data:
            if plate.get('is_following'):
                tracking_found = True
                confidence_val = float(plate.get('confidence', 0.0))
                if confidence_val < 80: confidence_color = '#dc3545'
                elif confidence_val < 90: confidence_color = '#ffc107'
                else: confidence_color = '#28a745'

                plate_img_tag = f'<img src="{plate.get("plate_image", "")}" alt="Plate Image" onclick=\'openModal(this, "Plate: {plate["plate_text"]}")\'>' if plate.get("plate_image") else ''
                frame_img_tag = f'<img src="{plate.get("frame_image", "")}" alt="Frame Image" onclick=\'openModal(this, "Frame: {plate["plate_text"]}")\'>' if plate.get("frame_image") else ''


                html_content += f'''
    <div class="plate-card following">
        <div class="warning-block follow-warning">👀 POTENTIAL TRACKING<br>{plate.get("follow_reason", "")}</div>
        <div class="plate-images">
            {plate_img_tag}
            {frame_img_tag}
        </div>
        <div class="plate-info">
            <h3>{plate['plate_text']}</h3>
            <p><span class="confidence" style="background-color:{confidence_color};">{confidence_val:.1f}%</span></p>
            <p><strong>Country:</strong> {plate.get('country_code', '')}</p>
            <p><strong>First Seen:</strong> {plate.get('first_appearance', 'N/A')}</p>
            <p><strong>Last Seen:</strong> {plate.get('last_appearance', 'N/A')}</p>
            <p><strong>Total Appearances:</strong> {plate.get('total_appearances', 1)}</p>
            <p><strong>Unique Videos:</strong> {plate.get('unique_videos', 0)}</p>
        </div>
        <div class="detection-details">
            <h4>Detection Timeline</h4>
            <div class="detection-gallery">
    '''
                # Add sorted detection gallery with intervals for tracking
                sorted_history = plate.get('detection_history', []) # Already sorted by time
                for i, d in enumerate(sorted_history):
                    frame_img = d.get('frame_image')
                    if frame_img:
                        display_time = d.get('real_timestamp') or d.get('detection_time','')
                        ts_obj = d.get('timestamp_obj')
                        time_label = ts_obj.strftime('%H:%M:%S') if ts_obj else ""
                        time_info = ""

                        if i > 0 and ts_obj:
                            prev_ts_obj = sorted_history[i-1].get('timestamp_obj')
                            if prev_ts_obj:
                                try:
                                    _, interval = calculate_time_difference(prev_ts_obj, ts_obj)
                                    time_info = f" (+{interval})" # Interval since last
                                except:
                                    time_info = "" # Ignore interval calc error

                        onclick_attr = f'onclick=\'openModal(this, "Detection {i+1} - {plate["plate_text"]} @ {display_time}")\''
                        html_content += f'''
                <div class="detection-item">
                    <img src="{frame_img}" alt="Detection {i+1}" {onclick_attr}>
                    <div class="detection-time" title="{display_time}{time_info}">{time_label}{time_info}</div>
                </div>'''

                html_content += '''
            </div> <!-- end detection-gallery -->
        </div> <!-- end detection-details -->
    </div> <!-- end plate-card -->
    '''
        if not tracking_found:
            html_content += '<p>No potential tracking cases identified based on current criteria.</p>'

        html_content += '''
            </div> <!-- end plates -->
        </div> <!-- end tracking-tab -->

        <div id="similar-tab" class="tab-content">
            <h2>Similar Plates Detected</h2>
    '''
        # --- Table for Similar Plates tab ---
        if all_similar_pairs_data:
            html_content += '''
            <table class="similar-table">
                <thead>
                    <tr><th>Plate 1</th><th>Plate 2</th><th>Similarity</th><th>Time Difference</th><th>Note</th></tr>
                </thead>
                <tbody>
    '''
            for plate1_data, plate2_data, ratio, distance, time_diff_secs, note in all_similar_pairs_data:
                # Use safe access for sqlite3.Row objects
                plate_text1 = decode_if_bytes(safe_get(plate1_data, 'plate_text', ''))
                plate_text2 = decode_if_bytes(safe_get(plate2_data, 'plate_text', ''))

                # Format time difference
                time_diff_str = "N/A"
                if time_diff_secs is not None:
                    # Dummy dates for formatting
                    dummy_dt = datetime.datetime.now()
                    try:
                        _, time_diff_str = calculate_time_difference(
                            dummy_dt, dummy_dt + datetime.timedelta(seconds=abs(time_diff_secs))
                        )
                    except:
                        pass # Keep N/A on error

                note_decoded = decode_if_bytes(note)

                html_content += f'''
                <tr>
                    <td>{plate_text1}</td>
                    <td>{plate_text2}</td>
                    <td>{ratio:.2f}</td>
                    <td>{time_diff_str}</td>
                    <td>{note_decoded}</td>
                </tr>'''

            html_content += '''
                </tbody>
            </table>
    '''
        else:
            html_content += '<p>No similar plate pairs found based on current analysis.</p>'

        # --- End of Tabs and Container ---
        html_content += '''
        </div> <!-- end similar-tab -->
    </div> <!-- end container -->

    <script>
    const modal = document.getElementById('imageModal');
    const modalImg = document.getElementById('modalImage');
    const modalCaption = document.getElementById('modalCaption');

    function openModal(imgElement, captionText) {
        if (!modal || !modalImg || !modalCaption) return;
        modal.style.display = "flex"; // Use flex for centering
        modalImg.src = imgElement.src;
        modalCaption.innerHTML = captionText;
    }

    function closeModal() {
        if (!modal) return;
        modal.style.display = "none";
        modalImg.src = ""; // Clear src
        modalCaption.innerHTML = "";
    }

    // Close modal if clicked outside the image or on close button
    modal.addEventListener('click', function(event) {
        if (event.target === modal ) { // Check if click is on backdrop
            closeModal();
        }
    });

    // Close modal on Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.style.display === 'flex') {
            closeModal();
        }
    });

    function showTab(tabId, clickedTabElement) {
        // Hide all tab content
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        // Deactivate all tab buttons
        document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));

        // Show the selected tab content
        const selectedTabContent = document.getElementById(tabId + '-tab');
        if (selectedTabContent) {
            selectedTabContent.classList.add('active');
        }
        // Activate the clicked tab button
        if (clickedTabElement) {
            clickedTabElement.classList.add('active');
        }
    }

    // --- Chart Initialization ---
    try {
        const ctxDate = document.getElementById('detectionsByDate').getContext('2d');
        new Chart(ctxDate, {
            type: 'line',
            data: {
                labels: ''' + date_labels + ''', // Use pre-formatted string list
                datasets: [{
                    label: 'Detections',
                    data: ''' + date_values + ''', // Use pre-formatted string list
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    borderWidth: 2,
                    tension: 0.1,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, // Allow chart to resize height
                plugins: {
                    title: { display: false }, // Title is in HTML H4
                    legend: { display: false }
                },
                scales: { y: { beginAtZero: true } }
            }
        });
    } catch (e) { console.error("Error creating date chart:", e); }

    try {
        const ctxStatus = document.getElementById('blacklistBreakdown').getContext('2d');
        new Chart(ctxStatus, {
            type: 'pie',
            data: {
                labels: ['Blacklisted', 'Tracking', 'Normal'],
                datasets: [{
                    data: ''' + pie_data + ''', // Use pre-formatted string list
                    backgroundColor: ['#dc3545', '#0d6efd', '#28a745'],
                    borderColor: '#fff',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, // Allow chart to resize height
                plugins: {
                    title: { display: false }, // Title is in HTML H4
                    legend: { position: 'bottom' }
                }
            }
        });
    } catch (e) { console.error("Error creating status chart:", e); }

    // Ensure the first tab is shown on load (redundant but safe)
    // showTab('plates', document.querySelector('.tab.active'));

    </script>
    </body>
    </html>
    '''

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        except IOError as e:
            logging.error(f"Failed to write HTML report to {path}: {e}")
            raise # Re-raise the exception to be caught by the outer handler













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

