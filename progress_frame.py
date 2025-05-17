# progress_frame.py

import tkinter as tk
from tkinter import ttk, simpledialog
import os
import threading
import datetime

from database import DB
from utils import format_time, extract_timestamp_from_filename


class ProgressFrame(ttk.Frame):
    """
    Фрейм для отображения списка обрабатываемых видео, их прогресса и общей статистики.
    Улучшенная версия с дополнительной информацией о временных метках и детекциях.
    """
    def __init__(self, master):
        super().__init__(master)
        self.video_statuses = {}
        self.db = DB()
        self.setup_ui()
        self.detections_update_thread = None
        self.stop_detections_update = False

    def setup_ui(self):
        """
        Создает элементы интерфейса: общий статус, прогресс-бар, скроллируемый список видео.
        """
        self.status_frame = ttk.Frame(self)
        self.status_frame.pack(fill=tk.X, pady=(0, 5))

        self.stats_frame = ttk.Frame(self.status_frame)
        self.stats_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.total_label = ttk.Label(self.stats_frame, text="Total: 0")
        self.total_label.pack(side=tk.LEFT, padx=5)

        self.processed_label = ttk.Label(self.stats_frame, text="Processed: 0")
        self.processed_label.pack(side=tk.LEFT, padx=5)

        self.plates_found_label = ttk.Label(self.stats_frame, text="Plates Found: 0")
        self.plates_found_label.pack(side=tk.LEFT, padx=5)

        self.blacklist_label = ttk.Label(self.stats_frame, text="⚠️ Blacklisted: 0", foreground='red')
        self.blacklist_label.pack(side=tk.LEFT, padx=5)
        
        # Добавляем метку для количества уникальных номеров
        self.unique_plates_label = ttk.Label(self.stats_frame, text="Unique Plates: 0")
        self.unique_plates_label.pack(side=tk.LEFT, padx=5)

        self.progress_frame = ttk.Frame(self)
        self.progress_frame.pack(fill=tk.X, pady=(0, 5))

        self.progress = ttk.Progressbar(self.progress_frame, mode='determinate')
        self.progress.pack(fill=tk.X)

        # Добавляем таб-интерфейс для разных представлений обработки
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Вкладка для видео
        self.videos_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.videos_frame, text="Videos")
        
        self.canvas = tk.Canvas(self.videos_frame)
        self.scrollbar = ttk.Scrollbar(self.videos_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind("<Configure>",
                                   lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Вкладка для обнаружений в реальном времени
        self.detections_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.detections_frame, text="Live Detections")
        
        # Treeview для отображения обнаружений в реальном времени
        columns = ('time', 'plate', 'confidence', 'video', 'status')
        self.detections_tree = ttk.Treeview(self.detections_frame, columns=columns, show='headings')
        
        self.detections_tree.heading('time', text='Time')
        self.detections_tree.heading('plate', text='Plate')
        self.detections_tree.heading('confidence', text='Confidence')
        self.detections_tree.heading('video', text='Source Video')
        self.detections_tree.heading('status', text='Status')
        
        self.detections_tree.column('time', width=150)
        self.detections_tree.column('plate', width=100)
        self.detections_tree.column('confidence', width=80)
        self.detections_tree.column('video', width=250)
        self.detections_tree.column('status', width=120)
        
        self.detections_tree.tag_configure('blacklisted', foreground='red')
        self.detections_tree.tag_configure('new', background='#e6ffec')
        self.detections_tree.tag_configure('repeat', background='#fff9e6')
        
        detections_scrollbar = ttk.Scrollbar(self.detections_frame, orient=tk.VERTICAL, command=self.detections_tree.yview)
        self.detections_tree.configure(yscrollcommand=detections_scrollbar.set)
        
        self.detections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detections_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Кнопка для открытия деталей выбранного обнаружения
        details_button = ttk.Button(self.detections_frame, text="Show Details", command=self.show_detection_details)
        details_button.pack(side=tk.BOTTOM, padx=5, pady=5)
        
        # Вкладка для статистики по времени обнаружения
        self.time_stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.time_stats_frame, text="Time Statistics")
        
        self.time_stats_text = tk.Text(self.time_stats_frame, wrap=tk.WORD, height=10)
        self.time_stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Прокрутка колесом мыши
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Переключение вкладок - обновление данных
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _on_tab_changed(self, event):
        """
        Обновляет вкладку, когда пользователь переключается на нее.
        """
        tab_id = self.notebook.select()
        tab_name = self.notebook.tab(tab_id, "text")
        
        if tab_name == "Live Detections":
            # Если переключились на вкладку Live Detections, запускаем обновление
            if self.detections_update_thread is None or not self.detections_update_thread.is_alive():
                self.stop_detections_update = False
                self.detections_update_thread = threading.Thread(target=self._update_detections_periodically, daemon=True)
                self.detections_update_thread.start()
        elif tab_name == "Time Statistics":
            # Обновляем статистику времени
            self.update_time_statistics()

    def _update_detections_periodically(self):
        """
        Периодически обновляет дерево обнаружений.
        """
        while not self.stop_detections_update:
            self._update_detections_tree()
            # Спим 2 секунды между обновлениями
            for _ in range(20):  # 20 * 0.1 = 2 секунды, но с проверкой флага stop каждые 0.1 секунды
                if self.stop_detections_update:
                    break
                tk.Widget.update(self)
                import time
                time.sleep(0.1)

    def _update_detections_tree(self):
        """
        Обновляет дерево обнаружений последними данными из БД.
        """
        try:
            # Запрашиваем последние 100 обнаружений из БД
            detections = self.db.exec('''
                SELECT d.*, p.plate_text, p.confidence, p.is_blacklisted, p.reason
                FROM plate_detections d
                JOIN plates p ON d.plate_id = p.id
                ORDER BY d.detection_time DESC
                LIMIT 100
            ''').fetchall()
            
            # Очищаем дерево
            self.detections_tree.delete(*self.detections_tree.get_children())
            
            for d in detections:
                # Определяем статус (новый или повторный)
                is_blacklisted = d['is_blacklisted']
                detection_count = self.db.exec('''
                    SELECT COUNT(*) FROM plate_detections WHERE plate_id = ?
                ''', (d['plate_id'],)).fetchone()[0]
                
                status = "Repeat Detection" if detection_count > 1 else "New"
                if is_blacklisted:
                    status = f"⚠️ BLACKLISTED: {d['reason']}"
                
                # Форматируем время
                detection_time = d['detection_time']
                try:
                    dt_obj = datetime.datetime.fromisoformat(detection_time)
                    formatted_time = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    formatted_time = detection_time
                
                # Получаем информацию о видеофайле
                source_file = d['source_file'] or "Unknown"
                real_timestamp = ""
                if d['real_timestamp']:
                    try:
                        ts = datetime.datetime.fromisoformat(d['real_timestamp'])
                        real_timestamp = f" ({ts.strftime('%Y-%m-%d %H:%M:%S')})"
                    except:
                        pass
                
                video_info = f"{source_file}{real_timestamp}"
                
                # Добавляем запись
                item_id = self.detections_tree.insert('', 0, values=(
                    formatted_time,
                    d['plate_text'],
                    f"{d['confidence']:.1f}%",
                    video_info,
                    status
                ))
                
                # Устанавливаем тег для стилизации
                if is_blacklisted:
                    self.detections_tree.item(item_id, tags=('blacklisted',))
                elif detection_count == 1:
                    self.detections_tree.item(item_id, tags=('new',))
                else:
                    self.detections_tree.item(item_id, tags=('repeat',))
        
        except Exception as e:
            import logging
            logging.error(f"Error updating detections tree: {e}", exc_info=True)

    def update_time_statistics(self):
        """
        Обновляет статистику времени обнаружения номеров.
        """
        try:
            self.time_stats_text.delete('1.0', tk.END)
            
            # Получаем статистику по временам суток
            hour_stats = self.db.exec('''
                SELECT 
                    CAST(strftime('%H', real_timestamp) AS INTEGER) as hour,
                    COUNT(*) as count
                FROM plate_detections
                WHERE real_timestamp IS NOT NULL
                GROUP BY hour
                ORDER BY hour
            ''').fetchall()
            
            if not hour_stats:
                self.time_stats_text.insert(tk.END, "No time statistics available yet.\n")
                return
            
            # Форматируем статистику по времени суток
            self.time_stats_text.insert(tk.END, "== Detections by Hour of Day ==\n\n")
            
            max_count = max(row['count'] for row in hour_stats)
            for row in hour_stats:
                hour = row['hour']
                count = row['count']
                bar_length = int(50 * count / max_count)
                time_range = f"{hour:02d}:00 - {hour:02d}:59"
                bar = "█" * bar_length
                self.time_stats_text.insert(tk.END, f"{time_range}: {bar} {count}\n")
            
            # Статистика по дням недели
            self.time_stats_text.insert(tk.END, "\n== Detections by Day of Week ==\n\n")
            day_stats = self.db.exec('''
                SELECT 
                    CAST(strftime('%w', real_timestamp) AS INTEGER) as day,
                    COUNT(*) as count
                FROM plate_detections
                WHERE real_timestamp IS NOT NULL
                GROUP BY day
                ORDER BY day
            ''').fetchall()
            
            days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
            max_count = max(row['count'] for row in day_stats) if day_stats else 0
            
            for row in day_stats:
                day_idx = row['day']
                count = row['count']
                bar_length = int(50 * count / max_count) if max_count > 0 else 0
                day_name = days[day_idx]
                bar = "█" * bar_length
                self.time_stats_text.insert(tk.END, f"{day_name.ljust(10)}: {bar} {count}\n")
            
            # Статистика по повторным обнаружениям
            self.time_stats_text.insert(tk.END, "\n== Repeat Detection Analysis ==\n\n")
            repeat_stats = self.db.exec('''
                SELECT 
                    p.plate_text,
                    COUNT(d.id) as detection_count,
                    MIN(d.real_timestamp) as first_detection,
                    MAX(d.real_timestamp) as last_detection
                FROM plates p
                JOIN plate_detections d ON p.id = d.plate_id
                GROUP BY p.id
                HAVING COUNT(d.id) > 1
                ORDER BY detection_count DESC
                LIMIT 10
            ''').fetchall()
            
            if repeat_stats:
                self.time_stats_text.insert(tk.END, "Top plates with most repeated detections:\n\n")
                for row in repeat_stats:
                    plate_text = row['plate_text']
                    count = row['detection_count']
                    
                    # Вычисляем временной интервал между первым и последним обнаружением
                    first = row['first_detection']
                    last = row['last_detection']
                    
                    time_span = "Unknown"
                    if first and last:
                        try:
                            first_dt = datetime.datetime.fromisoformat(first)
                            last_dt = datetime.datetime.fromisoformat(last)
                            diff = last_dt - first_dt
                            if diff.days > 0:
                                time_span = f"{diff.days} days, {diff.seconds // 3600} hours"
                            else:
                                hours = diff.seconds // 3600
                                minutes = (diff.seconds % 3600) // 60
                                time_span = f"{hours} hours, {minutes} minutes"
                        except:
                            pass
                    
                    self.time_stats_text.insert(tk.END, f"{plate_text}: {count} detections over {time_span}\n")
            else:
                self.time_stats_text.insert(tk.END, "No repeat detections found yet.\n")
            
        except Exception as e:
            import logging
            logging.error(f"Error updating time statistics: {e}", exc_info=True)
            self.time_stats_text.insert(tk.END, f"Error updating statistics: {str(e)}")

    def show_detection_details(self):
        """
        Показывает детали выбранного обнаружения в новом окне.
        """
        selection = self.detections_tree.selection()
        if not selection:
            return
            
        try:
            selected_values = self.detections_tree.item(selection[0])['values']
            plate_text = selected_values[1]
            source_video = selected_values[3].split(' (')[0]  # Убираем временную метку из строки
            
            # Получаем детали обнаружения из БД
            detection = self.db.exec('''
                SELECT d.*, p.plate_text, p.confidence, p.country_code, p.is_blacklisted
                FROM plate_detections d
                JOIN plates p ON d.plate_id = p.id
                WHERE p.plate_text = ? AND d.source_file = ?
                ORDER BY d.detection_time DESC
                LIMIT 1
            ''', (plate_text, source_video)).fetchone()
            
            if not detection:
                return
                
            # Создаем окно с деталями
            details_window = tk.Toplevel(self)
            details_window.title(f"Detection Details - {plate_text}")
            details_window.geometry("600x400")
            details_window.transient(self)
            
            # Верхний фрейм с изображениями
            images_frame = ttk.Frame(details_window)
            images_frame.pack(fill=tk.X, padx=10, pady=10)
            
            # Загружаем изображения
            from utils import load_and_resize_image
            plate_image = load_and_resize_image(detection['plate_image_path'], (200, 100))
            frame_image = load_and_resize_image(detection['frame_image_path'], (300, 200))
            
            if plate_image:
                plate_label = ttk.Label(images_frame, image=plate_image)
                plate_label.image = plate_image
                plate_label.pack(side=tk.LEFT, padx=5)
                
            if frame_image:
                frame_label = ttk.Label(images_frame, image=frame_image)
                frame_label.image = frame_image
                frame_label.pack(side=tk.LEFT, padx=5)
                
            # Нижний фрейм с текстовой информацией
            info_frame = ttk.LabelFrame(details_window, text="Detection Info")
            info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Извлекаем информацию
            real_timestamp = "Unknown"
            if detection['real_timestamp']:
                try:
                    ts = datetime.datetime.fromisoformat(detection['real_timestamp'])
                    real_timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    real_timestamp = detection['real_timestamp']
            
            # Форматируем информацию
            info_text = f"""
Plate Number: {detection['plate_text']}
Confidence: {detection['confidence']:.1f}%
Country Code: {detection['country_code']}
Detection Time: {detection['detection_time']}
Real Timestamp: {real_timestamp}
Source Video: {detection['source_file']}
Image Paths:
- Plate: {detection['plate_image_path']}
- Frame: {detection['frame_image_path']}
"""
            
            if detection['is_blacklisted']:
                info_text += "\n⚠️ THIS PLATE IS BLACKLISTED!"
            
            # Получаем информацию о других обнаружениях того же номера
            other_detections = self.db.exec('''
                SELECT d.detection_time, d.real_timestamp, d.source_file
                FROM plate_detections d
                JOIN plates p ON d.plate_id = p.id
                WHERE p.plate_text = ? AND d.id != ?
                ORDER BY d.detection_time DESC
                LIMIT 5
            ''', (plate_text, detection['id'])).fetchall()
            
            if other_detections:
                info_text += "\n\nOther Recent Detections:"
                for i, d in enumerate(other_detections):
                    real_ts = "Unknown"
                    if d['real_timestamp']:
                        try:
                            ts = datetime.datetime.fromisoformat(d['real_timestamp'])
                            real_ts = ts.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            real_ts = d['real_timestamp']
                    
                    info_text += f"\n{i+1}. {d['detection_time']} ({real_ts}) - {d['source_file']}"
            
            # Отображаем информацию
            info_text_widget = tk.Text(info_frame, wrap=tk.WORD)
            info_text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            info_text_widget.insert(tk.END, info_text)
            info_text_widget.config(state=tk.DISABLED)
            
            # Кнопки внизу
            buttons_frame = ttk.Frame(details_window)
            buttons_frame.pack(fill=tk.X, padx=10, pady=10)
            
            # Кнопка для открытия папки с изображениями
            def open_image_folder():
                folder_path = os.path.dirname(detection['frame_image_path'])
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(folder_path)
                    elif os.name == 'posix':  # macOS, Linux
                        try:
                            os.system(f'xdg-open "{folder_path}"')
                        except:
                            os.system(f'open "{folder_path}"')
                except Exception as e:
                    import logging
                    logging.error(f"Error opening folder: {e}")
            
            # Кнопка для добавления в blacklist
            def add_to_blacklist():
                reason = simpledialog.askstring("Add to Blacklist", "Enter reason:", parent=details_window)
                if reason:
                    danger_level = simpledialog.askstring("Add to Blacklist", 
                                                         "Enter danger level (LOW, MEDIUM, HIGH, CRITICAL):", 
                                                         parent=details_window)
                    if danger_level:
                        self.db.add_to_blacklist(plate_text, reason, danger_level)
                        tk.messagebox.showinfo("Success", f"Added {plate_text} to blacklist")
                        details_window.destroy()
            
            ttk.Button(buttons_frame, text="Open Image Folder", command=open_image_folder).pack(side=tk.LEFT, padx=5)
            
            if not detection['is_blacklisted']:
                ttk.Button(buttons_frame, text="Add to Blacklist", command=add_to_blacklist).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(buttons_frame, text="Close", command=details_window.destroy).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            import logging
            logging.error(f"Error showing detection details: {e}", exc_info=True)

    def _on_mousewheel(self, event):
        """
        Вертикальная прокрутка содержимого canvas при скролле колёсиком мыши.
        """
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def update_progress(self, processed, total, plates_found=0, blacklisted=0):
        """
        Обновляет суммарную статистику (количество видео, обработанных, найденных номеров и т.д.).
        """
        self.total_label.config(text=f"Total: {total}")
        self.processed_label.config(text=f"Processed: {processed}")
        self.plates_found_label.config(text=f"Plates Found: {plates_found}")
        self.blacklist_label.config(text=f"⚠️ Blacklisted: {blacklisted}")
        
        # Обновляем количество уникальных номеров
        unique_plates = self.db.exec('SELECT COUNT(DISTINCT plate_text) FROM plates').fetchone()[0]
        self.unique_plates_label.config(text=f"Unique Plates: {unique_plates}")

        if total > 0:
            progress_val = (processed / total) * 100
            self.progress['value'] = progress_val

    def clear_videos(self):
        """
        Очищает список видео и сбрасывает общий прогресс.
        """
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.video_statuses.clear()
        self.progress['value'] = 0
        self.update_progress(0, 0, 0, 0)
        
        # Если есть активный поток обновления, останавливаем его
        if self.detections_update_thread and self.detections_update_thread.is_alive():
            self.stop_detections_update = True
            self.detections_update_thread.join(timeout=1.0)

    def add_video(self, video_path, video_duration=0):
        """
        Добавляет новый элемент (строчку) в список видео с прогрессом.
        """
        frame = ttk.Frame(self.scrollable_frame)
        frame.pack(fill=tk.X, padx=5, pady=2)

        # Извлекаем временную метку из имени файла
        video_filename = os.path.basename(video_path)
        video_timestamp = extract_timestamp_from_filename(video_filename)
        
        # Добавляем дополнительную информацию о времени, если доступно
        video_info = video_filename
        if video_timestamp:
            video_info = f"{video_filename} ({video_timestamp.strftime('%Y-%m-%d %H:%M:%S')})"

        name_label = ttk.Label(frame, text=video_info)
        name_label.pack(side=tk.LEFT)

        progress = ttk.Progressbar(frame, mode='determinate', length=100)
        progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        time_label = ttk.Label(frame, text=f"0:00 / {format_time(video_duration)}")
        time_label.pack(side=tk.LEFT, padx=5)

        status_label = ttk.Label(frame, text="Queued")
        status_label.pack(side=tk.RIGHT, padx=5)

        self.video_statuses[video_path] = {
            'frame': frame,
            'name_label': name_label,
            'progress': progress,
            'time_label': time_label,
            'status_label': status_label,
            'duration': video_duration,
            'start_time': None,
            'timestamp': video_timestamp
        }
        return self.video_statuses[video_path]

    def update_video_progress(self, video_path, progress_value, current_time=None, status=None):
        """
        Обновляет прогресс (и метку времени, и статус) для конкретного видео.
        """
        if video_path in self.video_statuses:
            vs = self.video_statuses[video_path]
            vs['progress']['value'] = progress_value

            if current_time is not None:
                vs['time_label'].config(text=f"{format_time(current_time)} / {format_time(vs['duration'])}")

            if status:
                vs['status_label'].config(text=status)
                if "Blacklisted" in status:
                    vs['status_label'].config(foreground='red')

    def show_blacklist_alert(self, plate_text, reason, image_path=None):
        """
        Показывает всплывающее окно предупреждения, если номер найден в blacklist.
        """
        alert_window = tk.Toplevel(self)
        alert_window.title("⚠️ BLACKLIST ALERT!")
        alert_window.geometry("500x350")

        style = ttk.Style()
        style.configure('Alert.TLabel', foreground='red', font=('Helvetica', 12, 'bold'))

        ttk.Label(alert_window, text="⚠️ BLACKLISTED PLATE DETECTED! ⚠️", style='Alert.TLabel').pack(pady=10)
        ttk.Label(alert_window, text=f"Plate Number: {plate_text}", font=('Helvetica', 11)).pack(pady=5)
        ttk.Label(alert_window, text=f"Reason: {reason}", font=('Helvetica', 11)).pack(pady=5)
        
        # Если предоставлен путь к изображению, отображаем его
        if image_path and os.path.exists(image_path):
            from utils import load_and_resize_image
            img = load_and_resize_image(image_path, (300, 200))
            if img:
                img_label = ttk.Label(alert_window, image=img)
                img_label.image = img
                img_label.pack(pady=10)

        # Звуковое оповещение, если включено в настройках
        if self.db.get_setting('alert_sound', True):
            alert_window.bell()

        def close_alert():
            alert_window.destroy()

        ttk.Button(alert_window, text="Acknowledge", command=close_alert).pack(pady=10)

        alert_window.transient(self)
        alert_window.grab_set()

        # Центрируем окно относительно родителя
        x = self.winfo_x() + (self.winfo_width() - alert_window.winfo_width()) // 2
        y = self.winfo_y() + (self.winfo_height() - alert_window.winfo_height()) // 2
        alert_window.geometry(f"+{x}+{y}")
