# main.py

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import logging
import threading
import datetime

from database import DB
from processing_manager import VideoProcessingManager
from report_panel import ReportPanel
from settings_dialog import SettingsDialog
from progress_frame import ProgressFrame
from utils import extract_timestamp_from_filename
MAX_CONCURRENT_STREAMS = 2
# Добавляем в PATH путь к нужным DLL (DTKLPR5, DTKVID)
os.environ['PATH'] = '../../lib/windows/x64/' + os.pathsep + os.environ['PATH']

# Настройка логгирования (для отладки можно изменить уровень)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class MainApp:
    """
    Основное приложение с интерфейсом на Tkinter.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("LPR System")
        self.db = DB()
        self.profile = None
        self.processing_manager = None
        
        # Создаем директории для хранения изображений
        self.ensure_directories()
        
        self.setup_ui()

    def ensure_directories(self):
        """
        Создает необходимые директории для хранения данных.
        """
        directories = [
            "images",
            "blacklist_matches",
            "detection_history"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def setup_ui(self):
        """
        Создание всех элементов интерфейса (кнопки, фреймы и т.д.).
        """
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Верхняя панель (toolbar) с кнопками
        toolbar = ttk.Frame(self.main_frame)
        toolbar.pack(fill=tk.X, pady=5)

        button_info = [
            ("Select Profile", self.select_profile),
            ("Select Videos/Folder", self.select_input),
            ("Show Report", self.show_report),
            ("Settings", self.open_settings),
            ("Analyze Similar Plates", self.analyze_similar_plates),
        ]
        for txt, cmd in button_info:
            ttk.Button(toolbar, text=txt, command=cmd).pack(side=tk.LEFT, padx=2)

        self.profile_label = ttk.Label(toolbar, text="No profile selected")
        self.profile_label.pack(side=tk.RIGHT, padx=5)

        # Фрейм с прогресс-барами и статистикой по текущей обработке
        self.progress_frame = ProgressFrame(self.main_frame)
        self.progress_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Статус-бар (строка состояния)
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, padding=(2, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def select_profile(self):
        """
        Окно выбора (или создания) профиля из имеющихся в базе.
        """
        profiles = self.db.get_profiles()
        if not profiles:
            if messagebox.askyesno("No Profiles", "No profiles exist. Would you like to create one?"):
                self.create_profile()
            return

        profile_var = tk.StringVar(value=profiles[0])
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Profile")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Select a profile:", padding=10).pack()
        cb = ttk.Combobox(dialog, textvariable=profile_var, values=profiles, width=30)
        cb.pack(padx=10, pady=5)

        def on_select():
            self.profile = profile_var.get()
            self.profile_label.config(text=f"Profile: {self.profile}")
            self.status_var.set(f"Selected profile: {self.profile}")
            dialog.destroy()

        ttk.Button(dialog, text="Select", command=on_select).pack(pady=10)

    def select_input(self):
        """
        Окно выбора либо папки, либо отдельных видеофайлов для последующей обработки.
        """
        if not self.profile:
            messagebox.showwarning("Warning", "Please select a profile first")
            return

        # Всплывающее окно для выбора входных данных
        input_dialog = tk.Toplevel(self.root)
        input_dialog.title("Select Input")
        input_dialog.geometry("300x250")
        input_dialog.transient(self.root)
        input_dialog.grab_set()

        def select_folder():
            dir_path = filedialog.askdirectory(title="Select Video Folder")
            if dir_path:
                self.progress_frame.clear_videos()
                self.process_videos(dir_path)
                self.status_var.set(f"Processing videos from {dir_path}...")
            input_dialog.destroy()

        def select_files():
            file_paths = filedialog.askopenfilenames(
                title="Select Video Files",
                filetypes=[("Video files", "*.mp4 *.avi *.mov *.mkv *.flv *.wmv *.mpeg")]
            )
            if file_paths:
                self.progress_frame.clear_videos()
                self.process_videos(file_paths)
                self.status_var.set("Processing selected video files...")
            input_dialog.destroy()
            
        def select_rtsp():
            """
            Окно для ввода RTSP-ссылки.
            """
            rtsp_dialog = tk.Toplevel(input_dialog)
            rtsp_dialog.title("Enter RTSP URL")
            rtsp_dialog.geometry("400x150")
            rtsp_dialog.transient(input_dialog)
            rtsp_dialog.grab_set()
            
            ttk.Label(rtsp_dialog, text="Enter RTSP URL:").pack(pady=10)
            
            rtsp_var = tk.StringVar(value="rtsp://")
            rtsp_entry = ttk.Entry(rtsp_dialog, textvariable=rtsp_var, width=50)
            rtsp_entry.pack(padx=10, pady=5)
            
            def on_rtsp_submit():
                rtsp_url = rtsp_var.get()
                if rtsp_url and rtsp_url.startswith("rtsp://"):
                    self.progress_frame.clear_videos()
                    self.process_rtsp(rtsp_url)
                    self.status_var.set(f"Processing RTSP stream: {rtsp_url}")
                    rtsp_dialog.destroy()
                    input_dialog.destroy()
                else:
                    messagebox.showwarning("Invalid URL", "Please enter a valid RTSP URL starting with 'rtsp://'")
            
            ttk.Button(rtsp_dialog, text="Start Processing", command=on_rtsp_submit).pack(pady=10)

        ttk.Label(input_dialog, text="Select input source:", padding=10).pack()
        ttk.Button(input_dialog, text="Select Folder", command=select_folder).pack(pady=10, padx=20, fill=tk.X)
        ttk.Button(input_dialog, text="Select Files", command=select_files).pack(pady=10, padx=20, fill=tk.X)
        ttk.Button(input_dialog, text="RTSP Stream", command=select_rtsp).pack(pady=10, padx=20, fill=tk.X)

    def process_videos(self, input_paths):
        """
        Создает VideoProcessingManager и добавляет в очередь все выбранные видеофайлы.
        Запускает поток, который обрабатывает все видео (с учётом MAX_CONCURRENT_STREAMS).
        """
        self.processing_manager = VideoProcessingManager(self.profile, self.progress_frame)

        if isinstance(input_paths, str):
            # Обработка папки
            for root, _, files in os.walk(input_paths):
                for file in files:
                    if file.lower().endswith((".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv", ".mpeg")):
                        self.processing_manager.add_video(os.path.join(root, file))
        else:
            # Обработка списка файлов
            for file_path in input_paths:
                self.processing_manager.add_video(file_path)

        # Запуск в отдельном потоке, чтобы не блокировать GUI
        processing_thread = threading.Thread(target=self._process_videos_wrapper, daemon=True)
        processing_thread.start()
        
    def process_rtsp(self, rtsp_url):
        """
        Создает VideoProcessingManager и добавляет RTSP-поток в очередь.
        """
        self.processing_manager = VideoProcessingManager(self.profile, self.progress_frame)
        
        # Генерируем имя для RTSP-потока (используем текущую дату/время)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        stream_name = f"rtsp_stream_{timestamp}"
        
        self.processing_manager.add_rtsp_stream(rtsp_url, stream_name)
        
        # Запуск в отдельном потоке
        processing_thread = threading.Thread(target=self._process_videos_wrapper, daemon=True)
        processing_thread.start()

    def _process_videos_wrapper(self):
        """
        Запуск пакетной обработки в отдельном потоке.
        """
        try:
            self.processing_manager.process_batch()
            self.root.after(0, lambda: self.status_var.set("Processing completed"))
            
            # Автоматический анализ похожих номеров, если эта опция включена
            if self.db.get_setting('auto_analyze_similar', False):
                self.root.after(0, lambda: self.status_var.set("Processing completed. Analyzing similar plates..."))
                try:
                    self.db.analyze_similar_plates()
                    self.root.after(0, lambda: self.status_var.set("Processing and analysis completed"))
                except Exception as e:
                    logging.exception("Error in similar plates analysis:")
                    self.root.after(0, lambda: self.status_var.set(f"Processing completed but analysis failed: {str(e)}"))
            
        except Exception as e:
            logging.exception("Error in video processing:")
            self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))

    def show_report(self):
        """
        Открывает окно с отчетом (ReportPanel).
        """
        report_window = tk.Toplevel(self.root)
        report_window.title("LPR Report")
        report_window.geometry("1000x600")
        report_panel = ReportPanel(report_window)
        
        # Центрируем окно на экране
        report_window.update_idletasks()
        width = report_window.winfo_width()
        height = report_window.winfo_height()
        x = (report_window.winfo_screenwidth() // 2) - (width // 2)
        y = (report_window.winfo_screenheight() // 2) - (height // 2)
        report_window.geometry(f"{width}x{height}+{x}+{y}")

    def open_settings(self):
        """
        Открывает диалоговое окно с настройками системы.
        """
        SettingsDialog(self.root, self.db)
        
    def analyze_similar_plates(self):
        """
        Запускает анализ похожих номеров и показывает сообщение о результате.
        """
        progress_dialog = tk.Toplevel(self.root)
        progress_dialog.title("Analysis in Progress")
        progress_dialog.geometry("300x100")
        progress_dialog.transient(self.root)
        progress_dialog.grab_set()
        
        ttk.Label(progress_dialog, text="Analyzing similar plates...").pack(pady=10)
        progress = ttk.Progressbar(progress_dialog, mode='indeterminate')
        progress.pack(fill=tk.X, padx=20, pady=10)
        progress.start()
        
        def run_analysis():
            try:
                similar_plates = self.db.analyze_similar_plates()
                progress_dialog.destroy()
                
                result_dialog = tk.Toplevel(self.root)
                result_dialog.title("Analysis Results")
                result_dialog.geometry("400x200")
                result_dialog.transient(self.root)
                
                ttk.Label(result_dialog, 
                         text=f"Analysis complete!\nFound {len(similar_plates)} similar plate pairs.",
                         font=("Helvetica", 12)).pack(pady=20)
                
                def view_report():
                    result_dialog.destroy()
                    self.show_report()
                
                ttk.Button(result_dialog, text="View Report", command=view_report).pack(pady=10)
                ttk.Button(result_dialog, text="Close", command=result_dialog.destroy).pack(pady=10)
                
            except Exception as e:
                progress_dialog.destroy()
                messagebox.showerror("Error", f"Failed to analyze similar plates: {str(e)}")
        
        # Запускаем анализ в отдельном потоке
        analysis_thread = threading.Thread(target=run_analysis, daemon=True)
        analysis_thread.start()

    def create_profile(self):
        """
        Диалог для создания нового профиля.
        """
        name = simpledialog.askstring("Create Profile", "Enter profile name:")
        if name:
            try:
                self.db.add_profile(name)
                messagebox.showinfo("Success", f"Profile '{name}' created successfully")
                self.profile = name
                self.profile_label.config(text=f"Profile: {name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create profile: {str(e)}")

    def on_closing(self):
        """
        Обработчик закрытия главного окна.
        Если идёт процесс обработки, запрашивает подтверждение.
        """
        # Проверяем, есть ли активные потоки
        if self.processing_manager and self.processing_manager.active_threads:
            if messagebox.askyesno("Quit", "Processing is active. Stop and quit?"):
                self.processing_manager.stop_all()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    """
    Точка входа в программу. Спрашивает пароль, при верном пароле запускает Tkinter-приложение.
    """
    password = simpledialog.askstring("Password", "Enter password:", show="*")
    if password == "boris":
        root = tk.Tk()
        root.geometry("800x600")
        root.minsize(600, 400)
        app = MainApp(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)

        def setup_style():
            style = ttk.Style()
            style.configure('Danger.TLabel', foreground='red', font=('Helvetica', 10, 'bold'))
            style.configure('TButton', padding=6)
            style.configure('TEntry', padding=3)
            style.configure('TLabel', padding=3)
            style.configure("Treeview", background="#ffffff", foreground="black", rowheight=25, fieldbackground="#ffffff")
            style.map('Treeview', background=[('selected', '#0078D7')])

        setup_style()
        
        # Центрируем окно на экране
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
        
        root.mainloop()
    else:
        messagebox.showerror("Error", "Incorrect password")


if __name__ == "__main__":
    main()
