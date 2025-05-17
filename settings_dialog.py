# settings_dialog.py

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext # Added scrolledtext
import logging
import datetime
import statistics # Added for interval analysis
import os # Added for potential future use (e.g., sound file paths)

from database import DB
# Import constants potentially modified by settings
from constants import MAX_CONCURRENT_STREAMS
from utils import decode_if_bytes, calculate_time_difference, parse_date # Import needed utils


class SettingsDialog:
    """
    Диалоговое окно с настройками системы:
    - Количество потоков
    - Минимальная уверенность распознавания
    - Звуковое оповещение
    - Чувствительность обнаружения похожих номеров
    - Очистка базы данных
    - Добавление/удаление из blacklist
    - Создание новых профилей
    - Запуск анализа
    """
    def __init__(self, parent, db: DB): # Type hint for db
        self.parent = parent
        self.db = db
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Settings")
        # Make dialog modal
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.geometry("550x550") # Slightly wider/taller
        self.dialog.resizable(False, False) # Prevent resizing
        self.setup_ui()
        # Center dialog
        self.dialog.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f'+{x}+{y}')


    def setup_ui(self):
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0)) # More padding

        # --- Tab 1: Main Settings ---
        main_tab = ttk.Frame(notebook, padding="10")
        notebook.add(main_tab, text=" Processing ") # Add spaces for padding

        # Processing Settings
        process_frame = ttk.LabelFrame(main_tab, text="Core Processing", padding=10)
        process_frame.pack(fill=tk.X, pady=(0, 10))
        process_frame.columnconfigure(1, weight=1) # Allow entry to expand slightly

        ttk.Label(process_frame, text="Number of Threads:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.threads_entry = ttk.Entry(process_frame, width=10)
        self.threads_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.threads_entry.insert(0, self.db.get_setting('threads', '4'))
        ttk.Label(process_frame, text=f"(Max recommended: {os.cpu_count() or 4})").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

        ttk.Label(process_frame, text="Min Confidence (%):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.confidence_entry = ttk.Entry(process_frame, width=10)
        self.confidence_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.confidence_entry.insert(0, self.db.get_setting('min_confidence', '50'))

        # Similar Plates Detection Settings
        similar_frame = ttk.LabelFrame(main_tab, text="Similar Plates Detection", padding=10)
        similar_frame.pack(fill=tk.X, pady=(0, 10))
        similar_frame.columnconfigure(1, weight=1)

        ttk.Label(similar_frame, text="Levenshtein Distance Threshold:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.levenshtein_entry = ttk.Entry(similar_frame, width=10)
        self.levenshtein_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.levenshtein_entry.insert(0, self.db.get_setting('levenshtein_threshold', '2'))
        ttk.Label(similar_frame, text="(0-10, lower is stricter)").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)


        ttk.Label(similar_frame, text="Similarity Ratio Threshold:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ratio_entry = ttk.Entry(similar_frame, width=10)
        self.ratio_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.ratio_entry.insert(0, self.db.get_setting('similarity_ratio', '0.8'))
        ttk.Label(similar_frame, text="(0.0-1.0, higher is stricter)").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)

        self.auto_analyze_var = tk.BooleanVar(value=self.db.get_setting('auto_analyze_similar', False))
        ttk.Checkbutton(similar_frame, text="Auto-analyze similar plates after processing",
                       variable=self.auto_analyze_var).grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)

        # Tracking Detection Settings
        tracking_frame = ttk.LabelFrame(main_tab, text="Tracking Detection", padding=10)
        tracking_frame.pack(fill=tk.X, pady=(0, 10))
        tracking_frame.columnconfigure(1, weight=1)

        ttk.Label(tracking_frame, text="Time Window (seconds):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.tracking_time_entry = ttk.Entry(tracking_frame, width=10)
        self.tracking_time_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.tracking_time_entry.insert(0, self.db.get_setting('tracking_time_threshold', '300')) # 5 minutes default
        ttk.Label(tracking_frame, text="(Max time between detections)").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

        ttk.Label(tracking_frame, text="Min Detections in Window:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.min_detections_entry = ttk.Entry(tracking_frame, width=10)
        self.min_detections_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.min_detections_entry.insert(0, self.db.get_setting('min_tracking_detections', '3'))
        ttk.Label(tracking_frame, text="(Number of detections)").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)

        # Alerts
        alert_frame = ttk.LabelFrame(main_tab, text="Alerts", padding=10)
        alert_frame.pack(fill=tk.X, pady=(0, 10))

        self.alert_sound_var = tk.BooleanVar(value=self.db.get_setting('alert_sound', True))
        ttk.Checkbutton(alert_frame, text="Enable sound alert for blacklisted plates", variable=self.alert_sound_var).pack(padx=5, pady=5, anchor=tk.W)

        # --- Tab 2: Blacklist ---
        blacklist_tab = ttk.Frame(notebook, padding="10")
        notebook.add(blacklist_tab, text=" Blacklist ")

        bl_list_frame = ttk.LabelFrame(blacklist_tab, text="Blacklisted Plates", padding=10)
        bl_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.blacklist = tk.Listbox(bl_list_frame, height=10) # Set initial height
        self.blacklist.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(bl_list_frame, orient=tk.VERTICAL, command=self.blacklist.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.blacklist.config(yscrollcommand=scrollbar.set)

        # Load current blacklist
        self.refresh_blacklist()

        bl_buttons = ttk.Frame(blacklist_tab)
        bl_buttons.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(bl_buttons, text="Add Plate...", command=self.add_to_blacklist).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(bl_buttons, text="Remove Selected", command=self.remove_from_blacklist).pack(side=tk.LEFT)

        # --- Tab 3: Analysis ---
        analysis_tab = ttk.Frame(notebook, padding="10")
        notebook.add(analysis_tab, text=" Analysis ")

        # Analysis Tools
        analysis_tools_frame = ttk.LabelFrame(analysis_tab, text="Analysis Tools", padding=10)
        analysis_tools_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(analysis_tools_frame, text="Analyze Similar Plates",
                  command=self.analyze_similar_plates).pack(fill=tk.X, pady=3)

        ttk.Button(analysis_tools_frame, text="Find Tracking Cases",
                  command=self.find_tracking_cases).pack(fill=tk.X, pady=3)

        ttk.Button(analysis_tools_frame, text="Analyze Time Patterns",
                  command=self.analyze_time_patterns).pack(fill=tk.X, pady=3)

        # Analysis Status/Results
        self.analysis_status_frame = ttk.LabelFrame(analysis_tab, text="Analysis Results", padding=10)
        self.analysis_status_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.analysis_status_text = scrolledtext.ScrolledText(self.analysis_status_frame, wrap=tk.WORD, height=10, font=("Courier New", 9)) # Monospaced font
        self.analysis_status_text.pack(fill=tk.BOTH, expand=True)
        self.analysis_status_text.insert(tk.END, "Ready to analyze data. Select a tool above.\n")
        self.analysis_status_text.config(state=tk.DISABLED)

        # --- Tab 4: Profiles & Database ---
        profiles_db_tab = ttk.Frame(notebook, padding="10")
        notebook.add(profiles_db_tab, text=" Profiles & DB ")

        # Profiles
        profiles_frame = ttk.LabelFrame(profiles_db_tab, text="Profiles", padding=10)
        profiles_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(profiles_frame, text="Create New Profile...", command=self.create_profile).pack(fill=tk.X, pady=5)
        # Could add list/delete profiles here later

        # Database Management
        db_frame = ttk.LabelFrame(profiles_db_tab, text="Database Management", padding=10)
        db_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(db_frame, text="Clear ALL Data...", command=self.clear_database, style="Danger.TButton").pack(fill=tk.X, pady=5) # Use a style for danger
        # Add backup/restore later?

        # --- Save/Cancel Buttons ---
        button_frame = ttk.Frame(self.dialog, padding=(10, 0, 10, 10))
        button_frame.pack(fill=tk.X)

        ttk.Button(button_frame, text="Save Settings", command=self.save_settings, style="Accent.TButton").pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT)

        # Define styles (placeholders, actual look depends on theme)
        style = ttk.Style()
        style.configure("Danger.TButton", foreground="red")
        # style.configure("Accent.TButton", foreground="blue") # Example

    def refresh_blacklist(self):
        """ Reloads the blacklist into the listbox. """
        self.blacklist.delete(0, tk.END)
        try:
            for item in self.db.get_blacklist():
                plate = decode_if_bytes(item.get('plate_text', 'N/A'))
                reason = decode_if_bytes(item.get('reason', 'No reason'))
                danger = decode_if_bytes(item.get('danger_level', 'UNKNOWN'))
                self.blacklist.insert(
                    tk.END,
                    f"{plate} - {reason} ({danger})"
                )
        except Exception as e:
            logging.error(f"Failed to refresh blacklist: {e}", exc_info=True)
            self.blacklist.insert(tk.END, "Error loading blacklist.")

    def _update_analysis_status(self, message, append=False):
        """ Helper to update the analysis status text area. """
        self.analysis_status_text.config(state=tk.NORMAL)
        if not append:
            self.analysis_status_text.delete('1.0', tk.END)
        self.analysis_status_text.insert(tk.END, message)
        self.analysis_status_text.see(tk.END) # Scroll to end
        self.analysis_status_text.update_idletasks() # Ensure UI updates
        # Keep enabled if more messages might come, disable otherwise
        # self.analysis_status_text.config(state=tk.DISABLED)


    def analyze_similar_plates(self):
        """
        Запускает анализ похожих номеров и отображает результаты.
        """
        self._update_analysis_status("Analyzing similar plates...\n")

        try:
            # Get thresholds from current entry values (don't save yet)
            threshold_distance = float(self.levenshtein_entry.get())
            threshold_ratio = float(self.ratio_entry.get())
            self._update_analysis_status(f"Using Levenshtein Threshold: {threshold_distance}, Ratio Threshold: {threshold_ratio}\n", append=True)

            # Run analysis with current thresholds
            similar_plates = self.db.analyze_similar_plates(threshold_distance, threshold_ratio)

            result_message = f"Analysis complete! Found {len(similar_plates)} similar plate pairs.\n\n"
            self._update_analysis_status(result_message, append=True)

            # Display results
            if similar_plates:
                result_message = "Top similar plate pairs found:\n"
                for i, (plate1, plate2, ratio, distance, time_diff_sec, note) in enumerate(similar_plates[:15]): # Show more results
                    plate_text1 = decode_if_bytes(plate1['plate_text'])
                    plate_text2 = decode_if_bytes(plate2['plate_text'])
                    note_text = decode_if_bytes(note)

                    # Format time difference
                    time_diff_str = "N/A"
                    if time_diff_sec is not None:
                         dummy_dt = datetime.datetime.now()
                         try:
                             _, time_diff_str = calculate_time_difference(
                                 dummy_dt, dummy_dt + datetime.timedelta(seconds=abs(time_diff_sec))
                             )
                         except: pass # Ignore formatting errors

                    result_message += (
                        f"{i+1}. '{plate_text1}' <=> '{plate_text2}'\n"
                        f"   Similarity: {ratio:.2f}, Distance: {distance}, Time Diff: {time_diff_str}\n"
                        f"   Note: {note_text}\n\n"
                    )

                if len(similar_plates) > 15:
                    result_message += f"... and {len(similar_plates) - 15} more pairs.\n"
                self._update_analysis_status(result_message, append=True)
            else:
                self._update_analysis_status("No similar plates found with current threshold settings.\n", append=True)

        except ValueError as e:
             error_msg = f"Invalid threshold value: {e}\nPlease enter valid numbers."
             self._update_analysis_status(f"Error: {error_msg}\n", append=True)
             messagebox.showerror("Input Error", error_msg, parent=self.dialog)
        except Exception as e:
            logging.error(f"Error analyzing similar plates: {e}", exc_info=True)
            self._update_analysis_status(f"Error during analysis: {str(e)}\n", append=True)
        finally:
            self.analysis_status_text.config(state=tk.DISABLED) # Disable after completion/error


    def find_tracking_cases(self):
        """
        Находит случаи, когда номер, вероятно, следует за камерой.
        """
        self._update_analysis_status("Finding potential tracking cases...\n")

        try:
            # Get settings from current entry values
            tracking_time = int(self.tracking_time_entry.get())
            min_detections = int(self.min_detections_entry.get())
            self._update_analysis_status(f"Using Time Window: {tracking_time}s, Min Detections: {min_detections}\n", append=True)

            if tracking_time <= 0 or min_detections < 2:
                 raise ValueError("Tracking time must be positive and min detections >= 2.")

            # Run analysis (find_potential_follow_plates uses settings stored in DB,
            # so maybe we should pass them directly or update settings temporarily?)
            # For now, let's assume it uses the settings from DB. We should save first or pass them.
            # Let's pass them if the DB method allows it, otherwise save first.
            # Assuming find_potential_follow_plates can take args:
            # following_plates = self.db.find_potential_follow_plates(time_threshold_sec=tracking_time, min_detections=min_detections)
            # If not, we must save settings first (or warn user)
            # Let's warn user for now:
            # if (self.db.get_setting('tracking_time_threshold') != str(tracking_time) or
            #     self.db.get_setting('min_tracking_detections') != str(min_detections)):
            #      if not messagebox.askyesno("Confirm", "Tracking settings have changed. Save settings before running analysis?", parent=self.dialog):
            #          self._update_analysis_status("Analysis cancelled. Save settings first.\n", append=True)
            #          self.analysis_status_text.config(state=tk.DISABLED)
            #          return
            #      else:
            #          self.save_settings(show_success=False) # Save silently

            # Assuming the DB method uses stored settings:
            following_plates = self.db.find_potential_follow_plates() # This uses settings from DB

            result_message = f"Analysis complete! Found {len(following_plates)} potential tracking cases based on saved settings.\n\n"
            self._update_analysis_status(result_message, append=True)

            # Display results
            if following_plates:
                result_message = "Potential tracking cases found:\n"
                for i, case in enumerate(following_plates):
                    plate = case.get('plate', {})
                    plate_text = decode_if_bytes(plate.get('plate_text', 'N/A'))
                    reason = case.get('reason', 'N/A')
                    detections_list = case.get('detections', [])

                    result_message += (
                        f"{i+1}. Plate: '{plate_text}'\n"
                        f"   Reason: {reason}\n"
                        f"   Detections in sequence: {len(detections_list)}\n\n"
                    )
                self._update_analysis_status(result_message, append=True)
            else:
                self._update_analysis_status("No potential tracking cases found with saved settings.\n", append=True)

        except ValueError as e:
             error_msg = f"Invalid tracking settings: {e}\nPlease enter valid numbers."
             self._update_analysis_status(f"Error: {error_msg}\n", append=True)
             messagebox.showerror("Input Error", error_msg, parent=self.dialog)
        except Exception as e:
            logging.error(f"Error finding tracking cases: {e}", exc_info=True)
            self._update_analysis_status(f"Error during analysis: {str(e)}\n", append=True)
        finally:
            self.analysis_status_text.config(state=tk.DISABLED)


    def analyze_time_patterns(self):
        """
        Анализирует временные паттерны обнаружений.
        """
        self._update_analysis_status("Analyzing time patterns...\n")

        try:
            # --- Detections by Hour ---
            self._update_analysis_status("Fetching hourly stats...\n", append=True)
            hour_stats = self.db.exec('''
                SELECT CAST(strftime('%H', real_timestamp) AS INTEGER) as hour, COUNT(*) as count
                FROM plate_detections WHERE real_timestamp IS NOT NULL AND real_timestamp != ''
                GROUP BY hour ORDER BY hour
            ''').fetchall()

            if not hour_stats:
                self._update_analysis_status("No valid time data available for hourly analysis.\n", append=True)
            else:
                max_count = max((row['count'] for row in hour_stats), default=1)
                total_detections = sum(row['count'] for row in hour_stats)
                peak_hours = sorted(hour_stats, key=lambda x: x['count'], reverse=True)[:3] # Top 3 hours

                hourly_results = "\n== Detections by Hour of Day ==\n\n"
                for row in hour_stats:
                    hour = row['hour']
                    count = row['count']
                    percentage = (count / total_detections) * 100 if total_detections else 0
                    bar_length = int(30 * count / max_count) # Longer bar
                    time_range = f"{hour:02d}:00-{hour:02d}:59"
                    bar = "#" * bar_length
                    hourly_results += f"{time_range}: {bar} {count} ({percentage:.1f}%)\n"

                # ** FIX FOR THE SyntaxError HERE **
                # Create the list of formatted strings first
                peak_hour_strings = [f"{h['hour']:02d}:00" for h in peak_hours]
                # Then join them
                peak_hours_str = ', '.join(peak_hour_strings)
                # Finally, use the joined string in the f-string
                hourly_results += f"\nPeak hours: {peak_hours_str}\n"

                self._update_analysis_status(hourly_results, append=True)

            # --- Detections by Day of Week ---
            self._update_analysis_status("\nFetching daily stats...\n", append=True)
            day_stats = self.db.exec('''
                SELECT CAST(strftime('%w', real_timestamp) AS INTEGER) as day, COUNT(*) as count
                FROM plate_detections WHERE real_timestamp IS NOT NULL AND real_timestamp != ''
                GROUP BY day ORDER BY day
            ''').fetchall()

            if not day_stats:
                 self._update_analysis_status("No valid time data available for daily analysis.\n", append=True)
            else:
                days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
                # Ensure total_detections is recalculated if needed, or use previous one if scope is same
                if 'total_detections' not in locals() or not total_detections: # Safety check
                     total_detections = sum(row['count'] for row in day_stats)

                max_day_count = max((row['count'] for row in day_stats), default=1)
                daily_results = "\n== Detections by Day of Week ==\n\n"
                day_counts = {row['day']: row['count'] for row in day_stats} # Map for easy access

                for day_idx, day_name in enumerate(days):
                    count = day_counts.get(day_idx, 0) # Get count or 0 if no detections
                    percentage = (count / total_detections) * 100 if total_detections else 0
                    bar_length = int(30 * count / max_day_count)
                    bar = "#" * bar_length
                    daily_results += f"{day_name.ljust(4)}: {bar} {count} ({percentage:.1f}%)\n"
                self._update_analysis_status(daily_results, append=True)


            # --- Time Intervals ---
            self._update_analysis_status("\nAnalyzing time intervals between detections (Top 20 plates)...\n", append=True)
            multiple_detections_plates = self.db.exec('''
                SELECT p.id as plate_id, p.plate_text, COUNT(d.id) as count
                FROM plates p JOIN plate_detections d ON p.id = d.plate_id
                WHERE d.real_timestamp IS NOT NULL AND d.real_timestamp != ''
                GROUP BY p.id, p.plate_text HAVING COUNT(d.id) > 1
                ORDER BY count DESC LIMIT 20
            ''').fetchall()

            if multiple_detections_plates:
                interval_stats = []
                for plate_info in multiple_detections_plates:
                    plate_id = plate_info['plate_id']
                    detections_times = self.db.exec('''
                        SELECT real_timestamp FROM plate_detections
                        WHERE plate_id = ? AND real_timestamp IS NOT NULL AND real_timestamp != ''
                        ORDER BY real_timestamp
                    ''', (plate_id,)).fetchall()

                    if len(detections_times) < 2: continue

                    intervals_sec = []
                    for i in range(1, len(detections_times)):
                        time1 = parse_date(detections_times[i-1]['real_timestamp'])
                        time2 = parse_date(detections_times[i]['real_timestamp'])
                        if time1 and time2:
                            interval = (time2 - time1).total_seconds()
                            if interval >= 0: # Avoid issues with bad timestamps
                                intervals_sec.append(interval)

                    if intervals_sec:
                        try:
                            avg_interval = statistics.mean(intervals_sec)
                            interval_stats.append({
                                'plate_text': decode_if_bytes(plate_info['plate_text']),
                                'count': plate_info['count'],
                                'avg_interval': avg_interval,
                                'min_interval': min(intervals_sec),
                                'max_interval': max(intervals_sec)
                            })
                        except statistics.StatisticsError:
                             pass # Should not happen if intervals_sec is not empty

                interval_stats.sort(key=lambda x: x['avg_interval']) # Sort by shortest average interval

                interval_results = "\n== Avg Time Intervals (Plates Seen > 1 Time) ==\n\n"
                interval_results += "Plates with shortest avg intervals:\n"
                for i, stat in enumerate(interval_stats[:10]): # Top 10
                    _, avg_str = calculate_time_difference(datetime.datetime.now(), datetime.datetime.now() + datetime.timedelta(seconds=stat['avg_interval']))
                    _, min_str = calculate_time_difference(datetime.datetime.now(), datetime.datetime.now() + datetime.timedelta(seconds=stat['min_interval']))
                    _, max_str = calculate_time_difference(datetime.datetime.now(), datetime.datetime.now() + datetime.timedelta(seconds=stat['max_interval']))

                    interval_results += (
                        f"{i+1}. '{stat['plate_text']}' ({stat['count']} dets)\n"
                        f"   Avg: {avg_str} | Min: {min_str} | Max: {max_str}\n"
                    )
                self._update_analysis_status(interval_results, append=True)
            else:
                self._update_analysis_status("No plates with multiple valid detections found for interval analysis.\n", append=True)

        except Exception as e:
            logging.error(f"Error analyzing time patterns: {e}", exc_info=True)
            self._update_analysis_status(f"\nError during time analysis: {str(e)}\n", append=True)
        finally:
             self.analysis_status_text.config(state=tk.DISABLED) # Disable after completion/error


    def create_profile(self):
        """
        Диалоговое окно для создания нового профиля.
        """
        name = simpledialog.askstring("Create Profile", "Enter new profile name:", parent=self.dialog)
        if name and name.strip():
            name = name.strip()
            try:
                self.db.add_profile(name)
                messagebox.showinfo("Success", f"Profile '{name}' created successfully.", parent=self.dialog)
                # Optionally update profile dropdowns elsewhere in the app if needed
            except Exception as e:
                logging.error(f"Failed to create profile '{name}': {e}", exc_info=True)
                messagebox.showerror("Error", f"Failed to create profile: {str(e)}", parent=self.dialog)
        elif name is not None: # User pressed OK but entered empty string
             messagebox.showwarning("Input Required", "Profile name cannot be empty.", parent=self.dialog)

    def add_to_blacklist(self):
        """
        Диалоговое окно для добавления номера в blacklist.
        Uses a more robust dialog than simpledialog multiple times.
        """
        plate_text = simpledialog.askstring("Add to Blacklist", "Enter plate number:", parent=self.dialog)
        if not plate_text or not plate_text.strip():
            if plate_text is not None:
                 messagebox.showwarning("Input Required", "Plate number cannot be empty.", parent=self.dialog)
            return # Cancelled or empty

        plate_text = plate_text.strip().upper() # Standardize input

        # Check if already blacklisted
        existing = self.db.is_blacklisted(plate_text)
        if existing:
            if not messagebox.askyesno("Confirm", f"Plate {plate_text} is already blacklisted.\nDo you want to update its reason and danger level?", parent=self.dialog):
                return
            initial_reason = decode_if_bytes(existing.get('reason', ''))
            initial_danger = decode_if_bytes(existing.get('danger_level', 'HIGH'))
        else:
            initial_reason = ""
            initial_danger = "HIGH"

        # --- Create Details Dialog ---
        details_dialog = tk.Toplevel(self.dialog)
        details_dialog.title(f"Blacklist Details: {plate_text}")
        details_dialog.geometry("350x200")
        details_dialog.transient(self.dialog)
        details_dialog.grab_set()
        details_dialog.resizable(False, False)

        details_frame = ttk.Frame(details_dialog, padding="10")
        details_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(details_frame, text="Reason:").pack(anchor=tk.W, pady=(0, 2))
        reason_entry = ttk.Entry(details_frame, width=40)
        reason_entry.pack(fill=tk.X, pady=(0, 10))
        reason_entry.insert(0, initial_reason)

        ttk.Label(details_frame, text="Danger Level:").pack(anchor=tk.W, pady=(0, 2))
        danger_var = tk.StringVar(value=initial_danger)
        danger_options = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if initial_danger not in danger_options: danger_var.set("HIGH") # Default if invalid
        danger_cb = ttk.Combobox(details_frame, textvariable=danger_var, values=danger_options, state="readonly")
        danger_cb.pack(fill=tk.X, pady=(0, 15))

        button_frame_bl = ttk.Frame(details_frame)
        button_frame_bl.pack(fill=tk.X)

        def save_blacklist():
            reason = reason_entry.get().strip()
            danger = danger_var.get()
            if not reason:
                messagebox.showwarning("Input Required", "Please provide a reason.", parent=details_dialog)
                reason_entry.focus()
                return

            try:
                self.db.add_to_blacklist(plate_text, reason, danger)
                details_dialog.destroy()
                messagebox.showinfo("Success", f"Plate {plate_text} added/updated in blacklist.", parent=self.dialog)
                self.refresh_blacklist() # Update the listbox
            except Exception as e:
                logging.error(f"Failed to add/update {plate_text} in blacklist: {e}", exc_info=True)
                messagebox.showerror("Database Error", f"Failed to update blacklist: {str(e)}", parent=details_dialog)

        save_btn = ttk.Button(button_frame_bl, text="Save", command=save_blacklist, style="Accent.TButton")
        save_btn.pack(side=tk.RIGHT, padx=(5, 0))
        cancel_btn = ttk.Button(button_frame_bl, text="Cancel", command=details_dialog.destroy)
        cancel_btn.pack(side=tk.RIGHT)

        reason_entry.focus()
        details_dialog.bind('<Return>', lambda e: save_blacklist())
        details_dialog.bind('<Escape>', lambda e: details_dialog.destroy())

        # Center dialog
        details_dialog.update_idletasks()
        x = self.dialog.winfo_rootx() + (self.dialog.winfo_width() // 2) - (details_dialog.winfo_width() // 2)
        y = self.dialog.winfo_rooty() + (self.dialog.winfo_height() // 2) - (details_dialog.winfo_height() // 2)
        details_dialog.geometry(f'+{x}+{y}')

        details_dialog.wait_window()


    def remove_from_blacklist(self):
        """
        Удаление выбранного номера из списка blacklist.
        """
        selection_indices = self.blacklist.curselection()
        if not selection_indices:
            messagebox.showwarning("Selection Required", "Please select a plate to remove.", parent=self.dialog)
            return

        selected_index = selection_indices[0]
        item_text = self.blacklist.get(selected_index)
        # Extract plate number reliably (assuming format "PLATE - REASON (LEVEL)")
        try:
            plate_text = item_text.split(" - ")[0].strip()
        except IndexError:
            messagebox.showerror("Error", "Could not parse selected item.", parent=self.dialog)
            return

        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove '{plate_text}' from the blacklist?", parent=self.dialog):
            try:
                self.db.remove_from_blacklist(plate_text)
                self.blacklist.delete(selected_index) # Remove from listbox
                messagebox.showinfo("Success", f"Removed '{plate_text}' from blacklist.", parent=self.dialog)
            except Exception as e:
                logging.error(f"Failed to remove {plate_text} from blacklist: {e}", exc_info=True)
                messagebox.showerror("Database Error", f"Failed to remove from blacklist: {str(e)}", parent=self.dialog)


    def save_settings(self, show_success=True):
        """
        Сохранение изменений настроек.
        """
        try:
            # --- Validate Core Processing ---
            threads_str = self.threads_entry.get()
            threads = int(threads_str)
            cpu_count = os.cpu_count() or 1 # Default to 1 if undetectable
            if not (1 <= threads <= cpu_count * 4): # Allow up to 4x CPU count? Be generous.
                raise ValueError(f"Threads must be between 1 and {cpu_count * 4}.")

            confidence_str = self.confidence_entry.get()
            confidence = float(confidence_str)
            if not (0 <= confidence <= 100):
                raise ValueError("Confidence must be between 0 and 100.")

            # --- Validate Similar Plates ---
            levenshtein_str = self.levenshtein_entry.get()
            levenshtein = float(levenshtein_str) # Allow float for potential future use? Or enforce int? Let's allow float for now.
            if not (0 <= levenshtein <= 10): # Reasonable upper limit
                raise ValueError("Levenshtein distance threshold must be between 0 and 10.")

            ratio_str = self.ratio_entry.get()
            ratio = float(ratio_str)
            if not (0.0 <= ratio <= 1.0):
                raise ValueError("Similarity ratio threshold must be between 0.0 and 1.0.")

            # --- Validate Tracking ---
            tracking_time_str = self.tracking_time_entry.get()
            tracking_time = int(tracking_time_str)
            if tracking_time <= 0:
                raise ValueError("Tracking time window must be positive.")

            min_detections_str = self.min_detections_entry.get()
            min_detections = int(min_detections_str)
            if min_detections < 2:
                raise ValueError("Minimum detections for tracking must be at least 2.")

            # --- Save validated settings ---
            self.db.set_setting('threads', threads_str)
            self.db.set_setting('min_confidence', confidence_str)
            self.db.set_setting('alert_sound', str(self.alert_sound_var.get())) # Boolean converted to string
            self.db.set_setting('levenshtein_threshold', levenshtein_str)
            self.db.set_setting('similarity_ratio', ratio_str)
            self.db.set_setting('tracking_time_threshold', tracking_time_str)
            self.db.set_setting('min_tracking_detections', min_detections_str)
            self.db.set_setting('auto_analyze_similar', str(self.auto_analyze_var.get())) # Boolean converted to string

            # Update global constant if it exists and is imported
            try:
                 # Need to modify the global directly if it's used elsewhere immediately
                 global MAX_CONCURRENT_STREAMS
                 MAX_CONCURRENT_STREAMS = threads
                 logging.info(f"Global MAX_CONCURRENT_STREAMS updated to {threads}")
            except NameError:
                 logging.warning("Global MAX_CONCURRENT_STREAMS not found or not imported.")


            if show_success:
                messagebox.showinfo("Success", "Settings saved successfully!", parent=self.dialog)
            # Don't destroy dialog if called internally (e.g., before analysis)
            # self.dialog.destroy() # Only destroy if called directly by user action?

        except ValueError as e:
            messagebox.showerror("Validation Error", str(e), parent=self.dialog)
        except Exception as e:
            logging.error(f"Failed to save settings: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}", parent=self.dialog)


    def clear_database(self):
        """
        Полная очистка базы данных (plates, detections, blacklist, similar_plates).
        """
        warning_message = (
            "WARNING: This will permanently delete ALL data:\n"
            "- Detected Plates\n"
            "- Detection History\n"
            "- Blacklist\n"
            "- Similar Plate Analysis\n\n"
            "This action cannot be undone. Are you absolutely sure?"
        )
        if messagebox.askyesno("Confirm Database Deletion", warning_message, icon='warning', parent=self.dialog):
            # Extra confirmation step
            confirm = simpledialog.askstring("Final Confirmation",
                                             "Type 'DELETE ALL DATA' to proceed:",
                                             parent=self.dialog)
            if confirm == "DELETE ALL DATA":
                try:
                    self._update_analysis_status("Clearing database...") # Show status
                    self.db.clear_database()
                    self.refresh_blacklist() # Refresh the (now empty) list
                    self._update_analysis_status("Database cleared successfully.\nReady.")
                    messagebox.showinfo("Success", "Database cleared successfully.", parent=self.dialog)
                    # Optionally, trigger a refresh in the main application window here
                except Exception as e:
                    logging.error(f"Failed to clear database: {e}", exc_info=True)
                    messagebox.showerror("Error", f"Failed to clear database: {str(e)}", parent=self.dialog)
                    self._update_analysis_status(f"Error clearing database: {e}\nReady.")
                finally:
                    self.analysis_status_text.config(state=tk.DISABLED)

            else:
                messagebox.showinfo("Cancelled", "Database clearing cancelled.", parent=self.dialog)

