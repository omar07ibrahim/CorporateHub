# video_processor.py

import time
import logging
import datetime
import os
from PIL import Image, ImageDraw
import Levenshtein
import cv2

from DTKLPR5 import DTKLPRLibrary, LPREngine, LPRParams, BURN_POS
from DTKVID import DTKVIDLibrary, VideoCapture

from database import DB
from utils import format_time, extract_timestamp_from_filename


class VideoProcessor:
    """
    Класс, отвечающий за обработку одного видео:
    - Передача кадров в LPREngine
    - Колбэки при распознавании номеров (plate_callback)
    - Обработка blacklist
    - Сохранение в БД
    """
    def __init__(self, video_path, stream_id, profile, stop_event, status_widgets):
        self.video_path = video_path
        self.stream_id = stream_id
        self.profile = profile
        self.stop_event = stop_event
        self.status_widgets = status_widgets
        self.stopFlag = False

        # Извлекаем реальную временную метку из имени файла
        self.video_filename = os.path.basename(video_path)
        self.video_timestamp = extract_timestamp_from_filename(self.video_filename)
        if self.video_timestamp:
            logging.info(f"Extracted timestamp from video: {self.video_timestamp}")

        self.db = DB()

        # Собираем изначально список blacklist и plates (все sqlite3.Row превращаем в dict, чтоб удобно .get(...))
        raw_blacklist = self.db.get_blacklist()
        self.blacklist = {row['plate_text']: dict(row) for row in raw_blacklist}

        raw_known_plates = self.db.get_all_plates()
        self.known_plates = {p['plate_text']: dict(p) for p in raw_known_plates}

        self.plates_found = 0
        self.blacklist_found = 0
        self.frame_count = 0
        self.detected_plates = set() # <--- ADD THIS LINE

        # Для прогресса используем счётчик кадров
        self.cap = cv2.VideoCapture(self.video_path)
        self.total_frames = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT))
        self.cap.release()

        self.setup_lpr()

    def setup_lpr(self):
        """
        Инициализируем движок распознавания номеров, задаём нужные параметры.
        Слегка уменьшаем MinPlateWidth и увеличиваем MaxPlateWidth,
        чтобы захватить больше вариантов номеров.
        """
        self.params = LPRParams(DTKLPRLibrary('../../lib/windows/x64/'))
        # Уменьшаем минимальную ширину и увеличиваем макс. ширину:
        self.params.MinPlateWidth = 50
        self.params.MaxPlateWidth = 400
        # Ограничиваем страны при необходимости (пример):
        self.params.Countries = "LV"
        self.params.FormatPlateText = True
        
        # Добавляем в информацию метку времени из имени файла (если доступна)
        timestamp_info = ""
        if self.video_timestamp:
            timestamp_info = f" | {self.video_timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            
        self.params.BurnFormatString = f"%DATETIME% | Stream {self.stream_id}{timestamp_info} | Plate: %PLATE_NUM% | Conf: %CONFIDENCE%"
        self.params.NumThreads = 0
        # Если бы в библиотеке была настройка MinConfidence, мы бы могли тут её выставлять,
        # но в данном случае просто оставляем логику принятия/отбора номеров в коде.

    def _check_blacklist(self, plate_text):
        """
        Проверка на то, что номер (plate_text) похож на номера из self.blacklist
        через расстояние Левенштейна или ratio (здесь оставляем логику в DB).
        """
        for bp, bl_data in self.blacklist.items():
            # Для проверки схожести может использоваться динамический порог,
            # но здесь делаем простой <=2 для примера
            # (или можно вызвать DB._is_similar_plate, но это внутренний метод).
            if Levenshtein.distance(plate_text, bp) <= 2:
                self.blacklist_found += 1
                return bl_data
        return None



    def plate_callback(self, engine, plate):
        """
        Колбэк, вызываемый при распознавании номера.
        Сохраняем все распознавания для максимального покрытия.
        """
        if self.stop_event.is_set():
            return 1  # Прекращаем обработку

        # Всегда увеличиваем счетчик и сохраняем текст номера
        self.plates_found += 1
        pt = plate.Text()
        ts = datetime.datetime.now().isoformat()
        self.detected_plates.add(pt) 
        
        confidence = plate.Confidence()
        
        # Вывод информации в лог для отладки
        logging.debug(f"Detected plate: {pt}, confidence: {confidence}%, country: {plate.CountryCode()}")

        # Проверяем blacklist
        blacklist_match = self._check_blacklist(pt)

        # Ищем схожие номера среди уже известных
        similar_plates = [
            (p_text, data) for p_text, data in self.known_plates.items()
            if Levenshtein.distance(pt, p_text) <= 2
        ]

        if similar_plates:
            # Берём из схожих тот, у которого выше confidence
            best_match = max(similar_plates, key=lambda x: x[1]['confidence'])
            pid = best_match[1]['id']
            
            # Всегда сохраняем в историю обнаружений
            self._add_detection_history(plate, pid, ts)
            
            # Обновляем основную запись, если обнаружение с более высокой уверенностью
            if confidence > best_match[1]['confidence']:
                self._update_existing_plate(plate, best_match[1], ts)
                
                # Обновляем кэш known_plates
                updated_dict = dict(best_match[1])
                updated_dict['confidence'] = confidence
                updated_dict['last_appearance'] = ts
                self.known_plates[best_match[0]] = updated_dict
        else:
            # Сохраняем новый номер в БД
            pid = self._save_new_plate(plate, pt, ts)
            
            # Добавляем запись в историю обнаружений
            self._add_detection_history(plate, pid, ts)

        # Обрабатываем blacklist
        if blacklist_match:
            self._handle_blacklist_match(plate, ts, blacklist_match, pid)

        return 0

    def _add_detection_history(self, plate, pid, timestamp):
        """
        Добавляет запись в историю обнаружений plate_detections.
        Сохраняет дополнительные изображения для каждого обнаружения.
        """
        try:
            # Создаем папку для сохранения истории обнаружений
            os.makedirs("detection_history", exist_ok=True)
            
            # Формируем уникальные имена файлов (включаем timestamp для уникальности)
            plate_text = plate.Text()
            ts_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            
            # Сохраняем изображения в отдельных папках для каждого номера
            plate_dir = f"detection_history/{plate_text}"
            os.makedirs(plate_dir, exist_ok=True)
            
            pp = f"{plate_dir}/{plate_text}_plate_{ts_str}.jpg"
            fp = f"{plate_dir}/{plate_text}_frame_{ts_str}.jpg"

            # Сохраняем изображения
            plate.GetPlateImage().save(pp)
            
            img = plate.GetImage()
            draw = ImageDraw.Draw(img)
            
            # Добавляем информацию о времени и источнике на изображение
            source_info = f"Source: {self.video_filename}"
            if self.video_timestamp:
                source_info += f" ({self.video_timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
                
            draw.text(
                (10, 10),
                source_info,
                fill="yellow"
            )
            
            # Добавляем рамку вокруг номера
            draw.rectangle(
                [plate.X(), plate.Y(), plate.X() + plate.Width(), plate.Y() + plate.Height()],
                outline="green",
                width=3
            )
            
            img.save(fp)
            
            # Добавляем запись в базу данных
            self.db.add_plate_detection(pid, timestamp, self.video_filename, plate.Confidence(), pp, fp)
            
        except Exception as e:
            logging.error(f"Error adding detection history: {e}", exc_info=True)

    def _handle_blacklist_match(self, plate, ts, blacklist_data, pid):
        """
        Дополнительные действия, если распознанный номер — blacklist:
        - Сохраняем помеченную картинку в "blacklist_matches"
        - Добавляем запись в blacklist_alerts
        - Обновляем метку в UI
        """
        try:
            os.makedirs("blacklist_matches", exist_ok=True)
            fp = f"blacklist_matches/{plate.Text()}_{ts}.jpg"
            img = plate.GetImage()

            # Обводим красным
            draw = ImageDraw.Draw(img)
            draw.rectangle(
                [plate.X(), plate.Y(), plate.X() + plate.Width(), plate.Y() + plate.Height()],
                outline="red",
                width=3
            )
            
            # Добавляем информацию о времени файла видео (если доступно)
            timestamp_info = ""
            if self.video_timestamp:
                timestamp_info = f"Video timestamp: {self.video_timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
                
            draw.text(
                (10, 10),
                f"BLACKLISTED!\n{timestamp_info}Reason: {blacklist_data.get('reason','')}\nDanger: {blacklist_data.get('danger_level','')}",
                fill="red"
            )
            img.save(fp)

            self.db.exec('UPDATE plates SET is_blacklisted=1 WHERE id=?', (pid,))
            self.db.add_blacklist_alert(plate.Text(), fp)

            # Обновление статуса в интерфейсе
            self.status_widgets['status_label'].config(
                text=f"⚠️ BLACKLISTED plate detected: {plate.Text()}",
                foreground='red'
            )
        except Exception as e:
            logging.error(f"Error handling blacklist match: {e}", exc_info=True)

    def _update_existing_plate(self, plate, plate_data, ts):
        """
        Обновление уже существующего номера (повышаем confidence, last_appearance, сохраняем изображения).
        """
        try:
            pid = plate_data['id']
            os.makedirs("images", exist_ok=True)

            # --- FIX: Sanitize the timestamp for the filename ---
            # Create a safe timestamp string for filenames by replacing invalid characters
            filename_ts = ts.replace(":", "-").replace("T", "_").split(".")[0]
            pp = f"images/{plate.Text()}_plate_{filename_ts}.jpg"
            fp = f"images/{plate.Text()}_frame_{filename_ts}.jpg"
            # --- End of FIX ---

            plate.GetPlateImage().save(pp)
            img = plate.GetImage()
            draw = ImageDraw.Draw(img)

            outline_color = "red" if plate_data.get('is_blacklisted') else "green"
            draw.rectangle(
                [plate.X(), plate.Y(), plate.X() + plate.Width(), plate.Y() + plate.Height()],
                outline=outline_color,
                width=5
            )

            # Add info text (keep existing logic)
            info_text = f"Source: {self.video_filename}"
            if self.video_timestamp:
                info_text += f" ({self.video_timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
            draw.text((10, 10), info_text, fill="yellow")
            img.save(fp)

            # Update the database record for the plate appearance
            # Pass the original ISO timestamp 'ts' to the DB method
            self.db.update_plate_appearance(pid, ts, plate.Confidence())

            # Update the separate images table *if you are still using it*.
            # If images are only stored per detection in plate_detections, this call is not needed.
            # self.db.save_images(pid, pp, fp) # Uncomment if the 'images' table is essential

        except Exception as e:
            logging.error(f"Error updating existing plate {plate.Text()}: {e}", exc_info=True)
    def _save_new_plate(self, plate, pt, ts):
        """
        Сохранение нового номера в БД (+ изображения).
        Blacklist check is now handled within db.insert_plate.
        """
        try:
            # REMOVE the incorrect check: is_blacklisted = self.db.is_in_blacklist(pt)
            # The db.insert_plate method will handle checking against the blacklist

            # Prepare data for insertion
            # Use the current timestamp 'ts' (which is already an ISO string)
            # for both first and last appearance of a newly detected plate.
            plate_data_tuple = (
                pt,
                plate.Confidence(),
                plate.CountryCode(),
                plate.Timestamp(), # Original LPR timestamp (might be int/string)
                ts, # First appearance (current detection time as ISO string)
                ts, # Last appearance (current detection time as ISO string)
                self.profile
            )

            # Insert the plate (db.insert_plate handles blacklist logic)
            pid = self.db.insert_plate(plate_data_tuple)
            if pid is None: # Handle potential insertion failure
                logging.error(f"Failed to insert new plate {pt} into database.")
                return None

            # Fetch the newly inserted plate data to determine its final blacklist status
            # This status is determined *during* the insert_plate call
            new_row = self.db.get_plate_by_id(pid)
            if not new_row:
                 logging.error(f"Could not retrieve newly inserted plate with ID {pid}")
                 # Decide how to handle this - maybe proceed but log error?
                 # For now, let's assume it worked but log the issue.
                 is_blacklisted = False # Default if fetch fails
            else:
                is_blacklisted = new_row['is_blacklisted'] # Get status from DB after insertion

            # --- Proceed with saving images ---
            os.makedirs("images", exist_ok=True)
            # Use the ISO timestamp 'ts' for unique filenames
            filename_ts = ts.replace(":", "-").replace("T", "_").split(".")[0] # Create a safe timestamp string for filenames
            pp = f"images/{pt}_plate_{filename_ts}.jpg"
            fp = f"images/{pt}_frame_{filename_ts}.jpg"

            plate.GetPlateImage().save(pp)
            img = plate.GetImage()
            draw = ImageDraw.Draw(img)
            outline_color = "red" if is_blacklisted else "green" # Use status from DB
            draw.rectangle(
                [plate.X(), plate.Y(), plate.X() + plate.Width(), plate.Y() + plate.Height()],
                outline=outline_color,
                width=5
            )

            # Add info text (keep existing logic)
            info_text = f"Source: {self.video_filename}"
            if self.video_timestamp:
                info_text += f" ({self.video_timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
            draw.text((10, 10), info_text, fill="yellow")
            img.save(fp)

            # Update the separate images table *if you are still using it*.
            # If images are only stored per detection in plate_detections, this call is not needed.
            # self.db.save_images(pid, pp, fp) # Uncomment if the 'images' table is essential

            # Update the local cache (make sure new_row is a dict if it exists)
            if new_row:
                self.known_plates[pt] = dict(new_row)
            else:
                # Add a basic entry to known_plates even if fetch failed?
                self.known_plates[pt] = {
                    'id': pid,
                    'plate_text': pt,
                    'confidence': plate.Confidence(),
                    'is_blacklisted': is_blacklisted, # Use determined status
                    # Add other necessary fields with default/current values
                }


            return pid
        except Exception as e:
            # Log the specific plate text for better debugging
            logging.error(f"Error saving new plate {pt}: {e}", exc_info=True)
            return None
    def frame_callback(self, vc, frame, engine):
        """
        Колбэк при захвате каждого кадра.
        Оптимизирован для максимального распознавания.
        """
        if not self.stop_event.is_set():
            self.frame_count += 1
            
            # Обновляем прогресс по кадрам
            if self.total_frames > 0:
                progress_percent = (self.frame_count / self.total_frames) * 100
                self.status_widgets['progress']['value'] = progress_percent

                video_duration = self.status_widgets['duration']
                current_time = (self.frame_count / self.total_frames) * video_duration
                self.status_widgets['time_label'].config(
                    text=f"{format_time(current_time)} / {format_time(video_duration)}"
                )

            # Форсируем обработку каждого кадра для максимального обнаружения
            engine.PutFrame(frame, 0)

    def error_callback(self, vc, ec, engine):
        """
        Колбэк при ошибках захвата. Код 3 (EOF) — не критическая ошибка (конец файла).
        """
        if ec != 3:
            logging.error(f"Stream {self.stream_id} - Error: {ec}")
            self.status_widgets['status_label'].config(text=f"Error: {ec}")
        self.stopFlag = True

    def start_processing(self):
        """
        Запуск процесса распознавания номеров из видео.
        """
        try:
            # Обновляем статус с информацией о времени видео (если доступно)
            status_text = "Processing..."
            if self.video_timestamp:
                status_text = f"Processing video from {self.video_timestamp.strftime('%Y-%m-%d %H:%M:%S')}..."
                
            self.status_widgets['status_label'].config(text=status_text)
            
            engine = LPREngine(self.params, True, self.plate_callback)
            if engine.IsLicensed() != 0:
                self.status_widgets['status_label'].config(text="License Error")
                return

            cap = VideoCapture(
                self.frame_callback,
                self.error_callback,
                engine,
                DTKVIDLibrary('../../lib/windows/x64/')
            )
            cap.StartCaptureFromFile(self.video_path, 1)

            logging.info(f"Stream {self.stream_id} started: {self.video_path}")

            # Ждём, пока не будет установлен stopFlag или stop_event
            while not self.stopFlag and not self.stop_event.is_set():
                time.sleep(0.001)

            cap.StopCapture()
            logging.info(f"Stream {self.stream_id} stopped")

            if not self.stop_event.is_set():
                status_text = f"Completed - Found {self.plates_found} plates"
                if self.blacklist_found > 0:
                    status_text += f" (⚠️ {self.blacklist_found} blacklisted)"
                self.status_widgets['status_label'].config(
                    text=status_text,
                    foreground='red' if self.blacklist_found > 0 else 'black'
                )
            else:
                self.status_widgets['status_label'].config(text="Stopped")

            # После завершения обработки, запускаем анализ похожих номеров
            # Но не делаем это для каждого видео, т.к. это может быть долго
            # Можно сделать отдельную кнопку в интерфейсе для запуска анализа
            # self.db.analyze_similar_plates()

        except Exception as e:
            logging.error(f"Error processing stream {self.stream_id}: {e}", exc_info=True)
            self.status_widgets['status_label'].config(text=f"Error: {str(e)}")
