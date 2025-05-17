# database.py

import sqlite3
import datetime
import logging
import Levenshtein

from constants import DATABASE_PATH
from utils import decode_if_bytes, extract_timestamp_from_filename, calculate_time_difference, is_potential_follow


class DB:
    """
    Класс для работы с базой данных (SQLite).
    """
    def __init__(self, path=DATABASE_PATH):
        self.path = path
        self._init_db()

    def _init_db(self):
        """
        Инициализация структуры базы данных:
        - Таблицы: plates, images, blacklist, blacklist_alerts, profiles, settings
        - Начальные настройки (settings), в том числе уменьшенный порог min_confidence (50).
        """
        with sqlite3.connect(self.path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS plates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plate_text TEXT,
                    confidence REAL,
                    country_code TEXT,
                    timestamp TEXT, -- Original timestamp from LPR engine (might be string)
                    first_appearance TEXT, -- ISO format string
                    last_appearance TEXT, -- ISO format string
                    profile TEXT,
                    total_appearances INTEGER DEFAULT 1,
                    is_blacklisted BOOLEAN DEFAULT 0,
                    reason TEXT, -- Reason if blacklisted
                    danger_level TEXT -- Danger level if blacklisted
                );

                -- This table might be redundant if images are stored per detection
                -- Consider removing if not explicitly needed for the *latest* image only
                CREATE TABLE IF NOT EXISTS images (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plate_id INTEGER,
                    plate_image_path TEXT,
                    frame_image_path TEXT,
                    FOREIGN KEY(plate_id) REFERENCES plates(id)
                );

                CREATE TABLE IF NOT EXISTS plate_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plate_id INTEGER,
                    detection_time DATETIME,     -- Timestamp when the detection was processed/saved (ISO string)
                    real_timestamp DATETIME,    -- Временная метка из имени файла (ISO string or NULL)
                    source_file TEXT,           -- Имя исходного видеофайла
                    confidence REAL,
                    plate_image_path TEXT,
                    frame_image_path TEXT,
                    FOREIGN KEY(plate_id) REFERENCES plates(id)
                );

                CREATE TABLE IF NOT EXISTS similar_plates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plate_id1 INTEGER,
                    plate_id2 INTEGER,
                    similarity_score REAL,
                    time_diff_seconds INTEGER,
                    detection_note TEXT,
                    FOREIGN KEY(plate_id1) REFERENCES plates(id),
                    FOREIGN KEY(plate_id2) REFERENCES plates(id)
                );

                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plate_text TEXT UNIQUE,
                    reason TEXT,
                    danger_level TEXT,
                    date_added TEXT, -- ISO format string
                    last_seen TEXT, -- ISO format string (when this blacklisted plate was last detected)
                    location TEXT, -- Optional location info
                    notes TEXT -- Optional notes
                );

                CREATE TABLE IF NOT EXISTS blacklist_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plate_text TEXT,
                    detection_time TEXT, -- ISO format string
                    location TEXT, -- Optional location
                    image_path TEXT, -- Path to the specific frame where blacklisted plate was seen
                    processed BOOLEAN DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_name TEXT UNIQUE,
                    created_date TEXT, -- ISO format string
                    settings TEXT -- JSON string of profile-specific settings (optional)
                );

                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_name TEXT UNIQUE,
                    setting_value TEXT,
                    setting_type TEXT -- 'integer', 'float', 'boolean', 'string'
                );

                INSERT OR IGNORE INTO settings (setting_name, setting_value, setting_type)
                VALUES
                    ('threads', '4', 'integer'),
                    ('min_confidence', '50', 'float'),
                    ('save_blacklist_matches', 'true', 'boolean'),
                    ('alert_sound', 'true', 'boolean'),
                    ('levenshtein_threshold', '2', 'float'), -- Added default
                    ('similarity_ratio', '0.8', 'float'),   -- Added default
                    ('tracking_time_threshold', '300', 'integer'), -- Added default (5 min)
                    ('min_tracking_detections', '3', 'integer'), -- Added default
                    ('auto_analyze_similar', 'false', 'boolean'); -- Added default
            ''')

    def exec(self, query, params=()):
        """
        Универсальный метод для выполнения SQL-запросов.
        Возвращает объект курсора (sqlite3.Cursor).
        """
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row # Return rows as dictionary-like objects
            try:
                return conn.execute(query, params)
            except sqlite3.Error as e:
                logging.error(f"SQL Error: {e}\nQuery: {query}\nParams: {params}")
                raise # Re-raise the exception after logging

    def _is_similar_plate(self, p1, p2, threshold_distance=None, threshold_ratio=None):
        """
        Улучшенный метод для определения «похожих» номеров на основе Levenshtein.
        Использует динамический порог или значения из настроек.
        """
        if not p1 or not p2:
            return False
        p1 = decode_if_bytes(p1).strip()
        p2 = decode_if_bytes(p2).strip()

        # Get thresholds from settings if not provided
        if threshold_distance is None:
            threshold_distance = self.get_setting('levenshtein_threshold', 2.0)
        if threshold_ratio is None:
            threshold_ratio = self.get_setting('similarity_ratio', 0.8)

        len1, len2 = len(p1), len(p2)
        distance = Levenshtein.distance(p1, p2)
        ratio = Levenshtein.ratio(p1, p2)

        # Apply dynamic rules based on length if desired, or just use thresholds
        # Example dynamic logic (can be adjusted):
        if len1 <= 4 or len2 <= 4:
            return distance <= 1 # Stricter for very short plates
        elif len1 <= 7 or len2 <= 7:
            return distance <= threshold_distance # Use setting for medium length
        else:
            # Use ratio for longer plates OR distance, whichever matches
            return distance <= threshold_distance or ratio >= threshold_ratio

    def insert_plate(self, data):
        """
        Сохранение новой записи в таблицу plates.
        data ожидается в формате:
            (plate_text, confidence, country_code, lpr_timestamp,
             first_appearance_iso, last_appearance_iso, profile)
        """
        pt = data[0]
        is_blacklisted = False
        blacklist_info = None
        blacklist_plates_data = self.get_blacklist() # Fetch full data

        # Проверка на схожесть с номерами из blacklist
        for bp_data in blacklist_plates_data:
            bp_text = bp_data['plate_text']
            # Use the improved similarity check with settings
            if self._is_similar_plate(pt, bp_text):
                is_blacklisted = True
                blacklist_info = bp_data
                logging.info(f"New plate '{pt}' matched blacklist entry '{bp_text}'")
                break

        # Unpack data, assuming order is correct
        (plate_text, confidence, country_code, lpr_timestamp,
         first_appearance, last_appearance, profile) = data

        # Insert into plates table
        cur = self.exec('''
            INSERT INTO plates
            (plate_text, confidence, country_code, timestamp,
             first_appearance, last_appearance, profile, is_blacklisted,
             reason, danger_level, total_appearances)
            VALUES (?,?,?,?,?,?,?,?,?,?, 1)
        ''', (plate_text, confidence, country_code, decode_if_bytes(lpr_timestamp),
              first_appearance, last_appearance, profile, is_blacklisted,
              blacklist_info['reason'] if blacklist_info else None,
              blacklist_info['danger_level'] if blacklist_info else None))
        pid = cur.lastrowid

        # Update the images table (consider if this is still needed)
        # self.save_images(pid, None, None) # Initialize with None initially?

        return pid

    # Consider removing save_images if images are only stored per detection
    # def save_images(self, pid, pp, fp):
    #     """
    #     Сохранение путей к изображениям (plate_image, frame_image) в таблице images.
    #     DEPRECATED if images stored in plate_detections?
    #     """
    #     self.exec('INSERT OR REPLACE INTO images (plate_id, plate_image_path, frame_image_path) VALUES (?,?,?)',
    #               (pid, pp, fp))

    def add_plate_detection(self, pid, detection_time_iso, source_file, confidence, pp, fp):
        """
        Добавляет новую запись обнаружения в таблицу plate_detections.
        Извлекает реальную временную метку из имени исходного файла.
        Предотвращает дублирование обнаружений в течение короткого промежутка времени.
        """
        real_timestamp = extract_timestamp_from_filename(source_file)
        real_timestamp_str = real_timestamp.isoformat() if real_timestamp else None

        # Ensure detection_time_iso is string
        detection_time_iso_str = decode_if_bytes(detection_time_iso)

        # Check for recent detections of the same plate
        recent_detection = None
        try:
            # Parse detection_time_iso_str to datetime
            detection_time = datetime.datetime.fromisoformat(detection_time_iso_str)
            
            # Set the time window for considering a detection as "recent" (1 second)
            time_window_seconds = 1
            
            # Get the timestamp for one second earlier
            one_second_earlier = (detection_time - datetime.timedelta(seconds=time_window_seconds)).isoformat()
            
            # Query for recent detections of the same plate
            recent_detection = self.exec('''
                SELECT id, confidence, plate_image_path, frame_image_path
                FROM plate_detections
                WHERE plate_id = ? AND detection_time > ? AND detection_time <= ?
                ORDER BY confidence DESC
                LIMIT 1
            ''', (pid, one_second_earlier, detection_time_iso_str)).fetchone()
        except (ValueError, TypeError) as e:
            # Log error but continue with normal insertion
            logging.warning(f"Error checking for recent detections: {e}")
        
        # If there's a recent detection, only keep the one with higher confidence
        if recent_detection:
            if confidence > recent_detection['confidence']:
                # Update the existing record with the new, higher confidence detection
                self.exec('''
                    UPDATE plate_detections
                    SET confidence = ?, plate_image_path = ?, frame_image_path = ?
                    WHERE id = ?
                ''', (confidence, pp, fp, recent_detection['id']))
                logging.debug(f"Updated existing detection with higher confidence: {confidence} > {recent_detection['confidence']}")
            else:
                # Current detection has lower confidence, so we don't save it
                logging.debug(f"Skipped lower confidence detection: {confidence} < {recent_detection['confidence']}")
                return  # Early return, don't insert a new record
        
        # No recent detection found or insertion needed, proceed with normal insertion
        self.exec('''
            INSERT INTO plate_detections
            (plate_id, detection_time, real_timestamp, source_file, confidence, plate_image_path, frame_image_path)
            VALUES (?,?,?,?,?,?,?)
        ''', (pid, detection_time_iso_str, real_timestamp_str, source_file, confidence, pp, fp))

        # Update last_seen in blacklist if this plate is blacklisted
        plate_info = self.get_plate_by_id(pid)
        if plate_info and plate_info['is_blacklisted']:
            self.exec('''
                UPDATE blacklist SET last_seen = ?
                WHERE plate_text = ? AND (last_seen IS NULL OR last_seen < ?)
            ''', (real_timestamp_str or detection_time_iso_str, plate_info['plate_text'], real_timestamp_str or detection_time_iso_str))


    def get_all_plates(self):
        """
        Возвращает все данные из plates, объединяя с информацией из blacklist.
        Извлекает пути к изображению с НАИВЫСШЕЙ уверенностью из plate_detections.
        """
        return self.exec('''
            SELECT
                p.*,
                (SELECT plate_image_path FROM plate_detections WHERE plate_id=p.id ORDER BY confidence DESC LIMIT 1) as plate_image_path,
                (SELECT frame_image_path FROM plate_detections WHERE plate_id=p.id ORDER BY confidence DESC LIMIT 1) as frame_image_path,
                (SELECT confidence FROM plate_detections WHERE plate_id=p.id ORDER BY confidence DESC LIMIT 1) as best_detection_confidence,
                b.reason as blacklist_reason,
                b.danger_level as blacklist_danger_level
            FROM plates p
            LEFT JOIN blacklist b ON p.plate_text = b.plate_text
            ORDER BY p.last_appearance DESC
        ''').fetchall()

    def get_plate_by_text(self, plate_text):
        """
        Возвращает данные для номера по его тексту.
        """
        return self.exec('SELECT * FROM plates WHERE plate_text = ?', (plate_text,)).fetchone()

    def get_plate_detections(self, plate_id):
        """
        Возвращает историю всех обнаружений для указанного номера,
        устраняя дубликаты с одинаковыми timestamp и source_file.
        """
        # For similar plates functionality, get the plate text for the given ID
        plate_info = self.get_plate_by_id(plate_id)
        if not plate_info:
            return []
        
        plate_text = decode_if_bytes(plate_info['plate_text'])
        
        # Get all similar plates (including the original)
        similar_plate_ids = [plate_id]  # Start with the original plate ID
        similar_plates = self.exec('''
            SELECT id, plate_text FROM plates 
            WHERE id != ?
        ''', (plate_id,)).fetchall()
        
        # Find plates that are similar using Levenshtein distance
        for p in similar_plates:
            p_text = decode_if_bytes(p['plate_text'])
            if self._is_similar_plate(plate_text, p_text):
                similar_plate_ids.append(p['id'])
        
        # Create placeholders for the IN clause
        placeholders = ','.join('?' * len(similar_plate_ids))
        
        # Modified query that groups by timestamp and source_file to eliminate duplicates
        # Uses a subquery with ROW_NUMBER() to get only the highest confidence record for each group
        return self.exec(f'''
            WITH RankedDetections AS (
                SELECT 
                    pd.*,
                    p.plate_text,
                    ROW_NUMBER() OVER (
                        PARTITION BY pd.real_timestamp, pd.source_file, pd.plate_id
                        ORDER BY pd.confidence DESC
                    ) as row_num
                FROM plate_detections pd
                JOIN plates p ON pd.plate_id = p.id
                WHERE pd.plate_id IN ({placeholders})
            )
            SELECT * FROM RankedDetections
            WHERE row_num = 1
            ORDER BY detection_time DESC
        ''', tuple(similar_plate_ids)).fetchall()
    
    def get_detections_for_plates(self, plate_ids):
        """
        Возвращает все обнаружения для списка указанных plate_id.
        """
        if not plate_ids:
            return []
        # Create placeholders for the query (?, ?, ...)
        placeholders = ','.join('?' * len(plate_ids))
        query = f'''
            SELECT * FROM plate_detections
            WHERE plate_id IN ({placeholders})
            ORDER BY plate_id, detection_time DESC
        '''
        return self.exec(query, tuple(plate_ids)).fetchall()


    def get_similar_plates(self, plate_id):
        """
        Возвращает список похожих номеров для указанного plate_id из таблицы similar_plates.
        """
        return self.exec('''
            SELECT sp.*,
                   p1.plate_text as plate_text1, p1.confidence as confidence1, p1.first_appearance as first_appearance1,
                   p2.plate_text as plate_text2, p2.confidence as confidence2, p2.first_appearance as first_appearance2
            FROM similar_plates sp
            JOIN plates p1 ON sp.plate_id1 = p1.id
            JOIN plates p2 ON sp.plate_id2 = p2.id
            WHERE sp.plate_id1 = ? OR sp.plate_id2 = ?
            ORDER BY sp.similarity_score DESC
        ''', (plate_id, plate_id)).fetchall()

    def update_plate_appearance(self, pid, la_iso, confidence):
        """
        Обновляет last_appearance, confidence (если новое значение выше),
        и увеличивает total_appearances для существующей записи номера.
        """
        # Update last_appearance and total_appearances
        self.exec('''
            UPDATE plates
            SET last_appearance = ?,
                total_appearances = total_appearances + 1
            WHERE id = ?
        ''', (la_iso, pid))

        # Update confidence only if the new one is higher
        self.exec('''
            UPDATE plates
            SET confidence = ?
            WHERE id = ? AND confidence < ?
        ''', (confidence, pid, confidence))


        # No need to update images table here if using plate_detections

    def find_potential_follow_plates(self):
        """
        Находит номера, которые потенциально следуют за камерой
        (несколько последовательных обнаружений с небольшими интервалами).
        Использует настройки из БД.
        """
        plates = self.exec('SELECT id, plate_text FROM plates WHERE total_appearances >= ?',
                           (self.get_setting('min_tracking_detections', 3),)).fetchall()
        result = []

        # Get settings once
        time_threshold = self.get_setting('tracking_time_threshold', 300)
        min_detections_setting = self.get_setting('min_tracking_detections', 3)

        # Efficiently fetch detections for relevant plates
        plate_ids = [p['id'] for p in plates]
        all_detections_map = {}
        if plate_ids:
            detections_list = self.get_detections_for_plates(plate_ids)
            for d in detections_list:
                 p_id = d['plate_id']
                 if p_id not in all_detections_map:
                     all_detections_map[p_id] = []
                 all_detections_map[p_id].append(d)


        for plate in plates:
            plate_id = plate['id']
            detections = all_detections_map.get(plate_id, [])

            # Skip if fewer detections than required setting
            if len(detections) < min_detections_setting:
                continue

            # Process detections for this plate
            detection_times_data = []
            for d in detections: # d is sqlite3.Row
                # Safely get timestamp string, prioritizing real_timestamp
                ts_str = decode_if_bytes(d['real_timestamp']) if 'real_timestamp' in d.keys() and d['real_timestamp'] else None
                if not ts_str: # Fallback to detection_time
                    ts_str = decode_if_bytes(d['detection_time']) if 'detection_time' in d.keys() and d['detection_time'] else None

                if ts_str:
                    try:
                        # Use fromisoformat for parsing
                        dt = datetime.datetime.fromisoformat(ts_str)
                        # Safely get other needed fields
                        confidence = d['confidence'] if 'confidence' in d.keys() else 0.0
                        image_path = d['frame_image_path'] if 'frame_image_path' in d.keys() else ''
                        detection_times_data.append({
                            'detection_time': dt,
                            'confidence': confidence,
                            'image_path': image_path
                        })
                    except (ValueError, TypeError) as e:
                        logging.warning(f"Error parsing timestamp '{ts_str}' for plate {plate_id}: {e}")
            # Check if the number meets the tracking criteria using the utility function
            # Pass the threshold from settings
            is_follow, reason = is_potential_follow(detection_times_data, threshold_seconds=time_threshold)
            if is_follow:
                result.append({
                    'plate': dict(plate), # Convert Row to dict
                    'reason': reason,
                    'detections': [dict(d) for d in detections] # Convert Row to dict
                })

        return result

    def analyze_similar_plates(self, threshold_distance=None, threshold_ratio=None):
        """
        Анализирует все номера в базе и находит похожие пары.
        Сохраняет найденные пары в таблицу similar_plates.
        Использует пороги из настроек, если не переданы явно.

        Returns:
            List of tuples: (plate1_dict, plate2_dict, ratio, distance, time_diff_seconds, detection_note)
        """
        # Get thresholds from settings if not provided
        if threshold_distance is None:
            threshold_distance = self.get_setting('levenshtein_threshold', 2.0)
        if threshold_ratio is None:
            threshold_ratio = self.get_setting('similarity_ratio', 0.8)

        logging.info(f"Analyzing similar plates with dist_thresh={threshold_distance}, ratio_thresh={threshold_ratio}")

        # Очищаем предыдущие результаты
        self.exec('DELETE FROM similar_plates')

        plates = self.get_all_plates() # Fetch all plates data
        result = []
        processed_pairs = set() # To avoid duplicate (p1, p2) and (p2, p1) checks

        for i, plate1 in enumerate(plates):
            plate_id1 = plate1['id']
            plate_text1 = decode_if_bytes(plate1['plate_text']).strip()
            confidence1 = plate1['confidence']

            for plate2 in plates[i+1:]: # Compare each plate with subsequent ones
                plate_id2 = plate2['id']
                plate_text2 = decode_if_bytes(plate2['plate_text']).strip()
                confidence2 = plate2['confidence']

                # Skip identical text (already handled) or if pair already processed
                if plate_text1 == plate_text2 or (plate_id2, plate_id1) in processed_pairs:
                    continue

                # Use the DB's similarity check function which uses settings
                is_sim = self._is_similar_plate(plate_text1, plate_text2, threshold_distance, threshold_ratio)

                if is_sim:
                    # Calculate similarity score (ratio) and distance for storage/info
                    distance = Levenshtein.distance(plate_text1, plate_text2)
                    ratio = Levenshtein.ratio(plate_text1, plate_text2)

                    # Calculate time difference based on first appearance
                    time_diff_seconds = None
                    try:
                        # Use fromisoformat
                        time1 = datetime.datetime.fromisoformat(decode_if_bytes(plate1['first_appearance']))
                        time2 = datetime.datetime.fromisoformat(decode_if_bytes(plate2['first_appearance']))
                        time_diff_seconds = abs((time2 - time1).total_seconds())
                    except (ValueError, TypeError, KeyError) as e:
                        logging.warning(f"Could not calculate time diff for {plate_text1} & {plate_text2}: {e}")

                    # Determine which plate is likely more correct based on confidence
                    detection_note = ""
                    conf_diff = abs(confidence1 - confidence2) if confidence1 is not None and confidence2 is not None else 0
                    if conf_diff > 15: # Significant confidence difference
                        if confidence1 > confidence2:
                            detection_note = f"'{plate_text1}' has higher confidence ({confidence1:.1f}%)"
                        else:
                            detection_note = f"'{plate_text2}' has higher confidence ({confidence2:.1f}%)"
                    elif confidence1 is not None and confidence2 is not None:
                         detection_note = "Similar confidence levels"
                    else:
                         detection_note = "Confidence difference unclear"


                    # Record the similar pair in the database
                    self.exec('''
                        INSERT INTO similar_plates
                        (plate_id1, plate_id2, similarity_score, time_diff_seconds, detection_note)
                        VALUES (?,?,?,?,?)
                    ''', (plate_id1, plate_id2, ratio, time_diff_seconds, detection_note))

                    # Add to results list and processed set
                    result.append((dict(plate1), dict(plate2), ratio, distance, time_diff_seconds, detection_note))
                    processed_pairs.add((plate_id1, plate_id2))

        logging.info(f"Found {len(result)} similar plate pairs.")
        return result

    def add_to_blacklist(self, pt, reason="", danger_level="HIGH"):
        """
        Добавляет или обновляет номер в blacklist.
        """
        now = datetime.datetime.now().isoformat()
        try:
            # Use INSERT OR REPLACE to handle updates
            self.exec('''
                INSERT OR REPLACE INTO blacklist
                (plate_text, reason, danger_level, date_added, last_seen)
                VALUES (?, ?, ?, COALESCE((SELECT date_added FROM blacklist WHERE plate_text=?), ?), ?)
            ''', (pt, reason, danger_level, pt, now, now))
            logging.info(f"Added/Updated '{pt}' in blacklist. Reason: {reason}, Level: {danger_level}")
            self.update_blacklist_status_for_plate(pt) # Update only affected plate
        except sqlite3.Error as e:
            logging.error(f"Error adding/updating '{pt}' to blacklist: {e}")
            raise

    def update_blacklist_status_for_plate(self, plate_text_to_check):
        """
        Пересчитывает is_blacklisted, reason, danger_level для всех записей
        в 'plates', которые похожи на указанный 'plate_text_to_check'.
        """
        blacklist_entry = self.exec('SELECT reason, danger_level FROM blacklist WHERE plate_text = ?',
                                    (plate_text_to_check,)).fetchone()

        if not blacklist_entry:
            # If the entry was removed from blacklist, unmark related plates
            reason = None
            danger_level = None
            new_status = 0
        else:
            reason = blacklist_entry['reason']
            danger_level = blacklist_entry['danger_level']
            new_status = 1

        # Find all plates similar to the one added/removed from blacklist
        all_plates = self.exec('SELECT id, plate_text FROM plates').fetchall()
        for plate in all_plates:
            if self._is_similar_plate(plate['plate_text'], plate_text_to_check):
                self.exec('''
                    UPDATE plates
                    SET is_blacklisted = ?, reason = ?, danger_level = ?
                    WHERE id = ?
                ''', (new_status, reason, danger_level, plate['id']))
                logging.debug(f"Updated blacklist status for plate ID {plate['id']} ({plate['plate_text']}) to {new_status}")


    def remove_from_blacklist(self, pt):
        """
        Удаление номера из blacklist и обновление статусов в plates.
        """
        try:
            self.exec('DELETE FROM blacklist WHERE plate_text=?', (pt,))
            logging.info(f"Removed '{pt}' from blacklist.")
            # Update status for plates that might have matched the removed one
            self.update_blacklist_status_for_plate(pt)
        except sqlite3.Error as e:
            logging.error(f"Error removing '{pt}' from blacklist: {e}")
            raise

    def get_blacklist(self):
        """
        Возвращает все записи из blacklist.
        """
        # No need to join with plates here, count can be done separately if needed
        return self.exec('SELECT * FROM blacklist ORDER BY plate_text').fetchall()

    def is_blacklisted(self, pt):
        """
        Проверяет, существует ли номер pt в blacklist (точное совпадение).
        Возвращает данные строки или None.
        """
        return self.exec('SELECT * FROM blacklist WHERE plate_text=?', (pt,)).fetchone()


    def add_blacklist_alert(self, plate_text, image_path):
        """
        Записывает факт обнаружения номера из blacklist в таблицу blacklist_alerts.
        """
        now = datetime.datetime.now().isoformat()
        self.exec('''
            INSERT INTO blacklist_alerts (plate_text, detection_time, image_path)
            VALUES (?,?,?)
        ''', (plate_text, now, image_path))

    def get_unprocessed_alerts(self):
        """
        Возвращает все необработанные (processed=0) алерты из blacklist_alerts.
        """
        return self.exec('SELECT * FROM blacklist_alerts WHERE processed=0 ORDER BY detection_time DESC').fetchall()

    def mark_alert_processed(self, alert_id):
        """
        Ставит флаг processed=1 для указанного alert_id.
        """
        self.exec('UPDATE blacklist_alerts SET processed=1 WHERE id=?', (alert_id,))

    def get_plate_stats(self):
        """
        Собирает сводную статистику по номерам в базе.
        """
        stats = {}
        try:
            stats['total_plates'] = self.exec('SELECT COUNT(id) FROM plates').fetchone()[0]
            stats['blacklisted_count'] = self.exec('SELECT COUNT(id) FROM plates WHERE is_blacklisted = 1').fetchone()[0]

            avg_conf_result = self.exec('SELECT AVG(confidence) FROM plates').fetchone()
            stats['avg_confidence'] = avg_conf_result[0] if avg_conf_result and avg_conf_result[0] is not None else 0.0

            stats['total_detections'] = self.exec('SELECT COUNT(id) FROM plate_detections').fetchone()[0]

            # Count unique countries directly from plates
            stats['unique_countries'] = self.exec('SELECT COUNT(DISTINCT country_code) FROM plates WHERE country_code IS NOT NULL AND country_code != ""').fetchone()[0]

            stats['similar_plates_count'] = self.exec('SELECT COUNT(*) FROM similar_plates').fetchone()[0]

            # Recalculate potential follow count based on current settings (can be slow)
            # Consider caching this or calculating less frequently
            # follow_plates = self.find_potential_follow_plates()
            # stats['potential_follow_count'] = len(follow_plates)
            stats['potential_follow_count'] = "N/A" # Placeholder to avoid slow calculation

        except Exception as e:
            logging.error(f"Error getting plate stats: {e}")
            # Initialize stats with zeros or N/A on error
            stats = {
                'total_plates': 0, 'blacklisted_count': 0, 'avg_confidence': 0.0,
                'total_detections': 0, 'unique_countries': 0, 'similar_plates_count': 0,
                'potential_follow_count': 'Error'
            }
        return stats


    def get_plate_id(self, pt):
        """
        Возвращает id записи с plate_text == pt или None.
        """
        result = self.exec('SELECT id FROM plates WHERE plate_text=?', (pt,)).fetchone()
        return result[0] if result else None


    def get_plate_by_id(self, pid):
        """
        Возвращает запись из plates по её id.
        """
        return self.exec('SELECT * FROM plates WHERE id=?', (pid,)).fetchone()

    def add_profile(self, pn):
        """
        Создает новую запись в таблице profiles.
        """
        self.exec('INSERT INTO profiles (profile_name, created_date, settings) VALUES (?,?,?)',
                  (pn, datetime.datetime.now().isoformat(), '{}'))

    def get_profiles(self):
        """
        Возвращает список имен профилей.
        """
        return [r['profile_name'] for r in self.exec('SELECT profile_name FROM profiles ORDER BY profile_name')]

    def get_setting(self, sn, default=None):
        """
        Возвращает значение настройки по её имени (sn).
        """
        result = self.exec('SELECT setting_value, setting_type FROM settings WHERE setting_name=?', (sn,)).fetchone()
        if not result:
            # If setting doesn't exist but we have a default, create it
            if default is not None and sn == 'min_confidence':
                self.set_setting(sn, 30)  # Используем более низкий порог
                return 30
            return default

        value = result['setting_value']
        type_ = result['setting_type']
        return self._convert_setting_value(value, type_)

    def _convert_setting_value(self, value, type_):
        """
        Преобразует строковое значение в соответствующий тип (int, float, bool, str).
        """
        if value is None:
            return None # Handle None values gracefully
        try:
            if type_ == 'integer':
                return int(value)
            elif type_ == 'float':
                return float(value)
            elif type_ == 'boolean':
                return value.lower() == 'true'
            else: # string or unknown
                return str(value)
        except (ValueError, TypeError) as e:
            logging.error(f"Error converting setting value '{value}' to type '{type_}': {e}")
            # Return raw string or default based on policy
            return value # Return raw string on conversion error


    def set_setting(self, sn, sv):
        """
        Обновляет или вставляет настройку sn со значением sv.
        Определяет тип данных.
        """
        setting_type = 'string' # Default type
        if isinstance(sv, bool):
            setting_type = 'boolean'
            sv = str(sv).lower()
        elif isinstance(sv, int):
            setting_type = 'integer'
            sv = str(sv)
        elif isinstance(sv, float):
            setting_type = 'float'
            sv = str(sv)
        else: # Convert anything else to string
             sv = str(sv)

        # Use INSERT OR REPLACE (or separate INSERT/UPDATE)
        self.exec('''
            INSERT OR REPLACE INTO settings (setting_name, setting_value, setting_type)
            VALUES (?, ?, ?)
        ''', (sn, sv, setting_type))


    def clear_database(self):
        """
        Полностью удаляет и пересоздает структуру базы данных.
        """
        logging.warning("Clearing entire database!")
        with sqlite3.connect(self.path) as conn:
            # More robust dropping by querying existing tables first
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            script = ""
            for table in tables:
                 if not table.startswith("sqlite_"): # Avoid dropping system tables
                     script += f"DROP TABLE IF EXISTS {table};\n"
            if script:
                 conn.executescript(script)

        # Заново создаем структуру таблиц и начальные настройки
        self._init_db()
        logging.info("Database cleared and re-initialized.")