# utils.py

import os
import datetime
import re
from PIL import Image, ImageTk
import logging


def format_time(seconds):
    """
    Превращает количество секунд в строку формата mm:ss.
    """
    if seconds < 0:
        seconds = 0
    return f"{int(seconds // 60)}:{int(seconds % 60):02d}"


def load_and_resize_image(path, max_size):
    """
    Загружает изображение с диска, ресайзит его до max_size (width, height),
    возвращает объект ImageTk.PhotoImage.
    """
    try:
        if path and os.path.exists(path):
            img = Image.open(path)
            ratio = min(max_size[0] / img.width, max_size[1] / img.height)
            new_size = (int(img.width * ratio), int(img.height * ratio))
            resized_img = img.resize(new_size, Image.LANCZOS)
            return ImageTk.PhotoImage(resized_img)
    except Exception as e:
        logging.error(f"Error loading image {path}: {e}")
    return None


def decode_if_bytes(value):
    """
    Декодирует bytes -> str, если value является байтовой строкой.
    """
    return value.decode('utf-8') if isinstance(value, bytes) else value


def parse_date(date_str):
    """
    Parses a date string (ISO8601 or other common formats)
    and returns a datetime object or None on failure.
    """
    val = decode_if_bytes(date_str)
    if not val:
        return None
    try:
        # Attempt ISO format first
        return datetime.datetime.fromisoformat(val)
    except ValueError:
        # Add other formats to try if needed
        common_formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y%m%d%H%M%S', # From filename extraction
            '%Y-%m-%d',
        ]
        for fmt in common_formats:
            try:
                return datetime.datetime.strptime(val, fmt)
            except ValueError:
                continue # Try next format
        # If all formats fail, log a warning and return None
        # logging.warning(f"Could not parse date string: {val}") # Optional logging
        return None
    except Exception as e: # Catch other potential errors like TypeError
        # logging.error(f"Error parsing date string '{val}': {e}") # Optional logging
        return None


def extract_timestamp_from_filename(filename):
    """
    Извлекает временную метку из имени файла формата 00000006_20250226102711_NF.mp4.
    Возвращает datetime объект.
    """
    try:
        # Регулярное выражение для извлечения timestamp части из имени файла
        match = re.search(r'_(\d{14})_', filename)
        if match:
            timestamp_str = match.group(1)
            # Преобразуем строку в datetime объект (YYYYMMDDHHMMSS)
            timestamp = datetime.datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
            return timestamp
        
        # Альтернативный поиск даты в имени (если формат отличается)
        match = re.search(r'(\d{8})(\d{6})', filename)
        if match:
            date_part = match.group(1)
            time_part = match.group(2)
            timestamp_str = f"{date_part}{time_part}"
            timestamp = datetime.datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
            return timestamp
    except Exception as e:
        logging.error(f"Failed to extract timestamp from filename {filename}: {e}")
    
    return None


def calculate_time_difference(time1, time2):
    """
    Рассчитывает разницу между двумя datetime объектами.
    Возвращает разницу в секундах и человекочитаемый формат.
    """
    if not time1 or not time2:
        return None, "Unknown"
    
    diff = abs(time2 - time1)
    total_seconds = diff.total_seconds()
    
    # Формируем человекочитаемую строку
    if total_seconds < 60:
        return total_seconds, f"{int(total_seconds)} seconds"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return total_seconds, f"{int(minutes)} min {int(seconds)} sec"
    elif total_seconds < 86400:  # меньше суток
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return total_seconds, f"{int(hours)} hours {int(minutes)} min"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        return total_seconds, f"{int(days)} days {int(hours)} hours"


def is_potential_follow(detections, threshold_seconds=300, min_interval_seconds=2):
    """
    Анализирует последовательные обнаружения номера для определения, 
    не движется ли он вместе с камерой.
    
    Признаки:
    - Минимум 3 обнаружения
    - Интервал между обнаружениями < threshold_seconds (5 минут) и > min_interval_seconds (2 сек)
    - Стабильный паттерн обнаружений (без больших промежутков)
    
    Возвращает (bool, str) - результат и причину.
    """
    if not detections or len(detections) < 3:
        return False, "Not enough detections"
    
    # Сортируем по времени
    sorted_detections = sorted(detections, key=lambda x: x['detection_time'])
    
    # Проверяем интервалы между обнаружениями
    consistent_intervals = True
    valid_intervals = []
    
    for i in range(1, len(sorted_detections)):
        curr_time = sorted_detections[i]['detection_time']
        prev_time = sorted_detections[i-1]['detection_time']
        
        interval_seconds, _ = calculate_time_difference(curr_time, prev_time)
        if interval_seconds is None:
            continue
            
        # Ignore intervals that are too short (likely duplicate detections)
        if interval_seconds < min_interval_seconds:
            logging.debug(f"Ignoring too short interval: {interval_seconds} seconds")
            continue
            
        valid_intervals.append(interval_seconds)
        
        if interval_seconds > threshold_seconds:
            consistent_intervals = False
    
    # If there are no valid intervals after filtering, this isn't tracking
    if not valid_intervals:
        return False, "No valid detection intervals found"
    
    # Check if we still have enough detections after filtering
    if len(valid_intervals) < 2:  # We need at least 3 detections = 2 intervals
        return False, f"Not enough valid intervals ({len(valid_intervals)}) after filtering"
    
    # Если все интервалы маленькие, это подозрительно
    if consistent_intervals and valid_intervals and sum(valid_intervals) / len(valid_intervals) < threshold_seconds:
        avg_interval = sum(valid_intervals) / len(valid_intervals)
        return True, f"Multiple detections with average interval {int(avg_interval)} seconds"
    
    return False, "Inconsistent detection pattern"

def is_plate_similar(plate1, plate2, confidence1=None, confidence2=None):
    """
    Определяет, являются ли два номера схожими, с учетом уверенности распознавания.
    В случае, если уровни уверенности сильно различаются, предпочтение отдается номеру
    с более высоким уровнем уверенности.
    
    Возвращает (bool, str): результат и объяснение.
    """
    # Проверка на идентичность
    if plate1 == plate2:
        return True, "Identical plates"
    
    # Расстояние Левенштейна
    import Levenshtein
    distance = Levenshtein.distance(plate1, plate2)
    ratio = Levenshtein.ratio(plate1, plate2)
    
    # Определяем, насколько схожи номера
    if distance <= 2:
        # Если указана уверенность, используем её для дополнительного определения
        if confidence1 is not None and confidence2 is not None:
            confidence_diff = abs(confidence1 - confidence2)
            higher_conf = max(confidence1, confidence2)
            more_confident = "first" if confidence1 >= confidence2 else "second"
            
            if confidence_diff > 15:  # Значительная разница в уверенности
                return True, f"Similar plates (distance={distance}, ratio={ratio:.2f}). The {more_confident} plate has significantly higher confidence ({higher_conf:.1f}%)"
            else:
                return True, f"Similar plates (distance={distance}, ratio={ratio:.2f}) with comparable confidence levels"
        
        return True, f"Similar plates (distance={distance}, ratio={ratio:.2f})"
    
    # Проверяем на высокий ratio для более длинных номеров
    if len(plate1) >= 5 and len(plate2) >= 5 and ratio >= 0.8:
        return True, f"Similar plates (ratio={ratio:.2f})"
    
    return False, f"Different plates (distance={distance}, ratio={ratio:.2f})"
