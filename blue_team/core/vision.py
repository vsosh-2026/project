import face_recognition
import cv2
import numpy as np
import pickle
import time
from pathlib import Path

# Импортируем конфиги
from ..config import CAMERA_INDEX, FACE_TOLERANCE, FRAME_SCALING

class VisionSystem:
    """
    Система защиты v17.0 (Physics Based).
    
    ОТКАЗ ОТ НЕЙРОСЕТЕЙ (ONNX).
    Используется математический анализ физики изображения:
    1. YCrCb Skin Analysis: Проверка естественности спектра кожи.
    2. Laplacian Texture: Поиск пиксельной сетки (экраны) или размытия (бумага).
    3. HSV Glare: Поиск бликов от стекла.
    
    Не требует скачивания файлов. Работает автономно.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self.known_users = [] 
        self.update_cache()
        self.cap = None

    def update_cache(self):
        try:
            raw_data = self.db.get_all_encodings()
            new_cache = []
            for row in raw_data:
                if row[3]:
                    try:
                        dec = self.db.crypto.decrypt_bytes(row[3])
                        new_cache.append(pickle.loads(dec))
                    except: continue
            self.known_users = new_cache
            print(f"[VISION] Загружено эталонов лиц: {len(self.known_users)}")
        except: pass

    def _get_frame(self, high_res=False):
        if self.cap is None or not self.cap.isOpened():
            self.cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW)
            if not self.cap.isOpened(): return None
        ret, frame = self.cap.read()
        if not ret: return None
        if high_res: return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        try:
            small = cv2.resize(frame, (0, 0), fx=FRAME_SCALING, fy=FRAME_SCALING)
            return cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
        except: return None

    def check_authorization(self):
        if not self.known_users: return False
        rgb = self._get_frame(high_res=False)
        if rgb is None: return False
        locs = face_recognition.face_locations(rgb)
        if not locs: return False
        encs = face_recognition.face_encodings(rgb, locs)
        for enc in encs:
            matches = face_recognition.compare_faces(self.known_users, enc, tolerance=FACE_TOLERANCE)
            if True in matches: return True
        return False

    def _check_glare_hsv(self, img_bgr):
        """
        1. АНАЛИЗ БЛИКОВ (HSV).
        Экраны отражают свет ламп. Кожа рассеивает.
        """
        hsv = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2HSV)
        h, s, v = cv2.split(hsv)

        # Пиксели ярче 250 считаем жестким бликом
        glare_pixels = np.count_nonzero(v > 250)
        total_pixels = v.size
        glare_ratio = glare_pixels / total_pixels

        # Если > 1% лица в жестком блике — это стекло/экран
        if glare_ratio > 0.01:
            return False, f"Блик стекла ({glare_ratio:.3f})"
        
        return True, "OK"

    def _check_skin_ycrcb(self, img_bgr):
        """
        2. СПЕКТРАЛЬНЫЙ АНАЛИЗ (YCrCb).
        Человеческая кожа имеет очень специфический диапазон в каналах Cr и Cb.
        Экраны планшетов (RGB) часто выходят за эти рамки.
        """
        img_ycrcb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)
        
        # Диапазоны "здоровой кожи" в YCrCb (научные данные)
        # Y (Яркость) - игнорируем (любое освещение)
        # Cr (Красный компонент): 133-173
        # Cb (Синий компонент): 77-127
        min_skin = np.array([0, 133, 77], dtype=np.uint8)
        max_skin = np.array([255, 173, 127], dtype=np.uint8)

        # Создаем маску: какие пиксели похожи на кожу?
        mask = cv2.inRange(img_ycrcb, min_skin, max_skin)
        
        skin_pixels = cv2.countNonZero(mask)
        total_pixels = img_bgr.shape[0] * img_bgr.shape[1]
        skin_ratio = skin_pixels / total_pixels

        # Если меньше 50% лица похоже на человеческую кожу -> это подделка
        # (Например, синеватый экран или ч/б принтер)
        if skin_ratio < 0.50:
            return False, f"Неестественный спектр кожи ({skin_ratio:.2f})"
            
        return True, "OK"

    def _check_texture_laplacian(self, img_bgr):
        """
        3. АНАЛИЗ ТЕКСТУРЫ (Laplacian).
        Проверяет "зернистость" изображения.
        
        - Экран: Видна пиксельная решетка -> Высокая "резкость" шума.
        - Бумага: Размытие при печати -> Очень низкая резкость.
        - Живое лицо: Средняя естественная резкость.
        """
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
        
        # Вычисляем дисперсию Лапласиана (меру четкости граней)
        focus_measure = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # Пороги (нужно калибровать под камеру, но это средние значения)
        # < 100: Слишком мыльно (размытое фото/бумага)
        # > 900: Слишком резко (пиксельный шум экрана/зерно)
        
        if focus_measure < 80:
            return False, f"Размытая текстура (Бумага/Фото) Val:{focus_measure:.0f}"
        
        # Если камера HD, экраны могут давать шум > 1000
        # Живое лицо обычно в диапазоне 100 - 600
        if focus_measure > 1200:
            return False, f"Пиксельная сетка (Экран) Val:{focus_measure:.0f}"
            
        return True, f"OK ({focus_measure:.0f})"

    def check_liveness_and_auth(self):
        """
        Комбинированная физическая проверка.
        """
        FRAMES_TO_CHECK = 5
        
        print("[VISION] Сканирование (Physics Mode)...")

        for _ in range(FRAMES_TO_CHECK):
            if self.cap is None or not self.cap.isOpened():
                self.cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW)
            
            ret, frame_bgr = self.cap.read()
            if not ret: break
            
            small_bgr = cv2.resize(frame_bgr, (0, 0), fx=FRAME_SCALING, fy=FRAME_SCALING)
            rgb_small = cv2.cvtColor(small_bgr, cv2.COLOR_BGR2RGB)
            
            # 1. Поиск лиц
            locs = face_recognition.face_locations(rgb_small)
            if not locs:
                time.sleep(0.05)
                continue
            
            encs = face_recognition.face_encodings(rgb_small, locs)
            
            frame_is_clean = True
            valid_users_found = 0
            
            for i, face_loc in enumerate(locs):
                # --- АНАЛИЗ "ЖИВОСТИ" ---
                top, right, bottom, left = face_loc
                factor = 1.0 / FRAME_SCALING
                
                # Вырезаем лицо в полном разрешении для анализа текстуры
                # Чуть расширяем рамку, чтобы захватить контуры
                h, w, _ = frame_bgr.shape
                pad = 20
                y1 = max(0, int(top*factor) - pad)
                y2 = min(h, int(bottom*factor) + pad)
                x1 = max(0, int(left*factor) - pad)
                x2 = min(w, int(right*factor) + pad)
                
                face_crop = frame_bgr[y1:y2, x1:x2]
                
                if face_crop.size == 0: continue

                # ПРОВЕРКА 1: Блики
                is_live_glare, msg_glare = self._check_glare_hsv(face_crop)
                
                # ПРОВЕРКА 2: Спектр кожи (YCrCb)
                is_live_skin, msg_skin = self._check_skin_ycrcb(face_crop)
                
                # ПРОВЕРКА 3: Текстура (Laplacian)
                is_live_tex, msg_tex = self._check_texture_laplacian(face_crop)
                
                # Итоговый статус живости
                is_live = is_live_glare and is_live_skin and is_live_tex
                
                reason = "OK"
                if not is_live_glare: reason = msg_glare
                elif not is_live_skin: reason = msg_skin
                elif not is_live_tex: reason = msg_tex
                
                # --- АНАЛИЗ ЛИЧНОСТИ ---
                current_encoding = encs[i]
                is_known = False
                if self.known_users:
                    matches = face_recognition.compare_faces(self.known_users, current_encoding, tolerance=FACE_TOLERANCE)
                    if True in matches:
                        is_known = True
                
                # ЛОГИРОВАНИЕ
                status = ""
                if not is_known:
                    status = "ЧУЖОЙ"
                    frame_is_clean = False
                elif not is_live:
                    status = f"ФЕЙК [{reason}]"
                    frame_is_clean = False
                else:
                    status = "СОТРУДНИК"
                    valid_users_found += 1
                
                print(f"[DEBUG] Лицо #{i+1}: {status}")

                if not frame_is_clean:
                    print(f">>> БЛОКИРОВКА: {status} <<<")
                    return False, f"Доступ запрещен: {status}"

            # Если все чисто и есть сотрудник
            if frame_is_clean and valid_users_found > 0:
                print(f">>> УСПЕХ: Доступ разрешен <<<")
                return True, "Доступ разрешен."

            time.sleep(0.05)

        return False, "Доступ запрещен (Нет лиц)"

    def release(self):
        if self.cap:
            self.cap.release()
            self.cap = None