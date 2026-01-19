import os
import win32crypt  # Библиотека pywin32 для доступа к Windows DPAPI
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path
from ..config import KEY_VAULT_PATH

class CryptoManager:
    """
    Менеджер криптографии.
    Отвечает за:
    1. Инициализацию и защиту Мастер-ключа (через DPAPI).
    2. Шифрование/Дешифрование сырых данных (вектора лиц, ключи файлов).
    3. Шифрование файлов на диске с безопасным удалением оригиналов.
    """

    def __init__(self):
        # При инициализации сразу загружаем или создаем мастер-ключ
        self.master_key = self._load_or_create_master_key()

    def _load_or_create_master_key(self) -> bytes:
        """
        Загружает зашифрованный мастер-ключ из файла и расшифровывает его через DPAPI,
        либо создает новый, если файла нет.
        """
        if KEY_VAULT_PATH.exists():
            try:
                with open(KEY_VAULT_PATH, "rb") as f:
                    encrypted_blob = f.read()
                
                # ИСПРАВЛЕНИЕ:
                # CryptUnprotectData может возвращать кортеж разной длины (2 или 5 элементов)
                # в зависимости от версии. Нам всегда нужен второй элемент (индекс 1) - сами данные.
                result = win32crypt.CryptUnprotectData(
                    encrypted_blob, None, None, None, 0
                )
                return result[1]
                
            except Exception as e:
                # Если DPAPI не может расшифровать (например, ключ перенесен на другой ПК),
                # работа системы невозможна.
                raise RuntimeError(f"[CRYPTO FATAL] Не удалось расшифровать мастер-ключ через DPAPI. "
                                   f"Возможно, файл ключа был перемещен на другую машину. Ошибка: {e}")
        else:
            print("[CRYPTO] Генерация нового мастер-ключа...")
            # Генерация 32 байт (256 бит) криптостойкого случайного числа
            new_key = get_random_bytes(32)
            
            # Шифрование ключа средствами Windows (DPAPI).
            # Описание "BlueTeamMasterKey" может помочь при аудите.
            encrypted_blob = win32crypt.CryptProtectData(
                new_key, "BlueTeamMasterKey", None, None, None, 0
            )
            
            # Сохранение защищенного блоба на диск
            with open(KEY_VAULT_PATH, "wb") as f:
                f.write(encrypted_blob)
            
            return new_key

    def encrypt_bytes(self, data: bytes) -> bytes:
        """
        Шифрует байты мастер-ключом (AES-256-GCM).
        Используется для защиты векторов лиц и ключей файлов перед записью в БД.
        
        Format: [NONCE (12 bytes)] [TAG (16 bytes)] [CIPHERTEXT]
        """
        nonce = get_random_bytes(12)  # Стандартный размер nonce для GCM
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext

    def decrypt_bytes(self, encrypted_blob: bytes) -> bytes:
        """
        Расшифровывает данные мастер-ключом.
        Проверяет целостность (MAC tag) автоматически.
        """
        try:
            nonce = encrypted_blob[:12]
            tag = encrypted_blob[12:28]
            ciphertext = encrypted_blob[28:]
            
            cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Ошибка целостности данных (MAC check failed). Данные повреждены или ключ неверен.")

    def encrypt_file(self, file_path_str: str) -> tuple:
        """
        Полный цикл шифрования файла:
        1. Чтение оригинала.
        2. Генерация уникального ключа файла (File Key).
        3. Шифрование контента.
        4. Запись .enc файла.
        5. Безопасное удаление (Wipe) оригинала.
        6. Шифрование File Key мастер-ключом.
        
        Returns:
            tuple: (путь_к_новому_файлу_enc, зашифрованный_ключ_файла_blob)
        """
        path = Path(file_path_str)
        if not path.exists():
            raise FileNotFoundError(f"Файл не найден: {path}")

        # 1. Генерация уникального ключа для ЭТОГО файла
        file_key = get_random_bytes(32)

        # 2. Чтение данных
        with open(path, 'rb') as f:
            plaintext_data = f.read()

        # 3. Шифрование данных
        nonce = get_random_bytes(12)
        cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_data)

        # 4. Запись зашифрованного файла
        # Имя файла: original.docx -> original.docx.enc
        enc_path = path.parent / (path.name + ".enc")
        with open(enc_path, 'wb') as f:
            # Структура файла: Nonce + Tag + Data
            f.write(nonce + tag + ciphertext)

        # 5. Secure Delete (Wipe) оригинала
        # Простого os.remove недостаточно, данные остаются на диске.
        # Перезаписываем файл нулями перед удалением.
        try:
            file_size = path.stat().st_size
            with open(path, 'wb') as f:
                f.write(b'\x00' * file_size)
        except Exception as e:
            print(f"[WARN] Не удалось выполнить secure wipe для {path}: {e}")
        
        os.remove(path)

        # 6. Шифрование ключа файла мастер-ключом для сохранения в БД
        encrypted_file_key_blob = self.encrypt_bytes(file_key)

        return str(enc_path), encrypted_file_key_blob

    def decrypt_file_content(self, enc_path_str: str, encrypted_file_key_blob: bytes) -> bytes:
        """
        Расшифровывает содержимое файла в оперативную память (bytes).
        Не сохраняет расшифрованный файл на диск (это делает вызывающий код во временную папку при необходимости).
        
        Args:
            enc_path_str: Путь к .enc файлу.
            encrypted_file_key_blob: Зашифрованный мастер-ключом ключ этого файла (из БД).
        
        Returns:
            bytes: Расшифрованное содержимое файла.
        """
        path = Path(enc_path_str)
        if not path.exists():
            raise FileNotFoundError(f"Зашифрованный файл не найден: {path}")

        # 1. Расшифровка ключа файла (File Key) с помощью Мастер-ключа
        file_key = self.decrypt_bytes(encrypted_file_key_blob)

        # 2. Чтение зашифрованного файла
        with open(path, 'rb') as f:
            file_data = f.read()

        # Разбор структуры файла
        nonce = file_data[:12]
        tag = file_data[12:28]
        ciphertext = file_data[28:]

        # 3. Расшифровка контента
        cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        return decrypted_data