import sqlite3
import pickle
import os
from pathlib import Path

# Импортируем путь из конфигурации
from ..config import DB_PATH 
# Импортируем криптографию
from .crypto import CryptoManager

class DatabaseManager:
    """
    Менеджер базы данных.
    Отвечает за хранение пользователей, ролей, объектов защиты и ключей шифрования.
    Thread-safe реализация (использует локальные курсоры).
    """

    def __init__(self):
        self.db_path = str(DB_PATH)
        
        # Создаем папку data, если её нет
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Инициализируем криптографию
        self.crypto = CryptoManager()
        
        # Подключение к SQLite (check_same_thread=False нужен для работы GUI и потока защиты)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        
        self._init_tables()
        self._seed_roles()

    def _init_tables(self):
        """Создание структуры таблиц."""
        cur = self.conn.cursor()
        
        # 1. Роли
        cur.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)

        # 2. Пользователи (Сотрудники)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                enc_encoding BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 3. Приложения (Мониторинг)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                exe_name TEXT NOT NULL UNIQUE,
                is_active INTEGER DEFAULT 1
            )
        """)

        # 4. Файлы (Защищенное хранилище)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                enc_path TEXT NOT NULL UNIQUE,
                enc_key BLOB NOT NULL,
                status INTEGER DEFAULT 1
            )
        """)

        # 5. Права доступа к ФАЙЛАМ (RBAC)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_permissions (
                file_id INTEGER,
                role TEXT,
                PRIMARY KEY (file_id, role),
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
            )
        """)

        # 6. Права доступа к ПРИЛОЖЕНИЯМ (RBAC)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_permissions (
                app_id INTEGER,
                role TEXT,
                PRIMARY KEY (app_id, role),
                FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
            )
        """)
        
        self.conn.commit()
        cur.close()

    def _seed_roles(self):
        """Создает стандартные роли при первом запуске."""
        cur = self.conn.cursor()
        try:
            cur.execute("SELECT count(*) FROM roles")
            if cur.fetchone()[0] == 0:
                default_roles = ["Администратор", "Менеджер", "Сотрудник"]
                for r in default_roles:
                    cur.execute("INSERT INTO roles (name) VALUES (?)", (r,))
                self.conn.commit()
        except Exception:
            pass
        finally:
            cur.close()

    # =========================================================================
    # УПРАВЛЕНИЕ РОЛЯМИ
    # =========================================================================

    def get_roles_list(self):
        cur = self.conn.cursor()
        cur.execute("SELECT name FROM roles ORDER BY id")
        result = [row[0] for row in cur.fetchall()]
        cur.close()
        return result
    
    def add_role(self, name):
        cur = self.conn.cursor()
        try:
            cur.execute("INSERT INTO roles (name) VALUES (?)", (name,))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            cur.close()

    def delete_role(self, name):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM roles WHERE name=?", (name,))
        self.conn.commit()
        cur.close()
        
    def get_user_count_by_role(self, role_name):
        cur = self.conn.cursor()
        cur.execute("SELECT count(*) FROM users WHERE role=?", (role_name,))
        res = cur.fetchone()[0]
        cur.close()
        return res

    # =========================================================================
    # УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
    # =========================================================================

    def add_user(self, name, role, face_encoding):
        if face_encoding is None:
            return False
        cur = self.conn.cursor()
        try:
            # Сериализация + Шифрование биометрии
            encoding_bytes = pickle.dumps(face_encoding)
            encrypted_blob = self.crypto.encrypt_bytes(encoding_bytes)
            
            cur.execute(
                "INSERT INTO users (name, role, enc_encoding) VALUES (?, ?, ?)",
                (name, role, encrypted_blob)
            )
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error adding user: {e}")
            return False
        finally:
            cur.close()

    def get_users(self):
        """Возвращает список пользователей для UI."""
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, role FROM users")
        cols = ["id", "name", "role"]
        result = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.close()
        return result
    
    def get_all_encodings(self):
        """Возвращает сырые данные (включая зашифрованный BLOB) для VisionSystem."""
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, role, enc_encoding FROM users")
        result = cur.fetchall()
        cur.close()
        return result

    def delete_user(self, uid):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (uid,))
        self.conn.commit()
        cur.close()

    # =========================================================================
    # УПРАВЛЕНИЕ ПРИЛОЖЕНИЯМИ
    # =========================================================================

    def add_app(self, name, exe_path, allowed_roles):
        exe_name = os.path.basename(exe_path)
        cur = self.conn.cursor()
        
        cur.execute("SELECT id FROM apps WHERE exe_name=?", (exe_name,))
        if cur.fetchone():
            cur.close()
            return False

        try:
            cur.execute("INSERT INTO apps (name, exe_name) VALUES (?, ?)", (name, exe_name))
            aid = cur.lastrowid
            
            for role in allowed_roles:
                cur.execute("INSERT INTO app_permissions (app_id, role) VALUES (?, ?)", (aid, role))
            
            self.conn.commit()
            return True
        except Exception:
            return False
        finally:
            cur.close()

    def get_app_permissions(self, aid):
        cur = self.conn.cursor()
        cur.execute("SELECT role FROM app_permissions WHERE app_id=?", (aid,))
        result = [row[0] for row in cur.fetchall()]
        cur.close()
        return result

    def get_all_apps_raw(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, exe_name, is_active FROM apps")
        result = cur.fetchall()
        cur.close()
        return result
        
    def get_apps(self):
        """Для потока мониторинга (возвращает только активные)."""
        cur = self.conn.cursor()
        cur.execute("SELECT exe_name, name, is_active FROM apps WHERE is_active=1")
        result = [{"exe": row[0], "name": row[1]} for row in cur.fetchall()]
        cur.close()
        return result

    def delete_app(self, aid):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM apps WHERE id=?", (aid,))
        cur.execute("DELETE FROM app_permissions WHERE app_id=?", (aid,))
        self.conn.commit()
        cur.close()
    
    def toggle_app_status(self, aid, current_status):
        new_status = 0 if current_status == 1 else 1
        cur = self.conn.cursor()
        cur.execute("UPDATE apps SET is_active=? WHERE id=?", (new_status, aid))
        self.conn.commit()
        cur.close()

    # =========================================================================
    # УПРАВЛЕНИЕ ФАЙЛАМИ
    # =========================================================================

    def add_file(self, original_name, enc_path, enc_key, allowed_roles):
        cur = self.conn.cursor()
        try:
            cur.execute(
                "INSERT INTO files (original_name, enc_path, enc_key) VALUES (?, ?, ?)",
                (original_name, str(enc_path), enc_key)
            )
            fid = cur.lastrowid
            
            for role in allowed_roles:
                cur.execute("INSERT INTO file_permissions (file_id, role) VALUES (?, ?)", (fid, role))
            
            self.conn.commit()
            return True
        except Exception:
            return False
        finally:
            cur.close()

    def get_file_permissions(self, fid):
        cur = self.conn.cursor()
        cur.execute("SELECT role FROM file_permissions WHERE file_id=?", (fid,))
        result = [row[0] for row in cur.fetchall()]
        cur.close()
        return result

    def get_files(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id, original_name, enc_path, enc_key FROM files")
        result = cur.fetchall()
        cur.close()
        return result

    def get_file_by_id(self, fid):
        cur = self.conn.cursor()
        cur.execute("SELECT id, original_name, enc_path, enc_key FROM files WHERE id=?", (fid,))
        result = cur.fetchone()
        cur.close()
        return result

    def update_file_content_from_ram(self, fid, data_bytes):
        """
        Сохранение отредактированного файла из RAM обратно в шифрованный контейнер.
        """
        cur = self.conn.cursor()
        try:
            # 1. Получаем путь к существующему файлу
            rec = self.get_file_by_id(fid)
            if not rec: return False
            enc_path = rec[2]

            # 2. Генерируем новые ключи для безопасности
            from Crypto.Random import get_random_bytes
            from Crypto.Cipher import AES
            
            new_file_key = get_random_bytes(32)
            nonce = get_random_bytes(12)
            
            cipher = AES.new(new_file_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
            
            # 3. Перезаписываем физический файл
            with open(enc_path, 'wb') as f:
                f.write(nonce + tag + ciphertext)
                
            # 4. Шифруем новый ключ мастер-ключом и обновляем БД
            encrypted_key_blob = self.crypto.encrypt_bytes(new_file_key)
            
            cur.execute("UPDATE files SET enc_key=? WHERE id=?", (encrypted_key_blob, fid))
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"Error updating file: {e}")
            return False
        finally:
            cur.close()

    def delete_file_record(self, fid):
        rec = self.get_file_by_id(fid)
        if rec and os.path.exists(rec[2]):
            try:
                os.remove(rec[2])
            except:
                pass
        
        cur = self.conn.cursor()
        cur.execute("DELETE FROM files WHERE id=?", (fid,))
        cur.execute("DELETE FROM file_permissions WHERE file_id=?", (fid,))
        self.conn.commit()
        cur.close()

    def close(self):
        if self.conn:
            self.conn.close()