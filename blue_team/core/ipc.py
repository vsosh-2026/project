import socket
import json
import struct
import os
import win32crypt # Библиотека pywin32 для доступа к Windows CryptoAPI

# Настройки подключения
from ..config import TOKEN_PATH

IPC_PORT = 65432
HOST = '127.0.0.1'

class IPCClient:
    """
    Клиент для взаимодействия с Сервисом защиты (main_service.py).
    Использует TCP сокеты и Token-Based Authentication.
    """
    
    def __init__(self):
        self.token = None
        self._load_token()

    def _load_token(self):
        """
        Читает зашифрованный токен из файла и расшифровывает его через DPAPI.
        Это гарантирует, что только процессы, запущенные от того же пользователя (или SYSTEM),
        смогут прочитать токен.
        """
        if not os.path.exists(TOKEN_PATH):
            return

        try:
            with open(TOKEN_PATH, 'rb') as f:
                encrypted_data = f.read()
            
            # Расшифровка DPAPI (связана с TPM/User Credentials)
            # CryptUnprotectData возвращает кортеж, нам нужен элемент [1] (сами данные)
            decrypted_blob = win32crypt.CryptUnprotectData(
                encrypted_data, None, None, None, 0
            )[1]
            
            self.token = decrypted_blob.decode('utf-8')
            
        except Exception as e:
            # print(f"[IPC] Ошибка загрузки токена: {e}")
            self.token = None

    def send_command(self, command, data=None):
        """
        Отправка JSON команды на сервер.
        Автоматически добавляет токен.
        """
        # Если токена нет, пробуем перечитать (вдруг сервис только что запустился)
        if not self.token:
            self._load_token()
            if not self.token:
                return {'status': 'error', 'message': 'Auth token missing (Service not running?)'}

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Таймаут 2 секунды, чтобы GUI не зависал, если сервис тупит
                s.settimeout(2)
                s.connect((HOST, IPC_PORT))
                
                # Формируем пакет
                msg = {
                    'token': self.token,
                    'cmd': command, 
                    'data': data
                }
                msg_bytes = json.dumps(msg).encode('utf-8')
                
                # Протокол: [Длина сообщения (4 байта)] + [Само сообщение]
                s.sendall(struct.pack('>I', len(msg_bytes)))
                s.sendall(msg_bytes)
                
                # Ждем ответ
                # Сначала читаем длину ответа, если сервис поддерживает такой протокол
                # Но для простоты читаем буфер
                response_data = s.recv(4096)
                if not response_data:
                    return {'status': 'error', 'message': 'Empty response'}
                
                return json.loads(response_data.decode('utf-8'))
                
        except ConnectionRefusedError:
            return {'status': 'error', 'message': 'Service connection refused'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # --- API МЕТОДЫ ---

    def send_heartbeat(self, file_id):
        """
        Пинг от Редактора. Сообщает, что файл открыт.
        Возвращает действие: 'continue' или 'close'.
        """
        return self.send_command('HEARTBEAT', {'file_id': file_id})

    def reload_config(self):
        """
        Команда Сервису перечитать базу данных (новые приложения/юзеры).
        """
        return self.send_command('RELOAD_CONFIG')
    
    def get_status(self):
        """
        Запрос текущего статуса (Авторизован/Нет).
        """
        return self.send_command('GET_STATUS')