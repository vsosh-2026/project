import socket
import threading
import time
import struct
import json
import secrets
import win32crypt # pywin32 для защиты токена (DPAPI)

# Импорты ядра
from ..core.database import DatabaseManager
from ..core.vision import VisionSystem
from ..core.system import SystemController
# Конфигурация
from ..config import FACE_CHECK_INTERVAL, TOKEN_PATH
from ..core.ipc import IPC_PORT, HOST

class SecurityService:
    """
    Главный сервис защиты (Сервер).
    Работает как отдельный процесс. Управляет камерой и политиками доступа.
    """

    def __init__(self):
        # Инициализация подсистем
        self.db = DatabaseManager()
        self.vision = VisionSystem(self.db)
        self.system = SystemController()
        
        self.running = True
        
        # Состояние защиты
        self.global_auth_status = False # Текущий статус доступа (True = можно работать)
        self.last_viewer_heartbeat = 0  # Время последнего сигнала от Редактора
        
        # Состояние сессии (для Liveness)
        self.session_active = False     # Есть ли сейчас активная угроза/работа
        self.liveness_passed = False    # Пройден ли тест на живость в текущей сессии
        
        # Генерация и защита токена доступа (Shared Secret)
        self.auth_token = secrets.token_hex(32)
        self._save_token_encrypted()
        
        # Кэш черного списка приложений
        self.app_blacklist = []
        self._reload_config()

    def _save_token_encrypted(self):
        """
        Сохраняет токен в файл, шифруя его средствами Windows (DPAPI).
        Прочитать этот файл сможет только этот же пользователь на этом же ПК.
        """
        try:
            token_bytes = self.auth_token.encode('utf-8')
            # CryptProtectData(data, description, optional_entropy, reserved, prompt_struct, flags)
            encrypted_data = win32crypt.CryptProtectData(
                token_bytes, 
                "BlueTeamIPC", 
                None, 
                None, 
                None, 
                0
            )
            
            with open(TOKEN_PATH, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            print(f"[CRITICAL] Не удалось сохранить токен безопасности: {e}")

    def _reload_config(self):
        """Обновляет список запрещенных приложений и кэш лиц из БД."""
        apps = self.db.get_apps()
        self.app_blacklist = [a['exe'] for a in apps]
        self.vision.update_cache()
        print(f"[SERVICE] Конфигурация обновлена. Приложений под защитой: {len(self.app_blacklist)}")

    def start(self):
        """Запуск сервиса."""
        # Запускаем поток обработки команд (IPC)
        ipc_thread = threading.Thread(target=self._ipc_server_loop, daemon=True)
        ipc_thread.start()
        
        # Запускаем основной цикл защиты (в главном потоке)
        self._security_loop()

    # =========================================================================
    # IPC SERVER (ОБРАБОТКА КОМАНД)
    # =========================================================================

    def _ipc_server_loop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Разрешаем переиспользование порта, если сервис перезапускается
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((HOST, IPC_PORT))
            server.listen(5)
            print(f"[SERVICE] IPC Сервер запущен на {HOST}:{IPC_PORT}")
        except Exception as e:
            print(f"[CRITICAL] Ошибка запуска IPC: {e}")
            return

        while self.running:
            try:
                conn, addr = server.accept()
                with conn:
                    # Читаем заголовок (длина сообщения)
                    raw_len = conn.recv(4)
                    if not raw_len: continue
                    msg_len = struct.unpack('>I', raw_len)[0]
                    
                    # Читаем тело сообщения
                    data = conn.recv(msg_len)
                    request = json.loads(data.decode('utf-8'))
                    
                    # Обрабатываем и отвечаем
                    response = self._handle_request(request)
                    conn.sendall(json.dumps(response).encode('utf-8'))
            except Exception as e:
                print(f"[IPC ERROR] {e}")

    def _handle_request(self, req):
        """Обработка входящего JSON запроса."""
        # 1. Проверка токена
        if req.get('token') != self.auth_token:
            print(f"[SECURITY ALERT] Неверный токен в запросе!")
            return {'status': 'error', 'message': 'Unauthorized'}

        cmd = req.get('cmd')
        
        # 2. Обработка команд
        if cmd == 'HEARTBEAT':
            # Редактор сообщает, что он жив
            self.last_viewer_heartbeat = time.time()
            
            # Отвечаем действием: продолжать работу или закрыться
            if self.global_auth_status:
                return {'action': 'continue'}
            else:
                return {'action': 'close'}
                
        elif cmd == 'RELOAD_CONFIG':
            self._reload_config()
            return {'status': 'ok'}
            
        elif cmd == 'GET_STATUS':
            return {'status': 'ok', 'authorized': self.global_auth_status}
            
        return {'status': 'unknown_command'}

    # =========================================================================
    # SECURITY LOOP (МОНИТОРИНГ И ЗАЩИТА)
    # =========================================================================

    def _security_loop(self):
        """Главный цикл наблюдения."""
        
        # Буфер ошибок (Tolerance)
        consecutive_misses = 0
        MAX_MISSES = 2 # 3 секунды при интервале 0.5
        
        print("[SERVICE] Система защиты активна. Ожидание угроз...")
        
        while self.running:
            start_time = time.time()
            
            try:
                # 1. Проверка активности (Триггеры)
                running_pids = []
                if self.app_blacklist:
                    running_pids = self.system.get_running_processes_by_name(self.app_blacklist)
                
                # Редактор считается активным, если слал пинг менее 2 сек назад
                viewer_is_active = (time.time() - self.last_viewer_heartbeat) < 2.0
                
                # Нужна ли защита прямо сейчас?
                is_active_now = bool(running_pids) or viewer_is_active
                
                # --- СМЕНА СОСТОЯНИЯ (ПОКОЙ <-> АКТИВНОСТЬ) ---
                if is_active_now and not self.session_active:
                    print("\n[SERVICE] >>> ОБНАРУЖЕНА АКТИВНОСТЬ. СТАРТ ЗАЩИТЫ <<<")
                    self.session_active = True
                    self.liveness_passed = False # Новая сессия требует новой проверки
                    
                if not is_active_now:
                    # Если активности нет - спим
                    if self.session_active:
                        print("[SERVICE] Активность завершена. Камера выключена.")
                        self.session_active = False
                        if self.vision.cap: self.vision.release()
                        self.global_auth_status = True # Сброс в безопасное состояние
                
                # --- АКТИВНАЯ ФАЗА ---
                elif is_active_now:
                    
                    # ЭТАП A: LIVENESS CHECK (Только один раз в начале)
                    if not self.liveness_passed:
                        print("[SERVICE] Проверка на живость (Anti-Spoofing)...")
                        is_live, msg = self.vision.check_liveness_and_auth()
                        
                        if is_live:
                            print(f"[SERVICE] УСПЕХ: {msg}")
                            self.liveness_passed = True
                            self.global_auth_status = True
                            consecutive_misses = 0
                        else:
                            print(f"[SERVICE] ОТКАЗ: {msg}")
                            self.global_auth_status = False
                            # Мгновенная блокировка приложений
                            if running_pids:
                                for pid in running_pids: self.system.block_process_window(pid)
                            
                            # Пропускаем остаток цикла, пока не пройдем Liveness
                            continue 

                    # ЭТАП B: ОБЫЧНЫЙ МОНИТОРИНГ (Быстрый)
                    face_ok = self.vision.check_authorization()
                    
                    if face_ok:
                        # Все хорошо, лицо на месте
                        if consecutive_misses > 0:
                            pass # print("Лицо вернулось")
                        consecutive_misses = 0
                        self.global_auth_status = True
                    else:
                        # Лица нет
                        consecutive_misses += 1
                        # print(f"Лицо потеряно: {consecutive_misses}/{MAX_MISSES}")
                        
                        if consecutive_misses >= MAX_MISSES:
                            if self.global_auth_status:
                                print("!!! БЛОКИРОВКА (ТАЙМАУТ ОТСУТСТВИЯ) !!!")
                            self.global_auth_status = False
                            
                            # Если потеряли надолго - сбрасываем Liveness.
                            # При возвращении придется снова доказывать, что ты живой.
                            self.liveness_passed = False 

                    # ЭТАП C: ПРИМЕНЕНИЕ САНКЦИЙ К ПРИЛОЖЕНИЯМ
                    # (Редактор сам запросит статус через Heartbeat и закроется если False)
                    if running_pids:
                        if self.global_auth_status:
                            for pid in running_pids: self.system.unblock_process_window(pid)
                        else:
                            for pid in running_pids: self.system.block_process_window(pid)

            except Exception as e:
                print(f"[LOOP ERROR] {e}")
            
            # Умная задержка
            elapsed = time.time() - start_time
            sleep_time = max(0.1, FACE_CHECK_INTERVAL - elapsed)
            time.sleep(sleep_time)

if __name__ == "__main__":
    # Проверка прав администратора при запуске
    try:
        from blue_team import require_admin
        require_admin()
    except ImportError:
        pass
    
    service = SecurityService()
    service.start()