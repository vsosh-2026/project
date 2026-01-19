import psutil
import win32gui
import win32con
import win32process
import os
import sys
import winreg # Для работы с реестром
import ctypes # Для обновления иконок

class SystemController:
    """
    Контроллер операционной системы.
    Отвечает за:
    1. Поиск и блокировку процессов.
    2. Управление окнами (свернуть/развернуть).
    3. Настройку ассоциаций файлов в реестре.
    """

    def __init__(self):
        # Словарь: PID -> Список HWND (всех окон этого процесса)
        self.blocked_windows = {} 
        # Множество замороженных PID
        self.suspended_pids = set()

    # =========================================================================
    # УПРАВЛЕНИЕ ПРОЦЕССАМИ И ОКНАМИ
    # =========================================================================

    def get_running_processes_by_name(self, targets: list) -> list:
        """Ищет PID запущенных процессов из списка имен."""
        found_pids = set()
        targets_exe = {t.lower() for t in targets}
        targets_clean = {t.lower().replace(".exe", "") for t in targets}

        # 1. Поиск по списку процессов (psutil)
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in targets_exe:
                        found_pids.add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception: pass

        # 2. Поиск по окнам (WinAPI) - быстрее находит GUI приложения
        def enum_fast_callback(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                try:
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    if pid in found_pids: return True # Уже нашли
                    
                    # Можно добавить проверку заголовка, если нужно
                except: pass
            return True
        
        # (Опционально можно включить перебор окон, но psutil обычно хватает)
        return list(found_pids)

    def _get_all_windows_for_pid(self, pid: int):
        hwnds = []
        def callback(hwnd, _):
            _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
            if found_pid == pid:
                if win32gui.IsWindowVisible(hwnd) or win32gui.IsWindowEnabled(hwnd):
                    hwnds.append(hwnd)
            return True
        try: win32gui.EnumWindows(callback, None)
        except: pass
        return hwnds

    def block_process_window(self, pid: int):
        """Блокировка: Свернуть окна -> Скрыть -> Заморозить процесс."""
        if pid in self.suspended_pids: return

        windows = self._get_all_windows_for_pid(pid)
        if windows:
            self.blocked_windows[pid] = windows
            
            # Убираем фокус
            fg = win32gui.GetForegroundWindow()
            if fg in windows:
                try: win32gui.SetForegroundWindow(win32gui.GetDesktopWindow())
                except: pass

            for hwnd in windows:
                try:
                    win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                    win32gui.EnableWindow(hwnd, False)
                    win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
                except: pass

        if pid not in self.suspended_pids:
            try:
                p = psutil.Process(pid)
                p.suspend()
                self.suspended_pids.add(pid)
            except: pass

    def unblock_process_window(self, pid: int):
        """Разблокировка: Разморозить -> Показать окна."""
        if pid in self.suspended_pids:
            try:
                p = psutil.Process(pid)
                p.resume()
                self.suspended_pids.remove(pid)
            except: self.suspended_pids.discard(pid)

        if pid in self.blocked_windows:
            windows = self.blocked_windows[pid]
            for hwnd in windows:
                try:
                    if win32gui.IsWindow(hwnd):
                        win32gui.ShowWindow(hwnd, win32con.SW_SHOWNOACTIVATE)
                        win32gui.EnableWindow(hwnd, True)
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                except: pass
            del self.blocked_windows[pid]

    def release_all(self):
        """Аварийная разблокировка всего."""
        all_pids = set(list(self.suspended_pids) + list(self.blocked_windows.keys()))
        for pid in all_pids:
            self.unblock_process_window(pid)

    # =========================================================================
    # РАБОТА С РЕЕСТРОМ (ФАЙЛОВЫЕ АССОЦИАЦИИ)
    # =========================================================================

    def register_file_association(self):
        """
        Регистрирует расширение .enc в Windows, чтобы оно открывалось через file_opener.py.
        Вызывается при старте Конфигуратора.
        """
        try:
            # Путь к интерпретатору pythonw.exe (без консоли) или python.exe
            python_exe = sys.executable.replace("python.exe", "pythonw.exe")
            if not os.path.exists(python_exe): python_exe = sys.executable
            
            # Путь к скрипту-открывашке (в корне проекта)
            # Мы находимся в blue_team/core/system.py -> up 3 levels -> root
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            script_path = os.path.join(base_dir, "file_opener.py")
            
            if not os.path.exists(script_path):
                print(f"[SYSTEM] Скрипт {script_path} не найден! Ассоциация не настроена.")
                return False

            # Команда запуска: pythonw.exe file_opener.py "%1"
            command = f'"{python_exe}" "{script_path}" "%1"'
            
            # Имя класса файла в реестре
            prog_id = "BlueTeam.SecureFile"

            # 1. Создаем класс ProgID (описание типа файла)
            # HKCU\Software\Classes\BlueTeam.SecureFile
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{prog_id}") as key:
                winreg.SetValue(key, "", winreg.REG_SZ, "Blue Team Encrypted Document")
                
                # Иконка (используем стандартную иконку замка или питона)
                with winreg.CreateKey(key, "DefaultIcon") as icon_key:
                    # %SystemRoot%\System32\imageres.dll,-1030 (Замок)
                    # Но проще взять иконку питона пока что
                    winreg.SetValue(icon_key, "", winreg.REG_SZ, f"{python_exe},0")
                
                # Команда открытия (shell -> open -> command)
                with winreg.CreateKey(key, r"shell\open\command") as cmd_key:
                    winreg.SetValue(cmd_key, "", winreg.REG_SZ, command)

            # 2. Ассоциируем расширение .enc с этим классом
            # HKCU\Software\Classes\.enc
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.enc") as ext_key:
                winreg.SetValue(ext_key, "", winreg.REG_SZ, prog_id)
                # Content Type (опционально)
                winreg.SetValueEx(ext_key, "Content Type", 0, winreg.REG_SZ, "application/x-blue-team-secure")

            # 3. Уведомляем Explorer об изменениях (чтобы иконки обновились)
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, 0, 0) # SHCNE_ASSOCCHANGED

            print(f"[SYSTEM] Ассоциация .enc настроена на {script_path}")
            return True

        except Exception as e:
            print(f"[SYSTEM ERROR] Ошибка настройки реестра: {e}")
            return False