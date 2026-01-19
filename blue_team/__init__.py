import sys
import os
import ctypes
import subprocess

# Метаданные пакета
__version__ = '1.0.0'
__author__ = 'Blue Team Project'

def is_admin():
    """
    Проверяет, запущен ли текущий процесс с правами администратора.
    Использует Windows API shell32.IsUserAnAdmin.
    
    Returns:
        bool: True, если права есть, иначе False.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def require_admin():
    """
    Критическая функция инициализации.
    1. Проверяет наличие прав администратора.
    2. Если прав нет — перезапускает скрипт с запросом повышения (UAC).
    3. Если пользователь отказал в правах — завершает работу с ошибкой.
    """
    if is_admin():
        # Права уже есть, ничего не делаем, продолжаем выполнение программы
        return

    print("[Blue Team] Запрос прав администратора для доступа к TPM и управления окнами...")

    # Определение параметров для перезапуска
    # sys.executable — путь к интерпретатору python.exe
    # sys.argv — список аргументов командной строки (0 - имя скрипта)
    
    try:
        if sys.argv[0].endswith('.exe'):
            # Если программа скомпилирована в .exe (например, через PyInstaller)
            executable = sys.argv[0]
            params = sys.argv[1:]
        else:
            # Если запускается как Python-скрипт
            executable = sys.executable
            # sys.argv[0] - это путь к скрипту. Оставляем его и остальные аргументы.
            params = sys.argv
        
        # Собираем строку параметров, оборачивая каждый аргумент в кавычки 
        # на случай пробелов в путях (например "C:\Program Files\...")
        # Для .py скриптов: params[0] это путь к скрипту, params[1:] это аргументы скрипта.
        # ShellExecuteW требует: File=python.exe, Params="script.py" arg1 arg2
        
        if sys.argv[0].endswith('.exe'):
             cmd_params = " ".join([f'"{p}"' for p in params])
             cmd_file = executable
        else:
             # Для python: запускаем python.exe, а всё остальное (скрипт + args) передаем в params
             cmd_file = executable
             cmd_params = " ".join([f'"{p}"' for p in params])

        # Системный вызов для перезапуска с запросом прав ("runas")
        # hwnd=None, operation="runas", file=cmd_file, params=cmd_params, dir=None, show=1
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            cmd_file, 
            cmd_params, 
            None, 
            1
        )
        
        # Если ret > 32, значит запуск прошел успешно (окно UAC появилось)
        if int(ret) > 32:
            # Завершаем текущий процесс (без прав), так как запущен новый (с правами)
            sys.exit(0)
        else:
            # Коды ошибок Windows (например, 5 - Access Denied, если нажали "Нет")
            raise RuntimeError(f"Код возврата ShellExecute: {ret}")

    except Exception as e:
        # Обработка отказа пользователя или ошибки запуска
        error_title = "Ошибка запуска Blue Team"
        error_msg = (
            f"Не удалось получить права администратора.\n\n"
            f"Причина: {e}\n\n"
            "Приложение требует прав администратора для:\n"
            "1. Доступа к защищенному хранилищу ключей (DPAPI/TPM).\n"
            "2. Блокировки окон сторонних приложений.\n"
            "3. Управления файловой системой.\n\n"
            "Пожалуйста, запустите программу и нажмите 'Да' в окне UAC."
        )
        
        # Попытка показать графическое окно ошибки
        if os.name == 'nt':
            try:
                # 0x10 = Icon Hand (Error)
                ctypes.windll.user32.MessageBoxW(0, error_msg, error_title, 0x10)
            except:
                pass
        
        print(f"[CRITICAL] {error_msg}")
        sys.exit(1)

# Экспорт путей, чтобы при импорте пакета (import blue_team) 
# были доступны константы конфигурации.
# Это сработает только если config.py существует и корректен.
try:
    from .config import DATA_DIR, DB_PATH
except ImportError:
    pass