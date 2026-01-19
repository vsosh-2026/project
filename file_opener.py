import sys
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QApplication, QMessageBox

# Импорты внутренних модулей проекта
from blue_team.core.database import DatabaseManager
from blue_team.core.crypto import CryptoManager
from blue_team.ui.secure_viewer import SecureEditorWindow
from blue_team.core.ipc import IPCClient

def main():
    """
    Скрипт-обработчик для файлов .enc.
    Запускается Windows при двойном клике по файлу.
    """
    app = QApplication(sys.argv)
    
    # Настройка стиля под систему (чтобы окна ошибок выглядели нативно)
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(245, 245, 245))
    app.setPalette(palette)
    font = QtGui.QFont("Segoe UI", 9)
    app.setFont(font)
    
    # 1. Получаем путь к файлу из аргументов командной строки
    # (Windows передает путь к файлу как первый аргумент)
    if len(sys.argv) < 2:
        # Если скрипт запустили просто так, без файла
        sys.exit(0)

    # Приводим путь к нормальному абсолютному виду для сравнения
    clicked_file_path = os.path.normpath(os.path.abspath(sys.argv[1]))
    
    # 2. Подключаемся к БД для проверки легитимности файла
    db = DatabaseManager()
    
    target_record = None
    
    # Получаем список всех защищенных файлов
    try:
        all_files = db.get_files() # Возвращает список [(id, name, path, key), ...]
        
        for f in all_files:
            # Берем путь из базы
            db_path = os.path.normpath(os.path.abspath(f[2]))
            
            # Сравниваем пути (normcase учитывает, что в Windows С:\File и c:\file это одно и то же)
            if os.path.normcase(db_path) == os.path.normcase(clicked_file_path):
                target_record = f
                break
    except Exception as e:
        QMessageBox.critical(None, "Ошибка БД", f"Не удалось прочитать базу данных:\n{e}")
        sys.exit(1)
    
    # === СТРОГАЯ ПРОВЕРКА ===
    # Если файла нет в базе данных -> ОТКАЗ В ДОСТУПЕ
    if not target_record:
        QMessageBox.warning(None, "Доступ запрещен", 
                            f"Файл не найден в реестре защиты:\n{clicked_file_path}\n\n"
                            "Система Blue Team открывает только те файлы, которые были\n"
                            "официально зарегистрированы через Конфигуратор.")
        sys.exit(0)

    # 3. Проверяем, работает ли Сервис Защиты (Main Service)
    # Без него мы не сможем обеспечить биометрический контроль
    ipc = IPCClient()
    status = ipc.get_status()
    
    if status.get('status') == 'error':
        QMessageBox.critical(None, "Угроза безопасности", 
                             "Служба активного мониторинга (Service) не запущена!\n\n"
                             "Открытие конфиденциальных документов заблокировано.\n"
                             "Пожалуйста, обратитесь к администратору для запуска защиты.")
        sys.exit(1)

    # 4. Расшифровка и Запуск Редактора
    crypto = CryptoManager()
    
    try:
        fid = target_record[0]
        original_name = target_record[1]
        enc_path = target_record[2]
        enc_key_blob = target_record[3]
        
        # Расшифровка данных в оперативную память (RAM)
        data_bytes = crypto.decrypt_file_content(enc_path, enc_key_blob)
        
        # Инициализация окна редактора
        # Передаем security_service=None, так как мы в отдельном процессе.
        # Редактор внутри себя создаст IPCClient для общения с Сервисом.
        window = SecureEditorWindow(
            fid, original_name, data_bytes, db, None
        )
        
        # При закрытии окна редактора завершаем процесс полностью
        window.closed_signal.connect(app.quit)
        
        window.show()
        
        # Запуск цикла обработки событий
        sys.exit(app.exec_())
        
    except ValueError:
        QMessageBox.critical(None, "Ошибка доступа", 
                             "Неверный ключ шифрования или поврежденный файл.\n"
                             "Расшифровка невозможна.")
        sys.exit(1)
    except Exception as e:
        QMessageBox.critical(None, "Критическая ошибка", f"Сбой при открытии:\n{e}")
        sys.exit(1)

if __name__ == "__main__":
    main()