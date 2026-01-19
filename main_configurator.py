import sys
from PyQt5 import QtWidgets, QtGui, QtCore

# 1. Проверка прав администратора
# (Конфигуратор требует админа для настройки реестра и доступа к TPM)
try:
    from blue_team import require_admin
    require_admin()
except ImportError:
    pass

# Импорты
from blue_team.ui.main_window import ConfiguratorWindow
from blue_team.core.system import SystemController

def main():
    """
    Запуск панели администратора.
    """
    app = QtWidgets.QApplication(sys.argv)
    
    app.setApplicationName("Blue Team Security")
    app.setApplicationVersion("2.0.0 Enterprise")
    
    # --- НАСТРОЙКА СТИЛЯ (ОФИЦИАЛЬНЫЙ) ---
    app.setStyle("Fusion")
    
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(245, 245, 245))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(0, 0, 0))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(255, 255, 255))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(240, 240, 240))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor(0, 0, 0))
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(245, 245, 245))
    palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(0, 0, 0))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(0, 120, 215))
    palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor(255, 255, 255))
    app.setPalette(palette)
    
    font = QtGui.QFont("Segoe UI", 9)
    app.setFont(font)
    
    # --- АВТОМАТИЧЕСКАЯ НАСТРОЙКА РЕЕСТРА ---
    # При каждом запуске проверяем и обновляем ассоциации файлов .enc
    # Это гарантирует, что двойной клик будет работать
    print("[INIT] Настройка файловых ассоциаций...")
    sys_ctrl = SystemController()
    sys_ctrl.register_file_association()
    
    # --- ЗАПУСК ОКНА ---
    window = ConfiguratorWindow()
    window.showMaximized()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()