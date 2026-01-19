"""
Blue Team UI Package.

Этот пакет содержит компоненты графического интерфейса пользователя (GUI),
построенные на библиотеке PyQt5.

Основные модули:
1. main_window - Главное окно конфигуратора (управление пользователями, приложениями, файлами).
2. dialogs - Модальные окна для добавления новых объектов защиты и сотрудников.
"""

from .main_window import ConfiguratorWindow
from .dialogs import AddUserDialog, AddAppDialog, AddFileDialog

# Список публичных классов пакета
__all__ = [
    'ConfiguratorWindow',
    'AddUserDialog',
    'AddAppDialog',
    'AddFileDialog'
]
