"""
Blue Team Core Package.

Этот пакет объединяет основные модули бизнес-логики приложения:
1. CryptoManager - работа с криптографией (TPM/DPAPI, AES-256).
2. DatabaseManager - управление базой данных и хранением настроек.
3. VisionSystem - распознавание лиц и работа с камерой.
4. SystemController - управление процессами и окнами Windows.
"""

from .crypto import CryptoManager
from .database import DatabaseManager
from .vision import VisionSystem
from .system import SystemController

# Список имен, экспортируемых при импорте через from blue_team.core import *
__all__ = [
    'CryptoManager',
    'DatabaseManager',
    'VisionSystem',
    'SystemController'
]
