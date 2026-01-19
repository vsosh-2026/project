import io
import gc
import ctypes
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import (
    QMainWindow, QTextEdit, QLabel, QScrollArea, 
    QMessageBox, QWidget, QVBoxLayout, QAction, 
    QToolBar, QStackedWidget, QColorDialog, QFontComboBox, QSpinBox
)

from ..core.ipc import IPCClient

try:
    import docx
    HAS_DOCX_LIB = True
except ImportError:
    HAS_DOCX_LIB = False

# =============================================================================
# КЛАСС БЕЗОПАСНОГО ТЕКСТОВОГО ПОЛЯ
# =============================================================================
class SecureTextEdit(QTextEdit):
    """
    Текстовое поле, которое запрещает Copy/Cut, но разрешает Paste.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
    
    def keyPressEvent(self, event):
        # Разрешаем Вставку (Ctrl+V)
        if event.matches(QtGui.QKeySequence.Paste):
            super().keyPressEvent(event)
            return
            
        # Блокируем Копирование (Ctrl+C) и Вырезание (Ctrl+X)
        if event.matches(QtGui.QKeySequence.Copy) or event.matches(QtGui.QKeySequence.Cut):
            return 
            
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        # Создаем меню без пунктов копирования
        menu = self.createStandardContextMenu()
        for action in menu.actions():
            text = action.text().lower()
            if any(x in text for x in ['copy', 'cut', 'копировать', 'вырезать']):
                action.setVisible(False)
                action.setEnabled(False)
        menu.exec_(event.globalPos())

    def createMimeDataFromSelection(self):
        # Блокируем Drag-and-Drop текста наружу
        return QtCore.QMimeData()

    def insertFromMimeData(self, source):
        # Разрешаем Drag-and-Drop внутрь
        super().insertFromMimeData(source)


# =============================================================================
# ГЛАВНОЕ ОКНО РЕДАКТОРА
# =============================================================================
class SecureEditorWindow(QMainWindow):
    """
    Защищенный редактор.
    - Общается с сервисом защиты (IPC).
    - Блокирует скриншоты.
    - Автосохранение при угрозе.
    """
    closed_signal = QtCore.pyqtSignal()

    def __init__(self, file_id, filename, data_bytes, db_manager, security_service=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{filename} - Защищенный просмотр")
        self.resize(1000, 800)
        
        self.file_id = file_id
        self.filename = filename
        self.data_bytes = data_bytes
        self.db = db_manager
        
        # Клиент для связи с сервисом
        self.ipc = IPCClient()
        # Прямая ссылка (для режима монолита)
        self.service = security_service

        # 1. Защита от скриншотов
        if hasattr(ctypes, 'windll'):
            try:
                ctypes.windll.user32.SetWindowDisplayAffinity(int(self.winId()), 0x00000011)
            except: pass

        # 2. Уведомление сервиса (активация камеры)
        # Если это Монолит - включаем напрямую
        if self.service: 
            self.service.set_file_mode(True)
        # Если IPC - сервис узнает через Heartbeat
        
        # 3. Период инициализации (4 секунды)
        self.startup_grace_steps = 20 

        # UI Setup
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        
        # --- Экран Редактора ---
        self.editor_page = QWidget()
        self.editor_layout = QVBoxLayout(self.editor_page)
        self.editor_layout.setContentsMargins(0,0,0,0)
        
        self._init_toolbar()
        
        self.scroll = QScrollArea()
        self.scroll.setStyleSheet("background-color: #F0F0F0; border: none;")
        self.scroll.setWidgetResizable(True)
        
        self.paper_container = QWidget()
        self.playout = QVBoxLayout(self.paper_container)
        self.playout.setContentsMargins(40,40,40,40)
        self.playout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignHCenter)
        
        # Используем наш безопасный класс
        self.text_edit = SecureTextEdit()
        self.text_edit.setFixedWidth(850)
        self.text_edit.setMinimumHeight(1100)
        self.text_edit.setStyleSheet("""
            SecureTextEdit {
                background: white; color: black; border: 1px solid #CCC;
                padding: 40px; font-family: 'Times New Roman'; font-size: 12pt;
                selection-background-color: #0078D7; selection-color: white;
            }
        """)
        
        self.playout.addWidget(self.text_edit)
        self.scroll.setWidget(self.paper_container)
        self.editor_layout.addWidget(self.scroll)
        
        # --- Экран Заглушки (для Alt+Tab) ---
        self.lock_screen = QLabel("ОКНО НЕАКТИВНО\n(Защита от подглядывания)")
        self.lock_screen.setAlignment(QtCore.Qt.AlignCenter)
        self.lock_screen.setStyleSheet("background: #2D2D30; color: white; font-size: 16pt; font-weight: bold;")
        
        self.stack.addWidget(self.editor_page)
        self.stack.addWidget(self.lock_screen)
        
        self._render_content()
        
        # Таймер Heartbeat (200мс)
        self.auth_timer = QtCore.QTimer(self)
        self.auth_timer.timeout.connect(self._check_security_strict)
        self.auth_timer.start(200)
        
        self.statusBar().showMessage("Инициализация защищенного канала...", 4000)

    def _check_security_strict(self):
        """
        Проверка безопасности.
        Выполняется даже если окно свернуто (чтобы камера не выключалась).
        """
        # 1. Если окно свернуто -> Показываем заглушку, но НЕ ВЫХОДИМ из функции
        if not self.isActiveWindow():
            self.stack.setCurrentIndex(1)
            # Идем дальше отправлять Heartbeat!
        
        # 2. Если идет разогрев (Grace Period) -> Разрешаем
        if self.startup_grace_steps > 0:
            self.startup_grace_steps -= 1
            if self.isActiveWindow(): self.stack.setCurrentIndex(0)
            
            # Шлем пинг для IPC, чтобы разбудить камеру
            if not self.service: self.ipc.send_heartbeat(self.file_id)
            return

        # 3. Основная проверка
        
        # Вариант А: Монолит (прямая связь)
        if self.service:
            if self.service.is_authorized:
                if self.isActiveWindow(): self.stack.setCurrentIndex(0)
            else:
                self._close_panic()
            return

        # Вариант Б: Клиент-Сервер (IPC)
        # Отправляем Heartbeat, чтобы сервис знал, что мы живы
        resp = self.ipc.send_heartbeat(self.file_id)
        
        if resp.get('status') == 'error':
            # Сервис упал
            self._close_panic()
            return

        action = resp.get('action')
        
        if action == 'close':
            # Сервис сказал: "Лицо потеряно" (буфер истек)
            self._close_panic()
        elif action == 'continue':
            # Все ок. Если окно активно - показываем контент
            if self.isActiveWindow():
                if self.stack.currentIndex() != 0:
                    self.stack.setCurrentIndex(0)

    def _close_panic(self):
        """Аварийное сохранение и выход."""
        print("[SECURE VIEWER] Угроза безопасности (Timeout/Face Lost). Выход.")
        self._save(silent=True)
        self.close()

    def _init_toolbar(self):
        tb = QToolBar(); tb.setMovable(False)
        tb.setStyleSheet("QToolBar { background: #F9F9F9; border-bottom: 1px solid #CCC; padding: 5px; }")
        self.editor_layout.addWidget(tb)
        
        act_s = QAction("💾 Сохранить", self); act_s.triggered.connect(self._save)
        f = act_s.font(); f.setBold(True); act_s.setFont(f)
        tb.addAction(act_s); tb.addSeparator()
        
        self.fc = QFontComboBox()
        self.fc.setCurrentFont(QtGui.QFont("Times New Roman"))
        self.fc.currentFontChanged.connect(lambda f: self.text_edit.setCurrentFont(f))
        tb.addWidget(self.fc)
        
        self.ss = QSpinBox(); self.ss.setRange(8, 72); self.ss.setValue(12)
        self.ss.valueChanged.connect(lambda s: self.text_edit.setFontPointSize(s))
        tb.addWidget(self.ss); tb.addSeparator()
        
        act_b = QAction("B", self); act_b.triggered.connect(lambda: self._fmt(1))
        act_i = QAction("I", self); act_i.triggered.connect(lambda: self._fmt(2))
        act_u = QAction("U", self); act_u.triggered.connect(lambda: self._fmt(3))
        tb.addAction(act_b); tb.addAction(act_i); tb.addAction(act_u); tb.addSeparator()
        
        act_c = QAction("Цвет", self); act_c.triggered.connect(self._col)
        tb.addAction(act_c); tb.addSeparator()
        
        act_l = QAction("L", self); act_l.triggered.connect(lambda: self.text_edit.setAlignment(QtCore.Qt.AlignLeft))
        act_c = QAction("C", self); act_c.triggered.connect(lambda: self.text_edit.setAlignment(QtCore.Qt.AlignCenter))
        act_r = QAction("R", self); act_r.triggered.connect(lambda: self.text_edit.setAlignment(QtCore.Qt.AlignRight))
        tb.addAction(act_l); tb.addAction(act_c); tb.addAction(act_r)

        e = QWidget(); e.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        tb.addWidget(e)
        lbl = QLabel("SECURE MODE  "); lbl.setStyleSheet("color: green; font-weight: bold;")
        tb.addWidget(lbl)

    def _fmt(self, m):
        c = self.text_edit.textCursor()
        f = c.charFormat()
        if m==1: f.setFontWeight(QtGui.QFont.Bold if f.fontWeight()!=QtGui.QFont.Bold else QtGui.QFont.Normal)
        elif m==2: f.setFontItalic(not f.fontItalic())
        elif m==3: f.setFontUnderline(not f.fontUnderline())
        c.mergeCharFormat(f)
        self.text_edit.setTextCursor(c)

    def _col(self):
        col = QColorDialog.getColor(self.text_edit.textColor(), self)
        if col.isValid(): self.text_edit.setTextColor(col)

    def _save(self, silent=False):
        try:
            content = self.text_edit.toHtml().encode('utf-8')
            if self.db.update_file_content_from_ram(self.file_id, content):
                if not silent: self.statusBar().showMessage("Сохранено.", 2000)
        except: pass

    def _render_content(self):
        try:
            txt = self.data_bytes.decode('utf-8')
            if txt.strip().startswith("<!DOCTYPE HTML"):
                self.text_edit.setHtml(txt); return
        except: pass
        if self.filename.endswith('.docx') and HAS_DOCX_LIB:
            try:
                doc = docx.Document(io.BytesIO(self.data_bytes))
                self.text_edit.setPlainText("\n".join([p.text for p in doc.paragraphs]))
                return
            except: pass
        try: self.text_edit.setPlainText(self.data_bytes.decode('utf-8'))
        except: self.text_edit.setPlainText("<< BINARY >>")

    def changeEvent(self, event):
        # При потере фокуса переключаем на заглушку
        # Но таймер проверки НЕ останавливаем
        if event.type() == QtCore.QEvent.ActivationChange:
            if not self.isActiveWindow():
                self.stack.setCurrentIndex(1)
                QtWidgets.QApplication.clipboard().clear()
        super().changeEvent(event)

    def closeEvent(self, event):
        self.auth_timer.stop()
        if self.service: self.service.set_file_mode(False)
        self.data_bytes = None
        self.closed_signal.emit()
        gc.collect()
        event.accept()