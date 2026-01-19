import os
import face_recognition
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, 
    QDialogButtonBox, QFileDialog, QComboBox, 
    QLabel, QPushButton, QListWidget, QListWidgetItem,
    QTabWidget, QWidget, QMessageBox, QProgressBar, QHBoxLayout
)

# =========================================================================
# ДИАЛОГ СОЗДАНИЯ РОЛИ
# =========================================================================
class AddRoleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создание роли")
        self.resize(300, 120)
        
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Введите название новой роли:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Например: Аудитор")
        layout.addWidget(self.name_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def get_role_name(self):
        return self.name_input.text().strip()

# =========================================================================
# ВИДЖЕТ ВЫБОРА РОЛЕЙ (ЧЕКБОКСЫ)
# =========================================================================
class RoleSelectorWidget(QListWidget):
    def __init__(self, roles_list, parent=None):
        super().__init__(parent)
        self.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.setStyleSheet("background-color: #fff; border: 1px solid #ccc;")
        
        for role in roles_list:
            item = QListWidgetItem(role)
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.Unchecked)
            self.addItem(item)
            
    def get_selected_roles(self):
        """Возвращает список названий выбранных ролей."""
        roles = []
        for i in range(self.count()):
            item = self.item(i)
            if item.checkState() == QtCore.Qt.Checked:
                roles.append(item.text())
        return roles

# =========================================================================
# ДИАЛОГ ДОБАВЛЕНИЯ ФАЙЛА
# =========================================================================
class AddFileDialog(QDialog):
    def __init__(self, roles_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Импорт файла")
        self.resize(450, 400)
        self.selected_file = None
        self.selected_roles = []
        
        layout = QVBoxLayout(self)
        
        # Выбор файла
        file_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setReadOnly(True)
        self.path_input.setPlaceholderText("Файл не выбран")
        
        self.btn_select = QPushButton("Обзор...")
        self.btn_select.clicked.connect(self.browse)
        
        file_layout.addWidget(self.path_input)
        file_layout.addWidget(self.btn_select)
        layout.addLayout(file_layout)
        
        # Выбор ролей
        layout.addWidget(QLabel("Разрешить доступ ролям:"))
        self.role_selector = RoleSelectorWidget(roles_list)
        layout.addWidget(self.role_selector)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выбор файла")
        if path:
            self.selected_file = path
            self.path_input.setText(path)

    def accept(self):
        self.selected_roles = self.role_selector.get_selected_roles()
        
        if not self.selected_file:
            QMessageBox.warning(self, "Ошибка", "Необходимо выбрать файл.")
            return
        
        if not self.selected_roles:
            QMessageBox.warning(self, "Ошибка", "Выберите хотя бы одну роль.")
            return
            
        super().accept()

# =========================================================================
# ДИАЛОГ ДОБАВЛЕНИЯ ПРИЛОЖЕНИЯ
# =========================================================================
class AddAppDialog(QDialog):
    def __init__(self, roles_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить приложение")
        self.resize(450, 400)
        self.file_path = None
        
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        self.name_input = QLineEdit()
        form.addRow("Название:", self.name_input)
        layout.addLayout(form)
        
        # Выбор EXE
        exe_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setReadOnly(True)
        self.path_input.setPlaceholderText("Путь к .exe")
        
        self.btn_browse = QPushButton("Найти .exe")
        self.btn_browse.clicked.connect(self.browse)
        
        exe_layout.addWidget(self.path_input)
        exe_layout.addWidget(self.btn_browse)
        layout.addLayout(exe_layout)
        
        # Выбор ролей
        layout.addWidget(QLabel("Разрешить запуск ролям:"))
        self.role_selector = RoleSelectorWidget(roles_list)
        layout.addWidget(self.role_selector)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выбор исполняемого файла", filter="Executable (*.exe)")
        if path:
            self.file_path = path
            self.path_input.setText(path)
            if not self.name_input.text():
                self.name_input.setText(os.path.basename(path))

    def accept(self):
        self.selected_roles = self.role_selector.get_selected_roles()
        if not self.name_input.text() or not self.file_path:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля.")
            return
        super().accept()

# =========================================================================
# ДИАЛОГ ДОБАВЛЕНИЯ СОТРУДНИКА (ОДИНОЧНЫЙ / МАССОВЫЙ)
# =========================================================================
class AddUserDialog(QDialog):
    def __init__(self, roles_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавление сотрудников")
        self.resize(500, 450)
        self.single_user_data = None
        self.bulk_users_data = []
        self.roles_list = roles_list
        
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        self.tab_single = QWidget()
        self._setup_single_tab()
        self.tabs.addTab(self.tab_single, "Одиночный")
        
        self.tab_bulk = QWidget()
        self._setup_bulk_tab()
        self.tabs.addTab(self.tab_bulk, "Импорт из CSV")
        
    def _setup_single_tab(self):
        layout = QVBoxLayout(self.tab_single)
        
        form = QFormLayout()
        self.name_input = QLineEdit()
        self.role_combo = QComboBox()
        self.role_combo.addItems(self.roles_list)
        
        form.addRow("ФИО:", self.name_input)
        form.addRow("Роль:", self.role_combo)
        layout.addLayout(form)
        
        self.btn_photo = QPushButton("Загрузить фото лица...")
        self.btn_photo.clicked.connect(self.get_photo)
        layout.addWidget(self.btn_photo)
        
        self.lbl_status = QLabel("Фото не выбрано")
        self.lbl_status.setAlignment(QtCore.Qt.AlignCenter)
        self.lbl_status.setStyleSheet("color: #666; font-style: italic; margin: 10px;")
        layout.addWidget(self.lbl_status)
        
        layout.addStretch()
        
        self.btn_save = QPushButton("Сохранить")
        self.btn_save.clicked.connect(self.save_single)
        layout.addWidget(self.btn_save)
        
        self.face_encoding = None

    def _setup_bulk_tab(self):
        layout = QVBoxLayout(self.tab_bulk)
        
        info = QLabel("Формат файла (CSV/TXT):\nИмя Фамилия;Роль;Путь_к_файлу_фото.jpg")
        info.setStyleSheet("background: #f0f0f0; padding: 10px; border: 1px solid #ddd;")
        layout.addWidget(info)
        
        self.btn_csv = QPushButton("Выбрать файл списка...")
        self.btn_csv.clicked.connect(self.process_csv)
        layout.addWidget(self.btn_csv)
        
        layout.addWidget(QLabel("Журнал обработки:"))
        self.log_list = QListWidget()
        layout.addWidget(self.log_list)
        
        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

    def get_photo(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выбор фото", filter="Images (*.jpg *.png *.jpeg)")
        if path:
            self.lbl_status.setText("Обработка...")
            QtWidgets.qApp.processEvents()
            try:
                img = face_recognition.load_image_file(path)
                encs = face_recognition.face_encodings(img)
                if encs:
                    self.face_encoding = encs[0]
                    self.lbl_status.setText("Фото успешно обработано")
                    self.lbl_status.setStyleSheet("color: green;")
                else:
                    self.face_encoding = None
                    self.lbl_status.setText("Лицо не найдено на фото")
                    self.lbl_status.setStyleSheet("color: red;")
            except Exception as e:
                self.lbl_status.setText("Ошибка чтения файла")
                self.lbl_status.setStyleSheet("color: red;")

    def save_single(self):
        if not self.name_input.text():
            QMessageBox.warning(self, "Ошибка", "Введите ФИО.")
            return
        if self.face_encoding is None:
            QMessageBox.warning(self, "Ошибка", "Необходимо загрузить фото лица.")
            return
            
        self.single_user_data = (
            self.name_input.text(),
            self.role_combo.currentText(),
            self.face_encoding
        )
        self.accept()

    def process_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выбор файла CSV", filter="Text (*.txt *.csv)")
        if not path: return
        
        try:
            with open(path, 'r', encoding='utf-8') as f: lines = f.readlines()
        except:
             with open(path, 'r', encoding='cp1251') as f: lines = f.readlines()
        
        self.progress.setMaximum(len(lines))
        self.log_list.clear()
        self.bulk_users_data = []
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"): continue
            
            try:
                parts = line.split(';')
                if len(parts) >= 3:
                    name = parts[0].strip()
                    role = parts[1].strip()
                    img_path = parts[2].strip()
                    
                    if os.path.exists(img_path):
                        img = face_recognition.load_image_file(img_path)
                        encs = face_recognition.face_encodings(img)
                        if encs:
                            self.bulk_users_data.append((name, role, encs[0]))
                            self.log_list.addItem(f"OK: {name}")
                        else:
                            self.log_list.addItem(f"Ошибка (Лицо не найдено): {name}")
                    else:
                        self.log_list.addItem(f"Ошибка (Нет файла фото): {name}")
                else:
                    self.log_list.addItem(f"Ошибка формата: {line}")
            except Exception as e:
                self.log_list.addItem(f"Сбой обработки: {e}")
            
            self.progress.setValue(i+1)
            QtWidgets.qApp.processEvents()
            
        if self.bulk_users_data:
            QMessageBox.information(self, "Импорт", f"Обработано записей: {len(self.bulk_users_data)}")
            self.accept()
        else:
            QMessageBox.warning(self, "Импорт", "Корректных записей не найдено.")