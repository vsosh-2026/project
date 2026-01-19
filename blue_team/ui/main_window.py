import sys
import os
from datetime import datetime
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTableWidget, QTableWidgetItem, QPushButton, 
    QLabel, QHeaderView, QMessageBox, QTabWidget, 
    QSplitter, QGroupBox, QTextEdit
)

# Импорты ядра
from ..core.database import DatabaseManager
from ..core.crypto import CryptoManager
from ..core.ipc import IPCClient

# Импорты диалогов
from .dialogs import AddUserDialog, AddAppDialog, AddFileDialog, AddRoleDialog

class ConfiguratorWindow(QMainWindow):
    """
    Панель Администратора.
    Только настройка политик и БД.
    Открытие файлов происходит через Проводник Windows (file_opener.py).
    """
    
    def __init__(self):
        super().__init__()
        
        self.db = DatabaseManager()
        self.crypto = CryptoManager()
        
        # Клиент для связи с Сервисом (чтобы обновлять конфиг на лету)
        self.ipc = IPCClient()

        self.setWindowTitle("Blue Team Security | Панель Администратора")
        self.resize(1200, 800)
        
        # Проверка связи с Сервисом
        self._check_service_connection()
        
        self.setup_ui()
        self.load_data()

    def _check_service_connection(self):
        status = self.ipc.get_status()
        if status.get('status') == 'error':
            self.service_active = False
            QMessageBox.warning(self, "Статус службы", 
                                "Фоновая служба защиты не запущена!\n"
                                "Мониторинг приложений не работает.\n"
                                "Файлы открыть не получится.")
        else:
            self.service_active = True

    def setup_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Табы
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        self.tab_mgmt = QWidget()
        self.setup_management_tab()
        self.tabs.addTab(self.tab_mgmt, "Политики безопасности")

        self.tab_logs = QWidget()
        self.setup_logs_tab()
        self.tabs.addTab(self.tab_logs, "Журнал операций")

        # Footer
        footer = QHBoxLayout()
        footer.addWidget(QLabel("Служба защиты:"))
        self.lbl_service_status = QLabel("АКТИВНА" if self.service_active else "ОТКЛЮЧЕНА")
        color = "green" if self.service_active else "red"
        self.lbl_service_status.setStyleSheet(f"font-weight: bold; color: {color};")
        footer.addWidget(self.lbl_service_status)
        footer.addStretch()
        self.main_layout.addLayout(footer)

    def setup_logs_tab(self):
        layout = QVBoxLayout(self.tab_logs)
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("font-family: Consolas; font-size: 10pt;")
        layout.addWidget(self.log_area)

    def _log(self, msg):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_area.append(f"[{t}] {msg}")

    def setup_management_tab(self):
        layout = QHBoxLayout(self.tab_mgmt)
        splitter = QSplitter(QtCore.Qt.Horizontal)
        layout.addWidget(splitter)

        # === ЛЕВАЯ ЧАСТЬ ===
        left = QWidget(); l_lay = QVBoxLayout(left)
        l_lay.setContentsMargins(0, 0, 5, 0)

        # 1. Роли
        gb_roles = QGroupBox("Ролевая модель")
        l_roles = QVBoxLayout(gb_roles)
        self.roles_table = self._create_table(["Роль", "Сотрудников"])
        l_roles.addWidget(self.roles_table)
        
        btn_r = QHBoxLayout()
        b_add_r = QPushButton("Создать роль"); b_add_r.clicked.connect(self.action_add_role)
        b_del_r = QPushButton("Удалить"); b_del_r.clicked.connect(self.action_del_role)
        btn_r.addWidget(b_add_r); btn_r.addWidget(b_del_r)
        l_roles.addLayout(btn_r)
        l_lay.addWidget(gb_roles)

        # 2. Объекты защиты
        gb_obj = QGroupBox("Объекты защиты (Приложения и Файлы)")
        l_obj = QVBoxLayout(gb_obj)
        self.objects_table = self._create_table(["ID", "Тип", "Имя", "Доступ"])
        l_obj.addWidget(self.objects_table)
        
        btn_o = QHBoxLayout()
        b_app = QPushButton("+ Приложение"); b_app.clicked.connect(self.action_add_app)
        b_file = QPushButton("+ Файл (Шифрование)"); b_file.clicked.connect(self.action_add_file)
        # Кнопки "Открыть" здесь больше нет!
        b_del = QPushButton("Удалить / Расшифровать"); b_del.clicked.connect(self.action_del_object)
        
        btn_o.addWidget(b_app); btn_o.addWidget(b_file); btn_o.addWidget(b_del)
        l_obj.addLayout(btn_o)
        l_lay.addWidget(gb_obj)
        
        splitter.addWidget(left)

        # === ПРАВАЯ ЧАСТЬ ===
        right = QWidget(); r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(5, 0, 0, 0)
        
        gb_users = QGroupBox("Сотрудники")
        l_users = QVBoxLayout(gb_users)
        self.users_table = self._create_table(["ID", "ФИО", "Роль"])
        l_users.addWidget(self.users_table)
        
        btn_u = QHBoxLayout()
        b_add_u = QPushButton("Добавить"); b_add_u.clicked.connect(self.action_add_user)
        b_del_u = QPushButton("Удалить"); b_del_u.clicked.connect(self.action_del_user)
        btn_u.addWidget(b_add_u); btn_u.addWidget(b_del_u)
        l_users.addLayout(btn_u)
        r_lay.addWidget(gb_users)
        
        splitter.addWidget(right)
        splitter.setSizes([600, 600])

    def _create_table(self, headers):
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        t.setAlternatingRowColors(True)
        return t

    # --- ЗАГРУЗКА ---
    def load_data(self):
        self._load_roles(); self._load_objects(); self._load_users()

    def _load_roles(self):
        self.roles_table.setRowCount(0)
        for r in self.db.get_roles_list():
            row = self.roles_table.rowCount(); self.roles_table.insertRow(row)
            cnt = self.db.get_user_count_by_role(r)
            self.roles_table.setItem(row, 0, QTableWidgetItem(r))
            self.roles_table.setItem(row, 1, QTableWidgetItem(str(cnt)))

    def _load_objects(self):
        self.objects_table.setRowCount(0)
        # Apps
        for row in self.db.get_all_apps_raw():
            r = self.objects_table.rowCount(); self.objects_table.insertRow(r)
            roles = self.db.get_app_permissions(row[0])
            self.objects_table.setItem(r, 0, QTableWidgetItem(f"app_{row[0]}"))
            self.objects_table.setItem(r, 1, QTableWidgetItem("Приложение"))
            self.objects_table.setItem(r, 2, QTableWidgetItem(row[1]))
            self.objects_table.setItem(r, 3, QTableWidgetItem(", ".join(roles)))
        # Files
        for row in self.db.get_files():
            r = self.objects_table.rowCount(); self.objects_table.insertRow(r)
            roles = self.db.get_file_permissions(row[0])
            self.objects_table.setItem(r, 0, QTableWidgetItem(f"file_{row[0]}"))
            self.objects_table.setItem(r, 1, QTableWidgetItem("Файл"))
            self.objects_table.setItem(r, 2, QTableWidgetItem(row[1]))
            self.objects_table.setItem(r, 3, QTableWidgetItem(", ".join(roles)))

    def _load_users(self):
        self.users_table.setRowCount(0)
        for u in self.db.get_users():
            r = self.users_table.rowCount(); self.users_table.insertRow(r)
            self.users_table.setItem(r, 0, QTableWidgetItem(str(u['id'])))
            self.users_table.setItem(r, 1, QTableWidgetItem(u['name']))
            self.users_table.setItem(r, 2, QTableWidgetItem(u['role']))

    # --- ДЕЙСТВИЯ ---
    def action_add_role(self):
        dlg = AddRoleDialog(self)
        if dlg.exec_() and self.db.add_role(dlg.get_role_name()): 
            self._load_roles()
            self._log(f"Роль добавлена: {dlg.get_role_name()}")

    def action_del_role(self):
        row = self.roles_table.currentRow()
        if row < 0: return
        role = self.roles_table.item(row, 0).text()
        if role == "Администратор": QMessageBox.warning(self, "!", "Нельзя удалить."); return
        if QMessageBox.question(self, "?", "Удалить роль?") == QMessageBox.Yes:
            self.db.delete_role(role); self.load_data()
            self._log(f"Роль удалена: {role}")

    def action_add_app(self):
        dlg = AddAppDialog(self.db.get_roles_list(), self)
        if dlg.exec_():
            if self.db.add_app(dlg.name_input.text(), dlg.file_path, dlg.selected_roles):
                self._load_objects()
                self.ipc.reload_config()
                self._log(f"Приложение добавлено: {dlg.name_input.text()}")

    def action_add_file(self):
        dlg = AddFileDialog(self.db.get_roles_list(), self)
        if dlg.exec_():
            try:
                QtWidgets.qApp.setOverrideCursor(QtCore.Qt.WaitCursor)
                path, key = self.crypto.encrypt_file(dlg.selected_file)
                name = os.path.basename(dlg.selected_file)
                self.db.add_file(name, path, key, dlg.selected_roles)
                self._load_objects()
                self._log(f"Файл зашифрован: {name}")
                QMessageBox.information(self, "Готово", 
                    f"Файл '{name}' успешно зашифрован.\n"
                    "Оригинал удален.\n"
                    "Теперь открывайте .enc файл двойным кликом.")
            except Exception as e: QMessageBox.critical(self, "Error", str(e))
            finally: QtWidgets.qApp.restoreOverrideCursor()

    def action_del_object(self):
        row = self.objects_table.currentRow()
        if row < 0: return
        t, i = self.objects_table.item(row, 0).text().split('_')
        id_ = int(i)
        
        if QMessageBox.question(self, "?", "Удалить объект из базы?") == QMessageBox.No: return

        if t == 'app':
            self.db.delete_app(id_)
            self.ipc.reload_config()
            self._log("Приложение удалено из мониторинга.")
        elif t == 'file':
            # Экспорт
            reply = QMessageBox.question(self, "Экспорт", "Расшифровать файл перед удалением?", QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if reply == QMessageBox.Cancel: return
            if reply == QMessageBox.Yes:
                try:
                    rec = self.db.get_file_by_id(id_)
                    data = self.crypto.decrypt_file_content(rec[2], rec[3])
                    path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить", self.objects_table.item(row, 2).text())
                    if path: 
                        with open(path, 'wb') as f: f.write(data)
                    else: return
                except Exception as e: QMessageBox.critical(self, "Error", str(e)); return
            
            self.db.delete_file_record(id_)
            self._log("Файл удален из базы.")
        
        self._load_objects()

    def action_add_user(self):
        dlg = AddUserDialog(self.db.get_roles_list(), self)
        if dlg.exec_():
            if dlg.single_user_data: 
                self.db.add_user(*dlg.single_user_data)
                self._log(f"Сотрудник добавлен: {dlg.single_user_data[0]}")
            elif dlg.bulk_users_data: 
                for u in dlg.bulk_users_data: self.db.add_user(*u)
                self._log("Массовый импорт сотрудников завершен.")
            self.load_data()
            self.ipc.reload_config()

    def action_del_user(self):
        row = self.users_table.currentRow()
        if row < 0: return
        if QMessageBox.question(self, "?", "Удалить?") == QMessageBox.Yes:
            self.db.delete_user(int(self.users_table.item(row, 0).text()))
            self.load_data()
            self.ipc.reload_config()
            self._log("Сотрудник удален.")