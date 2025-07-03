from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QTabWidget,
    QTableWidget, QTableWidgetItem, QTextEdit, QComboBox, QLineEdit, QGroupBox, QHeaderView, QMessageBox
)
import re
import os
from collections import defaultdict

class FlexibleFileAnalyzer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_data = {
            'file1': {'path': None, 'name': None, 'content': [], 'index': {}},
            'file2': {'path': None, 'name': None, 'content': [], 'index': {}},
            'file3': {'path': None, 'name': None, 'content': [], 'index': {}}
        }
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        file_group = QGroupBox("Cargar Archivos TXT (1-3)")
        file_layout = QHBoxLayout()
        self.btn_file1 = QPushButton("Documento 1")
        self.btn_file1.clicked.connect(lambda: self.load_file(1))
        self.lbl_file1 = QLabel("No seleccionado")
        file_layout.addWidget(self.btn_file1)
        file_layout.addWidget(self.lbl_file1)
        self.btn_file2 = QPushButton("Documento 2")
        self.btn_file2.clicked.connect(lambda: self.load_file(2))
        self.lbl_file2 = QLabel("No seleccionado")
        file_layout.addWidget(self.btn_file2)
        file_layout.addWidget(self.lbl_file2)
        self.btn_file3 = QPushButton("Documento 3")
        self.btn_file3.clicked.connect(lambda: self.load_file(3))
        self.lbl_file3 = QLabel("No seleccionado")
        file_layout.addWidget(self.btn_file3)
        file_layout.addWidget(self.lbl_file3)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        query_group = QGroupBox("Opciones de Análisis")
        query_layout = QVBoxLayout()
        search_layout = QHBoxLayout()
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Buscar palabra, nombre o PID...")
        search_layout.addWidget(self.txt_search)
        self.btn_search = QPushButton("Buscar")
        self.btn_search.clicked.connect(self.search_content)
        search_layout.addWidget(self.btn_search)
        self.btn_clear = QPushButton("Limpiar")
        self.btn_clear.clicked.connect(self.clear_results)
        search_layout.addWidget(self.btn_clear)
        query_layout.addLayout(search_layout)
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Tipo:"))
        self.search_type = QComboBox()
        self.search_type.addItems([
            "Contenido exacto",
            "Contenido aproximado",
            "Nombre de persona",
            "Número/PID"
        ])
        type_layout.addWidget(self.search_type)
        self.btn_analyze_relations = QPushButton("Analizar Relaciones")
        self.btn_analyze_relations.clicked.connect(self.analyze_relations)
        type_layout.addWidget(self.btn_analyze_relations)
        query_layout.addLayout(type_layout)
        query_group.setLayout(query_layout)
        main_layout.addWidget(query_group)

        self.result_tabs = QTabWidget()
        self.tbl_results = QTableWidget()
        self.tbl_results.setColumnCount(5)
        self.tbl_results.setHorizontalHeaderLabels(["#", "Documento", "Línea", "Coincidencia", "Contenido"])
        self.tbl_results.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.result_tabs.addTab(self.tbl_results, "Resultados")
        self.txt_relations = QTextEdit()
        self.txt_relations.setReadOnly(True)
        self.result_tabs.addTab(self.txt_relations, "Relaciones")
        self.txt_stats = QTextEdit()
        self.txt_stats.setReadOnly(True)
        self.result_tabs.addTab(self.txt_stats, "Estadísticas")
        main_layout.addWidget(self.result_tabs)
        self.setLayout(main_layout)

    def load_file(self, file_num):
        key = f'file{file_num}'
        path, _ = QFileDialog.getOpenFileName(self, f"Seleccionar Documento {file_num}", "", "Text files (*.txt);;All files (*)")
        if path:
            self.file_data[key]['path'] = path
            self.file_data[key]['name'] = os.path.basename(path)
            getattr(self, f'lbl_file{file_num}').setText(self.file_data[key]['name'])
            self.analyze_file(key)
            self.update_stats()

    def analyze_file(self, file_key):
        try:
            with open(self.file_data[file_key]['path'], 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                self.file_data[file_key]['content'] = lines
                self.file_data[file_key]['index'] = {
                    'words': defaultdict(list),
                    'names': defaultdict(list),
                    'pids': defaultdict(list)
                }
                for line_num, line in enumerate(lines, 1):
                    line_text = line.strip()
                    if not line_text:
                        continue
                    words = re.findall(r'\b([a-záéíóúñ]{3,})\b', line_text.lower())
                    for word in words:
                        self.file_data[file_key]['index']['words'][word].append((line_num, line_text))
                    names = re.findall(r'\b([A-ZÁÉÍÓÚ][a-záéíóú]+\s[A-ZÁÉÍÓÚ][a-záéíóú]+)\b', line_text)
                    for name in names:
                        self.file_data[file_key]['index']['names'][name.lower()].append((line_num, line_text))
                    pids = re.findall(r'\b(\d{3,5})\b', line_text)
                    for pid in pids:
                        self.file_data[file_key]['index']['pids'][pid].append((line_num, line_text))
            return True
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo leer el archivo: {str(e)}")
            return False

    def search_content(self):
        query = self.txt_search.text().strip()
        if not query:
            QMessageBox.warning(self, "Error", "Ingrese un término de búsqueda")
            return
        if not any(self.file_data[f'file{i}']['path'] for i in [1, 2, 3]):
            QMessageBox.warning(self, "Error", "Cargue al menos un documento")
            return
        search_type = self.search_type.currentText()
        results = []
        for file_key in ['file1', 'file2', 'file3']:
            if not self.file_data[file_key]['path']:
                continue
            if search_type == "Contenido exacto":
                matches = self.search_exact(file_key, query)
            elif search_type == "Contenido aproximado":
                matches = self.search_approximate(file_key, query)
            elif search_type == "Nombre de persona":
                matches = self.search_names(file_key, query)
            else:
                matches = self.search_pids(file_key, query)
            results.extend([(file_key, *match) for match in matches])
        self.display_results(results)

    def search_exact(self, file_key, query):
        query = query.lower()
        return self.file_data[file_key]['index']['words'].get(query, [])

    def search_approximate(self, file_key, query):
        try:
            pattern = re.compile(query, re.IGNORECASE)
            matches = []
            for line_num, line in enumerate(self.file_data[file_key]['content'], 1):
                if pattern.search(line):
                    matches.append((line_num, f"~{query}~", line.strip()))
            return matches
        except re.error:
            QMessageBox.warning(self, "Error", "Expresión regular inválida")
            return []

    def search_names(self, file_key, query):
        query = query.lower()
        matches = []
        for name in self.file_data[file_key]['index']['names']:
            if query in name:
                matches.extend(self.file_data[file_key]['index']['names'][name])
        return matches

    def search_pids(self, file_key, query):
        if query.isdigit():
            return self.file_data[file_key]['index']['pids'].get(query, [])
        return []

    def analyze_relations(self):
        loaded_files = [file_key for file_key in ['file1', 'file2', 'file3'] if self.file_data[file_key]['path']]
        if len(loaded_files) < 1:
            QMessageBox.warning(self, "Error", "Cargue al menos un documento")
            return
        report = "=== RELACIONES ENTRE DOCUMENTOS ===\n\n"
        if len(loaded_files) > 1:
            common_pids = self.find_common_elements('pids')
            common_names = self.find_common_elements('names')
            common_words = self.find_common_elements('words', min_length=5)
            report += "PIDs COMUNES:\n"
            for pid in common_pids:
                report += f"\nPID {pid} encontrado en:\n"
                for file_key in loaded_files:
                    if pid in self.file_data[file_key]['index']['pids']:
                        count = len(self.file_data[file_key]['index']['pids'][pid])
                        report += f"- {self.file_data[file_key]['name']}: {count} veces\n"
            report += "\nNOMBRES COMUNES:\n"
            for name in common_names:
                report += f"\n{name.title()} encontrado en:\n"
                for file_key in loaded_files:
                    if name in self.file_data[file_key]['index']['names']:
                        count = len(self.file_data[file_key]['index']['names'][name])
                        report += f"- {self.file_data[file_key]['name']}: {count} veces\n"
            report += "\nPALABRAS CLAVE COMUNES (5+ letras):\n"
            for word in common_words:
                report += f"\n'{word}' encontrado en:\n"
                for file_key in loaded_files:
                    if word in self.file_data[file_key]['index']['words']:
                        count = len(self.file_data[file_key]['index']['words'][word])
                        report += f"- {self.file_data[file_key]['name']}: {count} veces\n"
        else:
            report += "Cargue al menos 2 documentos para analizar relaciones.\n"
        self.txt_relations.setPlainText(report)

    def find_common_elements(self, index_type, min_length=0):
        loaded_files = [file_key for file_key in ['file1', 'file2', 'file3'] if self.file_data[file_key]['path']]
        if len(loaded_files) < 2:
            return []
        sets = []
        for file_key in loaded_files:
            elements = set(k for k in self.file_data[file_key]['index'][index_type].keys() if len(k) >= min_length)
            sets.append(elements)
        common = set.intersection(*sets)
        return sorted(common)

    def display_results(self, results):
        self.tbl_results.setRowCount(len(results))
        for row, (file_key, line_num, match, content) in enumerate(results):
            self.tbl_results.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.tbl_results.setItem(row, 1, QTableWidgetItem(self.file_data[file_key]['name']))
            self.tbl_results.setItem(row, 2, QTableWidgetItem(str(line_num)))
            self.tbl_results.setItem(row, 3, QTableWidgetItem(match))
            self.tbl_results.setItem(row, 4, QTableWidgetItem(content))
        self.tbl_results.resizeColumnsToContents()

    def clear_results(self):
        self.tbl_results.setRowCount(0)
        self.txt_relations.clear()

    def update_stats(self):
        stats = "=== ESTADÍSTICAS ===\n\n"
        loaded_files = 0
        total_lines = 0
        total_words = 0
        total_names = 0
        total_pids = 0
        for file_key in ['file1', 'file2', 'file3']:
            if self.file_data[file_key]['path']:
                loaded_files += 1
                lines = len(self.file_data[file_key]['content'])
                words = len(self.file_data[file_key]['index']['words'])
                names = len(self.file_data[file_key]['index']['names'])
                pids = len(self.file_data[file_key]['index']['pids'])
                stats += f"DOCUMENTO {file_key[-1]}: {self.file_data[file_key]['name']}\n"
                stats += f"Líneas: {lines}\n"
                stats += f"Palabras únicas: {words}\n"
                stats += f"Nombres únicos: {names}\n"
                stats += f"PIDs únicos: {pids}\n\n"
                total_lines += lines
                total_words += words
                total_names += names
                total_pids += pids
        stats += f"TOTAL:\n"
        stats += f"Documentos cargados: {loaded_files}/3\n"
        stats += f"Líneas totales: {total_lines}\n"
        stats += f"Palabras únicas totales: {total_words}\n"
        stats += f"Nombres únicos totales: {total_names}\n"
        stats += f"PIDs únicos totales: {total_pids}\n"
        self.txt_stats.setPlainText(stats)
