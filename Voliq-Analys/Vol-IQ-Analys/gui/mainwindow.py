from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFileDialog, QTabWidget,
    QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem
)
from core.config_utils import cargar_config, cargar_yara_rules, cargar_ioc_yaml
from core.analysis_worker import AnalisisWorker
from gui.file_analyzer import FlexibleFileAnalyzer
import os

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vol-IQ-Analys - Análisis Forense Multiplataforma")
        self.resize(1200, 800)
        self.config = cargar_config()
        self.yara_rules = cargar_yara_rules(self.config['GENERAL'].get('yara_rules', ''))
        self.ioc_playbook = cargar_ioc_yaml(self.config['GENERAL'].get('ioc_yaml', ''))

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Pestaña principal de datos
        self.data_tab = QWidget()
        self.data_layout = QVBoxLayout()
        self.data_tab.setLayout(self.data_layout)
        self.tabs.addTab(self.data_tab, "Datos")

        # IOC
        self.ioc_tab = QTextEdit()
        self.ioc_tab.setReadOnly(True)
        self.tabs.addTab(self.ioc_tab, "IOC")

        # YARA
        self.yara_tab = QTextEdit()
        self.yara_tab.setReadOnly(True)
        self.tabs.addTab(self.yara_tab, "YARA")

        # RiskScore/Correlación
        self.risk_tab = QTextEdit()
        self.risk_tab.setReadOnly(True)
        self.tabs.addTab(self.risk_tab, "Correlación/RiskScore")

        # Flexible Búsqueda (intacta)
        self.busq_widget = FlexibleFileAnalyzer()
        self.tabs.addTab(self.busq_widget, "Búsqueda")

        # Exportación
        self.export_btn = QPushButton("Exportar datos")
        self.export_btn.clicked.connect(self.exportar_datos)
        layout.addWidget(self.export_btn)

        botones = QHBoxLayout()
        self.load_btn = QPushButton("Cargar archivos y analizar")
        self.load_btn.clicked.connect(self.cargar_y_analizar)
        botones.addWidget(self.load_btn)
        layout.addLayout(botones)

        self.archivos = {}

    def cargar_y_analizar(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Selecciona los archivos de Volatility TXT", "", "Archivos TXT (*.txt)")
        if not files:
            return

        self.archivos = {}
        for f in files:
            with open(f, "r", encoding="utf-8", errors="ignore") as ftxt:
                contenido = ftxt.read(500)
                if "LocalAddr" in contenido and "Proto" in contenido:
                    tipo = "netscan"
                elif "ImageFileName" in contenido:
                    tipo = "pslist"
                elif "CommandLine" in contenido or "cmd" in contenido:
                    tipo = "cmdline"
                elif "Offset" in contenido and "Name" in contenido:
                    tipo = "files"
                else:
                    tipo = os.path.basename(f)
            self.archivos[tipo] = f

        self.analisis_worker = AnalisisWorker(self.archivos, self.yara_rules, self.ioc_playbook)
        self.analisis_worker.progress.connect(self.show_status)
        self.analisis_worker.finished.connect(self.show_results)
        self.analisis_worker.start()

    def show_status(self, msg):
        QMessageBox.information(self, "Estado", msg)

    def show_results(self, resultados, ioc_report, yara_report, risk_score):
        import requests
        import re

        VT_API_KEY = "f1308fc34b348d52b3b2c7be694694c51543063e8a5b2551f60908ab18b04350"
        def analizar_ip_virustotal(ip):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": VT_API_KEY}
            try:
                r = requests.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    stats = r.json()['data']['attributes']['last_analysis_stats']
                    mal = stats.get('malicious', 0)
                    estado = "Malicioso" if mal > 3 else "OK"
                    return estado, mal
                else:
                    return "Error", "-"
            except Exception:
                return "Error", "-"

        for i in reversed(range(self.data_layout.count())):
            widget = self.data_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        for modulo, tabla in resultados.items():
            if not tabla:
                continue
            label = QLabel(f"<b>{modulo}</b>")
            self.data_layout.addWidget(label)
            t = QTableWidget()
            t.setRowCount(len(tabla))
            t.setColumnCount(len(tabla[0]))
            t.setHorizontalHeaderLabels(list(tabla[0].keys()))
            for row_i, row in enumerate(tabla):
                for col_i, key in enumerate(row):
                    t.setItem(row_i, col_i, QTableWidgetItem(str(row[key])))
            t.resizeColumnsToContents()
            self.data_layout.addWidget(t)

        ioc_text = ""
        ip_regex = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
        vt_results = {}

        for mod, iocs in ioc_report.items():
            if iocs:
                ioc_text += f"== {mod.upper()} ==\n"
                for i in iocs:
                    ips = ip_regex.findall(i)
                    if ips:
                        for ip in ips:
                            if ip not in vt_results:
                                estado, mal = analizar_ip_virustotal(ip)
                                vt_results[ip] = (estado, mal)
                            else:
                                estado, mal = vt_results[ip]
                            if estado == "Malicioso":
                                ioc_text += f"{i} | VirusTotal: {ip} [{estado} - {mal} motores]\n"
                            elif estado == "OK":
                                ioc_text += f"{i} | VirusTotal: {ip} [OK]\n"
                            else:
                                ioc_text += f"{i} | VirusTotal: {ip} [Error]\n"
                    else:
                        ioc_text += f"{i}\n"
        self.ioc_tab.setText(ioc_text or "Sin IOC críticos detectados.")

        yara_text = ""
        for mod, ylist in yara_report.items():
            if ylist:
                yara_text += f"== {mod.upper()} ==\n"
                for y in ylist:
                    yara_text += f"{y}\n"
        self.yara_tab.setText(yara_text or "Sin matches YARA detectados.")

        risk_text = ""
        for mod, rdict in risk_score.items():
            if rdict:
                risk_text += f"== {mod.upper()} ==\n"
                for pid, score in rdict.items():
                    risk_text += f"PID/Archivo: {pid}  Score: {score}\n"
        self.risk_tab.setText(risk_text or "Sin correlaciones sospechosas.")

    def exportar_datos(self):
        dlg = QFileDialog()
        path, _ = dlg.getSaveFileName(self, "Exportar como", "", "Archivo TXT (*.txt);;Archivo HTML (*.html)")
        if not path:
            return
        if self.tabs.currentIndex() == 0:
            contenido = ""
            for i in range(self.data_layout.count()):
                w = self.data_layout.itemAt(i).widget()
                if isinstance(w, QTableWidget):
                    contenido += "\n"
                    for row in range(w.rowCount()):
                        fila = []
                        for col in range(w.columnCount()):
                            item = w.item(row, col)
                            fila.append(item.text() if item else "")
                        contenido += "\t".join(fila) + "\n"
            if path.endswith(".html"):
                contenido = f"<pre>{contenido}</pre>"
            with open(path, "w", encoding="utf-8") as f:
                f.write(contenido)
            QMessageBox.information(self, "Exportación", "Exportación de datos completada.")
        else:
            idx = self.tabs.currentIndex()
            text = self.tabs.widget(idx).toPlainText()
            if path.endswith(".html"):
                text = f"<pre>{text}</pre>"
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            QMessageBox.information(self, "Exportación", "Exportación de datos completada.")


def set_dark_purple_theme(app):
    app.setStyleSheet("""
        QWidget {
            background-color: #181824;
            color: #f1f1f1;
            font-size: 15px;
        }
        QTabWidget::pane, QTabBar::tab {
            background: #181824;
            color: #a259fc;
        }
        QTabBar::tab:selected {
            background: #28203f;
            color: #fff;
            border-bottom: 2px solid #a259fc;
        }
        QTabBar::tab:!selected {
            background: #11111A;
            color: #a259fc;
        }
        QPushButton {
            background-color: #22223b;
            color: #fff;
            border: 1px solid #753bbd;
            border-radius: 7px;
            padding: 6px 14px;
        }
        QPushButton:hover {
            background-color: #2f284d;
            color: #fff;
            border: 1.5px solid #a259fc;
        }
        QLabel, QGroupBox, QComboBox, QLineEdit, QTextEdit {
            background: transparent;
        }
        QGroupBox {
            border: 1px solid #753bbd;
            margin-top: 10px;
            border-radius: 8px;
            font-weight: bold;
            color: #a259fc;
        }
        QLineEdit, QTextEdit {
            background-color: #232234;
            color: #fff;
            border: 1px solid #a259fc;
            border-radius: 5px;
        }
        QComboBox {
            background-color: #232234;
            color: #fff;
            border: 1px solid #a259fc;
            border-radius: 5px;
        }
        QComboBox QAbstractItemView {
            background-color: #232234;
            color: #a259fc;
            selection-background-color: #753bbd;
        }
        QTableWidget, QHeaderView::section {
            background-color: #232234;
            color: #fff;
            border: 0.5px solid #a259fc;
            font-size: 14px;
        }
        QTableWidget QTableCornerButton::section {
            background: #753bbd;
        }
        QTableWidget::item:selected {
            background-color: #a259fc;
            color: #fff;
        }
        QScrollBar:vertical, QScrollBar:horizontal {
            background: #181824;
            width: 10px;
            margin: 0px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
            background: #753bbd;
            min-height: 25px;
            border-radius: 6px;
        }
        QMessageBox {
            background-color: #181824;
            color: #fff;
        }
    """)
