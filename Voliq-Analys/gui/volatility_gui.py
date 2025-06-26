
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QFileDialog,
    QTabWidget, QTextEdit, QMenu, QCheckBox, QLineEdit, QMessageBox, QApplication
)
from PyQt6.QtCore import Qt
import os
import re
import csv
import shutil

from core.volatility_worker import VolatilityWorker

class VolatilityGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Voliq-Analys - Volatility3 GUI Forense")
        self.resize(1200, 800)
        self.full_output = ""
        self.image_path = None
        self.worker = None
        self.error_shown = False
        self.last_extracted_file = None
        self.volatility_path = self.detect_volatility_path()
        self.setup_ui()
        self.setStyleSheet(open("resources/style.qss", "r").read())

    # ... resto del código igual al ejemplo anterior ...

    def detect_volatility_path(self):
        possible_paths = [
            "/opt/volatility3",
            "/usr/local/bin/volatility3",
            os.path.expanduser("~/volatility3"),
            os.path.join(os.getcwd(), "volatility3")
        ]
        for path in possible_paths:
            if os.path.exists(os.path.join(path, "vol.py")):
                return path
        QMessageBox.critical(self, "Error",
                           "No se pudo encontrar Volatility3. Por favor instálelo o configure la ruta manualmente.")
        return None

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setup_offset_section(layout)
        self.setup_config_section(layout)
        self.setup_filters_section(layout)
        self.setup_plugins_section(layout)
        self.setup_output_section(layout)
        self.setup_status_bar(layout)
        self.setLayout(layout)
        self.update_plugins()

    def setup_offset_section(self, layout):
        offset_layout = QHBoxLayout()
        offset_layout.addWidget(QLabel("Extraer Dump por Offset virtual:"))
        self.offset_input = QLineEdit()
        self.offset_input.setPlaceholderText("Ejemplo: 0xc402ee5b16e0")
        offset_layout.addWidget(self.offset_input)
        self.offset_btn = QPushButton("Extraer offset (dumpfiles)")
        self.offset_btn.clicked.connect(self.run_offset_analysis)
        offset_layout.addWidget(self.offset_btn)
        self.move_offset_btn = QPushButton("Mover archivo extraído")
        self.move_offset_btn.setEnabled(False)
        self.move_offset_btn.clicked.connect(self.move_extracted_file)
        offset_layout.addWidget(self.move_offset_btn)
        layout.addLayout(offset_layout)

    def run_offset_analysis(self):
        if not hasattr(self, 'image_path') or not self.image_path:
            self.show_error("Debes seleccionar una imagen de memoria primero")
            return

        if not self.volatility_path:
            self.show_error("Ruta de Volatility3 no configurada")
            return

        virtaddr = self.offset_input.text().strip()
        if not virtaddr:
            self.show_error("Debes ingresar una dirección virtual (virtaddr)")
            return
        if not re.match(r"^0x[a-fA-F0-9]+$", virtaddr):
            self.show_error("Formato inválido de dirección virtual (ejemplo: 0xc402ee5b16e0)")
            return

        self.last_extracted_file = None  # Reset

        vol_script = os.path.join(self.volatility_path, "vol.py")
        command = [
            "python3", vol_script, "-f", self.image_path,
            "windows.dumpfiles", "--virtaddr", virtaddr
        ]

        self.prepare_for_execution()
        self.execute_command(command)

    def move_extracted_file(self):
        if not self.last_extracted_file or not os.path.exists(self.last_extracted_file):
            self.show_error("No se encontró el archivo extraído.")
            return
        dest_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar archivo extraído como", os.path.basename(self.last_extracted_file)
        )
        if dest_path:
            try:
                shutil.move(self.last_extracted_file, dest_path)
                self.status_label.setText(f"Archivo movido a: {dest_path}")
                self.move_offset_btn.setEnabled(False)
                self.last_extracted_file = None
            except Exception as e:
                self.show_error(f"No se pudo mover el archivo: {e}")
        else:
            self.status_label.setText("Operación de guardado cancelada")

    def setup_config_section(self, layout):
        config_layout = QHBoxLayout()
        config_layout.addWidget(QLabel("Sistema operativo:"))
        self.os_combo = QComboBox()
        self.os_combo.addItems(["Windows", "Linux", "MacOS"])
        self.os_combo.currentIndexChanged.connect(self.update_plugins)
        config_layout.addWidget(self.os_combo)
        self.label_img = QLabel("No se ha seleccionado ninguna imagen")
        self.load_button = QPushButton("Seleccionar imagen")
        self.load_button.clicked.connect(self.select_image)
        config_layout.addWidget(self.label_img)
        config_layout.addWidget(self.load_button)
        self.config_button = QPushButton("Configurar Volatility3")
        self.config_button.clicked.connect(self.set_volatility_path)
        config_layout.addWidget(self.config_button)
        layout.addLayout(config_layout)

    def set_volatility_path(self):
        path = QFileDialog.getExistingDirectory(
            self,
            "Seleccionar directorio de Volatility3",
            os.path.expanduser("~")
        )
        if path:
            if os.path.exists(os.path.join(path, "vol.py")):
                self.volatility_path = path
                self.status_label.setText(f"Volatility3 configurado en: {path}")
            else:
                QMessageBox.warning(self, "Error",
                                  "No se encontró vol.py en el directorio seleccionado")

    def setup_filters_section(self, layout):
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrar por PID:"))
        self.pid_filter = QLineEdit()
        self.pid_filter.setPlaceholderText("Ej: 1234, 5678 o 1234-5678")
        filter_layout.addWidget(self.pid_filter)
        filter_layout.addWidget(QLabel("Filtrar por usuario:"))
        self.user_filter = QLineEdit()
        self.user_filter.setPlaceholderText("Ej: Administrador, root")
        filter_layout.addWidget(self.user_filter)
        filter_layout.addWidget(QLabel("Filtrar por extensión:"))
        self.ext_filter = QLineEdit()
        self.ext_filter.setPlaceholderText("Ej: .exe, .dll")
        filter_layout.addWidget(self.ext_filter)
        layout.addLayout(filter_layout)

    def setup_plugins_section(self, layout):
        self.plugin_tabs = QTabWidget()
        layout.addWidget(QLabel("Selecciona un plugin:"))
        layout.addWidget(self.plugin_tabs)
        self.plugin_selectors = {}
        self.update_plugins()
        btn_layout = QHBoxLayout()
        self.run_button = QPushButton("Ejecutar plugin seleccionado")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self.run_analysis)
        btn_layout.addWidget(self.run_button)
        self.full_pid_analysis_btn = QPushButton("Análisis completo por PID")
        self.full_pid_analysis_btn.setEnabled(False)
        self.full_pid_analysis_btn.clicked.connect(self.run_full_pid_analysis)
        btn_layout.addWidget(self.full_pid_analysis_btn)
        self.stop_button = QPushButton("Detener análisis")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_analysis)
        btn_layout.addWidget(self.stop_button)
        layout.addLayout(btn_layout)

    def append_output(self, text, accumulate=False):
        match = re.search(r"File output: (.+)", text)
        if match:
            self.last_extracted_file = match.group(1).strip()
            self.move_offset_btn.setEnabled(True)
            self.status_label.setText(f"Archivo extraído: {self.last_extracted_file}")
        if accumulate:
            self.full_output += text + "\n"
            self.text_output.setPlainText(self.full_output)
        else:
            self.text_output.append(text)
        self.save_button.setEnabled(True)

    def setup_output_section(self, layout):
        save_layout = QHBoxLayout()
        self.auto_save_checkbox = QCheckBox("Guardar salida automáticamente como TXT")
        self.auto_save_checkbox.setChecked(False)
        save_layout.addWidget(self.auto_save_checkbox)
        self.save_button = QPushButton("Guardar salida")
        self.save_button.setEnabled(False)
        save_menu = QMenu(self)
        save_menu.addAction("Guardar como TXT", self.save_output_txt)
        save_menu.addAction("Guardar como CSV", self.save_output_csv)
        save_menu.addAction("Guardar como HTML", self.save_output_html)
        self.save_button.setMenu(save_menu)
        save_layout.addWidget(self.save_button)
        self.clear_button = QPushButton("Limpiar salida")
        self.clear_button.clicked.connect(self.clear_output)
        save_layout.addWidget(self.clear_button)
        layout.addLayout(save_layout)
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        layout.addWidget(QLabel("Resultados del análisis:"))
        layout.addWidget(self.text_output)

    def clear_output(self):
        self.text_output.clear()

    def setup_status_bar(self, layout):
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Listo")
        status_layout.addWidget(self.status_label)
        watermark = QLabel("Versión Completa 3.0 | by maloweer")
        watermark.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_layout.addWidget(watermark)
        layout.addLayout(status_layout)

    def update_plugins(self):
        os_type = self.os_combo.currentText()
        self.plugin_tabs.clear()
        self.plugin_selectors = {}
        plugins = self.get_plugins_for_os(os_type)
        for category, plugin_list in plugins.items():
            tab = QWidget()
            tab_layout = QVBoxLayout()
            combo = QComboBox()
            combo.addItems(plugin_list)
            tab_layout.addWidget(combo)
            tab.setLayout(tab_layout)
            self.plugin_tabs.addTab(tab, category)
            self.plugin_selectors[category] = combo

    def get_plugins_for_os(self, os_type):
        plugins = {
            "Windows": {
                "Procesos": [
                    "windows.pslist", "windows.pstree", "windows.psscan", 
                    "windows.cmdline", "windows.envars", "windows.privileges"
                ],
                "Red": [
                    "windows.netscan", "windows.netgraph", "windows.sockscan"
                ],
                "Memoria": [
                    "windows.vadinfo", "windows.vadwalk", "windows.memmap",
                    "windows.virtmap", "windows.volshell"
                ],
                "Archivos": [
                    "windows.filescan", "windows.dumpfiles", "windows.dlllist",
                    "windows.handles", "windows.driverscan"
                ],
                "Registro": [
                    "windows.registry.userassist", "windows.registry.printkey",
                    "windows.registry.shellbags", "windows.shimcache"
                ],
                "Malware": [
                    "windows.malfind", "windows.ssdt", "windows.callbacks",
                    "windows.driverirp", "windows.modscan"
                ],
                "Usuarios/Credenciales": [
                    "windows.hashdump", 
                    "windows.lsadump",
                    "windows.cachedump",
                    "windows.getsids",
                    "windows.registry.hivelist",
                    "windows.registry.hivescan",
                    "windows.registry.printkey -K 'SAM\\Domains\\Account\\Users'",
                    "windows.registry.printkey -K 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'",
                    "windows.sessions",
                    "windows.logonsessions"
                ]
            },
            "Linux": {
                "Procesos": [
                    "linux.pslist", "linux.pstree", "linux.psscan",
                    "linux.bash"
                ],
                "Red": [
                    "linux.netscan", "linux.netstat", "linux.ifconfig"
                ],
                "Sistema": [
                    "linux.check_modules", "linux.dmesg", "linux.mount",
                    "linux.filescan", "linux.lsof"
                ],
                "Usuarios": [
                    "linux.enumerate_users"
                ]
            },
            "MacOS": {
                "Procesos": [
                    "mac.pslist", "mac.pstree", "mac.psscan"
                ],
                "Red": [
                    "mac.netscan", "mac.netstat", "mac.ifconfig"
                ],
                "Sistema": [
                    "mac.kauth_scopes", "mac.notifiers", "mac.check_sysctl",
                    "mac.filescan", "mac.lsof"
                ],
                "Usuarios": [
                    "mac.keychaindump",
                    "mac.timeliner"
                ]
            }
        }
        return plugins.get(os_type, {})

    def select_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar imagen de memoria",
            "",
            "Archivos de memoria (*.mem *.raw *.bin *.dmp *.vmem *.crash);;Todos los archivos (*)"
        )
        if file_path:
            self.image_path = file_path
            self.label_img.setText(f"Imagen seleccionada: {os.path.basename(file_path)}")
            self.run_button.setEnabled(True)
            self.full_pid_analysis_btn.setEnabled(True)
            self.status_label.setText(f"Imagen cargada: {os.path.basename(file_path)}")

    def validate_pid(self, pid_text):
        if not pid_text:
            return True, None
        if "-" in pid_text:
            try:
                start, end = map(int, pid_text.split("-"))
                return True, f"{start}-{end}"
            except ValueError:
                return False, "Formato de rango de PID inválido. Use: 1000-2000"
        if "," in pid_text:
            try:
                pids = [int(pid.strip()) for pid in pid_text.split(",")]
                return True, ",".join(map(str, pids))
            except ValueError:
                return False, "Formato de lista de PIDs inválido. Use: 1000,1002,1005"
        try:
            pid = int(pid_text)
            return True, str(pid)
        except ValueError:
            return False, "PID debe ser un número entero"

    def build_command(self, plugin, pid_filter=None, user_filter=None, ext_filter=None):
        vol_script = os.path.join(self.volatility_path, "vol.py")
        command = ["python3", vol_script, "-f", self.image_path]
        if plugin.count('.') > 1:
            module, _, plugin_name = plugin.rpartition('.')
            command.extend([f"{module}", f"{plugin_name}"])
        else:
            plugin_parts = plugin.split()
            command.extend(plugin_parts)
        if pid_filter:
            command.extend(["--pid", pid_filter])
        if user_filter:
            command.extend(["--user", user_filter])
        if ext_filter and any(plugin.startswith(x) for x in [
            "windows.filescan", "windows.dumpfiles", "windows.dlllist",
            "linux.filescan", "mac.filescan"
        ]):
            command.extend(["--ext", ext_filter])
        return command

    def run_analysis(self):
        if not self.image_path:
            self.show_error("Debes seleccionar una imagen de memoria primero")
            return
        if not self.volatility_path:
            self.show_error("Ruta de Volatility3 no configurada")
            return
        current_tab = self.plugin_tabs.tabText(self.plugin_tabs.currentIndex())
        plugin = self.plugin_selectors.get(current_tab)
        if not plugin:
            return
        plugin = plugin.currentText()
        pid_text = self.pid_filter.text().strip()
        valid, pid_result = self.validate_pid(pid_text)
        if not valid:
            self.show_error(pid_result)
            return
        user_text = self.user_filter.text().strip()
        ext_text = self.ext_filter.text().strip()
        if ext_text and not re.match(r"^(\.[a-zA-Z0-9]+)(,\s*\.[a-zA-Z0-9]+)*$", ext_text):
            self.show_error("Formato de extensión inválido. Use: .exe,.dll o .exe, .dll")
            return
        command = self.build_command(plugin, pid_result, user_text, ext_text)
        self.prepare_for_execution()
        self.execute_command(command)

    def run_full_pid_analysis(self):
        if not self.image_path:
            self.show_error("Debes seleccionar una imagen de memoria primero")
            return
        if not self.volatility_path:
            self.show_error("Ruta de Volatility3 no configurada")
            return
        pid_text = self.pid_filter.text().strip()
        if not pid_text:
            self.show_error("Debes especificar un PID para el análisis completo")
            return
        if "-" in pid_text or "," in pid_text:
            self.show_error("El análisis completo requiere un único PID (no rangos ni listas)")
            return
        valid, pid_result = self.validate_pid(pid_text)
        if not valid:
            self.show_error(pid_result)
            return
        os_type = self.os_combo.currentText()
        self.prepare_for_execution()
        self.full_output = f"=== ANÁLISIS COMPLETO DEL PID {pid_result} ===\n\n"
        plugins_to_run = self.get_plugins_for_pid_analysis(os_type, pid_result)
        total_plugins = len(plugins_to_run)
        for i, (name, plugin) in enumerate(plugins_to_run):
            self.append_output(f"\n=== {name.upper()} ===\n")
            self.status_label.setText(f"Ejecutando {name}... ({i+1}/{total_plugins})")
            command = self.build_command(plugin, pid_result)
            self.execute_command(command, accumulate=True)
            QApplication.processEvents()
        self.status_label.setText("Análisis completo finalizado")
        self.save_button.setEnabled(True)
        if self.auto_save_checkbox.isChecked():
            self.auto_save_output_auto()

    def get_plugins_for_pid_analysis(self, os_type, pid):
        plugins = {
            "Windows": [
                ("Información del proceso", "windows.pslist"),
                ("Árbol de procesos", "windows.pstree"),
                ("Línea de comandos", "windows.cmdline"),
                ("Variables de entorno", "windows.envars"),
                ("Privilegios", "windows.privileges"),
                ("Handles y objetos", "windows.handles"),
                ("DLLs cargadas", "windows.dlllist"),
                ("Conexiones de red", "windows.netscan"),
                ("Regiones de memoria", "windows.vadinfo"),
                ("Hilos", "windows.threads"),
                ("Servicios", "windows.svcscan"),
                ("Credenciales", "windows.hashdump"),
                ("Sesiones", "windows.logonsessions")
            ],
            "Linux": [
                ("Información del proceso", "linux.pslist"),
                ("Mapas de memoria", "linux.proc_maps"),
                ("Archivos abiertos", "linux.lsof"),
                ("Conexiones de red", "linux.netscan"),
                ("Información de bash", "linux.bash"),
                ("Credenciales", "linux.enumerate_users")
            ],
            "MacOS": [
                ("Información del proceso", "mac.pslist"),
                ("Árbol de procesos", "mac.pstree"),
                ("Archivos abiertos", "mac.lsof"),
                ("Conexiones de red", "mac.netscan"),
                ("Mapas de memoria", "mac.proc_maps"),
                ("Keychain", "mac.keychaindump")
            ]
        }
        return plugins.get(os_type, [])

    def prepare_for_execution(self):
        self.text_output.clear()
        self.save_button.setEnabled(False)
        self.run_button.setEnabled(False)
        self.full_pid_analysis_btn.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.error_shown = False
        self.move_offset_btn.setEnabled(False)
        self.last_extracted_file = None
        QApplication.processEvents()

    def execute_command(self, command, accumulate=False):
        self.status_label.setText(f"Ejecutando: {' '.join(command)}")
        self.worker = VolatilityWorker(command, self.volatility_path)
        self.worker.output_received.connect(lambda output: self.append_output(output, accumulate))
        self.worker.error_occurred.connect(self.show_error)
        self.worker.analysis_finished.connect(self.analysis_finished)
        self.worker.progress_update.connect(self.show_progress)
        self.worker.start()

    def analysis_finished(self):
        self.status_label.setText("Análisis finalizado")
        self.run_button.setEnabled(True)
        self.full_pid_analysis_btn.setEnabled(True)
        self.stop_button.setEnabled(False)

    def stop_analysis(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.status_label.setText("Análisis detenido")
            self.run_button.setEnabled(True)
            self.full_pid_analysis_btn.setEnabled(True)
            self.stop_button.setEnabled(False)

    def show_error(self, message):
        if not self.error_shown:
            QMessageBox.critical(self, "Error", message)
            self.error_shown = True
        self.status_label.setText("Error durante el análisis")
        self.run_button.setEnabled(True)
        self.full_pid_analysis_btn.setEnabled(True)
        self.stop_button.setEnabled(False)

    def show_progress(self, message):
        self.status_label.setText(message)

    def save_output_txt(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Guardar como TXT", "", "Archivo de texto (*.txt)")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.text_output.toPlainText())

    def save_output_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Guardar como CSV", "", "Archivo CSV (*.csv)")
        if file_path:
            lines = self.text_output.toPlainText().splitlines()
            with open(file_path, "w", encoding="utf-8", newline='') as f:
                writer = csv.writer(f)
                for line in lines:
                    writer.writerow([line])

    def save_output_html(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Guardar como HTML", "", "Archivo HTML (*.html)")
        if file_path:
            html_content = f"""
            <html><body><pre>{self.text_output.toPlainText()}</pre></body></html>
            """
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)

    def auto_save_output_auto(self):
        base_name = os.path.splitext(os.path.basename(self.image_path))[0]
        default_name = f"{base_name}_volatility_output.txt"
        with open(default_name, "w", encoding="utf-8") as f:
            f.write(self.text_output.toPlainText())
        self.status_label.setText(f"Salida guardada automáticamente en {default_name}")

def main():
    app = QApplication(sys.argv)
    gui = VolatilityGUI()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
