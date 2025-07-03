import re
from PyQt6.QtCore import QThread, pyqtSignal
from collections import defaultdict
import iocextract
from utils.constants import MALICIOUS_IPS, SUSPICIOUS_KEYWORDS, BENIGN_PROCESSES, SUSPECT_LOCATIONS

class AnalisisWorker(QThread):
    finished = pyqtSignal(dict, dict, dict, dict)
    progress = pyqtSignal(str)

    def __init__(self, archivos, yara_rules, ioc_playbook):
        super().__init__()
        self.archivos = archivos
        self.yara_rules = yara_rules
        self.ioc_playbook = ioc_playbook

    def run(self):
        resultados = {}
        ioc_report = {}
        yara_report = {}
        risk_score = {}

        for nombre, ruta in self.archivos.items():
            self.progress.emit(f"Procesando {nombre}...")
            with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
                lineas = f.readlines()

            if any("LocalAddr" in l for l in lineas):
                tabla, ioc, risk = self.analizar_red(lineas)
            elif any("ImageFileName" in l for l in lineas):
                tabla, ioc, risk = self.analizar_pslist(lineas)
            elif any("Offset" in l and "Name" in l for l in lineas):
                tabla, ioc, risk = self.analizar_files_mejorado(lineas)
            elif any("CommandLine" in l for l in lineas) or any("cmd" in l for l in lineas):
                tabla, ioc, risk = self.analizar_cmdline_mejorado(lineas)
            else:
                tabla, ioc, risk = ([], {}, {})

            ioc_unique = list(sorted(set(ioc)))
            risk_suma = {}
            for key, val in risk.items():
                if key in risk_suma:
                    risk_suma[key] += val
                else:
                    risk_suma[key] = val

            resultados[nombre] = tabla
            ioc_report[nombre] = ioc_unique
            risk_score[nombre] = risk_suma

            if self.yara_rules:
                file_data = ''.join(lineas)
                matches = self.yara_rules.match(data=file_data.encode(errors="ignore"))
                yara_report[nombre] = [str(m) for m in matches] if matches else []

        self.finished.emit(resultados, ioc_report, yara_report, risk_score)

    def analizar_red(self, lineas):
        tabla = []
        headers = None
        iocs = []
        risk = {}
        for l in lineas:
            if "LocalAddr" in l and "Proto" in l:
                headers = re.split(r"\s+", l.strip())
                continue
            if headers and re.match(r"0x[a-fA-F0-9]+", l.strip()):
                parts = re.split(r"\s+", l.strip())
                row = dict(zip(headers, parts + [""] * (len(headers) - len(parts))))
                tabla.append(row)
                if row.get("ForeignAddr", "") in MALICIOUS_IPS or row.get("LocalAddr", "") in MALICIOUS_IPS:
                    iocs.append(f"IP sospechosa detectada: {row.get('ForeignAddr','')}:{row.get('ForeignPort','')}")
                    pid = row.get("PID", "")
                    if pid:
                        risk[pid] = risk.get(pid, 0) + 5
                ioc_ips = iocextract.extract_ips(' '.join(parts))
                for ip in ioc_ips:
                    if ip in MALICIOUS_IPS:
                        iocs.append(f"IP sospechosa IoC: {ip}")
                        pid = row.get("PID", "")
                        if pid:
                            risk[pid] = risk.get(pid, 0) + 3
        return tabla, iocs, risk

    def analizar_pslist(self, lineas):
        tabla = []
        headers = None
        iocs = []
        risk = {}
        NORMAL_SYSTEM_NAMES = BENIGN_PROCESSES + [
            "init", "systemd", "kthreadd", "rcu_sched", "ksoftirqd", "migration", "watchdog", "kworker",
            "kdevtmpfs", "bioset", "kblockd", "ata_sff", "md", "systemd-journald", "bash", "sh", "login",
            "agetty", "tty", "dhclient", "dbus-daemon", "polkitd"
        ]
        for l in lineas:
            if l.startswith("PID") and "ImageFileName" in l:
                headers = re.split(r"\s+", l.strip())
                continue
            if headers and re.match(r"^\d+", l.strip()):
                parts = re.split(r"\s+", l.strip())
                row = dict(zip(headers, parts + [""] * (len(headers) - len(parts))))
                tabla.append(row)
                exe = row.get("ImageFileName", "").lower()
                if exe not in [n.lower() for n in NORMAL_SYSTEM_NAMES] and exe.endswith(".exe"):
                    iocs.append(f"Proceso sospechoso fuera de lista normal: {exe}")
                    pid = row.get("PID", "")
                    if pid:
                        risk[pid] = risk.get(pid, 0) + 9
        return tabla, iocs, risk

    def analizar_files_mejorado(self, lineas):
        tabla = []
        headers = None
        iocs = []
        risk = {}
        for l in lineas:
            if l.startswith("Offset") and "Name" in l:
                headers = re.split(r"\s+", l.strip())
                continue
            if headers and re.match(r"0x[a-fA-F0-9]+", l.strip()):
                parts = re.split(r"\s+", l.strip(), maxsplit=len(headers)-1)
                row = dict(zip(headers, parts + [""] * (len(headers) - len(parts))))
                tabla.append(row)
                fpath = row.get("Name", "").lower()
                for key in SUSPICIOUS_KEYWORDS:
                    if key in fpath:
                        iocs.append(f"Archivo sospechoso: {fpath}")
                for regex in SUSPECT_LOCATIONS:
                    if re.search(regex, fpath):
                        iocs.append(f"Ruta sospechosa: {fpath}")
        return tabla, iocs, risk

    def analizar_cmdline_mejorado(self, lineas):
        tabla = []
        headers = None
        iocs = []
        risk = {}
        for l in lineas:
            if l.lower().startswith("pid") and "commandline" in l.lower():
                headers = re.split(r"\s+", l.strip())
                continue
            if headers and re.match(r"^\d+", l.strip()):
                parts = re.split(r"\s+", l.strip(), maxsplit=len(headers)-1)
                row = dict(zip(headers, parts + [""] * (len(headers) - len(parts))))
                tabla.append(row)
                cmd = row.get("CommandLine", "").lower()
                pid = row.get("PID", "")
                found = False
                for key in SUSPICIOUS_KEYWORDS:
                    if key in cmd:
                        iocs.append(f"Comando sospechoso: {cmd}")
                        risk[pid] = risk.get(pid, 0) + 6
                        found = True
                for regex in SUSPECT_LOCATIONS:
                    if re.search(regex, cmd):
                        iocs.append(f"Ruta sospechosa en cmdline: {cmd}")
                        risk[pid] = risk.get(pid, 0) + 4
                        found = True
        return tabla, iocs, risk
