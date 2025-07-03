# Vol-IQ-Analys

**Vol-IQ-Analys** es una plataforma modular para el análisis forense avanzado de artefactos generados por Volatility. Incluye búsqueda, correlación, detección de IoCs, análisis con YARA y exportación, todo en una interfaz gráfica profesional.

---

## Características

- **Interfaz gráfica** intuitiva (PyQt6, tema oscuro/morado).
- **Análisis automático** de artefactos de Volatility3: pslist, netscan, cmdline, files.
- **Búsqueda flexible** y análisis de relaciones entre varios archivos.
- **Detección avanzada de IoCs:** listas negras, YARA y playbooks YAML personalizados.
- **Correlación y RiskScore** de procesos y artefactos.
- **Exportación de resultados** a TXT y HTML.
- **Reputación de IPs** usando la API de VirusTotal.

---

## Requisitos

- **Python 3.8 o superior**

---

## Instalación de dependencias

Instala todas las dependencias necesarias ejecutando:

```bash
pip install PyQt6 yara-python iocextract pyyaml requests
