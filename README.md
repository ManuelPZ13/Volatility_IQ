# Suite Forense - Volatility3 GUI & Vol-IQ-Analys

Este proyecto reúne dos herramientas complementarias pensadas para potenciar el análisis forense de memoria RAM utilizando los artefactos generados por Volatility3. Ambas aplicaciones ofrecen una interfaz gráfica moderna, orientada tanto a analistas forenses profesionales como a estudiantes y entusiastas de la ciberseguridad.

---

## Volatility3 GUI Forense

Volatility3 GUI Forense es una aplicación gráfica que facilita la ejecución y gestión de los plugins de Volatility3 sin necesidad de interactuar con la línea de comandos. Está diseñada para agilizar el análisis de imágenes de memoria y para hacer más accesible todo el potencial de Volatility3 mediante:

- **Selección rápida de imágenes de memoria RAM** (formatos .mem, .raw, .bin, etc).
- **Configuración sencilla** de la ruta de Volatility3 y del sistema operativo analizado.
- **Ejecución de múltiples plugins** categorizados por tipo (procesos, red, archivos, malware, credenciales, etc).
- **Aplicación de filtros avanzados** (por PID, usuario o extensión de archivo) para personalizar el análisis.
- **Extracción de archivos por offset virtual** y movimiento sencillo de los dumps extraídos.
- **Exportación de resultados** en TXT, CSV y HTML, para facilitar la documentación y el reporte de hallazgos.
- **Interfaz intuitiva y visual** con un tema oscuro/morado profesional.

Ideal tanto para laboratorios, investigaciones incidentales como para quienes desean explorar los resultados de Volatility3 sin preocuparse por la complejidad de la terminal.

---

## Vol-IQ-Analys

Vol-IQ-Analys va un paso más allá, ofreciendo análisis avanzado, correlación y búsqueda entre múltiples archivos de salida de Volatility3. Está diseñada para escenarios donde se requiere profundizar, comparar y detectar relaciones entre distintos artefactos extraídos de la memoria.

Sus principales capacidades incluyen:

- **Carga simultánea de varios archivos forenses** generados por Volatility3 (por ejemplo, pslist, netscan, cmdline, files).
- **Correlación automática** para encontrar elementos en común (PIDs, nombres, rutas, palabras clave) entre archivos diferentes.
- **Detección avanzada de Indicadores de Compromiso (IoCs)** utilizando listas negras, reglas YARA y playbooks en YAML.
- **Cálculo de RiskScore** y visualización de correlaciones sospechosas para facilitar la priorización de hallazgos.
- **Búsquedas flexibles**: exactas, aproximadas, por nombres de persona o por PID.
- **Análisis de relaciones** entre procesos, archivos y comandos para reconstruir cadenas de ataque o persistencia.
- **Exportación fácil de todos los resultados** en TXT o HTML para informes o documentación.
- **Interfaz visual moderna y profesional**, también en tema oscuro/morado.

Pensada para contextos donde la correlación, el cruce de datos y la búsqueda detallada son clave para llegar a conclusiones forenses sólidas.

---

## Filosofía y estado del proyecto

Ambas herramientas buscan acercar el análisis forense de memoria a más personas, simplificando flujos complejos y haciendo accesibles técnicas avanzadas de correlación y búsqueda. El proyecto está en **fase de desarrollo activo**:  
- Se están agregando nuevas funcionalidades y mejorando la experiencia de usuario constantemente.  
- Pueden existir cambios frecuentes, ajustes y evoluciones en las capacidades de cada aplicación.

---

by maloweer | 2025

[LinkedIn - Manuel Pérez](https://www.linkedin.com/in/manuel-perez-ba7b432a0)
