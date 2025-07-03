#!/bin/bash

mkdir -p Vol-IQ-Analys/core
mkdir -p Vol-IQ-Analys/gui
mkdir -p Vol-IQ-Analys/utils
mkdir -p Vol-IQ-Analys/resources

touch Vol-IQ-Analys/main.py
touch Vol-IQ-Analys/core/__init__.py
touch Vol-IQ-Analys/core/analysis_worker.py
touch Vol-IQ-Analys/core/config_utils.py
touch Vol-IQ-Analys/gui/__init__.py
touch Vol-IQ-Analys/gui/mainwindow.py
touch Vol-IQ-Analys/gui/file_analyzer.py
touch Vol-IQ-Analys/utils/__init__.py
touch Vol-IQ-Analys/utils/constants.py
touch Vol-IQ-Analys/resources/style.qss
touch Vol-IQ-Analys/README.md

echo "¡Estructura Vol-IQ-Analys creada! Llena los archivos con el código correspondiente."
