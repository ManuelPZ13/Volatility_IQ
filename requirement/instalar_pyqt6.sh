#!/bin/bash

# Nombre del entorno virtual
VENV_NAME="venv_pyqt6"

echo "[+] Actualizando sistema..."
sudo apt update -y

echo "[+] Instalando dependencias del sistema..."
sudo apt install -y qtbase5-dev python3-venv python3-pip

echo "[+] Creando entorno virtual: $VENV_NAME"
python3 -m venv $VENV_NAME

echo "[+] Activando entorno virtual..."
source $VENV_NAME/bin/activate

echo "[+] Actualizando pip y setuptools..."
pip install --upgrade pip setuptools wheel

echo "[+] Instalando SIP actualizado..."
pip install --upgrade sip

echo "[+] Instalando PyQt6 desde binarios..."
pip install PyQt6 --only-binary=:all:

echo "[✓] Instalación completada. Entorno virtual activado."
echo "Para activar manualmente luego: source $VENV_NAME/bin/activate"
