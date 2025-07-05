#!/bin/bash

# Nombre del entorno virtual
VENV_DIR="venv"

# Lista de dependencias
DEPENDENCIAS="yara-python iocextract pyyaml configparser PyQt6 requests"

echo "[+] Instalador de entorno para VolIQ-Analys"

# Verifica si Python 3 está disponible
if ! command -v python3 &> /dev/null; then
    echo "[-] Python 3 no está instalado."
    exit 1
fi

# Crear entorno virtual si no existe
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creando entorno virtual..."
    python3 -m venv "$VENV_DIR"
else
    echo "[*] El entorno virtual ya existe."
fi

# Activar entorno virtual
source "$VENV_DIR/bin/activate"

# Actualizar pip
echo "[+] Actualizando pip..."
pip install --upgrade pip

# Instalar dependencias
echo "[+] Instalando dependencias: $DEPENDENCIAS"
pip install $DEPENDENCIAS

# Crear requirements.txt (opcional)
echo "$DEPENDENCIAS" | tr ' ' '\n' > requirements.txt
echo "[+] Archivo 'requirements.txt' creado."

echo "[✓] Entorno listo. Para usarlo:"
echo "    source $VENV_DIR/bin/activate"
echo "    python main.py"
