#!/bin/bash
# Instalación rápida de Volatility3 en /opt/volatility3 con símbolos (solo descarga y organiza el código oficial, sin instalar requirements.txt)

set -e

TMP_DIR="$HOME/volatility3"
FINAL_DIR="/opt/volatility3"
SYMBOLS_DIR="$FINAL_DIR/symbols"

echo "[*] Descargando Volatility3 oficial desde GitHub..."
git clone https://github.com/volatilityfoundation/volatility3.git "$TMP_DIR"

echo "[*] Creando directorio final en $FINAL_DIR..."
sudo mkdir -p "$FINAL_DIR"

echo "[*] Copiando archivos de Volatility3 a $FINAL_DIR..."
sudo cp -r "$TMP_DIR/"* "$FINAL_DIR/"

echo "[*] Descargando y extrayendo símbolos..."
sudo mkdir -p "$SYMBOLS_DIR"

declare -A SYMBOLS_URLS=(
    [windows]="https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
    [linux]="https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"
    [mac]="https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip"
)

for os in "${!SYMBOLS_URLS[@]}"; do
    ZIP_FILE="$SYMBOLS_DIR/${os}.zip"
    OS_DIR="$SYMBOLS_DIR/$os"
    echo "[*] Descargando símbolos de $os..."
    sudo wget -q "${SYMBOLS_URLS[$os]}" -O "$ZIP_FILE"
    sudo mkdir -p "$OS_DIR"
    echo "[*] Extrayendo símbolos de $os en $OS_DIR..."
    sudo unzip -q "$ZIP_FILE" -d "$OS_DIR"
    sudo rm "$ZIP_FILE"
done

echo "[*] Ajustando permisos en $FINAL_DIR..."
sudo chown -R $(whoami):$(whoami) "$FINAL_DIR"

echo
echo "[*] Volatility3 (código oficial) instalado en: $FINAL_DIR"
echo "[*] Símbolos extraídos en: $SYMBOLS_DIR"
echo "[*] Puedes ejecutar Volatility3 con: python3 $FINAL_DIR/vol.py"
echo "[*] ¡Listo para analizar memoria RAM!"

# Limpieza
rm -rf "$TMP_DIR"

exit 0

