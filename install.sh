#!/usr/bin/env bash
# install.sh - Instalador para Gopher 2.0 (servidor y cliente)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

log() {
    echo "[*] $1" >&2
}

error() {
    echo "[!] $1" >&2
    exit 1
}

# === Validación de requisitos ===
log "Verificando requisitos..."

if ! command -v python3 &>/dev/null; then
    error "python3 no encontrado. Instala Python 3.8+"
fi

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
    error "Se requiere Python 3.8 o superior"
fi

if ! command -v pip3 &>/dev/null; then
    error "pip3 no encontrado. Instala python3-pip"
fi

# === Crear entorno virtual ===
if [ ! -d "${VENV_DIR}" ]; then
    log "Creando entorno virtual en ${VENV_DIR}..."
    python3 -m venv "${VENV_DIR}"
fi

# === Activar y actualizar pip ===
log "Activando entorno virtual..."
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

log "Actualizando pip..."
python3 -m pip install --upgrade pip

# === Instalar dependencias ===
log "Instalando dependencias desde requirements.txt..."
if [ ! -f "${SCRIPT_DIR}/requirements.txt" ]; then
    error "requirements.txt no encontrado"
fi
python3 -m pip install -r "${SCRIPT_DIR}/requirements.txt"

# === Crear archivos por defecto ===
if [ ! -f "${SCRIPT_DIR}/selectors.json" ]; then
    log "Creando selectors.json de ejemplo..."
    cat > "${SCRIPT_DIR}/selectors.json" <<EOF
{
  "/": {
    "content": "Gopher 2.0\\n<python>print(f'\\\\nHora del servidor: {time.strftime(\\\"%Y-%m-%d %H:%M:%S\\\")}')</python>",
    "vars": {}
  },
  "/test": {
    "content": "Selector de prueba\\n<python>for i in range(3): print(f'Item {i}')</python>",
    "vars": {}
  }
}
EOF
fi

# === Permisos ===
chmod +x "${SCRIPT_DIR}/gopher2_server.py" "${SCRIPT_DIR}/gopher2_client.py" 2>/dev/null || true

log "✅ Instalación completada."
log "Ejecuta el servidor con: ./.venv/bin/python gopher2_server.py"
log "Ejecuta el cliente con:  ./.venv/bin/python gopher2_client.py gopher://127.0.0.1:7070/"
