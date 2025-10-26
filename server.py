# gopher2_server.py
import socket
import threading
import base64
import json
import os
import time
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# === CONFIGURACIÓN ===
HOST = "0.0.0.0"
PORT = 7070
AES_KEY = bytes.fromhex("88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff")  # 32 bytes
SELECTORS_FILE = "selectors.json"
MAX_SELECTOR_LEN = 255
MAX_CONTENT_LEN = 1024 * 1024  # 1 MB

# === CARGAR SELECTORES ===
def load_selectors():
    if not os.path.exists(SELECTORS_FILE):
        # Ejemplo inicial
        default = {
            "/": {
                "content": "Gopher 2.0\n<python>print(f'\\nHora del servidor: {time.strftime(\"%Y-%m-%d %H:%M:%S\")}')</python>",
                "vars": {"user": "anonymous", "hostname": "gopher2.local"}
            },
            "/test": {
                "content": "Selector de prueba\n<python>for i in range(3): print(f'Item {{i}}')</python>",
                "vars": {}
            }
        }
        with open(SELECTORS_FILE, "w") as f:
            json.dump(default, f, indent=2)
        return default
    with open(SELECTORS_FILE) as f:
        return json.load(f)

# === ENTORNO SEGURO PARA PYTHON ===
_SAFE_MODULES = {
    "time": __import__("time"),
    "math": __import__("math"),
    "datetime": __import__("datetime"),
    "json": __import__("json"),
}

def restricted_exec(code, context_vars):
    """
    Ejecuta código Python en entorno restringido.
    Devuelve la salida como string.
    """
    import io
    import sys
    from types import ModuleType

    # Variables permitidas (solo lectura)
    safe_globals = {
        "__builtins__": {
            "print": print,
            "len": len,
            "str": str,
            "int": int,
            "float": float,
            "range": range,
            "enumerate": enumerate,
            "zip": zip,
            "list": list,
            "dict": dict,
            "tuple": tuple,
            "set": set,
            "bool": bool,
            "None": None,
            "True": True,
            "False": False,
        }
    }
    safe_globals.update(_SAFE_MODULES)
    safe_globals.update(context_vars)

    # Capturar stdout
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()

    try:
        exec(code, safe_globals, {})
        output = captured_output.getvalue()
    except Exception as e:
        output = f"[Python Error: {e}]"
    finally:
        sys.stdout = old_stdout

    return output

# === RENDERIZAR SELECTOR ===
def render_selector(selector, selectors_db):
    if selector not in selectors_db:
        return f"Selector '{selector}' no encontrado"

    entry = selectors_db[selector]
    content = entry.get("content", "")
    vars_dict = entry.get("vars", {})

    if len(content) > MAX_CONTENT_LEN:
        return "[Error: contenido demasiado largo]"

    # Paso 1: Interpolar {{var}} → valor
    for key, value in vars_dict.items():
        content = content.replace(f"{{{{{key}}}}}", str(value))

    # Paso 2: Ejecutar bloques <python>...</python>
    final_parts = []
    i = 0
    while i < len(content):
        start = content.find("<python>", i)
        if start == -1:
            final_parts.append(content[i:])
            break
        end = content.find("</python>", start)
        if end == -1:
            final_parts.append(content[i:])
            break
        # Texto antes del bloque
        final_parts.append(content[i:start])
        # Código Python
        python_code = content[start + 8:end]
        output = restricted_exec(python_code, vars_dict)
        final_parts.append(output)
        i = end + 9

    return "".join(final_parts)

# === CIFRADO ===
def encrypt_response(plaintext: str) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()

# === MANEJAR CONEXIÓN ===
def handle_client(conn, addr, selectors_db):
    try:
        raw = conn.recv(1024)
        if not raw:
            return
        selector = raw.decode("ascii", errors="ignore").strip().rstrip("\r\n")
        if len(selector) > MAX_SELECTOR_LEN:
            selector = selector[:MAX_SELECTOR_LEN]

        logging.info(f"Petición de {addr}: '{selector}'")

        # Renderizar contenido
        try:
            plaintext = render_selector(selector, selectors_db)
        except Exception as e:
            plaintext = f"[Render Error: {e}]"

        # Cifrar
        try:
            b64_encrypted = encrypt_response(plaintext)
        except Exception as e:
            b64_encrypted = base64.b64encode(f"[Encrypt Error: {e}]".encode()).decode()

        # Formato Gopher: tipo 'i' (información)
        response = f"i{b64_encrypted}\terror.host\t1\r\n.\r\n"
        conn.sendall(response.encode("ascii"))
    except Exception as e:
        logging.error(f"Error en conexión: {e}")
    finally:
        conn.close()

# === SERVIDOR PRINCIPAL ===
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    selectors_db = load_selectors()
    logging.info(f"Selectores cargados: {list(selectors_db.keys())}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    logging.info(f"[*] Gopher 2.0 escuchando en gopher://0.0.0.0:{PORT}/")

    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr, selectors_db), daemon=True).start()
    except KeyboardInterrupt:
        logging.info("Servidor detenido.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
