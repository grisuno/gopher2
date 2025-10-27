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


def markdown_to_ansi(md_text: str) -> str:
    """
    Convierte un subconjunto seguro de Markdown a secuencias ANSI.
    Soporta: **negrita**, __negrita__, *cursiva*, _cursiva_,
             # Títulos, ## Subtítulos,
             - Listas, * Listas,
             > Bloques de cita.
    """
    if not isinstance(md_text, str):
        return ""

    # --- Paso 0: Escapar secuencias ANSI existentes ---
    import re
    def escape_ansi(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', text)
    text = escape_ansi(md_text)

    lines = text.split('\n')
    processed_lines = []
    in_blockquote = False

    for line in lines:
        original_line = line
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]

        # --- Bloques de cita ---
        if stripped.startswith('>'):
            in_blockquote = True
            content = stripped[1:].lstrip()
            processed_lines.append(f"{indent}\033[90m│ {content}\033[0m")
            continue
        else:
            if stripped == '' and in_blockquote:
                processed_lines.append(f"{indent}\033[90m│\033[0m")
            else:
                in_blockquote = False

        # --- Listas: - item, * item, + item ---
        list_match = re.match(r'^(\s*)([-*+])\s+(.+)$', line)
        if list_match:
            prefix, marker, content = list_match.groups()
            processed_lines.append(f"{prefix}• {content}")
            continue

        # --- Títulos ---
        title_match = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if title_match and indent == '':
            hashes, content = title_match.groups()
            level = len(hashes)
            if level <= 2:
                processed_lines.append(f"\n\033[1m{content}\033[0m\n")
            else:
                processed_lines.append(f"\033[1m{content}\033[0m")
            continue

        # Línea normal
        processed_lines.append(line)

    text = '\n'.join(processed_lines)

    # --- Énfasis: negrita y cursiva ---
    # Negrita: **...** o __...__
    text = re.sub(r'(\*\*|__)(.*?)\1', lambda m: f"\033[1m{m.group(2)}\033[0m", text)

    # Cursiva: *...* o _..._ (con límites de palabra para evitar falsos positivos)
    text = re.sub(r'(?<!\w)([*_])(.*?)\1(?!\w)', lambda m: f"\033[3m{m.group(2)}\033[0m", text)

    # --- Limpieza final ---
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text

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

def image_to_ansi(image_path: str, width: int = 50) -> str:
    """
    Convierte una imagen en una cadena de escape ANSI usando bloques ▀.
    Devuelve la representación como string, sin imprimir.
    """
    try:
        from PIL import Image
    except ImportError:
        return "[Error: Pillow no instalado. Imposible renderizar imagen.]"

    if not os.path.isfile(image_path):
        return f"[Error: archivo no encontrado: {image_path}]"

    if width < 1:
        width = 1
    if width > 200:  # Límite razonable para evitar DoS por ancho excesivo
        width = 200

    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
        orig_w, orig_h = img.size
        if orig_w == 0 or orig_h == 0:
            return "[Error: imagen vacía]"

        aspect_ratio = orig_h / orig_w
        new_width = width
        new_height = int(aspect_ratio * new_width * 0.5)
        if new_height < 2:
            new_height = 2

        img = img.resize((new_width, new_height))

        # Asegurar altura par
        if img.height % 2 == 1:
            img = img.crop((0, 0, img.width, img.height - 1))
            if img.height == 0:
                return "[Error: altura de imagen inválida tras ajuste]"

        lines = []
        for y in range(0, img.height, 2):
            line = ""
            for x in range(img.width):
                r1, g1, b1 = img.getpixel((x, y))
                r2, g2, b2 = img.getpixel((x, y + 1))
                # Asegurar valores en rango [0,255]
                r1, g1, b1 = max(0, min(255, r1)), max(0, min(255, g1)), max(0, min(255, b1))
                r2, g2, b2 = max(0, min(255, r2)), max(0, min(255, g2)), max(0, min(255, b2))
                line += f"\033[38;2;{r1};{g1};{b1};48;2;{r2};{g2};{b2}m▀\033[0m"
            lines.append(line)
        return "\n".join(lines)
    except Exception as e:
        return f"[Error al renderizar imagen: {e}]"


# === RENDERIZAR SELECTOR ===
def render_selector(selector, selectors_db):
    if selector not in selectors_db:
        return f"Selector '{selector}' no encontrado"

    entry = selectors_db[selector]
    content = entry.get("content", "")
    vars_dict = entry.get("vars", {})

    if len(content) > MAX_CONTENT_LEN:
        return "[Error: contenido demasiado largo]"

    # --- Paso 1: Interpolar {{var}} ---
    for key, value in vars_dict.items():
        content = content.replace(f"{{{{{key}}}}}", str(value))

    # --- Paso 2: Procesar <img> ---
    def is_safe_image_path(path: str) -> bool:
        if not path.startswith("/public/"):
            return False
        normalized = os.path.normpath(path)
        if not normalized.startswith("/public/") or ".." in normalized:
            return False
        if not normalized.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            return False
        return True

    parts_after_img = []
    i = 0
    while i < len(content):
        start = content.find("<img>", i)
        if start == -1:
            parts_after_img.append(content[i:])
            break
        end = content.find("</img>", start)
        if end == -1:
            parts_after_img.append(content[i:])
            break
        parts_after_img.append(content[i:start])
        img_path_raw = content[start + 5:end].strip()
        if not img_path_raw:
            parts_after_img.append("[Error: ruta de imagen vacía]")
        else:
            if is_safe_image_path(img_path_raw):
                system_path = img_path_raw.lstrip("/")
                if not os.path.isfile(system_path):
                    parts_after_img.append(f"[Error: archivo no encontrado: {system_path}]")
                else:
                    parts_after_img.append(image_to_ansi(system_path, width=50))
            else:
                parts_after_img.append("[Error: ruta de imagen no permitida]")
        i = end + 6

    content = "".join(parts_after_img)

    # --- Paso 3: Procesar <python> ---
    parts_after_python = []
    i = 0
    while i < len(content):
        start = content.find("<python>", i)
        if start == -1:
            parts_after_python.append(content[i:])
            break
        end = content.find("</python>", start)
        if end == -1:
            parts_after_python.append(content[i:])
            break
        parts_after_python.append(content[i:start])
        python_code = content[start + 8:end]
        output = restricted_exec(python_code, vars_dict)
        parts_after_python.append(output)
        i = end + 9

    content = "".join(parts_after_python)

    # --- Paso 4: Procesar <md> ---
    parts_after_md = []
    i = 0
    while i < len(content):
        start = content.find("<md>", i)
        if start == -1:
            parts_after_md.append(content[i:])
            break
        end = content.find("</md>", start)
        if end == -1:
            parts_after_md.append(content[i:])
            break
        parts_after_md.append(content[i:start])
        md_content = content[start + 4:end]
        parts_after_md.append(markdown_to_ansi(md_content))
        i = end + 5

    result = "".join(parts_after_md)

    # --- Verificación final de tamaño ---
    if len(result.encode('utf-8', errors='ignore')) > MAX_CONTENT_LEN:
        return "[Error: contenido renderizado excede 1 MB]"

    return result

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
