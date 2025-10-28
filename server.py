# server.py
import socket
import threading
import json
import os
import time
import logging
import io
import sys
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import signal

# === Cargar módulo de widgets ANSI ===
try:
    import ansi_widgets
    _ANSI_WIDGETS_AVAILABLE = True
except ImportError:
    _ANSI_WIDGETS_AVAILABLE = False

class SecureSession:
    INFO = b"gopher2_key_derivation"  # RFC 5869
    AES_KEY_LEN = 32

    def __init__(self, private_key=None):
        if private_key is None:
            self._private_key = x25519.X25519PrivateKey.generate()
        else:
            self._private_key = private_key
        self._aesgcm = None

    def get_public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive_shared_key(self, peer_public_key_bytes: bytes):
        if len(peer_public_key_bytes) != 32:
            raise ValueError("Clave pública debe ser 32 bytes (X25519)")
        try:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
            shared_secret = self._private_key.exchange(peer_public)
        except Exception as e:
            raise ValueError(f"Fallo en ECDH: {e}")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_LEN,
            salt=None,
            info=self.INFO,
        )
        aes_key = hkdf.derive(shared_secret)
        self._aesgcm = AESGCM(aes_key)

    def encrypt(self, plaintext: str) -> bytes:
        if self._aesgcm is None:
            raise RuntimeError("Clave compartida no derivada")
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = os.urandom(12)
        return nonce + self._aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> str:
        if self._aesgcm is None:
            raise RuntimeError("Clave compartida no derivada")
        if len(data) < 28:
            raise ValueError("Datos cifrados demasiado cortos")
        nonce, ciphertext = data[:12], data[12:]
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8", errors="replace")
        except Exception as e:
            raise ValueError(f"Fallo de autenticación o descifrado: {e}")

def load_server_key():
    key_path = "server_x25519_key.bin"
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return x25519.X25519PrivateKey.from_private_bytes(f.read())
    else:
        private_key = x25519.X25519PrivateKey.generate()
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return private_key

# === CONFIGURACIÓN ===
HOST = "0.0.0.0"
PORT = 7070
SELECTORS_FILE = "selectors.json"
MAX_SELECTOR_LEN = 255
MAX_CONTENT_LEN = 1024 * 1024  # 1 MB
MAX_PYTHON_OUTPUT = 50 * 1024  # 50 KB
PYTHON_TIMEOUT = 30.0  # segundos

_SERVER_SESSION = SecureSession(load_server_key())

def markdown_to_ansi(md_text: str) -> str:
    if not isinstance(md_text, str):
        return ""
    import re
    def escape_ansi(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', text)
    text = escape_ansi(md_text)
    lines = text.split('\n')
    processed_lines = []
    in_blockquote = False
    for line in lines:
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
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
        list_match = re.match(r'^(\s*)([-*+])\s+(.+)$', line)
        if list_match:
            prefix, marker, content = list_match.groups()
            processed_lines.append(f"{prefix}• {content}")
            continue
        title_match = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if title_match and indent == '':
            hashes, content = title_match.groups()
            level = len(hashes)
            if level <= 2:
                processed_lines.append(f"\n\033[1m{content}\033[0m\n")
            else:
                processed_lines.append(f"\033[1m{content}\033[0m")
            continue
        processed_lines.append(line)
    text = '\n'.join(processed_lines)
    text = re.sub(r'(\*\*|__)(.*?)\1', lambda m: f"\033[1m{m.group(2)}\033[0m", text)
    text = re.sub(r'(?<!\w)([*_])(.*?)\1(?!\w)', lambda m: f"\033[3m{m.group(2)}\033[0m", text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text

def load_selectors():
    if not os.path.exists(SELECTORS_FILE):
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

# === ENTORNO SEGURO PARA PYTHON CON LÍMITES ===
_SAFE_MODULES = {
    "time": __import__("time"),
    "math": __import__("math"),
    "datetime": __import__("datetime"),
    "json": __import__("json"),
}
if _ANSI_WIDGETS_AVAILABLE:
    _SAFE_MODULES["ansi_widgets"] = ansi_widgets

def safe_print(*args, **kwargs):
    print(*args, **kwargs)


def restricted_exec(code: str, context_vars: dict) -> str:
    import io, sys, threading
    safe_globals = {
        "__builtins__": {
            "print": safe_print,
            "round": round,
            "min": min,
            "max": max,
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
            "__import__": __import__,
        }
    }
    safe_globals.update(_SAFE_MODULES)
    safe_globals.update(context_vars)

    old_stdout = sys.stdout
    captured_output = io.StringIO()
    sys.stdout = captured_output
    result = [None]

    def target():
        try:
            exec(code, safe_globals, {})
            result[0] = captured_output.getvalue()
        except Exception as e:
            result[0] = f"[Python Error: {e}]"

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout=PYTHON_TIMEOUT)

    sys.stdout = old_stdout

    if thread.is_alive():
        # No se puede matar el hilo en Python puro, pero al menos limitamos la salida
        return "[Error: tiempo de ejecución excedido (1s)]"

    output = result[0] or ""
    if len(output.encode('utf-8', errors='ignore')) > MAX_PYTHON_OUTPUT:
        return "[Error: salida de Python excede 50 KB]"

    return output

def image_to_ansi(image_path: str, width: int = 50) -> str:
    try:
        from PIL import Image
    except ImportError:
        return "[Error: Pillow no instalado. Imposible renderizar imagen.]"
    
    if width < 1:
        width = 1
    if width > 200:
        width = 200

    # Validar que la ruta comience exactamente con "/public/"
    if not image_path.startswith("/public/"):
        return "[Error: ruta debe comenzar con /public/]"

    # Extraer la parte relativa
    rel_part = image_path[8:]  # "/public/".length == 8

    # Rechazar si hay componentes vacíos o peligrosos
    if not rel_part or ".." in rel_part or rel_part.startswith("/") or "//" in rel_part:
        return "[Error: ruta no permitida]"

    # Validar extensión
    if not rel_part.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        return "[Error: formato no soportado]"

    # Construir ruta segura
    base_dir = os.path.abspath("public")
    full_path = os.path.abspath(os.path.join(base_dir, rel_part))

    # Verificar que la ruta final esté dentro de "public/"
    if not full_path.startswith(base_dir + os.sep) and full_path != base_dir:
        return "[Error: ruta fuera de public/]"

    if not os.path.isfile(full_path):
        return f"[Error: archivo no encontrado: {full_path}]"

    try:
        img = Image.open(full_path)
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
        if img.height % 2 == 1:
            img = img.crop((0, 0, img.width, img.height - 1))
            if img.height == 0:
                return "[Error: altura inválida]"
        lines = []
        for y in range(0, img.height, 2):
            line = ""
            for x in range(img.width):
                r1, g1, b1 = img.getpixel((x, y))
                r2, g2, b2 = img.getpixel((x, y + 1))
                r1, g1, b1 = max(0, min(255, r1)), max(0, min(255, g1)), max(0, min(255, b1))
                r2, g2, b2 = max(0, min(255, r2)), max(0, min(255, g2)), max(0, min(255, b2))
                line += f"\033[38;2;{r1};{g1};{b1};48;2;{r2};{g2};{b2}m▀\033[0m"
            lines.append(line)
        return "\n".join(lines)
    except Exception as e:
        return f"[Error al renderizar imagen: {e}]"

def render_selector(selector: str, selectors_db: dict) -> str:
    if selector not in selectors_db:
        # === Página de error 404 estilizada ===
        error_content = (
            "\033[1;31m⚠️  ERROR 404\033[0m\n"
            "\033[90m╔══════════════════════════════════════╗\033[0m\n"
            "\033[90m║ Selector no encontrado                ║\033[0m\n"
            f"\033[90m║ Solicitado: {selector:<30} ║\033[0m\n"
            "\033[90m║                                      ║\033[0m\n"
            "\033[90m║ ¿Quizás alguno de estos?             ║\033[0m\n"
            "\033[90m║ • /                                  ║\033[0m\n"
            "\033[90m║ • /about                             ║\033[0m\n"
            "\033[90m║ • /docs                              ║\033[0m\n"
            "\033[90m╚══════════════════════════════════════╝\033[0m"
        )
        return error_content

    entry = selectors_db[selector]
    content = entry.get("content", "")
    vars_dict = entry.get("vars", {})

    if len(content) > MAX_CONTENT_LEN:
        return "[Error: contenido demasiado largo]"

    # === Paso 1: Procesar <img> ===
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
            parts_after_img.append(image_to_ansi(img_path_raw, width=100))
        i = end + 6
    content = "".join(parts_after_img)

    # === Paso 2: Procesar <python> ===
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

    # === Paso 3: Interpolar {{var}} ===
    for key, value in vars_dict.items():
        content = content.replace(f"{{{{{key}}}}}", str(value))

    # === Paso 4: Procesar <md> ===
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

    if len(result.encode('utf-8', errors='ignore')) > MAX_CONTENT_LEN:
        return "[Error: contenido renderizado excede 1 MB]"

    return result

def handle_client(conn, addr, selectors_db):
    try:
        client_pubkey = conn.recv(32)
        if len(client_pubkey) != 32:
            conn.close()
            return

        session = SecureSession(load_server_key())
        try:
            session.derive_shared_key(client_pubkey)
        except Exception as e:
            logging.error(f"ECDH fallido con {addr}: {e}")
            conn.close()
            return

        server_pubkey = session.get_public_key_bytes()
        conn.sendall(server_pubkey)

        raw_enc = conn.recv(4096)
        if not raw_enc:
            return
        try:
            selector = session.decrypt(raw_enc).strip()
        except Exception as e:
            logging.error(f"Descifrado de selector fallido: {e}")
            return

        if len(selector) > MAX_SELECTOR_LEN:
            selector = selector[:MAX_SELECTOR_LEN]

        logging.info(f"Petición de {addr}: '{selector}'")

        try:
            plaintext = render_selector(selector, selectors_db)
        except Exception as e:
            plaintext = f"[Render Error: {e}]"

        try:
            encrypted_response = session.encrypt(plaintext)
            conn.sendall(len(encrypted_response).to_bytes(4, 'big'))
            conn.sendall(encrypted_response)
        except Exception as e:
            logging.error(f"Cifrado de respuesta fallido: {e}")

    except Exception as e:
        logging.error(f"Error en conexión: {e}")
    finally:
        conn.close()

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
