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
MAX_SELECTOR_LEN = 512  # subido de 255: deja sitio a ?query de formularios
MAX_CONTENT_LEN = 1024 * 1024  # 1 MB
MAX_PYTHON_OUTPUT = 50 * 1024  # 50 KB
PYTHON_TIMEOUT = 30.0  # segundos

_SERVER_SESSION = SecureSession(load_server_key())

def markdown_to_ansi(md_text: str) -> str:
    """Markdown -> ANSI. Sabor web (titulares, links numerados, code, hr)
    sin JS ni trackers. Links [txt](/sel) se vuelven '[n] txt' + tabla al final."""
    if not isinstance(md_text, str):
        return ""
    import re
    def escape_ansi(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', text)
    text = escape_ansi(md_text)
    links: list[tuple[str, str]] = []
    def _link_repl(m):
        txt, url = m.group(1), m.group(2).strip()
        # Solo selectores internos o gopher:// mismo mundo. Nada de http tracking.
        if url.startswith(("http://", "https://", "//")) and not url.startswith("gopher://"):
            # Web externa: mostrar como texto, no seguir (anti-phishing/trackers)
            return f"\033[4m{txt}\033[0m \033[90m[externo bloqueado: {url[:60]}]\033[0m"
        links.append((txt, url))
        return f"\033[1;36m{txt}\033[0m\033[90m[{len(links)}]\033[0m"
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', _link_repl, text)
    lines = text.split('\n')
    processed_lines = []
    in_blockquote = False
    in_code = False
    for line in lines:
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        if stripped.startswith('```'):
            in_code = not in_code
            processed_lines.append(f"\033[90m{'─' * 40}\033[0m")
            continue
        if in_code:
            processed_lines.append(f"\033[97;40m{line}\033[0m")
            continue
        if re.match(r'^\s*(-{3,}|\*{3,}|_{3,})\s*$', line):
            processed_lines.append("\033[90m" + "─" * 50 + "\033[0m")
            continue
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
            processed_lines.append(f"{prefix}\033[33m•\033[0m {content}")
            continue
        title_match = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if title_match and indent == '':
            hashes, content = title_match.groups()
            level = len(hashes)
            colors = {1: "\033[1;96m", 2: "\033[1;95m", 3: "\033[1;93m"}
            c = colors.get(level, "\033[1m")
            if level <= 2:
                processed_lines.append(f"\n{c}{content}\033[0m\n\033[90m{'─' * len(content)}\033[0m")
            else:
                processed_lines.append(f"{c}{content}\033[0m")
            continue
        processed_lines.append(line)
    text = '\n'.join(processed_lines)
    text = re.sub(r'`([^`]+)`', lambda m: f"\033[7m{m.group(1)}\033[0m", text)
    text = re.sub(r'(\*\*|__)(.*?)\1', lambda m: f"\033[1m{m.group(2)}\033[0m", text)
    text = re.sub(r'(?<!\w)([*_])(.*?)\1(?!\w)', lambda m: f"\033[3m{m.group(2)}\033[0m", text)
    # <a href="/sel">txt</a> estilo web -> mismo formato numerado
    def _a_repl(m):
        url, txt = m.group(1).strip(), m.group(2).strip()
        if url.startswith(("http://", "https://")):
            return f"\033[4m{txt}\033[0m \033[90m[externo bloqueado]\033[0m"
        links.append((txt, url))
        return f"\033[1;36m{txt}\033[0m\033[90m[{len(links)}]\033[0m"
    text = re.sub(r'<a\s+href="([^"]+)">([^<]+)</a>', _a_repl, text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    if links:
        text += "\n\n\033[90m─ Links (escribe número o 'go N'): ─\033[0m\n"
        for i, (txt, url) in enumerate(links, 1):
            text += f"\033[90m[{i}]\033[0m \033[36m{txt}\033[0m → \033[90m{url}\033[0m\n"
        # Bloque máquina para que el cliente browse parseé sin adivinar
        text += "\x1fLINKS:" + "|".join(u for _, u in links) + "\x1f"
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

def image_to_ansi(image_path: str, width: int = 0) -> str:
    """Wrapper fino sobre image_renderer (rápido + GIF + caché).
    width=0 -> auto según terminal. Mantiene saneo estricto /public/."""
    try:
        import image_renderer as _ir
        return _ir.render_image(image_path, width=width or 0)
    except ImportError:
        pass
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        return "[Error: Pillow no instalado. Imposible renderizar imagen.]"
    # Fallback: si image_renderer.py no existe pero Pillow sí, error claro.
    return "[Error: image_renderer.py no encontrado]"

def parse_query(selector: str) -> tuple[str, dict]:
    """Parte '/base?nombre=Juan&edad=22' -> ('/base', {'nombre':'Juan',...}).
    Saneo anti-inyección: claves [a-zA-Z0-9_], máx 32 chars, valores máx 200."""
    import urllib.parse as _up
    import re as _re
    if "?" not in selector:
        return selector, {}
    base, _, qs = selector.partition("?")
    out: dict = {}
    try:
        for k, v in _up.parse_qsl(qs, keep_blank_values=True)[:20]:
            k = k.strip()[:32]
            if not _re.fullmatch(r"[A-Za-z0-9_]+", k):
                continue
            out[k] = v.strip()[:200]
    except Exception:
        pass
    return base, out


def sanitize_text(s: str, maxlen: int = 200) -> str:
    """Quita ANSI, saltos y control para guestbook/vars de usuario."""
    import re as _re
    s = _re.sub(r"\033\[[0-9;]*[a-zA-Z]", "", s)
    s = s.replace("\n", " ").replace("\r", " ").replace("\x1f", "").replace("\x1e", "")
    return s.strip()[:maxlen]


GUESTBOOK_FILE = "guestbook.json"
GUESTBOOK_MAX = 50

def guestbook_load() -> list:
    try:
        with open(GUESTBOOK_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def guestbook_add(nick: str, msg: str):
    nick, msg = sanitize_text(nick, 30) or "anon", sanitize_text(msg, 140)
    if not msg:
        return
    entries = guestbook_load()
    entries.append({"nick": nick, "msg": msg,
                    "ts": datetime.now().strftime("%Y-%m-%d %H:%M")})
    with open(GUESTBOOK_FILE, "w", encoding="utf-8") as f:
        json.dump(entries[-GUESTBOOK_MAX:], f, ensure_ascii=False, indent=1)


def render_form_block(action: str, inner: str) -> str:
    """Convierte <form action> + <input ...> en texto ANSI + bloque máquina
    \\x1fFORM:{json}\\x1f para que el cliente sepa qué pedir."""
    import re as _re
    import json as _json
    import html as _html
    action = action.strip() or "/"
    if not action.startswith(("/", "gopher://")):
        action = "/"
    fields = []
    for m in _re.finditer(
        r'<input\s+name="([^"]+)"(?:\s+prompt="([^"]*)")?(?:\s+default="([^"]*)")?\s*/?>',
        inner):
        name, prompt, default = m.group(1), m.group(2) or m.group(1), m.group(3) or ""
        name = sanitize_text(name, 32)
        import re as _re2
        if not _re2.fullmatch(r"[A-Za-z0-9_]+", name):
            continue
        fields.append({"name": name, "prompt": sanitize_text(prompt, 60) or name,
                       "default": sanitize_text(default, 60)})
    if not fields:  # <form> sin inputs con nombre válido
        return "\n\033[90m[form vacío → " + action + "]\033[0m"
    lines = [f"\n\033[1;33m✎ Form → {action}\033[0m"]
    for f in fields:
        hint = f" [{f['default']}]" if f["default"] else ""
        lines.append(f"  \033[90m•\033[0m \033[36m{f['name']}\033[0m: {f['prompt']}{hint}")
    lines.append(f"  \033[90mescribe:\033[0m \033[1msend {' '.join(f['name']+'=...' for f in fields)}\033[0m"
                 + (f"  o  \033[1msend {fields[0]['name']}=valor\033[0m" if len(fields) == 1 else ""))
    machine = "\x1fFORM:" + _json.dumps({"action": action, "fields": fields},
                                        ensure_ascii=False, separators=(",", ":")) + "\x1f"
    return "\n".join(lines) + machine


def render_selector(selector: str, selectors_db: dict, img_width: int = 0) -> str:
    # Query string estilo web (?a=1&b=2), sin cookies ni trackers
    base, query = parse_query(selector)
    selector = base
    if selector not in selectors_db:
        # === Página de error 404 estilizada + índice vivo ===
        known = sorted(k for k in selectors_db if not k.startswith("/anim/frame"))
        sugg = "\n".join(f"\033[90m║ • {k:<36} ║\033[0m" for k in known[:14])
        return (
            "\033[1;31m⚠️  ERROR 404\033[0m\n"
            "\033[90m╔════════════════════════════════════════╗\033[0m\n"
            "\033[90m║ Selector no encontrado                 ║\033[0m\n"
            f"\033[90m║ Solicitado: {selector[:28]:<28} ║\033[0m\n"
            "\033[90m║                                        ║\033[0m\n"
            "\033[90m║ ¿Quizás alguno de estos?              ║\033[0m\n"
            f"{sugg}\n"
            "\033[90m╚════════════════════════════════════════╝\033[0m"
        )

    entry = selectors_db[selector]
    content = entry.get("content", "")
    vars_dict = dict(entry.get("vars", {}))
    # Query del usuario (?nombre=Juan) gana sobre vars por defecto — sin cookies
    for k, v in query.items():
        vars_dict[k] = sanitize_text(v)

    # Guestbook persistente: /guestbook?nick=X&msg=Y guarda y lista
    if selector == "/guestbook" and ("nick" in query or "msg" in query):
        if query.get("msg", "").strip():
            guestbook_add(query.get("nick", "anon"), query.get("msg", ""))
    if selector == "/guestbook":
        gb = guestbook_load()[-10:]
        if gb:
            vars_dict["guestbook_list"] = "\n".join(
                f"• {e['nick']}: {e['msg']}  \033[90m({e['ts']})\033[0m" for e in gb)
        else:
            vars_dict["guestbook_list"] = "\033[90m(aún vacío — ¡firma primero!)\033[0m"

    if len(content) > MAX_CONTENT_LEN:
        return "[Error: contenido demasiado largo]"

    # === Paso 1: Procesar <img>...</img>, <img width=..>...</img> y <gif>...</gif> ===
    # <gif> = GIF animado multi-frame en una sola respuesta (cliente lo anima).
    # <img width=80> = ancho explícito; sin width = auto (terminal servidor, clamp 20..160).
    import re as _re
    def _render_img_block(block: str) -> str:
        block = block.strip()
        if not block:
            return "[Error: ruta de imagen vacía]"
        try:
            import image_renderer as _ir
            path, w = _ir.parse_img_tag(block, default_width=img_width)
            return _ir.render_image(path, width=w)
        except ImportError:
            return image_to_ansi(block.strip().split()[0], width=0)
    # <img ...> con o sin atributos: <img>path</img> o <img width=80>path</img>
    content = _re.sub(r'<img(?:\s+width\s*=\s*(\d{1,3}))?\s*>(.*?)</img>',
                      lambda m: _render_img_block(
                          (f"width={m.group(1)} " if m.group(1) else "") + m.group(2).strip()
                      ), content, flags=_re.DOTALL)
    # <gif>path</gif> o <gif width=80>path</gif> — fuerza max_frames=24
    def _render_gif_block(m):
        inner = ((f"width={m.group(1)} " if m.group(1) else "") + m.group(2).strip()).strip()
        if not inner:
            return "[Error: ruta GIF vacía]"
        try:
            import image_renderer as _ir
            path, w = _ir.parse_img_tag(inner, default_width=img_width)
            return _ir.render_image(path, width=w, max_frames=24)
        except ImportError:
            return image_to_ansi(inner.split()[0], width=0)
    content = _re.sub(r'<gif(?:\s+width\s*=\s*(\d{1,3}))?\s*>(.*?)</gif>',
                      _render_gif_block, content, flags=_re.DOTALL)

    # === Paso 1b: Formularios estilo web <form action="/x"><input name=...></form> ===
    # Sin JS ni cookies: el cliente hace `send campo=valor` -> GET /x?campo=valor
    content = _re.sub(r'<form\s+action="([^"]+)"\s*>(.*?)</form>',
                      lambda m: render_form_block(m.group(1), m.group(2)),
                      content, flags=_re.DOTALL)
    # <input> suelto = auto-form hacia el propio selector
    def _solo_input(m):
        tag = m.group(0)
        return render_form_block(selector, tag)
    content = _re.sub(r'<input\s+name="[^"]+"(?:\s+prompt="[^"]*")?(?:\s+default="[^"]*")?\s*/?>',
                      _solo_input, content)

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

        # Ancho terminal del cliente: "selector\x1fW=120" (compatible: viejos lo ven como 404)
        img_width = 0
        if "\x1fW=" in selector:
            sel_part, _, w_part = selector.partition("\x1fW=")
            try:
                img_width = max(20, min(160, int(''.join(c for c in w_part[:4] if c.isdigit()) or 0)))
            except ValueError:
                img_width = 0
            selector = sel_part.strip() or "/"

        if len(selector) > MAX_SELECTOR_LEN:
            selector = selector[:MAX_SELECTOR_LEN]

        logging.info(f"Petición de {addr}: '{selector}' (w={img_width or 'auto'})")

        try:
            plaintext = render_selector(selector, selectors_db, img_width=img_width)
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
