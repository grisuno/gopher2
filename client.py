#!/usr/bin/env python3
# client.py
import socket
import sys
import base64
import argparse
import logging
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import time
# === Clase SecureSession: ECDH + HKDF para clave AES ===
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os, sys

# === CONFIGURACIÓN ===
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_SELECTOR_LEN = 512  # igual que servidor: formularios con ?query

class SecureSession:
    """
    Negocia una clave AES efímera mediante ECDH (X25519) y HKDF.
    Proporciona métodos para cifrar/descifrar.
    """
    INFO = b"gopher2_key_derivation"
    AES_KEY_LEN = 32  # 256 bits

    def __init__(self):
        # Generar par de claves efímero
        self._private_key = x25519.X25519PrivateKey.generate()
        self._shared_key = None
        self._aesgcm = None

    def get_public_key_fingerprint(self) -> str:
        """Devuelve la huella SHA256 de la clave pública en formato legible."""
        pub_bytes = self.get_public_key_bytes()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pub_bytes)
        fingerprint = digest.finalize()
        # Formato: 00:11:22:... (como SSH)
        return ":".join(f"{b:02x}" for b in fingerprint)

    def get_public_key_bytes(self) -> bytes:
        """Devuelve la clave pública serializada (32 bytes)."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive_shared_key(self, peer_public_key_bytes: bytes):
        """Deriva la clave compartida usando ECDH + HKDF."""
        if len(peer_public_key_bytes) != 32:
            raise ValueError("Clave pública debe ser 32 bytes (X25519)")

        try:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
            shared_secret = self._private_key.exchange(peer_public)
        except Exception as e:
            raise ValueError(f"Fallo en ECDH: {e}")

        # Derivar clave AES con HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_LEN,
            salt=None,
            info=self.INFO,
        )
        aes_key = hkdf.derive(shared_secret)
        self._aesgcm = AESGCM(aes_key)

    def encrypt(self, plaintext: str) -> bytes:
        """Cifra texto plano → nonce (12) + ciphertext + tag (16)."""
        if self._aesgcm is None:
            raise RuntimeError("Clave compartida no derivada")
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> str:
        """Descifra nonce + ciphertext → texto plano."""
        if self._aesgcm is None:
            raise RuntimeError("Clave compartida no derivada")
        if len(data) < 28:  # 12 (nonce) + 16 (tag) mínimo
            raise ValueError("Datos cifrados demasiado cortos")
        nonce = data[:12]
        ciphertext = data[12:]
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8", errors="replace")
        except Exception as e:
            raise ValueError(f"Fallo de autenticación o descifrado: {e}")



def decrypt_response(b64_data: str) -> str:
    try:
        data = base64.b64decode(b64_data)
        if len(data) < 12 + 16:  # nonce (12) + tag (16) mínimo
            raise ValueError("Datos cifrados demasiado cortos")
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(AES_KEY)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8", errors="replace")
    except InvalidTag:
        raise ValueError("Fallo de autenticación: clave incorrecta o datos corruptos")
    except Exception as e:
        raise ValueError(f"Error al descifrar: {e}")


def get_known_hosts_path() -> str:
    home = os.path.expanduser("~")
    return os.path.join(home, ".gopher2", "known_hosts")

def save_server_fingerprint(host: str, port: int, fingerprint: str):
    os.makedirs(os.path.dirname(get_known_hosts_path()), exist_ok=True)
    with open(get_known_hosts_path(), "a") as f:
        f.write(f"{host}:{port} {fingerprint}\n")

def get_saved_fingerprint(host: str, port: int) -> str | None:
    try:
        with open(get_known_hosts_path()) as f:
            for line in f:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    saved_addr, saved_fp = parts
                    if saved_addr == f"{host}:{port}":
                        return saved_fp
    except FileNotFoundError:
        return None
    return None
    
def _term_width(default: int = 80) -> int:
    try:
        import shutil
        return max(20, min(160, shutil.get_terminal_size(fallback=(default, 24)).columns))
    except Exception:
        return default


def fetch_gopher2(url: str) -> tuple[str, str, int, SecureSession]:
    """
    Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.
    Envía ancho del terminal (\\x1fW=NN) para render responsive en servidor.
    """
    parsed = urlparse(url)
    if parsed.scheme != "gopher":
        raise ValueError("Solo se admite gopher://")
    
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 7070
    selector = parsed.path or "/"
    if parsed.query:  # formularios: /hola?nombre=Neo (sin cookies)
        selector += "?" + parsed.query

    if len(selector) > MAX_SELECTOR_LEN:
        raise ValueError(f"Selector demasiado largo (> {MAX_SELECTOR_LEN} bytes)")

    with socket.create_connection((host, port), timeout=10) as sock:
        client_session = SecureSession()
        sock.sendall(client_session.get_public_key_bytes())

        server_pubkey = sock.recv(32)
        if len(server_pubkey) != 32:
            raise ValueError("Clave pública del servidor inválida")

        client_session.derive_shared_key(server_pubkey)

        # TOFU: verificar huella
        digest = hashes.Hash(hashes.SHA256())
        digest.update(server_pubkey)
        current_fingerprint = ":".join(f"{b:02x}" for b in digest.finalize())
        saved_fingerprint = get_saved_fingerprint(host, port)

        if saved_fingerprint is None:
            print(f"Advertencia: clave del servidor no conocida.", file=sys.stderr)
            print(f"Huella: {current_fingerprint}", file=sys.stderr)
            print("¿Confiar en este servidor? (s/N): ", end="", file=sys.stderr)
            if input().lower() != 's':
                raise RuntimeError("Conexión abortada por el usuario")
            save_server_fingerprint(host, port, current_fingerprint)
        elif saved_fingerprint != current_fingerprint:
            raise RuntimeError(
                f"¡ALERTA DE SEGURIDAD!\n"
                f"La huella del servidor ha cambiado.\n"
                f"Guardada: {saved_fingerprint}\n"
                f"Actual:  {current_fingerprint}\n"
                f"Posible ataque MITM."
            )

        encrypted_selector = client_session.encrypt(f"{selector}\x1fW={_term_width()}")
        sock.sendall(encrypted_selector)

        len_bytes = sock.recv(4)
        if len(len_bytes) != 4:
            raise ValueError("No se recibió longitud de respuesta")
        response_len = int.from_bytes(len_bytes, 'big')
        if response_len > MAX_RESPONSE_SIZE:
            raise ValueError("Respuesta demasiado grande")

        response_data = b""
        while len(response_data) < response_len:
            chunk = sock.recv(min(4096, response_len - len(response_data)))
            if not chunk:
                break
            response_data += chunk

        if len(response_data) != response_len:
            raise ValueError("Respuesta incompleta")

        content = client_session.decrypt(response_data)
        return content, host, port, client_session

def play_animation_if_needed(base_selector: str, host: str, port: int, session: SecureSession):
    """
    Reproduce animación si base_selector == '/anim'.
    Se detiene al primer frame inexistente (detectado por contenido de error 404).
    Redibujado robusto: home-cursor + clear-down (sin `clear` ni trucos de
    borrado de 1 línea que se desalinean si un frame trae \\n de más/menos).
    """
    base_selector = base_selector.split("?", 1)[0]
    if base_selector.rstrip('/') != '/anim':
        return False

    print("\033[90mIniciando animación...\033[0m", file=sys.stderr)
    frame_count = 0
    delay = 0.15
    print("\033[?25l", end="", flush=True)  # ocultar cursor durante la animación

    try:
        for i in range(100):  # límite de seguridad
            frame_selector = f"/anim/frame{i:02d}"
            print(f"\r\033[90mCargando {frame_selector}...\033[0m",
                  end="", file=sys.stderr, flush=True)

            try:
                # Nueva conexión segura para este frame
                with socket.create_connection((host, port), timeout=5) as sock2:
                    new_session = SecureSession()
                    sock2.sendall(new_session.get_public_key_bytes())

                    server_pubkey = sock2.recv(32)
                    if len(server_pubkey) != 32:
                        raise ValueError("Clave pública del servidor inválida")

                    # Verificar huella (TOFU)
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(server_pubkey)
                    current_fingerprint = ":".join(f"{b:02x}" for b in digest.finalize())
                    saved_fingerprint = get_saved_fingerprint(host, port)
                    if saved_fingerprint != current_fingerprint:
                        raise RuntimeError("Huella del servidor cambió durante animación")

                    new_session.derive_shared_key(server_pubkey)
                    encrypted_selector = new_session.encrypt(frame_selector)
                    sock2.sendall(encrypted_selector)

                    # Recibir respuesta
                    len_bytes = sock2.recv(4)
                    if len(len_bytes) != 4:
                        raise ValueError("No se recibió longitud")
                    response_len = int.from_bytes(len_bytes, 'big')
                    if response_len > MAX_RESPONSE_SIZE:
                        raise ValueError("Respuesta demasiado grande")

                    response_data = b""
                    while len(response_data) < response_len:
                        chunk = sock2.recv(min(4096, response_len - len(response_data)))
                        if not chunk:
                            break
                        response_data += chunk

                    if len(response_data) != response_len:
                        raise ValueError("Respuesta incompleta")

                    content = new_session.decrypt(response_data)

                    # 🔍 DETECCIÓN DE ERROR 404
                    if "ERROR 404" in content or "Selector no encontrado" in content:
                        if i == 0:
                            print(f"\033[91mError: primer frame no disponible.\033[0m", file=sys.stderr)
                            return False
                        else:
                            # Fin natural: no hay más frames
                            time.sleep(0.3)
                            break

                    # Mostrar frame válido (normalizado: sin \n final colgando,
                    # primer frame limpia pantalla, resto reusa con \033[H + \033[J)
                    frame = content.rstrip("\n")
                    if frame_count == 0:
                        sys.stdout.write("\033[2J\033[H" + frame + "\033[J")
                    else:
                        sys.stdout.write("\033[H" + frame + "\033[J")
                    sys.stdout.flush()
                    frame_count += 1

            except (ValueError, RuntimeError, socket.timeout, ConnectionRefusedError, OSError) as e:
                if i == 0:
                    print(f"\n\033[91mError crítico al cargar el primer frame: {e}\033[0m", file=sys.stderr)
                    return False
                else:
                    time.sleep(0.3)
                    break
            except KeyboardInterrupt:
                print("\n\033[90mAnimación interrumpida.\033[0m", file=sys.stderr)
                return True

            time.sleep(delay)
    finally:
        print("\033[?25h", end="", flush=True)  # restaurar cursor siempre

    print(f"\n\033[92m✅ Animación completada ({frame_count} frames).\033[0m", file=sys.stderr)
    return True
    
FRAME_SEP = "\x1eFRAME\x1e"
DUR_PREFIX = "\x1eDUR:"

def extract_links(content: str) -> tuple[str, list[str]]:
    """Separa bloque máquina \x1fLINKS:a|b\x1f -> (texto limpio, [urls])."""
    links: list[str] = []
    if "\x1fLINKS:" in content:
        pre, _, rest = content.partition("\x1fLINKS:")
        urls, _, post = rest.partition("\x1f")
        links = [u for u in urls.split("|") if u]
        content = pre + post
    return content, links

def extract_forms(content: str) -> tuple[str, list[dict]]:
    """Separa bloques \x1fFORM:{json}\x1f -> (texto limpio, [forms]).
    Formato servidor: {"action": "/hola", "fields": [{"name","prompt","default"}]}."""
    import json as _json
    forms: list[dict] = []
    while "\x1fFORM:" in content:
        pre, _, rest = content.partition("\x1fFORM:")
        payload, _, post = rest.partition("\x1f")
        try:
            f = _json.loads(payload)
            if isinstance(f, dict) and f.get("action") and f.get("fields"):
                forms.append(f)
        except Exception:
            pass
        content = pre + post
    return content, forms

def build_query(action: str, answers: dict) -> str:
    """action + dict -> '/base?k=v&...' con quote. Sin cookies."""
    import urllib.parse as _up
    base, _, existing = action.partition("?")
    qs = _up.urlencode({k: str(v)[:200] for k, v in answers.items()})
    if existing:
        qs = existing + ("&" + qs if qs else "")
    return base + ("?" + qs if qs else "")

def display_content(content: str) -> tuple[list[str], list[dict]]:
    """Muestra contenido. GIF multi-frame se anima. Devuelve (links, forms)."""
    frames, dur_ms = None, 120
    if FRAME_SEP in content or content.startswith(DUR_PREFIX):
        try:
            import image_renderer as _ir
            frames, dur_ms = _ir.split_animation(content)
        except ImportError:
            # Fallback mínimo sin el módulo
            dur_ms = 120
            if content.startswith(DUR_PREFIX):
                head, _, rest = content.partition("\x1e")
                content = rest
            frames = content.split(FRAME_SEP) if FRAME_SEP in content else [content]
    if frames and len(frames) > 1:
        delay = max(0.04, min(2.0, dur_ms / 1000.0))
        print("\033[?25l", end="", flush=True)
        try:
            # Redibujado con home-cursor: tolera frames con distinto alto y
            # con/sin \n final (esa era la "línea que se saltaba").
            sys.stdout.write("\033[2J\033[H" + frames[0].rstrip("\n") + "\033[J")
            sys.stdout.flush()
            while True:
                for f in frames[1:] + frames[:1]:
                    time.sleep(delay)
                    sys.stdout.write("\033[H" + f.rstrip("\n") + "\033[J")
                    sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n\033[90m[GIF detenido — Ctrl+C]\033[0m")
            txt, links = extract_links("".join(frames[:1]))
            _, forms = extract_forms(txt)
            return links, forms
        finally:
            print("\033[?25h", end="", flush=True)
        return [], []
    content, links = extract_links(content)
    content, forms = extract_forms(content)
    print(content, end="" if content.endswith("\n") else "\n")
    return links, forms

def _navigate(dest: str, host0: str, port0: int, history: list[str], idx: int) -> tuple[list[str], int, str, int]:
    """Resuelve link (interno o gopher://) -> (history, idx, host, port)."""
    if dest.startswith("gopher://"):
        p = urlparse(dest)
        host0 = p.hostname or host0
        port0 = p.port or port0
        dest = (p.path or "/") + (("?" + p.query) if p.query else "")
    history = history[:idx + 1] + [dest]
    return history, idx + 1, host0, port0

def _submit_form(form: dict) -> dict:
    """Pregunta campo por campo en terminal. Enter = default. Sin eco de red extra."""
    answers: dict = {}
    for f in form.get("fields", []):
        name = f.get("name", "?")
        prompt = f.get("prompt", name)
        default = f.get("default", "")
        hint = f" [{default}]" if default else ""
        try:
            val = input(f"\033[33m{prompt}{hint}:\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        answers[name] = val if val else default
    return answers

def browse(start_url: str):
    """Modo navegador WWW (sin trackers): historial back/forward, go N, reload.
    Formularios con `send` / `fill`. Sin cookies, sin JS, sin referer."""
    parsed0 = urlparse(start_url)
    host0, port0 = parsed0.hostname or "127.0.0.1", parsed0.port or 7070
    sel0 = (parsed0.path or "/") + (("?" + parsed0.query) if parsed0.query else "")
    history: list[str] = [sel0]
    idx = 0
    links: list[str] = []
    forms: list[dict] = []
    while True:
        sel = history[idx]
        base_sel = sel.split("?", 1)[0]
        url = f"gopher://{host0}:{port0}{sel}"
        print(f"\033[90m── gopher2 ⌁ {url} ──\033[0m")
        try:
            content, host, port, session = fetch_gopher2(url)
            # Flipbook clásico /anim/* sigue funcionando (ignora ?query)
            if play_animation_if_needed(base_sel, host, port, session):
                links, forms = [], []
            else:
                links, forms = display_content(content)
        except Exception as e:
            print(f"\033[91mError: {e}\033[0m")
            links, forms = [], []
        hint = "\033[90m[back|fwd|reload|go N|/selector|q"
        if forms:
            hint += "|fill|send ...]"
        else:
            hint += "]"
        print(hint + "\033[0m")
        try:
            cmd = input(f"\033[1;36mgopher2:{sel}>\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\033[90mbye\033[0m")
            break
        if cmd in ("q", "quit", "exit"):
            break
        elif cmd in ("b", "back"):
            if idx > 0:
                idx -= 1
            else:
                print("\033[90m(sin atrás)\033[0m")
        elif cmd in ("f", "fwd", "forward"):
            if idx < len(history) - 1:
                idx += 1
            else:
                print("\033[90m(sin adelante)\033[0m")
        elif cmd in ("r", "reload"):
            continue
        elif cmd.startswith("go "):
            try:
                n = int(cmd[3:].strip()) - 1
                if 0 <= n < len(links):
                    history, idx, host0, port0 = _navigate(links[n], host0, port0, history, idx)
                else:
                    print("\033[91mLink fuera de rango\033[0m")
            except ValueError:
                print("\033[91mUso: go N\033[0m")
        elif cmd.isdigit():
            n = int(cmd) - 1
            if 0 <= n < len(links):
                history, idx, host0, port0 = _navigate(links[n], host0, port0, history, idx)
            else:
                print("\033[91mLink fuera de rango\033[0m")
        elif cmd in ("fill", "form", "send") and forms:
            # Interactivo campo por campo contra el primer form
            answers = _submit_form(forms[0])
            dest = build_query(forms[0]["action"], answers)
            history, idx, host0, port0 = _navigate(dest, host0, port0, history, idx)
        elif cmd.startswith("send") and forms:
            # `send Juan` (1 campo) o `send nombre=Juan, ciudad=X`
            rest = cmd[4:].strip()
            form = forms[0]
            fields = [f["name"] for f in form.get("fields", [])]
            answers: dict = {}
            if not rest:
                answers = _submit_form(form)
            elif "=" not in rest and len(fields) == 1:
                answers = {fields[0]: rest}
            else:
                import re as _re
                for part in _re.split(r"[,&;]+", rest):
                    if "=" in part:
                        k, _, v = part.partition("=")
                        answers[k.strip()] = v.strip()
            if answers:
                dest = build_query(form["action"], answers)
                history, idx, host0, port0 = _navigate(dest, host0, port0, history, idx)
            else:
                print("\033[91mUso: send nombre=valor | send Valor (1 campo) | fill\033[0m")
        elif cmd.startswith("/"):
            history = history[:idx + 1] + [cmd]
            idx += 1
        elif cmd == "":
            continue
        else:
            print("\033[90mTip: número de link, /selector, back, q"
                  + (", fill/send para formularios" if forms else "") + "\033[0m")

def main():
    parser = argparse.ArgumentParser(description="Cliente Gopher 2.0: contenido dinámico + cifrado + animaciones")
    parser.add_argument("url", help="URL en formato gopher://host:port/selector")
    parser.add_argument("--browse", "-b", action="store_true",
                        help="Modo navegador WWW (historial, links numerados, sin trackers)")
    args = parser.parse_args()

    try:
        if args.browse:
            browse(args.url)
            return
        content, host, port, session = fetch_gopher2(args.url)
        _p = urlparse(args.url)
        selector = (_p.path or "/")

        # Detectar si es una animación flipbook clásica
        if play_animation_if_needed(selector, host, port, session):
            return  # animación ya mostrada

        # GIF de una sola respuesta o página normal (con links numerados)
        links, forms = display_content(content)
        if forms and not args.browse:
            print(f"\033[90m[TIP: usa -b/--browse y el comando 'fill' para rellenar "
                  f"{len(forms)} formulario(s)]\033[0m")

    except KeyboardInterrupt:
        sys.exit("\nInterrumpido por el usuario.")
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()
