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
MAX_SELECTOR_LEN = 255

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
    
def fetch_gopher2(url: str) -> tuple[str, str, int, SecureSession]:
    """
    Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.
    """
    parsed = urlparse(url)
    if parsed.scheme != "gopher":
        raise ValueError("Solo se admite gopher://")
    
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 7070
    selector = parsed.path or "/"

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

        encrypted_selector = client_session.encrypt(selector)
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
    """
    if base_selector.rstrip('/') != '/anim':
        return False

    print("\033[90mIniciando animación...\033[0m", file=sys.stderr)
    frame_count = 0
    delay = 0.15

    for i in range(100):  # límite de seguridad
        frame_selector = f"/anim/frame{i:02d}"
        os.system('clear')
        print(f"\033[90mCargando {frame_selector}...\033[0m", flush=True)

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

                # Mostrar frame válido
                print("\033[1A\033[2K", end="")
                print(content, end="", flush=True)
                frame_count += 1

        except (ValueError, RuntimeError, socket.timeout, ConnectionRefusedError, OSError) as e:
            if i == 0:
                print(f"\033[91mError crítico al cargar el primer frame: {e}\033[0m", file=sys.stderr)
                return False
            else:
                time.sleep(0.3)
                break
        except KeyboardInterrupt:
            print("\n\033[90mAnimación interrumpida.\033[0m", file=sys.stderr)
            return True

        time.sleep(delay)

    print(f"\n\033[92m✅ Animación completada ({frame_count} frames).\033[0m", file=sys.stderr)
    return True
    
def main():
    parser = argparse.ArgumentParser(description="Cliente Gopher 2.0: contenido dinámico + cifrado + animaciones")
    parser.add_argument("url", help="URL en formato gopher://host:port/selector")
    args = parser.parse_args()

    try:
        content, host, port, session = fetch_gopher2(args.url)
        selector = urlparse(args.url).path or "/"

        # Detectar si es una animación
        if play_animation_if_needed(selector, host, port, session):
            return  # animación ya mostrada

        # Si no es animación, mostrar contenido normal
        print(content, end="")

    except KeyboardInterrupt:
        sys.exit("\nInterrumpido por el usuario.")
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()
