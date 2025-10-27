#!/usr/bin/env python3
# gopher2_client.py
import socket
import sys
import base64
import argparse
import logging
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# === Clase SecureSession: ECDH + HKDF para clave AES ===
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

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

def fetch_gopher2(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "gopher":
        raise ValueError("Solo se admite gopher://")
    
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 7070
    selector = parsed.path or "/"

    if len(selector) > MAX_SELECTOR_LEN:
        raise ValueError(f"Selector demasiado largo (> {MAX_SELECTOR_LEN} bytes)")

    with socket.create_connection((host, port), timeout=10) as sock:
        # Paso 1: Crear sesión y enviar clave pública
        session = SecureSession()
        sock.sendall(session.get_public_key_bytes())

        # Paso 2: Recibir clave pública del servidor
        server_pubkey = sock.recv(32)
        if len(server_pubkey) != 32:
            raise ValueError("Clave pública del servidor inválida")
        session.derive_shared_key(server_pubkey)

        # Paso 3: Enviar selector cifrado
        encrypted_selector = session.encrypt(selector)
        sock.sendall(encrypted_selector)

        # Paso 4: Recibir respuesta (4 bytes de longitud + datos)
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

        return session.decrypt(response_data)

def main():
    parser = argparse.ArgumentParser(description="Cliente Gopher 2.0: contenido dinámico + cifrado")
    parser.add_argument("url", help="URL en formato gopher://host:port/selector")
    
    args = parser.parse_args()


    try:
        content = fetch_gopher2(args.url)
        print(content, end="")
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()
