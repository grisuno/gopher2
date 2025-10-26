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

# === CONFIGURACIÓN ===
AES_KEY = bytes.fromhex("88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff")  # 32 bytes
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_SELECTOR_LEN = 255

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
    port = parsed.port or 70
    selector = parsed.path or "/"

    if len(selector) > MAX_SELECTOR_LEN:
        raise ValueError(f"Selector demasiado largo (> {MAX_SELECTOR_LEN} bytes)")

    # Conectar
    with socket.create_connection((host, port), timeout=10) as sock:
        request = f"{selector}\r\n"
        sock.sendall(request.encode("ascii"))
        
        # Recibir respuesta completa
        response = b""
        while len(response) < MAX_RESPONSE_SIZE:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Detectar fin de respuesta Gopher (.\r\n)
            if b"\r\n.\r\n" in response:
                response = response.split(b"\r\n.\r\n", 1)[0]
                break
        else:
            raise ValueError("Respuesta demasiado grande")

    if not response:
        raise ValueError("Respuesta vacía del servidor")

    # Interpretar respuesta Gopher
    response_str = response.decode("ascii", errors="ignore")
    lines = response_str.splitlines()
    if not lines:
        raise ValueError("Respuesta sin líneas")

    first_line = lines[0]
    if first_line.startswith("i"):
        # Formato: i<contenido>\thost\tport
        parts = first_line.split("\t", 2)
        if len(parts) >= 1:
            b64_payload = parts[0][1:]  # quitar 'i'
        else:
            raise ValueError("Formato Gopher inválido")
    else:
        # Respuesta cruda (como en tu C2)
        b64_payload = first_line.strip()

    if not b64_payload:
        raise ValueError("Payload Base64 vacío")

    return decrypt_response(b64_payload)

def main():
    parser = argparse.ArgumentParser(description="Cliente Gopher 2.0: contenido dinámico + cifrado")
    parser.add_argument("url", help="URL en formato gopher://host:port/selector")
    parser.add_argument("--key", help="Clave AES-256 en hex (32 bytes)", default=None)
    args = parser.parse_args()

    global AES_KEY
    if args.key:
        if len(args.key) != 64:
            sys.exit("Error: la clave debe ser 64 caracteres hex (32 bytes)")
        try:
            AES_KEY = bytes.fromhex(args.key)
        except ValueError:
            sys.exit("Error: clave no es hexadecimal válido")

    try:
        content = fetch_gopher2(args.url)
        print(content, end="")
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()
