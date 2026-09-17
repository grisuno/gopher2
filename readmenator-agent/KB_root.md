# Subsystem: root

## ansi_widgets.py
- Layer: presentation
- Doc: ansi_widgets.py
- Language: py
- Symbols:
  - `_clamp` (function, line 6) `def _clamp(value, low, high)`
  - `_sanitize_key` (function, line 9) `def _sanitize_key(key)`
  - `_sanitize_value` (function, line 14) `def _sanitize_value(value)`
  - `bar_chart` (function, line 20) `def bar_chart(data, width, max_bar_width, color_map)`
  - `bordered_panel` (function, line 75) `def bordered_panel(title, content, style)`
  - `progress_bar` (function, line 101) `def progress_bar(value, max_val, width)`
  - `ansi_time_theme` (function, line 111) `def ansi_time_theme()`
- Imported by: `server.py`

## app.py
- Layer: utility
- Doc: app.py  Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licenci
- Language: py

## client.py
- Layer: infrastructure
- Doc: client.py
- Language: py
- Symbols:
  - `SecureSession` (class, line 24) `class SecureSession`
  - `decrypt_response` (method, line 101) `def decrypt_response(b64_data)`
  - `get_known_hosts_path` (method, line 117) `def get_known_hosts_path()`
  - `save_server_fingerprint` (method, line 121) `def save_server_fingerprint(host, port, fingerprint)`
  - `get_saved_fingerprint` (method, line 126) `def get_saved_fingerprint(host, port)`
  - `fetch_gopher2` (method, line 139) `def fetch_gopher2(url)`
  - `play_animation_if_needed` (method, line 209) `def play_animation_if_needed(base_selector, host, port, session)`
  - `main` (method, line 299) `def main()`
  - `__init__` (method, line 32) `def __init__(self)`
  - `get_public_key_fingerprint` (method, line 38) `def get_public_key_fingerprint(self)`
  - `get_public_key_bytes` (method, line 47) `def get_public_key_bytes(self)`
  - `derive_shared_key` (method, line 54) `def derive_shared_key(self, peer_public_key_bytes)`
  - `encrypt` (method, line 75) `def encrypt(self, plaintext)`
  - `decrypt` (method, line 85) `def decrypt(self, data)`

## install.sh
- Layer: utility
- Doc: install.sh - Instalador para Gopher 2.0 (servidor y cliente)
- Language: sh
- Symbols:
  - `log` (function, line 9)
  - `error` (function, line 13)

## server.py
- Layer: utility
- Doc: server.py
- Language: py
- Symbols:
  - `SecureSession` (class, line 24) `class SecureSession`
  - `load_server_key` (method, line 78) `def load_server_key()`
  - `markdown_to_ansi` (method, line 104) `def markdown_to_ansi(md_text)`
  - `load_selectors` (method, line 148) `def load_selectors()`
  - `safe_print` (method, line 176) `def safe_print()`
  - `restricted_exec` (method, line 180) `def restricted_exec(code, context_vars)`
  - `image_to_ansi` (method, line 238) `def image_to_ansi(image_path, width)`
  - `render_selector` (method, line 305) `def render_selector(selector, selectors_db)`
  - `handle_client` (method, line 397) `def handle_client(conn, addr, selectors_db)`
  - `main` (method, line 446) `def main()`
  - `__init__` (method, line 28) `def __init__(self, private_key)`
  - `get_public_key_bytes` (method, line 35) `def get_public_key_bytes(self)`
  - `derive_shared_key` (method, line 41) `def derive_shared_key(self, peer_public_key_bytes)`
  - `encrypt` (method, line 58) `def encrypt(self, plaintext)`
  - `decrypt` (method, line 66) `def decrypt(self, data)`
  - `escape_ansi` (method, line 108) `def escape_ansi(text)`
  - `target` (method, line 214) `def target()`
- Depends on: `ansi_widgets.py`
