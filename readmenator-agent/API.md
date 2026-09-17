# API

## ansi_widgets.py

### _clamp (function) `def _clamp(value, low, high)`
- Defined: `ansi_widgets.py:6`
- Imported by: `server.py`

### _sanitize_key (function) `def _sanitize_key(key)`
- Defined: `ansi_widgets.py:9`
- Imported by: `server.py`

### _sanitize_value (function) `def _sanitize_value(value)`
- Defined: `ansi_widgets.py:14`
- Imported by: `server.py`

### bar_chart (function) `def bar_chart(data, width, max_bar_width, color_map)`
- Defined: `ansi_widgets.py:20`
- Imported by: `server.py`

### bordered_panel (function) `def bordered_panel(title, content, style)`
- Defined: `ansi_widgets.py:75`
- Imported by: `server.py`

### progress_bar (function) `def progress_bar(value, max_val, width)`
- Defined: `ansi_widgets.py:101`
- Imported by: `server.py`

### ansi_time_theme (function) `def ansi_time_theme()`
- Defined: `ansi_widgets.py:111`
- Imported by: `server.py`

## client.py

### decrypt_response (method) `def decrypt_response(b64_data)`
- Defined: `client.py:101`

### get_known_hosts_path (method) `def get_known_hosts_path()`
- Defined: `client.py:117`

### save_server_fingerprint (method) `def save_server_fingerprint(host, port, fingerprint)`
- Defined: `client.py:121`

### get_saved_fingerprint (method) `def get_saved_fingerprint(host, port)`
- Defined: `client.py:126`

### fetch_gopher2 (method) `def fetch_gopher2(url)`
- Defined: `client.py:139`
- Doc: Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.

### play_animation_if_needed (method) `def play_animation_if_needed(base_selector, host, port, session)`
- Defined: `client.py:209`
- Doc: Reproduce animación si base_selector == '/anim'.

### main (method) `def main()`
- Defined: `client.py:299`

### __init__ (method) `def __init__(self)`
- Defined: `client.py:32`

### get_public_key_fingerprint (method) `def get_public_key_fingerprint(self)`
- Defined: `client.py:38`
- Doc: Devuelve la huella SHA256 de la clave pública en formato legible.

### get_public_key_bytes (method) `def get_public_key_bytes(self)`
- Defined: `client.py:47`
- Doc: Devuelve la clave pública serializada (32 bytes).

### derive_shared_key (method) `def derive_shared_key(self, peer_public_key_bytes)`
- Defined: `client.py:54`
- Doc: Deriva la clave compartida usando ECDH + HKDF.

### encrypt (method) `def encrypt(self, plaintext)`
- Defined: `client.py:75`
- Doc: Cifra texto plano → nonce (12) + ciphertext + tag (16).

### decrypt (method) `def decrypt(self, data)`
- Defined: `client.py:85`
- Doc: Descifra nonce + ciphertext → texto plano.

## install.sh

### log (function)
- Defined: `install.sh:9`

### error (function)
- Defined: `install.sh:13`

## server.py

### load_server_key (method) `def load_server_key()`
- Defined: `server.py:78`
- Depends on: `ansi_widgets.py`

### markdown_to_ansi (method) `def markdown_to_ansi(md_text)`
- Defined: `server.py:104`
- Depends on: `ansi_widgets.py`

### load_selectors (method) `def load_selectors()`
- Defined: `server.py:148`
- Depends on: `ansi_widgets.py`

### safe_print (method) `def safe_print()`
- Defined: `server.py:176`
- Depends on: `ansi_widgets.py`

### restricted_exec (method) `def restricted_exec(code, context_vars)`
- Defined: `server.py:180`
- Depends on: `ansi_widgets.py`

### image_to_ansi (method) `def image_to_ansi(image_path, width)`
- Defined: `server.py:238`
- Depends on: `ansi_widgets.py`

### render_selector (method) `def render_selector(selector, selectors_db)`
- Defined: `server.py:305`
- Depends on: `ansi_widgets.py`

### handle_client (method) `def handle_client(conn, addr, selectors_db)`
- Defined: `server.py:397`
- Depends on: `ansi_widgets.py`

### main (method) `def main()`
- Defined: `server.py:446`
- Depends on: `ansi_widgets.py`

### __init__ (method) `def __init__(self, private_key)`
- Defined: `server.py:28`
- Depends on: `ansi_widgets.py`

### get_public_key_bytes (method) `def get_public_key_bytes(self)`
- Defined: `server.py:35`
- Depends on: `ansi_widgets.py`

### derive_shared_key (method) `def derive_shared_key(self, peer_public_key_bytes)`
- Defined: `server.py:41`
- Depends on: `ansi_widgets.py`

### encrypt (method) `def encrypt(self, plaintext)`
- Defined: `server.py:58`
- Depends on: `ansi_widgets.py`

### decrypt (method) `def decrypt(self, data)`
- Defined: `server.py:66`
- Depends on: `ansi_widgets.py`

### escape_ansi (method) `def escape_ansi(text)`
- Defined: `server.py:108`
- Depends on: `ansi_widgets.py`

### target (method) `def target()`
- Defined: `server.py:214`
- Depends on: `ansi_widgets.py`
