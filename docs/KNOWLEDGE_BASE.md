# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis. See more [here](https://github.com/grisuno/ReadMenator)

**Total Files Parsed:** 5 | **Total Symbols Extracted:** 40 | **Total Imports:** 40

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray:5 5,color:#aaa;
    server_py["server.py (py)"]
    class server_py mod;
    server_py_SecureSession["SecureSession"]
    class server_py_SecureSession cls;
    server_py --> server_py_SecureSession
    server_py_load_server_key["load_server_key"]
    class server_py_load_server_key fn;
    server_py --> server_py_load_server_key
    server_py_markdown_to_ansi["markdown_to_ansi"]
    class server_py_markdown_to_ansi fn;
    server_py --> server_py_markdown_to_ansi
    server_py_load_selectors["load_selectors"]
    class server_py_load_selectors fn;
    server_py --> server_py_load_selectors
    server_py_safe_print["safe_print"]
    class server_py_safe_print fn;
    server_py --> server_py_safe_print
    client_py["client.py (py)"]
    class client_py mod;
    client_py_SecureSession["SecureSession"]
    class client_py_SecureSession cls;
    client_py --> client_py_SecureSession
    client_py_decrypt_response["decrypt_response"]
    class client_py_decrypt_response fn;
    client_py --> client_py_decrypt_response
    client_py_get_known_hosts_path["get_known_hosts_path"]
    class client_py_get_known_hosts_path fn;
    client_py --> client_py_get_known_hosts_path
    client_py_save_server_fingerprint["save_server_fingerprint"]
    class client_py_save_server_fingerprint fn;
    client_py --> client_py_save_server_fingerprint
    client_py_get_saved_fingerprint["get_saved_fingerprint"]
    class client_py_get_saved_fingerprint fn;
    client_py --> client_py_get_saved_fingerprint
    ansi_widgets_py["ansi_widgets.py (py)"]
    class ansi_widgets_py mod;
    ansi_widgets_py__clamp["_clamp"]
    class ansi_widgets_py__clamp fn;
    ansi_widgets_py --> ansi_widgets_py__clamp
    ansi_widgets_py__sanitize_key["_sanitize_key"]
    class ansi_widgets_py__sanitize_key fn;
    ansi_widgets_py --> ansi_widgets_py__sanitize_key
    ansi_widgets_py__sanitize_value["_sanitize_value"]
    class ansi_widgets_py__sanitize_value fn;
    ansi_widgets_py --> ansi_widgets_py__sanitize_value
    ansi_widgets_py_bar_chart["bar_chart"]
    class ansi_widgets_py_bar_chart fn;
    ansi_widgets_py --> ansi_widgets_py_bar_chart
    ansi_widgets_py_bordered_panel["bordered_panel"]
    class ansi_widgets_py_bordered_panel fn;
    ansi_widgets_py --> ansi_widgets_py_bordered_panel
    app_py["app.py (py)"]
    class app_py mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
    install_sh_log["log"]
    class install_sh_log fn;
    install_sh --> install_sh_log
    install_sh_error["error"]
    class install_sh_error fn;
    install_sh --> install_sh_error
    ext_time["time"]
    class ext_time ext;
    ansi_widgets_py -.->|imports| ext_time
    ext_math["math"]
    class ext_math ext;
    ansi_widgets_py -.->|imports| ext_math
    ext_typing["typing"]
    class ext_typing ext;
    ansi_widgets_py -.->|imports| ext_typing
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
    ext_socket["socket"]
    class ext_socket ext;
    client_py -.->|imports| ext_socket
    ext_sys["sys"]
    class ext_sys ext;
    client_py -.->|imports| ext_sys
    ext_base64["base64"]
    class ext_base64 ext;
    client_py -.->|imports| ext_base64
    ext_argparse["argparse"]
    class ext_argparse ext;
    client_py -.->|imports| ext_argparse
    ext_logging["logging"]
    class ext_logging ext;
    client_py -.->|imports| ext_logging
    ext_urllib_parse["urllib.parse"]
    class ext_urllib_parse ext;
    client_py -.->|imports| ext_urllib_parse
    ext_cryptography_hazmat_primitives_ciphers_aead["cryptography.hazmat.primitives.ciphers.aead"]
    class ext_cryptography_hazmat_primitives_ciphers_aead ext;
    client_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers_aead
    ext_cryptography_exceptions["cryptography.exceptions"]
    class ext_cryptography_exceptions ext;
    client_py -.->|imports| ext_cryptography_exceptions
    client_py -.->|imports| ext_time
    ext_cryptography_hazmat_primitives_asymmetric["cryptography.hazmat.primitives.asymmetric"]
    class ext_cryptography_hazmat_primitives_asymmetric ext;
    client_py -.->|imports| ext_cryptography_hazmat_primitives_asymmetric
    ext_cryptography_hazmat_primitives["cryptography.hazmat.primitives"]
    class ext_cryptography_hazmat_primitives ext;
    client_py -.->|imports| ext_cryptography_hazmat_primitives
    ext_cryptography_hazmat_primitives_kdf_hkdf["cryptography.hazmat.primitives.kdf.hkdf"]
    class ext_cryptography_hazmat_primitives_kdf_hkdf ext;
    client_py -.->|imports| ext_cryptography_hazmat_primitives_kdf_hkdf
    client_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers_aead
    client_py -.->|imports| ext_cryptography_hazmat_primitives
    client_py -.->|imports| ext_os
    client_py -.->|imports| ext_sys
    server_py -.->|imports| ext_socket
    ext_threading["threading"]
    class ext_threading ext;
    server_py -.->|imports| ext_threading
    ext_json["json"]
    class ext_json ext;
    server_py -.->|imports| ext_json
    server_py -.->|imports| ext_os
    server_py -.->|imports| ext_time
    server_py -.->|imports| ext_logging
    ext_io["io"]
    class ext_io ext;
    server_py -.->|imports| ext_io
    server_py -.->|imports| ext_sys
    ext_datetime["datetime"]
    class ext_datetime ext;
    server_py -.->|imports| ext_datetime
    server_py -.->|imports| ext_cryptography_hazmat_primitives_asymmetric
    server_py -.->|imports| ext_cryptography_hazmat_primitives
    server_py -.->|imports| ext_cryptography_hazmat_primitives_kdf_hkdf
    server_py -.->|imports| ext_cryptography_hazmat_primitives_ciphers_aead
    ext_signal["signal"]
    class ext_signal ext;
    server_py -.->|imports| ext_signal
    ext_ansi_widgets["ansi_widgets"]
    class ext_ansi_widgets ext;
    server_py -.->|imports| ext_ansi_widgets
    ext_re["re"]
    class ext_re ext;
    server_py -.->|imports| ext_re
    server_py -.->|imports| ext_io
    server_py -.->|imports| ext_sys
    server_py -.->|imports| ext_threading
    ext_PIL["PIL"]
    class ext_PIL ext;
    server_py -.->|imports| ext_PIL
```

---

## Architecture Reference

### PY (4 files)

#### `ansi_widgets.py`
**Path:** `ansi_widgets.py`

**Functions:**
- `_clamp` (line 6) `def _clamp(value, low, high)`
- `_sanitize_key` (line 9) `def _sanitize_key(key)`
- `_sanitize_value` (line 14) `def _sanitize_value(value)`
- `bar_chart` (line 20) `def bar_chart(data, width, max_bar_width, color_map)`
- `bordered_panel` (line 75) `def bordered_panel(title, content, style)`
- `progress_bar` (line 101) `def progress_bar(value, max_val, width)`
- `ansi_time_theme` (line 111) `def ansi_time_theme()`

#### `app.py`
**Path:** `app.py`

*No symbols extracted*

#### `client.py`
**Path:** `client.py`

**Classes:**
- `SecureSession` (line 24) `class SecureSession` - *Negocia una clave AES efímera mediante ECDH (X25519) y HKDF.
Proporciona métodos para cifrar/descifrar.*

**Functions:**
- `decrypt_response` (line 101) `def decrypt_response(b64_data)`
- `get_known_hosts_path` (line 117) `def get_known_hosts_path()`
- `save_server_fingerprint` (line 121) `def save_server_fingerprint(host, port, fingerprint)`
- `get_saved_fingerprint` (line 126) `def get_saved_fingerprint(host, port)`
- `fetch_gopher2` (line 139) `def fetch_gopher2(url)` - *Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.*
- `play_animation_if_needed` (line 209) `def play_animation_if_needed(base_selector, host, port, session)` - *Reproduce animación si base_selector == '/anim'.
Se detiene al primer frame inexistente (detectado por contenido de error 404).*
- `main` (line 299) `def main()`
- `__init__` (line 32) `def __init__(self)`
- `get_public_key_fingerprint` (line 38) `def get_public_key_fingerprint(self)` - *Devuelve la huella SHA256 de la clave pública en formato legible.*
- `get_public_key_bytes` (line 47) `def get_public_key_bytes(self)` - *Devuelve la clave pública serializada (32 bytes).*
- `derive_shared_key` (line 54) `def derive_shared_key(self, peer_public_key_bytes)` - *Deriva la clave compartida usando ECDH + HKDF.*
- `encrypt` (line 75) `def encrypt(self, plaintext)` - *Cifra texto plano → nonce (12) + ciphertext + tag (16).*
- `decrypt` (line 85) `def decrypt(self, data)` - *Descifra nonce + ciphertext → texto plano.*

#### `server.py`
**Path:** `server.py`

**Classes:**
- `SecureSession` (line 24) `class SecureSession`

**Functions:**
- `load_server_key` (line 78) `def load_server_key()`
- `markdown_to_ansi` (line 104) `def markdown_to_ansi(md_text)`
- `load_selectors` (line 148) `def load_selectors()`
- `safe_print` (line 176) `def safe_print()`
- `restricted_exec` (line 180) `def restricted_exec(code, context_vars)`
- `image_to_ansi` (line 238) `def image_to_ansi(image_path, width)`
- `render_selector` (line 305) `def render_selector(selector, selectors_db)`
- `handle_client` (line 397) `def handle_client(conn, addr, selectors_db)`
- `main` (line 446) `def main()`
- `__init__` (line 28) `def __init__(self, private_key)`
- `get_public_key_bytes` (line 35) `def get_public_key_bytes(self)`
- `derive_shared_key` (line 41) `def derive_shared_key(self, peer_public_key_bytes)`
- `encrypt` (line 58) `def encrypt(self, plaintext)`
- `decrypt` (line 66) `def decrypt(self, data)`
- `escape_ansi` (line 108) `def escape_ansi(text)`
- `target` (line 214) `def target()`

### SH (1 files)

#### `install.sh`
**Path:** `install.sh`

**Functions:**
- `log` (line 9)
- `error` (line 13)
