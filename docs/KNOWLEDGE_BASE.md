# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis.

**Total Files Parsed:** 5 | **Total Symbols Extracted:** 40 | **Total Imports:** 40

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray: 5 5,color:#aaa;
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
- `_clamp` (line 6)
- `_sanitize_key` (line 9)
- `_sanitize_value` (line 14)
- `bar_chart` (line 20)
- `bordered_panel` (line 75)
- `progress_bar` (line 101)
- `ansi_time_theme` (line 111)

#### `app.py`
**Path:** `app.py`

*No symbols extracted*

#### `client.py`
**Path:** `client.py`

**Classs:**
- `SecureSession` (line 24) - *Negocia una clave AES efímera mediante ECDH (X25519) y HKDF.
Proporciona métodos para cifrar/descifrar.*

**Functions:**
- `decrypt_response` (line 101)
- `get_known_hosts_path` (line 117)
- `save_server_fingerprint` (line 121)
- `get_saved_fingerprint` (line 126)
- `fetch_gopher2` (line 139) - *Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.*
- `play_animation_if_needed` (line 209) - *Reproduce animación si base_selector == '/anim'.
Se detiene al primer frame inexistente (detectado por contenido de error 404).*
- `main` (line 299)
- `__init__` (line 32)
- `get_public_key_fingerprint` (line 38) - *Devuelve la huella SHA256 de la clave pública en formato legible.*
- `get_public_key_bytes` (line 47) - *Devuelve la clave pública serializada (32 bytes).*
- `derive_shared_key` (line 54) - *Deriva la clave compartida usando ECDH + HKDF.*
- `encrypt` (line 75) - *Cifra texto plano → nonce (12) + ciphertext + tag (16).*
- `decrypt` (line 85) - *Descifra nonce + ciphertext → texto plano.*

#### `server.py`
**Path:** `server.py`

**Classs:**
- `SecureSession` (line 24)

**Functions:**
- `load_server_key` (line 78)
- `markdown_to_ansi` (line 104)
- `load_selectors` (line 148)
- `safe_print` (line 176)
- `restricted_exec` (line 180)
- `image_to_ansi` (line 238)
- `render_selector` (line 305)
- `handle_client` (line 397)
- `main` (line 446)
- `__init__` (line 28)
- `get_public_key_bytes` (line 35)
- `derive_shared_key` (line 41)
- `encrypt` (line 58)
- `decrypt` (line 66)
- `escape_ansi` (line 108)
- `target` (line 214)

### SH (1 files)

#### `install.sh`
**Path:** `install.sh`

**Functions:**
- `log` (line 9)
- `error` (line 13)
