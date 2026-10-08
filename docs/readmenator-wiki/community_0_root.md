# root

*Community 0 | 4 files | cohesion 1.00*

## Definition

This community groups 4 file(s) rooted at `root` with dominant language py (cohesion 1.00). Central symbols: `SecureSession`, `__init__`, `_a_repl`, `_clamp`, `_composite`, `_frame_to_halfblock`, `_link_repl`, `_navigate`. Core file: `server.py` (27 symbols). Documented purpose: — reemplazo mejorado de image_to_ansi / image_to_bash Mezcla lo mejor de LazyOwn/banner.py + optimizaciones para gopher2: - half-block "▀" con fg=arriba, bg=aba.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `ansi_widgets.py` | py | presentation | 7 | yes |
| `client.py` | py | infrastructure | 22 | yes |
| `image_renderer.py` | py | presentation | 8 | yes |
| `server.py` | py | utility | 27 | yes |

## Key Symbols

- `_clamp` (function, `ansi_widgets.py:6`) `def _clamp(value, low, high)`
- `_sanitize_key` (function, `ansi_widgets.py:9`) `def _sanitize_key(key)`
- `_sanitize_value` (function, `ansi_widgets.py:14`) `def _sanitize_value(value)`
- `bar_chart` (function, `ansi_widgets.py:20`) `def bar_chart(data, width, max_bar_width, color_map)`
- `bordered_panel` (function, `ansi_widgets.py:75`) `def bordered_panel(title, content, style)`
- `progress_bar` (function, `ansi_widgets.py:101`) `def progress_bar(value, max_val, width)`
- `ansi_time_theme` (function, `ansi_widgets.py:111`) `def ansi_time_theme()`
- `SecureSession` (class, `client.py:24`) `class SecureSession` - Negocia una clave AES efímera mediante ECDH (X25519) y HKDF.
- `__init__` (method, `client.py:32`) `def __init__(self)`
- `get_public_key_fingerprint` (method, `client.py:38`) `def get_public_key_fingerprint(self)` - Devuelve la huella SHA256 de la clave pública en formato legible.
- `get_public_key_bytes` (method, `client.py:47`) `def get_public_key_bytes(self)` - Devuelve la clave pública serializada (32 bytes).
- `derive_shared_key` (method, `client.py:54`) `def derive_shared_key(self, peer_public_key_bytes)` - Deriva la clave compartida usando ECDH + HKDF.
- `encrypt` (method, `client.py:75`) `def encrypt(self, plaintext)` - Cifra texto plano → nonce (12) + ciphertext + tag (16).
- `decrypt` (method, `client.py:85`) `def decrypt(self, data)` - Descifra nonce + ciphertext → texto plano.
- `decrypt_response` (method, `client.py:101`) `def decrypt_response(b64_data)`
- `get_known_hosts_path` (method, `client.py:117`) `def get_known_hosts_path()`
- `save_server_fingerprint` (method, `client.py:121`) `def save_server_fingerprint(host, port, fingerprint)`
- `get_saved_fingerprint` (method, `client.py:126`) `def get_saved_fingerprint(host, port)`
- `_term_width` (method, `client.py:139`) `def _term_width(default)`
- `fetch_gopher2` (method, `client.py:147`) `def fetch_gopher2(url)` - Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.
- `play_animation_if_needed` (method, `client.py:220`) `def play_animation_if_needed(base_selector, host, port, session)` - Reproduce animación si base_selector == '/anim'.
- `extract_links` (method, `client.py:325`) `def extract_links(content)` - Separa bloque máquina LINKS:a\|b -> (texto limpio, [urls]).
- `extract_forms` (method, `client.py:335`) `def extract_forms(content)` - Separa bloques FORM:{json} -> (texto limpio, [forms]).
- `build_query` (method, `client.py:352`) `def build_query(action, answers)` - action + dict -> '/base?k=v&...' con quote. Sin cookies.
- `display_content` (method, `client.py:361`) `def display_content(content)` - Muestra contenido. GIF multi-frame se anima. Devuelve (links, forms).
- `_navigate` (method, `client.py:401`) `def _navigate(dest, host0, port0, history, idx)` - Resuelve link (interno o gopher://) -> (history, idx, host, port).
- `_submit_form` (method, `client.py:411`) `def _submit_form(form)` - Pregunta campo por campo en terminal. Enter = default. Sin eco de red extra.
- `browse` (method, `client.py:427`) `def browse(start_url)` - Modo navegador WWW (sin trackers): historial back/forward, go N, reload.
- `main` (method, `client.py:527`) `def main()`
- `terminal_width` (function, `image_renderer.py:29`) `def terminal_width(default)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 5
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [dataflow UNCHECKED_ALLOC] `server.py:573` `main` `sock`: Result of allocator stored in `sock` is never checked against NULL.

## Open Questions

- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `ansi_widgets.py`
- `client.py`
- `image_renderer.py`
- `server.py`
