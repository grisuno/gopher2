# Subsystem: root

## ansi_widgets.py
- Layer: presentation
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
- Doc: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación...
- Layer: utility
- Language: py

## client.py
- Doc: SecureSession: Negocia una clave AES efímera mediante ECDH (X25519) y HKDF.
- Layer: infrastructure
- Language: py
- Symbols:
  - `SecureSession` (class, line 24) `class SecureSession`
  - `decrypt_response` (method, line 101) `def decrypt_response(b64_data)`
  - `get_known_hosts_path` (method, line 117) `def get_known_hosts_path()`
  - `save_server_fingerprint` (method, line 121) `def save_server_fingerprint(host, port, fingerprint)`
  - `get_saved_fingerprint` (method, line 126) `def get_saved_fingerprint(host, port)`
  - `_term_width` (method, line 139) `def _term_width(default)`
  - `fetch_gopher2` (method, line 147) `def fetch_gopher2(url)`
  - `play_animation_if_needed` (method, line 220) `def play_animation_if_needed(base_selector, host, port, session)`
  - `extract_links` (method, line 325) `def extract_links(content)`
  - `extract_forms` (method, line 335) `def extract_forms(content)`
  - `build_query` (method, line 352) `def build_query(action, answers)`
  - `display_content` (method, line 361) `def display_content(content)`
  - `_navigate` (method, line 401) `def _navigate(dest, host0, port0, history, idx)`
  - `_submit_form` (method, line 411) `def _submit_form(form)`
  - `browse` (method, line 427) `def browse(start_url)`
  - `main` (method, line 527) `def main()`
  - `__init__` (method, line 32) `def __init__(self)`
  - `get_public_key_fingerprint` (method, line 38) `def get_public_key_fingerprint(self)`
  - `get_public_key_bytes` (method, line 47) `def get_public_key_bytes(self)`
  - `derive_shared_key` (method, line 54) `def derive_shared_key(self, peer_public_key_bytes)`
  - `encrypt` (method, line 75) `def encrypt(self, plaintext)`
  - `decrypt` (method, line 85) `def decrypt(self, data)`
- Depends on: `image_renderer.py`

## image_renderer.py
- Doc: — reemplazo mejorado de image_to_ansi / image_to_bash Mezcla lo mejor de LazyOwn/banner.py +...
- Layer: presentation
- Language: py
- Symbols:
  - `terminal_width` (function, line 29) `def terminal_width(default)`
  - `resolve_public_path` (function, line 34) `def resolve_public_path(image_path, base_dir)`
  - `_composite` (function, line 52) `def _composite(img)`
  - `_frame_to_halfblock` (function, line 62) `def _frame_to_halfblock(img_rgb, width)`
  - `_render_cached` (function, line 96) `def _render_cached(full_path, mtime, width, max_frames)`
  - `render_image` (function, line 128) `def render_image(image_path, width, max_frames, base_dir)`
  - `split_animation` (function, line 150) `def split_animation(payload)`
  - `parse_img_tag` (function, line 165) `def parse_img_tag(tag_body, default_width)`
- Imported by: `client.py`, `server.py`

## install.sh
- Doc: Instalador para Gopher 2.0 (servidor y cliente)
- Layer: utility
- Language: sh
- Symbols:
  - `log` (function, line 9)
  - `error` (function, line 13)

## server.py
- Doc: markdown_to_ansi: Markdown -> ANSI.
- Layer: utility
- Language: py
- Symbols:
  - `SecureSession` (class, line 24) `class SecureSession`
  - `load_server_key` (method, line 78) `def load_server_key()`
  - `markdown_to_ansi` (method, line 104) `def markdown_to_ansi(md_text)`
  - `load_selectors` (method, line 188) `def load_selectors()`
  - `safe_print` (method, line 216) `def safe_print()`
  - `restricted_exec` (method, line 220) `def restricted_exec(code, context_vars)`
  - `image_to_ansi` (method, line 278) `def image_to_ansi(image_path, width)`
  - `parse_query` (method, line 293) `def parse_query(selector)`
  - `sanitize_text` (method, line 313) `def sanitize_text(s, maxlen)`
  - `guestbook_load` (method, line 324) `def guestbook_load()`
  - `guestbook_add` (method, line 332) `def guestbook_add(nick, msg)`
  - `render_form_block` (method, line 343) `def render_form_block(action, inner)`
  - `render_selector` (method, line 376) `def render_selector(selector, selectors_db, img_width)`
  - `handle_client` (method, line 509) `def handle_client(conn, addr, selectors_db)`
  - `main` (method, line 568) `def main()`
  - `__init__` (method, line 28) `def __init__(self, private_key)`
  - `get_public_key_bytes` (method, line 35) `def get_public_key_bytes(self)`
  - `derive_shared_key` (method, line 41) `def derive_shared_key(self, peer_public_key_bytes)`
  - `encrypt` (method, line 58) `def encrypt(self, plaintext)`
  - `decrypt` (method, line 66) `def decrypt(self, data)`
  - `escape_ansi` (method, line 110) `def escape_ansi(text)`
  - `_link_repl` (method, line 114) `def _link_repl(m)`
  - `_a_repl` (method, line 172) `def _a_repl(m)`
  - `target` (method, line 254) `def target()`
  - `_render_img_block` (method, line 421) `def _render_img_block(block)`
  - `_render_gif_block` (method, line 437) `def _render_gif_block(m)`
  - `_solo_input` (method, line 456) `def _solo_input(m)`
- Depends on: `ansi_widgets.py`, `image_renderer.py`
