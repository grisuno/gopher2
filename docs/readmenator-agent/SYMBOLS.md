# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `_clamp` | function | `ansi_widgets.py:6` | `def _clamp(value, low, high)` |
| `_sanitize_key` | function | `ansi_widgets.py:9` | `def _sanitize_key(key)` |
| `_sanitize_value` | function | `ansi_widgets.py:14` | `def _sanitize_value(value)` |
| `ansi_time_theme` | function | `ansi_widgets.py:111` | `def ansi_time_theme()` |
| `bar_chart` | function | `ansi_widgets.py:20` | `def bar_chart(data, width, max_bar_width, color_map)` |
| `bordered_panel` | function | `ansi_widgets.py:75` | `def bordered_panel(title, content, style)` |
| `progress_bar` | function | `ansi_widgets.py:101` | `def progress_bar(value, max_val, width)` |
| `SecureSession` | class | `client.py:24` | `class SecureSession` |
| `__init__` | method | `client.py:32` | `def __init__(self)` |
| `_navigate` | method | `client.py:401` | `def _navigate(dest, host0, port0, history, idx)` |
| `_submit_form` | method | `client.py:411` | `def _submit_form(form)` |
| `_term_width` | method | `client.py:139` | `def _term_width(default)` |
| `browse` | method | `client.py:427` | `def browse(start_url)` |
| `build_query` | method | `client.py:352` | `def build_query(action, answers)` |
| `decrypt` | method | `client.py:85` | `def decrypt(self, data)` |
| `decrypt_response` | method | `client.py:101` | `def decrypt_response(b64_data)` |
| `derive_shared_key` | method | `client.py:54` | `def derive_shared_key(self, peer_public_key_bytes)` |
| `display_content` | method | `client.py:361` | `def display_content(content)` |
| `encrypt` | method | `client.py:75` | `def encrypt(self, plaintext)` |
| `extract_forms` | method | `client.py:335` | `def extract_forms(content)` |
| `extract_links` | method | `client.py:325` | `def extract_links(content)` |
| `fetch_gopher2` | method | `client.py:147` | `def fetch_gopher2(url)` |
| `get_known_hosts_path` | method | `client.py:117` | `def get_known_hosts_path()` |
| `get_public_key_bytes` | method | `client.py:47` | `def get_public_key_bytes(self)` |
| `get_public_key_fingerprint` | method | `client.py:38` | `def get_public_key_fingerprint(self)` |
| `get_saved_fingerprint` | method | `client.py:126` | `def get_saved_fingerprint(host, port)` |
| `main` | method | `client.py:527` | `def main()` |
| `play_animation_if_needed` | method | `client.py:220` | `def play_animation_if_needed(base_selector, host, port, session)` |
| `save_server_fingerprint` | method | `client.py:121` | `def save_server_fingerprint(host, port, fingerprint)` |
| `_composite` | function | `image_renderer.py:52` | `def _composite(img)` |
| `_frame_to_halfblock` | function | `image_renderer.py:62` | `def _frame_to_halfblock(img_rgb, width)` |
| `_render_cached` | function | `image_renderer.py:96` | `def _render_cached(full_path, mtime, width, max_frames)` |
| `parse_img_tag` | function | `image_renderer.py:165` | `def parse_img_tag(tag_body, default_width)` |
| `render_image` | function | `image_renderer.py:128` | `def render_image(image_path, width, max_frames, base_dir)` |
| `resolve_public_path` | function | `image_renderer.py:34` | `def resolve_public_path(image_path, base_dir)` |
| `split_animation` | function | `image_renderer.py:150` | `def split_animation(payload)` |
| `terminal_width` | function | `image_renderer.py:29` | `def terminal_width(default)` |
| `error` | function | `install.sh:13` | `` |
| `log` | function | `install.sh:9` | `` |
| `SecureSession` | class | `server.py:24` | `class SecureSession` |
| `__init__` | method | `server.py:28` | `def __init__(self, private_key)` |
| `_a_repl` | method | `server.py:172` | `def _a_repl(m)` |
| `_link_repl` | method | `server.py:114` | `def _link_repl(m)` |
| `_render_gif_block` | method | `server.py:437` | `def _render_gif_block(m)` |
| `_render_img_block` | method | `server.py:421` | `def _render_img_block(block)` |
| `_solo_input` | method | `server.py:456` | `def _solo_input(m)` |
| `decrypt` | method | `server.py:66` | `def decrypt(self, data)` |
| `derive_shared_key` | method | `server.py:41` | `def derive_shared_key(self, peer_public_key_bytes)` |
| `encrypt` | method | `server.py:58` | `def encrypt(self, plaintext)` |
| `escape_ansi` | method | `server.py:110` | `def escape_ansi(text)` |
| `get_public_key_bytes` | method | `server.py:35` | `def get_public_key_bytes(self)` |
| `guestbook_add` | method | `server.py:332` | `def guestbook_add(nick, msg)` |
| `guestbook_load` | method | `server.py:324` | `def guestbook_load()` |
| `handle_client` | method | `server.py:509` | `def handle_client(conn, addr, selectors_db)` |
| `image_to_ansi` | method | `server.py:278` | `def image_to_ansi(image_path, width)` |
| `load_selectors` | method | `server.py:188` | `def load_selectors()` |
| `load_server_key` | method | `server.py:78` | `def load_server_key()` |
| `main` | method | `server.py:568` | `def main()` |
| `markdown_to_ansi` | method | `server.py:104` | `def markdown_to_ansi(md_text)` |
| `parse_query` | method | `server.py:293` | `def parse_query(selector)` |
| `render_form_block` | method | `server.py:343` | `def render_form_block(action, inner)` |
| `render_selector` | method | `server.py:376` | `def render_selector(selector, selectors_db, img_width)` |
| `restricted_exec` | method | `server.py:220` | `def restricted_exec(code, context_vars)` |
| `safe_print` | method | `server.py:216` | `def safe_print()` |
| `sanitize_text` | method | `server.py:313` | `def sanitize_text(s, maxlen)` |
| `target` | method | `server.py:254` | `def target()` |
