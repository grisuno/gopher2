# API

## ansi_widgets.py
Imported by: `server.py`
- `bar_chart` (function) `ansi_widgets.py:20` `def bar_chart(data, width, max_bar_width, color_map)`
- `bordered_panel` (function) `ansi_widgets.py:75` `def bordered_panel(title, content, style)`
- `progress_bar` (function) `ansi_widgets.py:101` `def progress_bar(value, max_val, width)`
- `ansi_time_theme` (function) `ansi_widgets.py:111` `def ansi_time_theme()`

## client.py
Depends on: `image_renderer.py`
- `SecureSession.__init__` (method) `client.py:32` `def __init__(self)`
- `SecureSession.get_public_key_fingerprint` (method) `client.py:38` `def get_public_key_fingerprint(self)` -- Devuelve la huella SHA256 de la clave pública en formato legible.
- `SecureSession.get_public_key_bytes` (method) `client.py:47` `def get_public_key_bytes(self)` -- Devuelve la clave pública serializada (32 bytes).
- `SecureSession.derive_shared_key` (method) `client.py:54` `def derive_shared_key(self, peer_public_key_bytes)` -- Deriva la clave compartida usando ECDH + HKDF.
- `SecureSession.encrypt` (method) `client.py:75` `def encrypt(self, plaintext)` -- Cifra texto plano → nonce (12) + ciphertext + tag (16).
- `SecureSession.decrypt` (method) `client.py:85` `def decrypt(self, data)` -- Descifra nonce + ciphertext → texto plano.
- `SecureSession.decrypt_response` (method) `client.py:101` `def decrypt_response(b64_data)`
- `SecureSession.get_known_hosts_path` (method) `client.py:117` `def get_known_hosts_path()`
- `SecureSession.save_server_fingerprint` (method) `client.py:121` `def save_server_fingerprint(host, port, fingerprint)`
- `SecureSession.get_saved_fingerprint` (method) `client.py:126` `def get_saved_fingerprint(host, port)`
- `SecureSession.fetch_gopher2` (method) `client.py:147` `def fetch_gopher2(url)` -- Devuelve (contenido, host, puerto, sesión) para permitir animación posterior.
- `SecureSession.play_animation_if_needed` (method) `client.py:220` `def play_animation_if_needed(base_selector, host, port, session)` -- Reproduce animación si base_selector == '/anim'.
- `SecureSession.extract_links` (method) `client.py:325` `def extract_links(content)` -- Separa bloque máquina LINKS:a|b -> (texto limpio, [urls]).
- `SecureSession.extract_forms` (method) `client.py:335` `def extract_forms(content)` -- Separa bloques FORM:{json} -> (texto limpio, [forms]).
- `SecureSession.build_query` (method) `client.py:352` `def build_query(action, answers)` -- action + dict -> '/base?k=v&...' con quote.
- `SecureSession.display_content` (method) `client.py:361` `def display_content(content)` -- Muestra contenido.
- `SecureSession.browse` (method) `client.py:427` `def browse(start_url)` -- Modo navegador WWW (sin trackers): historial back/forward, go N, reload.
- `SecureSession.main` (method) `client.py:527` `def main()`

## image_renderer.py
Imported by: `client.py`, `server.py`
- `terminal_width` (function) `image_renderer.py:29` `def terminal_width(default)`
- `resolve_public_path` (function) `image_renderer.py:34` `def resolve_public_path(image_path, base_dir)` -- Valida y resuelve ruta.
- `render_image` (function) `image_renderer.py:128` `def render_image(image_path, width, max_frames, base_dir)` -- API principal. width=0 -> auto (ancho terminal).
- `split_animation` (function) `image_renderer.py:150` `def split_animation(payload)` -- Inverso: separa payload multi-frame -> (frames, duración_ms).
- `parse_img_tag` (function) `image_renderer.py:165` `def parse_img_tag(tag_body, default_width)` -- Acepta: '/public/a.png' | '/public/a.png width=80' | 'width=80 /public/a.png'.

## install.sh
- `log` (function) `install.sh:9`
- `error` (function) `install.sh:13`

## server.py
Depends on: `ansi_widgets.py`, `image_renderer.py`
- `SecureSession.__init__` (method) `server.py:28` `def __init__(self, private_key)`
- `SecureSession.get_public_key_bytes` (method) `server.py:35` `def get_public_key_bytes(self)`
- `SecureSession.derive_shared_key` (method) `server.py:41` `def derive_shared_key(self, peer_public_key_bytes)`
- `SecureSession.encrypt` (method) `server.py:58` `def encrypt(self, plaintext)`
- `SecureSession.decrypt` (method) `server.py:66` `def decrypt(self, data)`
- `SecureSession.load_server_key` (method) `server.py:78` `def load_server_key()`
- `SecureSession.markdown_to_ansi` (method) `server.py:104` `def markdown_to_ansi(md_text)` -- Markdown -> ANSI.
- `SecureSession.escape_ansi` (method) `server.py:110` `def escape_ansi(text)`
- `SecureSession.load_selectors` (method) `server.py:188` `def load_selectors()`
- `SecureSession.safe_print` (method) `server.py:216` `def safe_print()`
- `SecureSession.restricted_exec` (method) `server.py:220` `def restricted_exec(code, context_vars)`
- `SecureSession.target` (method) `server.py:254` `def target()`
- `SecureSession.image_to_ansi` (method) `server.py:278` `def image_to_ansi(image_path, width)` -- Wrapper fino sobre image_renderer (rápido + GIF + caché). width=0 -> auto según terminal.
- `SecureSession.parse_query` (method) `server.py:293` `def parse_query(selector)` -- Parte '/base?nombre=Juan&edad=22' -> ('/base', {'nombre':'Juan',...}).
- `SecureSession.sanitize_text` (method) `server.py:313` `def sanitize_text(s, maxlen)` -- Quita ANSI, saltos y control para guestbook/vars de usuario.
- `SecureSession.guestbook_load` (method) `server.py:324` `def guestbook_load()`
- `SecureSession.guestbook_add` (method) `server.py:332` `def guestbook_add(nick, msg)`
- `SecureSession.render_form_block` (method) `server.py:343` `def render_form_block(action, inner)` -- Convierte <form action> + <input ...> en texto ANSI + bloque máquina \x1fFORM:{json}\x1f para que el cliente sepa...
- `SecureSession.render_selector` (method) `server.py:376` `def render_selector(selector, selectors_db, img_width)`
- `SecureSession.handle_client` (method) `server.py:509` `def handle_client(conn, addr, selectors_db)`
- `SecureSession.main` (method) `server.py:568` `def main()`
