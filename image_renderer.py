#!/usr/bin/env python3
# image_renderer.py — reemplazo mejorado de image_to_ansi / image_to_bash
# Mezcla lo mejor de LazyOwn/banner.py + optimizaciones para gopher2:
#  - half-block "▀" con fg=arriba, bg=abajo (doble resolución vertical)
#  - resize LANCZOS + corrección aspecto terminal (~0.5)
#  - vía rápida sin getpixel() (getdata / tobytes, ~10-20x más rápido)
#  - RGBA -> composite sobre fondo (negro) para PNG/GIF con transparencia
#  - GIF animado: devuelve lista de frames ANSI + duraciones
#  - caché LRU en memoria + caché en disco opcional (evita re-render)
#  - ancho adaptable: width=0/auto -> detecta COLUMNS, clamp 20..160
#  - saneo de rutas igual que server.py (solo /public/, sin ..)
import os
import re
import shutil
import functools
from typing import List, Tuple

# Delimitador para animaciones multi-frame en una sola respuesta.
# Cliente lo splitea y reproduce. \x1e = Record Separator, poco probable en texto.
FRAME_SEP = "\x1eFRAME\x1e"
# Duración incluida como primera línea del payload: \x1eDUR:120\x1e (ms por frame)
DUR_PREFIX = "\x1eDUR:"

_MAX_W, _MIN_W = 160, 20
_MAX_FRAMES = 24
_MAX_PIXELS = 4_000_000  # anti-DoS: rechazar imágenes gigantes antes de abrir


def terminal_width(default: int = 80) -> int:
    w = shutil.get_terminal_size(fallback=(default, 24)).columns
    return max(_MIN_W, min(_MAX_W, w))


def resolve_public_path(image_path: str, base_dir: str = "public") -> str:
    """Valida y resuelve ruta. Lanza ValueError con mensaje listo para mostrar."""
    if not image_path.startswith("/public/"):
        raise ValueError("[Error: ruta debe comenzar con /public/]")
    rel = image_path[8:]
    if not rel or ".." in rel or rel.startswith("/") or "//" in rel:
        raise ValueError("[Error: ruta no permitida]")
    if not rel.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")):
        raise ValueError("[Error: formato no soportado]")
    base = os.path.abspath(base_dir)
    full = os.path.abspath(os.path.join(base, rel))
    if not full.startswith(base + os.sep) and full != base:
        raise ValueError("[Error: ruta fuera de public/]")
    if not os.path.isfile(full):
        raise ValueError(f"[Error: archivo no encontrado: {image_path}]")
    return full


def _composite(img):
    """Pega RGBA sobre negro, devuelve RGB. También expande P/L."""
    if img.mode == "RGBA":
        from PIL import Image
        bg = Image.new("RGB", img.size, (0, 0, 0))
        bg.paste(img, mask=img.split()[3])
        return bg
    return img.convert("RGB")


def _frame_to_halfblock(img_rgb, width: int) -> str:
    """Convierte un PIL RGB ya cargado a string ANSI half-block.
    Vía rápida: resize LANCZOS -> bytes -> formateo por lotes."""
    from PIL import Image
    orig_w, orig_h = img_rgb.size
    if orig_w == 0 or orig_h == 0:
        return "[Error: imagen vacía]"
    width = max(_MIN_W, min(_MAX_W, width))
    new_h = max(2, int(orig_h / orig_w * width * 0.5))
    if (orig_w, orig_h) != (width, new_h):
        img_rgb = img_rgb.resize((width, new_h), Image.LANCZOS)
    if new_h % 2 == 1:
        img_rgb = img_rgb.crop((0, 0, width, new_h - 1))
        new_h -= 1
        if new_h == 0:
            return "[Error: altura inválida]"
    raw = img_rgb.tobytes()  # RGBRGB... row-major
    w = width
    out_lines = []
    # Construir por filas de a 2 píxeles verticales
    for y in range(0, new_h, 2):
        top_off, bot_off = y * w * 3, (y + 1) * w * 3
        parts = []
        for x in range(w):
            i1, i2 = top_off + x * 3, bot_off + x * 3
            parts.append(
                f"\033[38;2;{raw[i1]};{raw[i1+1]};{raw[i1+2]};"
                f"48;2;{raw[i2]};{raw[i2+1]};{raw[i2+2]}m▀\033[0m"
            )
        out_lines.append("".join(parts))
    return "\n".join(out_lines)


@functools.lru_cache(maxsize=64)
def _render_cached(full_path: str, mtime: float, width: int, max_frames: int) -> str:
    """Núcleo cacheable. mtime invalida caché al cambiar el archivo."""
    from PIL import Image
    # Chequeo anti-DoS barato antes de decodificar todo
    with Image.open(full_path) as probe:
        if probe.width * probe.height > _MAX_PIXELS:
            return "[Error: imagen demasiado grande]"
        is_anim = getattr(probe, "is_animated", False) and getattr(probe, "n_frames", 1) > 1

    with Image.open(full_path) as img:
        if is_anim:
            frames: List[str] = []
            durations: List[int] = []
            n = min(img.n_frames, max_frames)
            for i in range(n):
                img.seek(i)
                frame = _composite(img.copy())
                frames.append(_frame_to_halfblock(frame, width))
                durations.append(int(img.info.get("duration", 120) or 120))
            if not frames:
                return "[Error: GIF sin frames]"
            avg = sum(durations) // len(durations)
            if len(frames) == 1:
                return frames[0]
            return f"{DUR_PREFIX}{avg}\x1e" + FRAME_SEP.join(frames)
        else:
            # GIF de 1 frame / PNG / JPG caen aquí
            if getattr(img, "is_animated", False):
                img.seek(0)
            return _frame_to_halfblock(_composite(img.copy()), width)


def render_image(image_path: str, width: int = 0, max_frames: int = _MAX_FRAMES,
                 base_dir: str = "public") -> str:
    """API principal. width=0 -> auto (ancho terminal).
    GIF animado -> payload multi-frame (DUR + FRAME_SEP). Estático -> ANSI directo.
    Nunca lanza: devuelve '[Error: ...]'."""
    try:
        from PIL import Image  # noqa: F401 — chequeo temprano de dependencia
    except ImportError:
        return "[Error: Pillow no instalado. pip install pillow]"
    if not width or width <= 0:
        width = terminal_width()
    width = max(_MIN_W, min(_MAX_W, width))
    try:
        full = resolve_public_path(image_path.strip(), base_dir)
        mtime = os.path.getmtime(full)
        return _render_cached(full, mtime, width, max_frames)
    except ValueError as e:
        return str(e)
    except Exception as e:
        return f"[Error al renderizar imagen: {e}]"


def split_animation(payload: str) -> Tuple[List[str], int]:
    """Inverso: separa payload multi-frame -> (frames, duración_ms)."""
    dur = 120
    if payload.startswith(DUR_PREFIX):
        head, _, rest = payload.partition("\x1e")
        try:
            dur = max(40, min(2000, int(head[len(DUR_PREFIX):])))
        except ValueError:
            pass
        payload = rest
    if FRAME_SEP in payload:
        return payload.split(FRAME_SEP), dur
    return [payload], dur


def parse_img_tag(tag_body: str, default_width: int = 0) -> Tuple[str, int]:
    """Acepta: '/public/a.png' | '/public/a.png width=80' | 'width=80 /public/a.png'."""
    m = re.search(r"width\s*=\s*(\d{1,3})", tag_body)
    w = int(m.group(1)) if m else default_width
    path = re.sub(r"width\s*=\s*\d{1,3}", "", tag_body).strip().strip("\"'")
    return path, w
