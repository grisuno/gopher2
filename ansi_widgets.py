# ansi_widgets.py
import time
import math
from typing import Dict, Union, List

def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))

def _sanitize_key(key: str) -> str:
    if not isinstance(key, str):
        key = str(key)
    return key.replace("\n", "\\n").replace("\r", "\\r").replace("\033", "")

def _sanitize_value(value: Union[int, float]) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

def bar_chart(
    data: Dict[str, Union[int, float]],
    width: int = 50,
    max_bar_width: int = 40,
    color_map: Dict[str, str] = None
) -> str:
    if not isinstance(data, dict):
        return "[Error: bar_chart requiere un diccionario]"
    if width < 10:
        width = 10
    if width > 100:
        width = 100
    if max_bar_width < 1:
        max_bar_width = 1
    if max_bar_width > 80:
        max_bar_width = 80

    if not data:
        return "[Gráfico vacío]"

    sanitized_data = {}
    total_len = 0
    for k, v in data.items():
        sk = _sanitize_key(k)
        sv = _sanitize_value(v)
        sanitized_data[sk] = sv
        total_len += len(sk) + 20
        if total_len > 10000:  # Límite anti-DoS
            break

    if not sanitized_data:
        return "[Datos inválidos]"

    max_val = max(sanitized_data.values())
    if max_val <= 0:
        max_val = 1

    lines = []
    for label, value in sanitized_data.items():
        bar_width = int((value / max_val) * max_bar_width)
        bar = "█" * bar_width
        color = ""
        reset = "\033[0m"
        if color_map and label in color_map:
            color = color_map[label]
        elif value > max_val * 0.8:
            color = "\033[91m"  # rojo
        elif value > max_val * 0.5:
            color = "\033[93m"  # amarillo
        else:
            color = "\033[92m"  # verde
        lines.append(f"{label:<15} {color}{bar}{reset} ({value:.1f})")

    return "\n".join(lines)

def bordered_panel(title: str, content: str, style: str = "single") -> str:
    if not isinstance(content, str):
        content = str(content)
    if not isinstance(title, str):
        title = str(title)

    # Caracteres de caja
    chars = {
        "single": {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│"},
        "double": {"tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║"},
    }.get(style, {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│"})

    lines = content.split("\n")
    max_line_len = max(len(line) for line in lines) if lines else 0
    title_len = len(title)
    width = max(max_line_len, title_len, 20)
    width = min(width, 100)  # Límite anti-DoS

    top_border = f"{chars['tl']}{chars['h'] * (width + 2)}{chars['tr']}"
    title_line = f"{chars['v']} {title.center(width)} {chars['v']}"
    separator = f"{chars['v']} {' ' * width} {chars['v']}"
    content_lines = [f"{chars['v']} {line.ljust(width)} {chars['v']}" for line in lines]
    bottom_border = f"{chars['bl']}{chars['h'] * (width + 2)}{chars['br']}"

    return "\n".join([top_border, title_line, separator] + content_lines + [separator, bottom_border])

def progress_bar(value: float, max_val: float = 100.0, width: int = 30) -> str:
    if max_val <= 0:
        max_val = 100.0
    ratio = _clamp(value / max_val, 0.0, 1.0)
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    percent = ratio * 100
    color = "\033[92m" if percent >= 100 else "\033[93m" if percent >= 50 else "\033[91m"
    return f"{color}{bar}\033[0m {percent:.1f}%"

def ansi_time_theme() -> str:
    hour = time.localtime().tm_hour
    if 6 <= hour < 12:
        return "\033[96m"  # cian - mañana
    elif 12 <= hour < 18:
        return "\033[93m"  # amarillo - tarde
    elif 18 <= hour < 22:
        return "\033[95m"  # magenta - noche
    else:
        return "\033[90m"  # gris oscuro - madrugada