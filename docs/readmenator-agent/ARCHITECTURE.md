# Architecture

## Internal Dependencies

- `client.py` -> `image_renderer.py`
- `server.py` -> `ansi_widgets.py`
- `server.py` -> `image_renderer.py`

## External Imports

- `ansi_widgets.py` -> math, time, typing
- `app.py` -> os
- `client.py` -> argparse, base64, cryptography.exceptions, cryptography.hazmat.primitives, cryptography.hazmat.primitives.asymmetric, cryptography.hazmat.primitives.ciphers.aead, cryptography.hazmat.primitives.kdf.hkdf, json, logging, os, re, shutil, socket, sys, time, urllib.parse
- `image_renderer.py` -> PIL, functools, os, re, shutil, typing
- `server.py` -> PIL, cryptography.hazmat.primitives, cryptography.hazmat.primitives.asymmetric, cryptography.hazmat.primitives.ciphers.aead, cryptography.hazmat.primitives.kdf.hkdf, datetime, html, io, json, logging, os, re, signal, socket, sys, threading, time, urllib.parse
