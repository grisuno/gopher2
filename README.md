# Gopher 2.0

<img width="720" height="720" alt="image" src="https://github.com/user-attachments/assets/0545fc20-c99f-446d-8bce-8b916d1ae553" />


Un protocolo minimalista inspirado en Gopher, pero con:
- **Contenido dinámico** (mediante bloques `<python>...</python>` ejecutados en el servidor)
- **Cifrado de extremo a extremo** (AES-256-GCM con clave precompartida)
- **Sin JavaScript, sin HTTP, sin rastreo**

Ideal para:
- Sitios privados cifrados
- APIs minimalistas
- Canales de comunicación seguros
- Experimentación con redes alternativas

<img width="5179" height="9036" alt="NotebookLM Mind Map (1)" src="https://github.com/user-attachments/assets/68ecc493-38c4-4db1-ac2e-961d0c144346" />


---

## 🔐 Filosofía de seguridad

- **El cliente nunca ejecuta código**: solo descifra y muestra texto.
- **El servidor ejecuta Python en entorno restringido**: sin `os`, `subprocess`, ni `import` arbitrario.
- **Toda comunicación es opaca sin la clave AES**.
- **Validación estricta** de selectores, tamaños y formatos.

---

## 🚀 Instalación

```bash
git clone <tu-repo>
cd gopher2
./install.sh
```

## Requiere:

- Python 3.8+
- pip3
- Acceso a internet (para instalar cryptography)

## ▶️ Uso

1. Iniciar el servidor

```bash

./.venv/bin/python gopher2_server.py
```

Por defecto escucha en 0.0.0.0:7070.

El contenido se define en selectors.json. Ejemplo:

```json
{
  "/hello": {
    "content": "Hola\\n<python>print(f'Desde: {time.strftime(\"%H:%M\")}')</python>",
    "vars": {}
  }
}
```

2. Consultar con el cliente
```bash

./.venv/bin/python gopher2_client.py gopher://127.0.0.1:7070/hello
```
Salida:

```text
Hola
Desde: 14:30
```

3. Personalizar clave AES
Edita AES_KEY en ambos archivos (gopher2_server.py, gopher2_client.py) o usa --key en el cliente:

```bash

./.venv/bin/python gopher2_client.py --key "a1b2..." gopher://...
```
La clave debe ser 64 caracteres hexadecimales (32 bytes). 

## 📁 Estructura de archivos
server.py: servidor dinámico (como PHP en Gopher)
client.py: cliente ligero con descifrado
selectors.json: base de datos de contenido (fácil migración a MongoDB)
install.sh: instalador seguro y reproducible
requirements.txt: dependencias mínimas

## ⚠️ Advertencias
No expongas el servidor a internet sin firewall.
La clave AES debe mantenerse secreta.
Los bloques <python> solo deben contener código de confianza (definido por el administrador del servidor).

## 🧪 Pruebas rápidas
```bash
# Terminal 1
./.venv/bin/python gopher2_server.py

# Terminal 2
./.venv/bin/python gopher2_client.py gopher://127.0.0.1:7070/
```

Deberías ver la hora del servidor cifrada en tránsito y descifrada en el cliente.

Gopher 2.0 no es un reemplazo de HTTP.
Es una alternativa para quienes valoran la simplicidad, la privacidad y el control total. 



![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 🔗 Links 
- 🔗 [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
- 🔗 [https://www.patreon.com/c/LazyOwn](https://www.patreon.com/c/LazyOwn)
- 🔗 [https://deepwiki.com/grisuno/gopher2](https://deepwiki.com/grisuno/gopher2)
- 🔗 [https://www.youtube.com/watch?v=rOWuOgCh284](https://www.youtube.com/watch?v=rOWuOgCh284)
- 🔗 [https://www.podbean.com/media/share/pb-jy5sy-19a4d5a](https://www.podbean.com/media/share/pb-jy5sy-19a4d5a)
- 🔗 [https://ko-fi.com/Y8Y2Z73AV](https://ko-fi.com/Y8Y2Z73AV)
- 🔗 [https://medium.com/@lazyown.redteam/%EF%B8%8F-gopher-2-0-when-your-website-is-a-secret-society-and-only-members-get-the-decrypted-menu-08dae04e4a42](https://medium.com/@lazyown.redteam/%EF%B8%8F-gopher-2-0-when-your-website-is-a-secret-society-and-only-members-get-the-decrypted-menu-08dae04e4a42)

