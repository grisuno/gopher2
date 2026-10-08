# orphans

*Community 1 | 2 files | cohesion 0.00*

## Definition

This community groups 2 file(s) rooted at `root` with dominant language py (cohesion 0.00). Central symbols: `error`, `log`. Core file: `install.sh` (2 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `install.sh` | sh | utility | 2 | yes |

## Key Symbols

- `log` (function, `install.sh:9`)
- `error` (function, `install.sh:13`)

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- What would break if the most connected file in orphans changed?
- Should orphans be split, given cohesion 0.00?

## Sources

- `app.py`
- `install.sh`
