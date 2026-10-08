# Second Brain

*Last synthesized: 2026-10-07 | 6 files | 2 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `server.py`, `image_renderer.py`, `client.py`. Architecturally it is 3 layers, dominant utility (3 files) across 2 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Communities are self-contained in the resolved import graph; no cross-boundary bridges were recorded.

Open work clusters around documentation (100% file coverage), 0 security findings, 0 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 6 |
| Symbols | 66 |
| Resolved imports | 5 |
| Languages | py, sh |
| Communities | 2 |
| Doc coverage | 100% (6/6 files) |
| Security findings | 0 |
| Estimated read cost | ~1598 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target readmenator_gopher2_1mww3v1t
```

## Concept Wiki

- [root (4 files, cohesion 1.00)](./community_0_root.md)
- [orphans (2 files, cohesion 0.00)](./community_1_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `server.py` | 6.7 |
| `image_renderer.py` | 4.8 |
| `client.py` | 4.2 |
| `ansi_widgets.py` | 2.7 |
| `install.sh` | 0.2 |

## Strongest Connections

- No cross-community connections recorded.

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
