# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `server.py` (score: 6.70)
- `image_renderer.py` (score: 4.80, imported by 2 files)
- `client.py` (score: 4.20)
- `ansi_widgets.py` (score: 2.70, imported by 1 files)
- `install.sh` (score: 0.20)
- `app.py` (score: 0.00)

## Blast Radius (change impact)

Editing these files can break the listed number of dependents. Run their tests after any change.

- `image_renderer.py` -- 2 direct, 2 total dependents
- `ansi_widgets.py` -- 1 direct, 1 total dependents

## Hotspots (complexity + centrality)

- `server.py` -- complexity: 1.0, centrality: 1.0, combined: 1.0
- `client.py` -- complexity: 0.8, centrality: 0.6, combined: 0.7
- `image_renderer.py` -- complexity: 0.3, centrality: 0.4, combined: 0.3
- `ansi_widgets.py` -- complexity: 0.3, centrality: 0.1, combined: 0.2
- `install.sh` -- complexity: 0.1, centrality: 0.0, combined: 0.0
- `app.py` -- complexity: 0.0, centrality: 0.0, combined: 0.0

## Dataflow Issues (INFERRED, review each lead)

- `server.py:573` `main` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
