# dachs_cli_writer_tui.py

Curses/TUI Writer (mc-ähnliche Bedienung).

## Aufruf
```bash
python3 dachs_cli_writer_tui.py --block <id> [optionen]
```

## Schalter
- `--port`
- `--baud`
- `--block` (Pflicht)
- `--auth-level`
- `--auth-pass4`
- `--rx-timeout`
- `--pack-file`
- `--dry-run`

## Tasten
- Pfeile: Navigation
- Enter: Feld editieren
- F2 oder `s`: Speichern
- F4 oder `r`: Neu auslesen
- F6: Raw/Scaled umschalten
- F10 / Esc / `q`: Beenden

Hinweis: Je Terminal senden F-Tasten unterschiedliche Escape-Sequenzen; `s`/`r` funktionieren immer.
