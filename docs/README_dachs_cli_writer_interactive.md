# dachs_cli_writer_interactive.py

Prompt-basierter interaktiver Writer.

## Aufruf
```bash
python3 dachs_cli_writer_interactive.py --block <id> [optionen]
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

## Prompt-Befehle
- `show` Werte anzeigen
- `set <key> <value>` skaliert setzen
- `setraw <key> <raw>` Rohwert setzen
- `setdate <key> DD.MM.YYYY` Datum direkt setzen
- `save` speichern
- `quit` abbrechen
