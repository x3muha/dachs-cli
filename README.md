# dachs-cli v2

CLI-/TUI-Toolset für MSR2-Regler (lesen, dekodieren, sichern, schreiben).
Alle v2-Tools nutzen das versionierte Pack (`msr2_pack_master_version.json`) und `dachs_core.py` als gemeinsame Basis.

## Anwendungen (kurz)

- `dachs_cli_v2.py`  
  Lesen/Decodieren von Blöcken (`read-block`, `readall`, `readall-decoded`).

- `msr_backup_v2.py`  
  Vollständiger Backup-Lauf (2 Passes), Auth, Diff zwischen Pass1/Pass2.

- `dachs_cli_writer_tui_v2.py`  
  Interaktive TUI zum Anzeigen/Ändern/Speichern von Feldern inkl. Auth, Blockwechsel, optional Hex-Ansicht.

- `auth_v2.py`  
  Reiner Auth-Call (PW4-Berechnung + Level-Request/Grant).

---

## `dachs_cli_v2.py`

### Global
- `--port` (Default `/dev/ttyUSB0`)
- `--baud` (Default `19200`)

### `watch-link`
- `--count`
- `--interval`
- `--rx-timeout`

### `read-block`
- `--block` (Pflicht)
- `--packet`
- `--rx-timeout`

### `readall`
- `--blocks` (CSV)
- `--interval`
- `--loops`
- `--rx-timeout`
- `--wait-between-blocks` (optional; wenn gesetzt überschreibt Intervall als Block-Wartezeit)

### `readall-decoded`
- `--blocks` (CSV)
- `--interval`
- `--loops`
- `--rx-timeout`
- `--wait-between-blocks` (optional)
- `--data-xml`
- `--struct-dir`
- `--format-dir`
- `--pack-file` (Default: versioniertes Pack)
- `--pack-rev` (Default: `50`)
- `--labels-file`
- `--show-reserved`
- `--text-only`
- `--key-only`
- `--show-msr-menu-code`

### `list-keys`
- `--mapping`
- `--limit`

---

## `msr_backup_v2.py`

- `--port`
- `--baud`
- `--rx-timeout`
- `--pause-between-passes`
- `--pause-between-blocks`
- `--wait-between-blocks` (Alias zu `pause-between-blocks`)
- `--blocks` (CSV Override; ohne Angabe: alle bekannten Blöcke aus Pack)
- `--pack-file`
- `--pack-rev`
- `--output`
- `--no-decode`
- `--auth-level` (Default `5`, `<0` = Auth skip)
- `--auth-pass4`
- `--no-flush-before-read`
- `--retry-on-timeout`

---

## `dachs_cli_writer_tui_v2.py`

- `--port`
- `--baud`
- `--block` (Startblock)
- `--all-blocks` (lädt bekannte Blöcke und erlaubt schnellen Blockwechsel)
- `--auth-level` (Default `5`)
- `--auth-pass4`
- `--rx-timeout`
- `--wait-between-blocks`
- `--pack-file`
- `--pack-rev`
- `--dry-run`
- `--show-reserved`
- `--no-hex`

### TUI-Shortcuts
- `↑/↓`, `PgUp/PgDn`: Navigation
- `Enter`: Inline-Edit im Feld
- `b`: Block-Auswahlmodus (mit `↑/↓`, `Enter`)
- `F2` / `s`: Speichern
- `F4` / `r`: Reload
- `F6`: Raw-Mode umschalten
- `F10` / `Esc` / `q`: Beenden

---

## `auth_v2.py`

- `--port`
- `--baud`
- `--rx-timeout`
- `--auth-level` (Pflicht)
- `--auth-pass4` (optional)
- `--retries`
- `--json`

---

## Kern-/Daten-Dateien

- `dachs_core.py` – gemeinsamer Transport/Decode/Batch-Read-Core
- `msr2_pack_master_version.json` – versioniertes Layout/Mapping
- `msr2_formats_v2.json` – Format-/Value-Mapping
- `msr_transport.py`, `msr_read.py`, `msr_decode.py` – modulare Re-Exports auf v2-Core
