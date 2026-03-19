# dachs-cli v2

CLI-/TUI-Toolset für MSR2-Regler (lesen, dekodieren, sichern, schreiben).
Alle v2-Tools nutzen das versionierte Pack (`msr2_pack_master_version.json`) und `dachs_core.py` als gemeinsame Basis.

## Anwendungen

- `dachs_cli_v2.py`  
  Lesen/Decodieren von Blöcken (`read-block`, `readall`, `readall-decoded`, `watch-link`).
- `msr_backup_v2.py`  
  Backup mit 2 Lese-Pässen, Auth, Diff zwischen Pass1/Pass2.
- `dachs_cli_writer_tui_v2.py`  
  Interaktive TUI zum Anzeigen/Ändern/Speichern mit Auth und Blockwechsel.
- `auth_v2.py`  
  Nur Authentifizierung (PW4, angeforderter/granteter Level).

---

## `dachs_cli_v2.py`

### Global
- `--port`  
  Serial-Port (Standard: `/dev/ttyUSB0`).
- `--baud`  
  Baudrate (Standard: `19200`).

### `watch-link`
- `--count`  
  Anzahl Keepalive-/Watch-Zyklen.
- `--interval`  
  Pause zwischen Zyklen in Sekunden.
- `--rx-timeout`  
  Timeout für Antworten vom Regler.

### `read-block`
- `--block`  
  Zu lesender Block (Pflicht).
- `--packet`  
  Start-Paketnummer (PN) für den Request.
- `--rx-timeout`  
  Timeout für den Block-Read.

### `readall`
- `--blocks`  
  CSV-Liste der Blöcke (`20,22,24,...`).
- `--interval`  
  Standardwartezeit zwischen Block-Reads.
- `--loops`  
  Wie oft die Blockliste komplett gelesen wird.
- `--rx-timeout`  
  Timeout je Block.
- `--wait-between-blocks`  
  Explizite Wartezeit zwischen Blöcken; überschreibt `--interval`.

### `readall-decoded`
- `--blocks`  
  CSV-Liste der zu dekodierenden Blöcke.
- `--interval`  
  Standardwartezeit zwischen Blöcken.
- `--loops`  
  Anzahl kompletter Lese-Durchläufe.
- `--rx-timeout`  
  Timeout je Block.
- `--wait-between-blocks`  
  Explizite Wartezeit pro Block; überschreibt `--interval`.
- `--data-xml`  
  Pfad zur Data-XML (Legacy/XML-Pfad).
- `--struct-dir`  
  XML-Strukturverzeichnis für Legacy-Decodepfade.
- `--format-dir`  
  Format-/Properties-Verzeichnis für Legacy-Decodepfade.
- `--pack-file`  
  Pack-Datei mit Layout/Format (Standard: versioniertes Pack).
- `--pack-rev`  
  Zielrevision im versionierten Pack (Standard: `50`).
- `--labels-file`  
  Zusätzliche Label-Datei (`*.properties`) für Anzeigenamen.
- `--show-reserved`  
  Reservierte/uninteressante Felder mit anzeigen.
- `--text-only`  
  Nur Klartextlabel anzeigen (ohne `[key]`).
- `--key-only`  
  Nur technische Keys anzeigen (ohne Label).
- `--show-msr-menu-code`  
  Handbuch-/Menücode (`msr_menu_code`) neben Feldwert anzeigen.

### `list-keys`
- `--mapping`  
  Mapping-Datei als Quelle für Key-Liste.
- `--limit`  
  Maximalzahl auszugebender Keys.

---

## `msr_backup_v2.py`

- `--port`  
  Serial-Port.
- `--baud`  
  Baudrate.
- `--rx-timeout`  
  Timeout pro Blockread.
- `--pause-between-passes`  
  Wartezeit zwischen Pass1 und Pass2.
- `--pause-between-blocks`  
  Wartezeit zwischen Blöcken.
- `--wait-between-blocks`  
  Alias für `--pause-between-blocks`.
- `--blocks`  
  CSV-Override der Blockliste; ohne Angabe: alle bekannten Blöcke aus Pack.
- `--pack-file`  
  Verwendete Pack-Datei.
- `--pack-rev`  
  Zielrevision für pack-basiertes Materialisieren.
- `--output`  
  Ausgabedatei für Backup-JSON.
- `--no-decode`  
  Nur Rohdaten sichern, ohne Decode-Abschnitte.
- `--auth-level`  
  Gewünschter Auth-Level (Default `5`, `<0` = Auth überspringen).
- `--auth-pass4`  
  PW4 explizit vorgeben statt berechnen.
- `--no-flush-before-read`  
  Kein Input-Buffer-Flush vor Read.
- `--retry-on-timeout`  
  Retries pro Block bei Timeout/leerem Read.

---

## `dachs_cli_writer_tui_v2.py`

- `--port`  
  Serial-Port.
- `--baud`  
  Baudrate.
- `--block`  
  Startblock beim Öffnen der TUI.
- `--all-blocks`  
  Preload/Cache für bekannte Blöcke aktivieren (schneller Blockwechsel).
- `--auth-level`  
  Gewünschter Auth-Level für Schreiben.
- `--auth-pass4`  
  PW4 manuell vorgeben.
- `--rx-timeout`  
  Timeout je Read/Write-Operation.
- `--wait-between-blocks`  
  Wartezeit zwischen Block-Reads im Batch/Preload.
- `--pack-file`  
  Pack-Datei für Layout/Formats.
- `--pack-rev`  
  Zielrevision im versionierten Pack.
- `--dry-run`  
  Änderungen lokal testen, ohne echten Write.
- `--show-reserved`  
  Reservierte Felder anzeigen.
- `--hide-name`  
  Name-Spalte ausblenden (mehr Platz für Wert/Raw).
- `--hide-object` / `--hide-objekt`  
  Objekt-Spalte ausblenden (mehr Platz für Wert/Raw).
- `--no-hex`  
  HEX-Bereich unten ausblenden.

### TUI-Shortcuts
- `↑/↓`, `PgUp/PgDn`: Feldnavigation
- `←/→`: Block vor/zurück
- `Enter`: Inline-Edit
- `b`: Blockliste öffnen (`↑/↓`, `Enter`, `Esc`)
- `n`: Name-Spalte live ein/aus
- `o`: Objekt-Spalte live ein/aus
- `F2` / `s`: Speichern
- `F4` / `r`: Reload aktueller Block
- `F6`: Raw-Mode umschalten
- `F10` / `Esc` / `q`: Beenden

---

## `auth_v2.py`

- `--port`  
  Serial-Port.
- `--baud`  
  Baudrate.
- `--rx-timeout`  
  Timeout für Auth-Frames.
- `--auth-level`  
  Anzufordernder Auth-Level (Pflicht).
- `--auth-pass4`  
  PW4 manuell (sonst automatisch berechnet).
- `--retries`  
  Wiederholungen bei fehlender/ungültiger Antwort.
- `--json`  
  Ausgabe als JSON (maschinenlesbar).

---

## Kern-/Daten-Dateien

- `dachs_core.py` – gemeinsamer Transport/Decode/Batch-Read-Core
- `msr2_pack_master_version.json` – versioniertes Layout/Mapping
- `msr2_formats_v2.json` – Format-/Value-Mapping
- `labels_master.properties` – lokale Label-/Suffix-Overrides
- `msr_transport.py`, `msr_read.py`, `msr_decode.py` – modulare Re-Exports auf v2-Core

---

## Startbeispiele (Copy & Paste)

### `dachs_cli_v2.py`

- Link beobachten (5 Zyklen):
```bash
python3 dachs_cli_v2.py --port /dev/ttyUSB0 watch-link --count 5 --interval 1
```

- Einzelnen Block roh lesen:
```bash
python3 dachs_cli_v2.py --port /dev/ttyUSB0 read-block --block 20
```

- Mehrere Blöcke lesen (roh):
```bash
python3 dachs_cli_v2.py --port /dev/ttyUSB0 readall --blocks 20,22,24 --loops 1 --wait-between-blocks 0
```

- Dekodiert lesen (Block 18):
```bash
python3 dachs_cli_v2.py --port /dev/ttyUSB0 readall-decoded --blocks 18 --pack-rev 50 --loops 1
```

- Dekodiert lesen mit Menücodes:
```bash
python3 dachs_cli_v2.py --port /dev/ttyUSB0 readall-decoded --blocks 20,22 --pack-rev 50 --show-msr-menu-code
```

### `msr_backup_v2.py`

- Standard-Backup (alle bekannten Pack-Blöcke):
```bash
python3 msr_backup_v2.py --port /dev/ttyUSB0 --pack-rev 50
```

- Backup mit eigener Blockliste:
```bash
python3 msr_backup_v2.py --port /dev/ttyUSB0 --blocks 18,20,22,24,26 --pack-rev 50
```

- Backup ohne Decode (nur Rohdaten):
```bash
python3 msr_backup_v2.py --port /dev/ttyUSB0 --no-decode --pack-rev 50
```

### `dachs_cli_writer_tui_v2.py`

- TUI auf Startblock 20 (nur aktueller Block, kein All-Blocks-Preload):
```bash
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --block 20 --pack-rev 50
```

- TUI auf Block 20 + Rest im Hintergrund puffern (`--all-blocks`):
```bash
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --block 20 --pack-rev 50 --all-blocks --rx-timeout 0.9 --wait-between-blocks 0
```

- TUI auf Block 18 (Meldungsliste) mit All-Blocks-Buffer:
```bash
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --block 18 --pack-rev 50 --all-blocks
```

- TUI Dry-Run (Änderungen testen ohne echten Write):
```bash
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --block 22 --pack-rev 50 --dry-run
```

### `auth_v2.py`

- Auth-Level 5 als JSON testen:
```bash
python3 auth_v2.py --port /dev/ttyUSB0 --auth-level 5 --json
```

- Auth mit manuellem PW4:
```bash
python3 auth_v2.py --port /dev/ttyUSB0 --auth-level 5 --auth-pass4 3478 --json
```


- TUI mit maximalem Platz für Wert/Raw (Name+Objekt aus):
```bash
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --block 18 --pack-rev 50 --all-blocks --hide-name --hide-object
```
