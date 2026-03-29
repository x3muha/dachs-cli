# dachs-cli v2

Sauberes v2-Toolset für MSR2 auf Raspberry Pi:
- **CLI v2** (lesen/decodieren)
- **TUI v2** (anzeigen + schreiben)
- **Backup v2** (vollständige Sicherung)

Projektstruktur (aktuell):
- `dachs_cli_v2.py` → CLI v2
- `dachs_cli_writer_tui_v2.py` → TUI v2
- `dachs_backup_v2.py` / `msr_backup_v2.py` → Backup v2
- `core/` → Core + Auth + Pack/Format/Labels
- `knx/` → KNX-Tools (v2)

---

## 1) Installation (Raspberry Pi OS, aktuell)

### 1) Systempakete
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-serial git
```

Optional (nur wenn nötig):
```bash
sudo usermod -aG dialout $USER
# danach neu einloggen
```

### 2) Repo holen
```bash
git clone git@github.com:x3muha/dachs-cli.git
cd dachs-cli
```

### 3) Python-venv für optionale Tools (z. B. KNX/xknx)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install xknx
```

### 4) Schnelltest
```bash
python3 dachs_cli_v2.py --help
python3 dachs_cli_writer_tui_v2.py --help
python3 dachs_backup_v2.py --help
```

---

## 2) CLI v2 (`dachs_cli_v2.py`)

Kurzbeschreibung:
- Liest MSR2-Blöcke roh oder dekodiert.
- Nutzt Pack/Format aus `core/` (v2-Standard).

### Schalter

**Global**
- `--port` Serial-Port (Default: `/dev/ttyUSB0`)
- `--baud` Baudrate (Default: `19200`)

**Commands**
- `watch-link`
  - `--count` Anzahl Zyklen
  - `--interval` Pause zwischen Zyklen
  - `--rx-timeout` Timeout

- `read-block`
  - `--block` Block-ID (Pflicht)
  - `--packet` Start-PN
  - `--rx-timeout` Timeout

- `readall`
  - `--blocks` CSV-Liste Blöcke
  - `--loops` Anzahl Durchläufe
  - `--interval` Standardpause
  - `--wait-between-blocks` explizite Blockpause
  - `--rx-timeout` Timeout

- `readall-decoded`
  - `--blocks` CSV-Liste Blöcke
  - `--loops` Anzahl Durchläufe
  - `--interval` / `--wait-between-blocks`
  - `--rx-timeout`
  - `--pack-file` optionales Pack-Override
  - `--pack-rev` Pack-Revision (Default `50`)
  - `--labels-file` optionales Label-Override
  - `--show-reserved` reservierte Felder anzeigen
  - `--text-only` nur Labels
  - `--key-only` nur Keys
  - `--show-msr-menu-code` Handbuchcode anzeigen

### Beispiele
```bash
# Einzelblock roh lesen
python3 dachs_cli_v2.py --port /dev/ttyUSB0 --baud 19200 read-block --block 20 --rx-timeout 0.9

# Dekodiert lesen (Hauptblöcke)
python3 dachs_cli_v2.py --port /dev/ttyUSB0 --baud 19200 readall-decoded --blocks 20,22,24 --loops 1 --pack-rev 50 --rx-timeout 0.9
```

---

## 3) TUI v2 (`dachs_cli_writer_tui_v2.py`)

Kurzbeschreibung:
- Interaktive Ansicht/Editor für Blöcke.
- Blockwechsel, Raw-Mode, Save/Reload, Auth-Flow.

### Schalter
- `--port` Serial-Port
- `--baud` Baudrate
- `--block` Startblock (Pflicht)
- `--all-blocks` bekannte Blöcke laden (schneller Wechsel)
- `--auth-level` Auth-Level (Default `5`)
- `--auth-pass4` PW4 manuell
- `--rx-timeout` Timeout
- `--wait-between-blocks` Pause zwischen Blockreads
- `--pack-file` optionales Pack-Override (sonst Auto-Detect)
- `--pack-rev` Pack-Revision (Default `50`)
- `--dry-run` Writes simulieren
- `--show-reserved` reservierte Felder anzeigen
- `--hide-name` Name-Spalte ausblenden
- `--hide-object` Objekt-Spalte ausblenden
- `--no-hex` HEX-Bereich unten ausblenden

### Beispiele
```bash
# Standard TUI
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --baud 19200 --block 18 --all-blocks --pack-rev 50 --rx-timeout 0.9

# TUI mit mehr Platz für Werte
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --baud 19200 --block 18 --all-blocks --hide-name --hide-object --pack-rev 50 --rx-timeout 0.9

# Dry-Run (kein echter Write)
python3 dachs_cli_writer_tui_v2.py --port /dev/ttyUSB0 --baud 19200 --block 22 --all-blocks --dry-run --pack-rev 50
```

### Wichtige Tasten
- `↑/↓`, `PgUp/PgDn` Feldnavigation
- `←/→` Blockwechsel
- `Enter` Edit
- `F2`/`s` Speichern
- `F4`/`r` Reload
- `F6` Raw-Mode
- `n` Name-Spalte toggle
- `o` Objekt-Spalte toggle
- `Esc`/`q`/`F10` Beenden

---

## 4) Backup v2 (`dachs_backup_v2.py`)

Kurzbeschreibung:
- Vollbackup mit Auth, Retry, optional Decode.
- Geeignet für Vergleich/Archivierung.

### Schalter
- `--port` Serial-Port
- `--baud` Baudrate
- `--rx-timeout` Timeout
- `--pause-between-passes` Pause zwischen Pass1/Pass2
- `--pause-between-blocks` Pause zwischen Blöcken
- `--wait-between-blocks` Alias für `--pause-between-blocks`
- `--blocks` CSV-Blockliste (sonst alle aus Pack)
- `--pack-file` Pack-Override
- `--pack-rev` Revision (Default `50`)
- `--output` Ausgabedatei
- `--no-decode` nur Rohdaten
- `--auth-level` Default `5` (`<0` = ohne Auth)
- `--auth-pass4` PW4 manuell
- `--no-flush-before-read` kein Flush vor Read
- `--retry-on-timeout` Retries je Block

### Beispiele
```bash
# Voller Backup-Lauf (empfohlen)
python3 dachs_backup_v2.py --port /dev/ttyUSB0 --baud 19200 --rx-timeout 0.9 --auth-level 5 --retry-on-timeout 3 --pause-between-blocks 0.05 --pause-between-passes 0.2 --pack-file core/msr2_pack_master_version.json --pack-rev 50 --output msr_backup_$(date +%Y%m%d_%H%M%S)_full.json

# Nur Rohdaten
python3 dachs_backup_v2.py --port /dev/ttyUSB0 --pack-rev 50 --no-decode --output msr_backup_raw.json
```

---


## Cache Reader

- `dachs_cache_reader_v2.py` schreibt `cache/dachs_cache_v2.json` als Quelle für den KNX-Daemon.


### KNX Daemon Cache-Reader Modus

In `knx/config/knx_dachs_daemon_config_v2.json`:
- `cache_reader.mode: "every"` → lesen, warten `interval_s`, wieder lesen
- `cache_reader.mode: "loop"` → lesen, Ende, sofort wieder lesen

`cache_reader.interval_s` wird für `mode: "every"` verwendet (Default 60s).
