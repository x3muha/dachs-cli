# dachs-cli

README (Deutsch)

## Deutsch

CLI-Tool zum Auslesen eines Senertec Dachs (MSR2) über einen optischen Lesekopf (RS232/USB-Serial-Adapter).

Hinweis: Für den Normalbetrieb (`readall-decoded`) reicht `git clone` + Python/pyserial.
Kein externer Source-Tree nötig.

### Features (aktueller Stand)

- MSR2 Telegramm-Transport (inkl. CRC)
- stabiler Block-Scan mit konfigurierbarem Intervall
- Dekodierung über vorbereitete Mapping-Dateien:
  - `msr2_pack_master.json` (Struktur + Faktoren + Einheiten)
  - `labels_master.properties` (deutsche Labels)
- Ausgabe standardmäßig: `Label [Key] = Wert Einheit`
- Ausgabe optional umschaltbar:
  - `--text-only` => nur Label
  - `--key-only` => nur `[Key]`

### Installation (frisches Raspberry Pi OS / Raspbian)

#### 1) Systempakete installieren

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip python3-serial
```

#### 2) Repository klonen

```bash
git clone git@github.com:x3muha/dachs-cli.git
cd dachs-cli
```

#### 3) Python-Umgebung erstellen

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install pyserial
```

#### 4) Serielle Berechtigung setzen (wichtig)

```bash
sudo usermod -aG dialout $USER
```
Danach einmal neu einloggen (oder reboot), damit `/dev/ttyUSB*` nutzbar ist.

#### 5) Optional: UTF-8 für korrekte Umlaute

```bash
echo 'export LANG=C.UTF-8' >> ~/.bashrc
echo 'export LC_ALL=C.UTF-8' >> ~/.bashrc
echo 'export PYTHONIOENCODING=utf-8' >> ~/.bashrc
source ~/.bashrc
```

### Nutzung

```bash
# Ein Block dekodiert lesen
python dachs_cli.py --port /dev/ttyUSB0 read-block --block 22

# Standard-Liveabfrage (ohne --blocks): 20,22,24,26
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded

# Mehrere Blöcke dekodiert lesen (Default-Intervall 3.5s)
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded --blocks 20,22,24,26

# Vollscan über alle gängigen Blöcke
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded \
  --blocks 18,20,22,24,26,28,30,31,32,34,36,50,52,54,56,60,62,66,70,76,80,82,84,86,88,90,92,94,100,102,104,110,112,114

# Reserve-/Res-Felder zusätzlich einblenden
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded --blocks 24 --show-reserved

# Nur Textlabels anzeigen (ohne [Key])
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded --blocks 24 --text-only

# Nur technische Keys anzeigen (ohne Label)
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded --blocks 24 --key-only

# Optional: eigene Pack-/Label-Dateien erzwingen
# (nur nötig, wenn du die Dateien selbst geändert hast oder sie nicht im Startverzeichnis liegen)
python dachs_cli.py --port /dev/ttyUSB0 readall-decoded --blocks 24 \
  --pack-file /pfad/zu/msr2_pack_master.json \
  --labels-file /pfad/zu/labels_master.properties

# Link-/Transporttest
python dachs_cli.py --port /dev/ttyUSB0 watch-link --count 20 --interval 0.5
```

### Schalter / Optionen (wichtig)

Global:
- `--port` (Default: `/dev/ttyUSB0`)
- `--baud` (Default: `19200`)

`read-block`:
- `--block` (Pflicht)
- `--packet` (Default: `0`)
- `--rx-timeout`

`readall`:
- `--blocks` (CSV)
- `--interval` (Default: `3.5`)
- `--loops`
- `--rx-timeout`

`readall-decoded`:
- `--blocks` (CSV, Default: `20,22,24,26`)
- `--interval` (Default: `3.5`)
- `--loops`
- `--rx-timeout`
- `--pack-file` (optional, auto-lookup wenn nicht gesetzt)
- `--labels-file` (optional, auto-lookup wenn nicht gesetzt)
- `--show-reserved` (Reservefelder anzeigen)
- `--text-only` (nur Textlabel anzeigen)
- `--key-only` (nur `[Key]` anzeigen)

`watch-link`:
- `--count`
- `--interval`
- `--rx-timeout`

### Blockübersicht

Siehe: `BLOCKS.md`

### Wichtige Dateien

- `dachs_cli.py` – Haupt-CLI
- `build_msr2_map.py` – baut Master-Map aus Source/XML/Properties
- `msr2_master_map.json` – kombinierte Mapping-Basis
- `msr2_pack_master.json` – Laufzeit-Pack für Decode/Faktor/Einheiten
- `labels_master.properties` – deutsche Labelzuordnung
- `servicecodes_de.properties` – Servicecode-Texte (bundled, lokal)
- `meldehist_types_de.properties` – MeldeHIST-Typtexte (bundled, lokal)
