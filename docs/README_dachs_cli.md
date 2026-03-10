# dachs_cli.py — Handbuch

Reader/Decoder für MSR2 über Serial.

## Syntax
```bash
python3 dachs_cli.py [--port /dev/ttyUSB0] [--baud 19200] <subcommand> [optionen]
```

## Globale Schalter
- `--port` Serial-Port (Default `/dev/ttyUSB0`)
- `--baud` Baudrate (Default `19200`)

## Subcommands

### watch-link
Transporttest.
Schalter: `--count`, `--interval`, `--rx-timeout`

### read-block
Einzelblock lesen.
Schalter: `--block` (Pflicht), `--packet`, `--rx-timeout`

### readall
Mehrere Blöcke zyklisch lesen.
Schalter: `--blocks`, `--interval`, `--loops`, `--rx-timeout`

### readall-decoded
Dekodierte Ausgabe mit Labels/Einheiten.
Schalter:
- `--blocks`
- `--interval`
- `--loops`
- `--rx-timeout`
- `--data-xml`
- `--struct-dir`
- `--format-dir`
- `--pack-file`
- `--labels-file`
- `--show-reserved`
- `--text-only`
- `--key-only`

### list-keys
Extrahierte Keys/Mappings anzeigen.

## Beispiele
```bash
python3 dachs_cli.py --port /dev/ttyUSB0 watch-link --count 10 --interval 0.5
python3 dachs_cli.py --port /dev/ttyUSB0 read-block --block 22 --rx-timeout 2.0
python3 dachs_cli.py --port /dev/ttyUSB0 readall-decoded --blocks 20,22,24,26 --loops 1 --interval 0.2 --rx-timeout 2.0
```
