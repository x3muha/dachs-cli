# dachs_cli_writer.py

Nicht-interaktiver Writer für genau **einen Key** pro Aufruf.
Ablauf: Read -> Auth -> Modify -> Write -> Verify.

## Aufruf
```bash
python3 dachs_cli_writer.py -block <id> -wert <KEY> <VALUE> [optionen]
```

## Schalter
- `--port` Serial-Port (Default `/dev/ttyUSB0`)
- `--baud` Baudrate (Default `19200`)
- `-block`, `--block` Zielblock
- `-wert`, `--wert KEY VALUE` Key + Zielwert
- `--auth-level` gewünschtes Auth-Level
- `--auth-pass4` 4-stelliges Passwort-Override
- `--auth-probe` Auth-Testmodus (kein Write)
- `--auth-probe-pass4` CSV-Passwörter für Probe
- `--auth-probe-levels` CSV-Level für Probe
- `--force-auth` Auth immer neu ausführen
- `--query-auth-level` nur Auth-Level abfragen, kein Write
- `--debug` zusätzliche Debug-Ausgaben
- `--rx-timeout` Timeout in Sekunden
- `--flush-before-read` Buffer vor Reads leeren (Default aktiv)
- `--no-flush-before-read` Flush deaktivieren
- `--pack-file` Pack-Datei (`msr2_pack_master.json`)
- `--dry-run` nichts schreiben, nur vorbereiten
- `--raw-value` VALUE als Rohwert schreiben (ohne Skalierung)
- `--list-writable` write-fähige Blöcke/Keys aus XML zeigen
- `--data-xml` XML-Datei für `--list-writable`
- `--struct-dir` Struct-Verzeichnis für `--list-writable`

## Beispiele
```bash
# skaliert
python3 dachs_cli_writer.py -block 50 -wert Hka_Ew.usSollGenerator 5.3 --auth-level 5

# roh
python3 dachs_cli_writer.py -block 22 -wert Hka_Bd.ulBetriebssekunden 220627466 --auth-level 5 --raw-value

# nur Auth abfragen
python3 dachs_cli_writer.py -block 110 -wert Adresse1.aName1 X --auth-level 5 --query-auth-level
```
