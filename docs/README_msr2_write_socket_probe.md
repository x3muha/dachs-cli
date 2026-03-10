# msr2_write_socket_probe.py

Low-Level Probe für Read/Auth/Write inklusive Rohframe-Ausgabe.

## Aufruf
```bash
python3 msr2_write_socket_probe.py --block <id> --key <KEY> --value <VALUE> --auth-pass4 <PW4> [optionen]
```

## Schalter
- `--port`
- `--baud`
- `--block` (Pflicht)
- `--key` (Pflicht)
- `--value` (Pflicht)
- `--auth-level`
- `--auth-pass4` (Pflicht)
- `--pack-file`
- `--data-xml`
- `--timeout`
- `--dry-run`
