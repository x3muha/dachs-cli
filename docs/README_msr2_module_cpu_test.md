# msr2_module_cpu_test.py

Diagnose-Skript für Modul/CPU-Adressierung beim Schreiben.

## Aufruf
```bash
python3 msr2_module_cpu_test.py [optionen]
```

## Schalter
- `--port`
- `--baud`
- `--module`
- `--cpu`
- `--timeout`
- `--auth-level`
- `--auth-pass4`
- `--write-name`

## Zweck
Vergleicht Verhalten bei unterschiedlichen `module/cpu`-Kombinationen (Read/Auth/Write/Readback).
