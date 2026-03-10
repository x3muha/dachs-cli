# build_msr2_map.py

Erzeugt aus dem dachsweb-Source-Tree eine konsolidierte MSR2-Mapping-Datei.

## Aufruf
```bash
python3 build_msr2_map.py [--base <pfad>] [--regler <id>] [--out <datei>]
```

## Schalter
- `--base`
  - Pfad zu `.../source/senertec/dachsweb`
  - Optional; bei Standard-Setup meist nicht nötig.
- `--regler`
  - Regler-ID, z. B. `5`
  - Default: `5`
- `--out`
  - Ausgabedatei
  - Beispiel: `msr2_master_map.json`

## Beispiel
```bash
python3 build_msr2_map.py --base /root/senertec/source/senertec/dachsweb --regler 5 --out msr2_master_map.json
```
