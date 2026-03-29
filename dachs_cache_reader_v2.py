#!/usr/bin/env python3
import argparse, json, time
from pathlib import Path
from core import dachs_core as dc
import dachs_cli_v2 as v2


def materialize(pack_file: Path, rev: str, blocks: list[int]):
    tmp_pack, _ = v2._materialize_pack_for_blocks(pack_file, blocks, str(rev), fallback_formats=(Path('core/msr2_formats_v2.json') if Path('core/msr2_formats_v2.json').exists() else Path('msr2_formats_v2.json')))
    p = json.loads(Path(tmp_pack).read_text())
    return p.get('layouts', {}), p.get('formats', {})


def load_points(path: Path):
    cfg = json.loads(path.read_text())
    pts = [p for p in (cfg.get('points') or []) if isinstance(p, dict) and p.get('aktiv') and str(p.get('knx_adresse','')).strip()]
    return cfg, pts


def main():
    ap = argparse.ArgumentParser(prog='dachs_cache_reader_v2')
    ap.add_argument('--points', default='knx/config/knx_points_v2.json')
    ap.add_argument('--cache', default='cache/dachs_cache_v2.json')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--rx-timeout', type=float, default=0.9)
    ap.add_argument('--wait-between-blocks', type=float, default=0.0)
    ap.add_argument('--interval', type=float, default=60.0)
    ap.add_argument('--once', action='store_true')
    args = ap.parse_args()

    cfg, pts = load_points(Path(args.points))
    if not pts:
        print('Keine aktiven Punkte konfiguriert.')
        return

    blocks = sorted(set(int(p['block']) for p in pts))
    layouts, formats = materialize(Path(cfg.get('pack_file','msr2_pack_master_version.json')), cfg.get('pack_rev','50'), blocks)

    while True:
        payloads = dc.read_blocks_batch(args.port, args.baud, blocks, args.rx_timeout,
                                        wait_between_blocks=args.wait_between_blocks,
                                        flush_before_read=True,
                                        retry_on_timeout=1)
        values = {}
        for b, payload in (payloads or {}).items():
            lay = layouts.get(str(int(b)), [])
            dec = dc._decode_fields(payload, lay)
            for k, v in dec.items():
                vv, unit = dc._apply_format(k, v, formats)
                values[k] = {
                    'block': int(b),
                    'raw': v,
                    'value': vv,
                    'unit': unit,
                    'ts': int(time.time())
                }

        out = {
            'schema': 'dachs-cache/v1',
            'updated_unix': int(time.time()),
            'count': len(values),
            'values': values,
        }
        Path(args.cache).write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
        print(f"cache updated: {args.cache} ({len(values)} keys)")

        if args.once:
            break
        time.sleep(max(0.0, float(args.interval)))


if __name__ == '__main__':
    main()
