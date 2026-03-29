#!/usr/bin/env python3
import argparse
import json
import time
from pathlib import Path

from core import dachs_core as dc


def calc_pw4(serial: str, bstd_hours: int) -> str:
    n = int(serial[-3:]) if serial and serial[-3:].isdigit() else 0
    return f"{(n + 2749 + ((bstd_hours % 10000) // 2)) & 0xFFFF:04d}"


def _read_block_with_retry(ser, block: int, timeout: float, retries: int = 3):
    pn = 0
    for attempt in range(retries + 1):
        try:
            ser.reset_input_buffer()
        except Exception:
            pass
        dc.send_service(ser, b'', pn, timeout); pn = (pn + 1) & 0x0F
        _, _, rx, _ = dc.send_service(ser, bytes([block & 0xFF]), pn, timeout)
        if rx and len(rx) >= 8 and rx[0] == 0x02:
            payload = rx[5:-2][1:]
            if payload:
                return payload
        if attempt < retries:
            time.sleep(0.2)
    return None


def do_auth(port: str, baud: int, timeout: float, level: int, pass4_override: str | None, retries: int = 3):
    pack_path = (Path('core/msr2_pack_master_version.json') if Path('core/msr2_pack_master_version.json').exists() else Path('msr2_pack_master_version.json'))
    obj = json.loads(pack_path.read_text())
    if isinstance(obj.get('layouts'), dict):
        layouts = obj.get('layouts', {})
    else:
        import dachs_cli_v2 as v2
        tmp_pack, _tmp_labels = v2._materialize_pack_for_blocks(pack_path, [20,22], '50', fallback_formats=(Path('core/msr2_formats_v2.json') if Path('core/msr2_formats_v2.json').exists() else Path('msr2_formats_v2.json')))
        layouts = json.loads(Path(tmp_pack).read_text()).get('layouts', {})
    ser = dc.open_port(port, baud)
    if not ser:
        return {'ok': False, 'error': 'open_port_failed'}

    try:
        with ser:
            p20 = _read_block_with_retry(ser, 20, timeout, retries)
            p22 = _read_block_with_retry(ser, 22, timeout, retries)
            if not p20 or not p22:
                return {'ok': False, 'error': 'read_20_22_failed'}

            d20 = dc._decode_fields(p20, layouts.get('20', []))
            d22 = dc._decode_fields(p22, layouts.get('22', []))

            serial = str(d20.get('Hka_Bd_Stat.uchSeriennummer', '')).strip()
            bstd_hours = int(d22.get('Hka_Bd.ulBetriebssekunden', 0) or 0) // 3600
            computed_pw4 = calc_pw4(serial, bstd_hours)

            pw4 = pass4_override.strip() if pass4_override else computed_pw4
            if len(pw4) != 4 or not pw4.isdigit():
                return {'ok': False, 'error': 'invalid_pw4'}

            pn = 0
            dc.send_service(ser, b'', pn, timeout); pn = (pn + 1) & 0x0F
            auth = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), level & 0xFF])
            _, ack, rx_auth, _ = dc.send_service(ser, auth, pn, timeout)

            granted = None
            if rx_auth and rx_auth[0] == 0x02 and len(rx_auth) >= 8:
                data = rx_auth[5:-2]
                if len(data) >= 2 and data[0] == 0xFE:
                    granted = int(data[1])

            ok = granted == level
            return {
                'ok': ok,
                'requested': level,
                'granted': granted,
                'serial': serial,
                'bstd_hours': bstd_hours,
                'computed_pw4': computed_pw4,
                'pw4_used': pw4,
                'ack': dc.to_hex(ack) if ack else None,
                'rx': dc.to_hex(rx_auth) if rx_auth else None,
            }
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def main():
    ap = argparse.ArgumentParser(prog='auth.py', description='Standalone MSR auth helper')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--rx-timeout', type=float, default=2.0)
    ap.add_argument('--auth-level', type=int, required=True)
    ap.add_argument('--auth-pass4', default='')
    ap.add_argument('--retries', type=int, default=3)
    ap.add_argument('--json', action='store_true', help='machine-readable JSON output')
    args = ap.parse_args()

    res = do_auth(args.port, args.baud, args.rx_timeout, int(args.auth_level), args.auth_pass4 or None, max(0, int(args.retries)))

    if args.json:
        print(json.dumps(res, ensure_ascii=False))
    else:
        if res.get('ok'):
            print(f"OK requested={res.get('requested')} granted={res.get('granted')} pw4={res.get('pw4_used')} serial={res.get('serial')} bstd={res.get('bstd_hours')}")
        else:
            print(f"NOT_OK error={res.get('error', '-')} requested={res.get('requested')} granted={res.get('granted')} pw4={res.get('pw4_used')}")

    return 0 if res.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
