#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import dachs_cli as dc


def _load_pack(path: Path):
    p = json.loads(path.read_text())
    return p.get('layouts', {}), p.get('formats', {})


def _field_map(layout):
    out = {}
    i = 0
    for f in layout:
        if f.get('kind') == 'space':
            i += int(f.get('length', 0) or 0)
            continue
        if f.get('kind') != 'data':
            continue
        key = f.get('key', '')
        typ = (f.get('type') or 'Byte').lower()
        unsigned = bool(f.get('unsigned'))
        rep = int(f.get('repeat', 1) or 1)
        arr = int(f.get('length', 0) or 0)
        n = rep if rep > 1 else (arr if arr > 1 else 1)
        sz = 1 if typ == 'byte' else 2 if typ == 'short' else 4 if typ == 'long' else (arr if typ == 'string' else 1)
        if typ == 'string':
            n = 1
        for idx in range(n):
            k = f"{key}[{idx}]" if n > 1 else key
            out[k] = {'offset': i, 'type': typ, 'unsigned': unsigned, 'size': sz, 'base_key': key}
            i += sz
    return out


def _read_block_payload(ser, block, pn, timeout):
    _tx, _ack, rx, _dt = dc.send_service(ser, bytes([block & 0xFF]), pn, timeout)
    if not rx or rx[0] != 0x02 or len(rx) < 8:
        return None
    data = rx[5:-2]
    if not data:
        return None
    return data[1:]


def _find_key_block(layouts, key):
    for b, layout in layouts.items():
        fmap = _field_map(layout)
        if key in fmap:
            return int(b)
        if key + '[0]' in fmap:
            return int(b)
    return None


def _msr_password(serial_number: str, bstd: int, auth_level: int) -> str:
    s = str(serial_number)[-3:]
    try:
        n = int(s)
    except Exception:
        n = 0
    dez = (n + 2749 + ((int(bstd) % 10000) // 2)) & 0xFFFF
    return f"{dez:04d}{int(auth_level)}"


def _set_raw(payload: bytearray, meta: dict, raw: int):
    off = meta['offset']
    typ = meta['type']
    u = meta['unsigned']
    if typ == 'byte':
        payload[off:off+1] = int(raw).to_bytes(1, 'little', signed=not u)
    elif typ == 'short':
        payload[off:off+2] = int(raw).to_bytes(2, 'little', signed=not u)
    elif typ == 'long':
        payload[off:off+4] = int(raw).to_bytes(4, 'little', signed=not u)
    else:
        raise ValueError(f"write not supported for type: {typ}")


def main():
    ap = argparse.ArgumentParser(prog='dachs_cli_writer')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('-block', '--block', type=int, default=None)
    ap.add_argument('-wert', '--wert', nargs=2, metavar=('KEY', 'VALUE'), required=True)
    ap.add_argument('--auth-level', type=int, default=3)
    ap.add_argument('--rx-timeout', type=float, default=1.8)
    ap.add_argument('--pack-file', default='msr2_pack_master.json')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    key = args.wert[0]
    wanted_value = float(args.wert[1])

    layouts, formats = _load_pack(Path(args.pack_file))

    target_block = args.block
    if target_block is None:
        target_block = _find_key_block(layouts, key)
        if target_block is None:
            raise SystemExit(f"key not found in layouts: {key}")

    layout = layouts.get(str(target_block), [])
    fmap = _field_map(layout)
    if key not in fmap:
        if key + '[0]' in fmap:
            key = key + '[0]'
        else:
            raise SystemExit(f"key not in block {target_block}: {key}")

    meta = fmap[key]
    fmt = formats.get(meta['base_key'], {})
    divisor = float(fmt.get('divisor', 1) or 1)
    adder = float(fmt.get('adder', 0) or 0)
    raw = int(round((wanted_value - adder) * divisor))

    ser = dc.open_port(args.port, args.baud)
    if not ser:
        return 2

    pn = 0
    with ser:
        # sync
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F

        p20 = _read_block_payload(ser, 20, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        p22 = _read_block_payload(ser, 22, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if not p20 or not p22:
            raise SystemExit('could not read block 20/22 for auth inputs')

        dec20 = dc._decode_fields(p20, layouts.get('20', []))
        dec22 = dc._decode_fields(p22, layouts.get('22', []))

        serial_no = str(dec20.get('Hka_Bd_Stat.uchSeriennummer', '')).strip()
        bsec = int(dec22.get('Hka_Bd.ulBetriebssekunden', 0) or 0)
        bstd = bsec // 3600

        if not serial_no:
            raise SystemExit('serial number not found (block 20)')

        pw = _msr_password(serial_no, bstd, args.auth_level)
        auth_payload = bytes([126, ord(pw[0]), ord(pw[1]), ord(pw[2]), ord(pw[3]), int(args.auth_level) & 0xFF])

        txa, acka, rxa, dta = dc.send_service(ser, auth_payload, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        print(f"AUTH serial={serial_no} bstd={bstd} auth={args.auth_level} pw4={pw[:4]} ack={dc.to_hex(acka) if acka else '-'} rx={dc.to_hex(rxa) if rxa else '-'}")

        # post-auth sync frame helps some controllers to resume block reads
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F

        cur_payload = _read_block_payload(ser, target_block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if cur_payload is None:
            raise SystemExit(f"could not read target block {target_block}")

        before_dec = dc._decode_fields(bytes(cur_payload), layout)
        before_v = before_dec.get(key)

        new_payload = bytearray(cur_payload)
        _set_raw(new_payload, meta, raw)

        print(f"WRITE block={target_block} key={key} value={wanted_value} raw={raw} before={before_v} dry_run={args.dry_run}")

        if not args.dry_run:
            service = bytes([(target_block + 1) & 0xFF]) + bytes(new_payload)
            txw, ackw, rxw, dtw = dc.send_service(ser, service, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
            print(f"WRITE_TX={dc.to_hex(txw)}")
            print(f"WRITE_ACK={dc.to_hex(ackw) if ackw else '-'}")
            print(f"WRITE_RX={dc.to_hex(rxw) if rxw else '-'}")

            verify = _read_block_payload(ser, target_block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
            if verify is not None:
                after_dec = dc._decode_fields(bytes(verify), layout)
                print(f"VERIFY key={key} value={after_dec.get(key)}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
