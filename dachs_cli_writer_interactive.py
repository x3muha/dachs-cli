#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
import sys
from pathlib import Path

sys.path.insert(0, '/root/senertec/dachs-cli')
import dachs_cli as dc


def load_pack(p):
    obj = json.loads(Path(p).read_text())
    return obj.get('layouts', {}), obj.get('formats', {})


def field_map(layout):
    out = {}
    i = 0
    for f in layout:
        if f.get('kind') == 'space':
            i += int(f.get('length', 0) or 0)
            continue
        if f.get('kind') != 'data':
            continue
        k = f.get('key', '')
        t = (f.get('type') or 'Byte').lower()
        u = bool(f.get('unsigned'))
        rep = int(f.get('repeat', 1) or 1)
        arr = int(f.get('length', 0) or 0)
        n = rep if rep > 1 else (arr if arr > 1 else 1)
        sz = 1 if t == 'byte' else 2 if t == 'short' else 4 if t == 'long' else (arr if t == 'string' else 1)
        if t == 'string':
            n = 1
        for idx in range(n):
            kk = f"{k}[{idx}]" if n > 1 else k
            out[kk] = {'offset': i, 'type': t, 'unsigned': u, 'size': sz, 'base_key': k}
            i += sz
    return out


def raw_from_payload(payload, meta):
    o = meta['offset']; t = meta['type']; u = meta['unsigned']
    if t == 'byte':
        return int.from_bytes(payload[o:o+1], 'little', signed=not u)
    if t == 'short':
        return int.from_bytes(payload[o:o+2], 'little', signed=not u)
    if t == 'long':
        return int.from_bytes(payload[o:o+4], 'little', signed=not u)
    if t == 'string':
        n = int(meta.get('size', 0) or 0)
        return payload[o:o+n].split(b'\x00', 1)[0].decode('latin-1', errors='ignore')
    return None


def set_raw(payload, meta, raw):
    o = meta['offset']; t = meta['type']; u = meta['unsigned']
    if t == 'byte':
        payload[o:o+1] = int(raw).to_bytes(1, 'little', signed=not u)
    elif t == 'short':
        payload[o:o+2] = int(raw).to_bytes(2, 'little', signed=not u)
    elif t == 'long':
        payload[o:o+4] = int(raw).to_bytes(4, 'little', signed=not u)
    elif t == 'string':
        n = int(meta.get('size', 0) or 0)
        b = str(raw).encode('latin-1', errors='ignore')[:n]
        payload[o:o+n] = b + (b'\x00' * max(0, n-len(b)))


def to_raw(val, meta, formats, raw_mode):
    if meta['type'] == 'string':
        return str(val)
    x = float(val)
    if raw_mode:
        return int(round(x))
    fmt = formats.get(meta['base_key'], {})
    div = float(fmt.get('divisor', 1) or 1)
    add = float(fmt.get('adder', 0) or 0)
    return int(round((x - add) * div))


def read_block(ser, block, pn, timeout):
    _tx,_ack,rx,_dt = dc.send_service(ser, bytes([block & 0xFF]), pn, timeout)
    if not rx or rx[0] != 0x02 or len(rx) < 8:
        return None
    d = rx[5:-2]
    return d[1:] if d else None


def msr_pw4(serial_no, bstd):
    n = int(str(serial_no)[-3:]) if str(serial_no)[-3:].isdigit() else 0
    return f"{(n + 2749 + ((int(bstd) % 10000)//2)) & 0xFFFF:04d}"


def main():
    ap = argparse.ArgumentParser(prog='dachs_cli_writer_interactive')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--block', type=int, required=True)
    ap.add_argument('--auth-level', type=int, default=2)
    ap.add_argument('--auth-pass4', default=None)
    ap.add_argument('--rx-timeout', type=float, default=2.0)
    ap.add_argument('--pack-file', default='/root/senertec/dachs-cli/msr2_pack_master.json')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    layouts, formats = load_pack(args.pack_file)
    layout = layouts.get(str(args.block), [])
    if not layout:
        raise SystemExit(f'no layout for block {args.block}')
    fmap = field_map(layout)

    ser = dc.open_port(args.port, args.baud)
    pn = 0
    with ser:
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F

        p20 = read_block(ser, 20, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        p22 = read_block(ser, 22, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if not p20 or not p22:
            raise SystemExit('cannot read auth inputs')
        d20 = dc._decode_fields(p20, layouts.get('20', []))
        d22 = dc._decode_fields(p22, layouts.get('22', []))
        serial = str(d20.get('Hka_Bd_Stat.uchSeriennummer', '')).strip()
        bstd = int(d22.get('Hka_Bd.ulBetriebssekunden', 0) or 0) // 3600
        pw4 = args.auth_pass4.strip() if args.auth_pass4 else msr_pw4(serial, bstd)
        auth = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), int(args.auth_level) & 0xFF])
        _txa, acka, rxa, _ = dc.send_service(ser, auth, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        print(f"AUTH serial={serial} bstd={bstd} auth={args.auth_level} pw4={pw4} ack={dc.to_hex(acka) if acka else '-'} rx={dc.to_hex(rxa) if rxa else '-'}")

        pn = 0
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F

        payload = read_block(ser, args.block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if payload is None:
            raise SystemExit(f'cannot read block {args.block}')
        buf = bytearray(payload)

        print(f"\nInteractive block {args.block}. Commands: show | set <key> <value> | setraw <key> <raw> | setdate <key> DD.MM.YYYY | save | quit")

        def show_vals():
            dec = dc._decode_fields(bytes(buf), layout)
            for k in fmap.keys():
                print(f"{k} = {dec.get(k)} (raw={raw_from_payload(bytes(buf), fmap[k])})")

        show_vals()
        while True:
            line = input('writer> ').strip()
            if not line:
                continue
            if line == 'quit':
                print('aborted')
                return 0
            if line == 'show':
                show_vals(); continue
            if line == 'save':
                break

            parts = line.split(maxsplit=2)
            if len(parts) < 3 or parts[0] not in ('set', 'setraw', 'setdate'):
                print('usage: set <key> <value> | setraw <key> <raw> | setdate <key> DD.MM.YYYY | show | save | quit')
                continue
            cmd, key, val = parts
            if key not in fmap and (key + '[0]') in fmap:
                key = key + '[0]'
            if key not in fmap:
                print('unknown key'); continue
            if cmd == 'setdate':
                try:
                    dt = datetime.strptime(val, '%d.%m.%Y').replace(tzinfo=timezone.utc)
                    base = datetime(2000, 1, 1, tzinfo=timezone.utc)
                    raw = int((dt - base).total_seconds())
                except Exception:
                    print('ERR: date format must be DD.MM.YYYY')
                    continue
            else:
                raw = to_raw(val, fmap[key], formats, raw_mode=(cmd == 'setraw'))
            set_raw(buf, fmap[key], raw)
            dec = dc._decode_fields(bytes(buf), layout).get(key)
            print(f"OK {key} -> {dec} (raw={raw})")

        if args.dry_run:
            print('DRY_RUN stop before write')
            return 0

        svc = bytes([(args.block + 1) & 0xFF]) + bytes(buf)
        txw, ackw, rxw, _ = dc.send_service(ser, svc, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        print(f"WRITE_TX={dc.to_hex(txw)}")
        print(f"WRITE_ACK={dc.to_hex(ackw) if ackw else '-'}")
        print(f"WRITE_RX={dc.to_hex(rxw) if rxw else '-'}")

        after = read_block(ser, args.block, pn, args.rx_timeout)
        if after is not None:
            print('--- readback ---')
            dec = dc._decode_fields(after, layout)
            for k in fmap.keys():
                print(f"{k} = {dec.get(k)}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
