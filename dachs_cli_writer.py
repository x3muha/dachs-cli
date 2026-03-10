#!/usr/bin/env python3
import argparse
import json
import re
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
        if key in fmap or (key + '[0]') in fmap:
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


def _flush_serial(ser, drain_ms: int = 120):
    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()
    except Exception:
        return
    import time
    end = time.time() + (max(0, int(drain_ms)) / 1000.0)
    while time.time() < end:
        d = ser.read(512)
        if not d:
            break

def _set_raw(payload: bytearray, meta: dict, raw):
    off = meta['offset']
    typ = meta['type']
    u = meta['unsigned']
    if typ == 'byte':
        payload[off:off+1] = int(raw).to_bytes(1, 'little', signed=not u)
    elif typ == 'short':
        payload[off:off+2] = int(raw).to_bytes(2, 'little', signed=not u)
    elif typ == 'long':
        payload[off:off+4] = int(raw).to_bytes(4, 'little', signed=not u)
    elif typ == 'string':
        n = int(meta.get('size', 0) or 0)
        b = str(raw).encode('latin-1', errors='ignore')[:n]
        payload[off:off+n] = b + (b'\x00' * max(0, n - len(b)))
    else:
        raise ValueError(f"write not supported for type: {typ}")


def _parse_entity_fields(struct_dir: Path, entity_name: str):
    p = struct_dir / f"{entity_name}.xml"
    if not p.exists():
        return []
    txt = p.read_text(errors='ignore')
    return re.findall(r'<data[^>]*\bkey="([^"]+)"', txt)


def _parse_block_fields_from_dataxml(data_xml: Path, struct_dir: Path):
    txt = data_xml.read_text(errors='ignore')
    blocks = {}
    for m in re.finditer(r'<block\b([^>]*)>(.*?)</block>', txt, flags=re.S):
        attrs = m.group(1)
        body = m.group(2)
        idm = re.search(r'\bid="(\d+)"', attrs)
        if not idm:
            continue
        bid = int(idm.group(1))
        w = re.search(r'\bwrite="([^"]+)"', attrs)
        if not w:
            continue
        write_cmd = w.group(1)
        keys = []

        # struct prefixes
        for sm in re.finditer(r'<struct[^>]*\bkey="([^"]+)"[^>]*>(.*?)</struct>', body, flags=re.S):
            prefix = sm.group(1)
            inner = sm.group(2)
            # direct data in struct
            for k in re.findall(r'<data[^>]*\bkey="([^"]+)"', inner):
                keys.append(f"{prefix}.{k}")
            # entity includes in struct
            for en in re.findall(r'&([A-Za-z0-9_]+);', inner):
                for k in _parse_entity_fields(struct_dir, en):
                    keys.append(f"{prefix}.{k}")

        # top-level direct data
        for k in re.findall(r'<data[^>]*\bkey="([^"]+)"', body):
            if f".{k}" not in ''.join(keys):
                keys.append(k)

        blocks[bid] = {'write': write_cmd, 'keys': keys}
    return blocks


def list_writable(data_xml: Path, struct_dir: Path, only_block: int | None = None):
    blocks = _parse_block_fields_from_dataxml(data_xml, struct_dir)
    if not blocks:
        print(f"No writable blocks found in {data_xml}")
        return 1

    for bid in sorted(blocks):
        if only_block is not None and bid != only_block:
            continue
        info = blocks[bid]
        print(f"[block {bid}] write={info['write']} keys={len(info['keys'])}")
        for k in info['keys']:
            print(f"  {k}")
    return 0




def _auth_attempt(ser, pn, timeout, pw4: str, level: int):
    payload = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), int(level) & 0xFF])
    tx, ack, rx, dt = dc.send_service(ser, payload, pn, timeout)
    a = dc.to_hex(ack) if ack else "-"
    r = dc.to_hex(rx) if rx else "-"
    print("AUTH_PROBE level=%s pw4=%s tx=%s ack=%s rx=%s dt_ms=%.1f" % (level, pw4, dc.to_hex(tx), a, r, dt*1000.0))
    return tx, ack, rx, dt

def main():
    ap = argparse.ArgumentParser(prog='dachs_cli_writer')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('-block', '--block', type=int, default=None)
    ap.add_argument('-wert', '--wert', nargs=2, metavar=('KEY', 'VALUE'))
    ap.add_argument('--auth-level', type=int, default=3)
    ap.add_argument('--auth-pass4', default=None, help='4-digit auth pass prefix (without auth level digit)')
    ap.add_argument('--auth-probe', action='store_true', help='Probe auth responses and exit')
    ap.add_argument('--auth-probe-pass4', default=None, help='Comma list e.g. 5631,5632')
    ap.add_argument('--auth-probe-levels', default='0,1,2,3', help='Comma list levels')
    ap.add_argument('--force-auth', action='store_true', help='force auth handshake')
    ap.add_argument('--query-auth-level', action='store_true', help='query auth then exit')
    ap.add_argument('--debug', action='store_true', help='verbose debug output')
    ap.add_argument('--rx-timeout', type=float, default=1.8)
    ap.add_argument('--flush-before-read', action='store_true', default=True)
    ap.add_argument('--no-flush-before-read', dest='flush_before_read', action='store_false')
    ap.add_argument('--pack-file', default='msr2_pack_master.json')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--raw-value', action='store_true', help='write provided numeric value as raw register value (skip divisor/adder conversion)')

    ap.add_argument('--list-writable', action='store_true', help='List writable blocks/keys from dachsweb source XML')
    ap.add_argument('--data-xml', default='/root/senertec/source/senertec/dachsweb/msr/xml/regler/5/data.xml')
    ap.add_argument('--struct-dir', default='/root/senertec/source/senertec/dachsweb/msr/xml/regler/5/struct')

    args = ap.parse_args()

    if args.list_writable:
        return list_writable(Path(args.data_xml), Path(args.struct_dir), args.block)

    if not args.wert:
        raise SystemExit('missing -wert KEY VALUE (or use --list-writable)')

    key = args.wert[0]
    wanted_value = args.wert[1]

    layouts, formats = _load_pack(Path(args.pack_file))

    target_block = args.block
    if target_block is None:
        target_block = _find_key_block(layouts, key)
        if target_block is None:
            raise SystemExit(f"key not found in layouts: {key}")

    layout = layouts.get(str(target_block), [])
    if not layout:
        raise SystemExit(f"no decoder layout in pack for block {target_block} (tip: use --list-writable)")

    fmap = _field_map(layout)
    if key not in fmap:
        if key + '[0]' in fmap:
            key = key + '[0]'
        else:
            raise SystemExit(f"key not in block {target_block}: {key}")

    meta = fmap[key]
    fmt = formats.get(meta['base_key'], {})
    if meta['type'] == 'string':
        raw = str(wanted_value)
    else:
        num_value = float(wanted_value)
        if args.raw_value:
            raw = int(round(num_value))
        else:
            divisor = float(fmt.get('divisor', 1) or 1)
            adder = float(fmt.get('adder', 0) or 0)
            raw = int(round((num_value - adder) * divisor))

    ser = dc.open_port(args.port, args.baud)
    if not ser:
        return 2

    pn = 0
    with ser:
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F

        if args.auth_level >= 0:
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
            computed_pw4 = _msr_password(serial_no, bstd, args.auth_level)[:4]
            if args.auth_pass4:
                pw4 = args.auth_pass4.strip()
                pw_src = 'override'
            else:
                pw4 = computed_pw4
                pw_src = 'auto'
            if len(pw4) != 4 or not pw4.isdigit():
                raise SystemExit('auth-pass4 must be exactly 4 digits')
            auth_payload = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), int(args.auth_level) & 0xFF])
            _txa, acka, rxa, _dta = dc.send_service(ser, auth_payload, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
            print(f"AUTH serial={serial_no} bstd={bstd} auth={args.auth_level} pw4={pw4} computed_pw4={computed_pw4} source={pw_src} ack={dc.to_hex(acka) if acka else '-'} rx={dc.to_hex(rxa) if rxa else '-'}")
            if args.query_auth_level:
                return 0
            # resync packet numbering after auth attempt (controller may not answer with normal frame)
            pn = 0
            if args.flush_before_read:
                _flush_serial(ser, 180)
            dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        else:
            print('AUTH skipped (--auth-level < 0)')

        if args.flush_before_read:
            _flush_serial(ser)
        cur_payload = _read_block_payload(ser, target_block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if cur_payload is None:
            raise SystemExit(f"could not read target block {target_block} with generic read-block flow")

        before_dec = dc._decode_fields(bytes(cur_payload), layout)
        before_v = before_dec.get(key)

        new_payload = bytearray(cur_payload)
        _set_raw(new_payload, meta, raw)

        print(f"WRITE block={target_block} key={key} value={wanted_value} raw={raw} mode={'raw' if args.raw_value else 'scaled'} before={before_v} dry_run={args.dry_run}")

        if not args.dry_run:
            service = bytes([(target_block + 1) & 0xFF]) + bytes(new_payload)
            txw, ackw, rxw, _dtw = dc.send_service(ser, service, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
            print(f"WRITE_TX={dc.to_hex(txw)}")
            print(f"WRITE_ACK={dc.to_hex(ackw) if ackw else '-'}")
            print(f"WRITE_RX={dc.to_hex(rxw) if rxw else '-'}")

            if args.flush_before_read:
                _flush_serial(ser)
            verify = _read_block_payload(ser, target_block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
            if verify is not None:
                after_dec = dc._decode_fields(bytes(verify), layout)
                print(f"VERIFY key={key} value={after_dec.get(key)}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
