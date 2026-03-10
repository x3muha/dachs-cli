#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import dachs_cli as dc


def load_pack(path):
    p = json.loads(Path(path).read_text())
    return p.get('layouts', {}), p.get('formats', {})


def field_map(layout):
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


def payload_len(layout):
    m = field_map(layout)
    if not m:
        return 0
    return max(v['offset'] + v['size'] for v in m.values())


def parse_dataxml_block_cmd(data_xml, block):
    txt = Path(data_xml).read_text(errors='ignore')
    import re
    m = re.search(rf'<block\s+id="{int(block)}"([^>]*)>', txt)
    if not m:
        return None, None, 1
    attrs = m.group(1)
    r = re.search(r'\bread="([^"]+)"', attrs)
    w = re.search(r'\bwrite="([^"]+)"', attrs)
    o = re.search(r'\breadOffset="(\d+)"', attrs)
    return (r.group(1) if r else None), (w.group(1) if w else None), (int(o.group(1)) if o else 1)


def build_cmd(cmd, block_len, payload=b''):
    out = bytearray()
    for p in [x.strip() for x in cmd.split(',') if x.strip()]:
        if p == '%l':
            out.append(block_len & 0xFF)
        elif p == '%d':
            b = bytearray(block_len)
            b[:min(len(payload), block_len)] = payload[:min(len(payload), block_len)]
            out.extend(b)
        elif p == '%m':
            out.append(0)
        elif p.startswith('0x'):
            out.append(int(p, 16) & 0xFF)
        else:
            out.append(int(p) & 0xFF)
    return bytes(out)


def decode_payload(rx, read_offset):
    if not rx or rx[0] != 0x02 or len(rx) < 8:
        return None
    data = rx[5:-2]
    if len(data) <= read_offset:
        return None
    return data[read_offset:]


def set_value(buf, meta, value):
    off = meta['offset']
    typ = meta['type']
    u = meta['unsigned']
    if typ == 'string':
        n = meta['size']
        b = str(value).encode('latin-1', errors='ignore')[:n]
        buf[off:off+n] = b + (b'\x00' * (n - len(b)))
    elif typ == 'byte':
        buf[off:off+1] = int(value).to_bytes(1, 'little', signed=not u)
    elif typ == 'short':
        buf[off:off+2] = int(value).to_bytes(2, 'little', signed=not u)
    elif typ == 'long':
        buf[off:off+4] = int(value).to_bytes(4, 'little', signed=not u)


def log_step(tag, tx, ack, rx, dt):
    print(f"[{tag}] tx={dc.to_hex(tx)} ack={dc.to_hex(ack) if ack else '-'} rx={dc.to_hex(rx) if rx else '-'} dt_ms={(dt*1000.0):.1f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--block', type=int, required=True)
    ap.add_argument('--key', required=True)
    ap.add_argument('--value', required=True)
    ap.add_argument('--auth-level', type=int, default=2)
    ap.add_argument('--auth-pass4', required=True)
    ap.add_argument('--pack-file', default='/root/senertec/dachs-cli/msr2_pack_master.json')
    ap.add_argument('--data-xml', default='/root/senertec/source/senertec/dachsweb/msr/xml/regler/5/data.xml')
    ap.add_argument('--timeout', type=float, default=2.0)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    layouts, _formats = load_pack(args.pack_file)
    layout = layouts.get(str(args.block), [])
    if not layout:
        raise SystemExit('no layout for block')
    fmap = field_map(layout)
    key = args.key if args.key in fmap else (args.key + '[0]' if (args.key + '[0]') in fmap else None)
    if not key:
        raise SystemExit('key not in layout')

    read_cmd, write_cmd, read_offset = parse_dataxml_block_cmd(args.data_xml, args.block)
    if read_cmd is None:
        read_cmd = str(args.block)
    if write_cmd is None:
        write_cmd = f"{args.block+1},%d"

    blen = payload_len(layout)

    ser = dc.open_port(args.port, args.baud)
    if not ser:
        raise SystemExit(2)

    pn = 0
    with ser:
        tx, ack, rx, dt = dc.send_service(ser, b'', pn, args.timeout); log_step('sync', tx, ack, rx, dt); pn = (pn + 1) & 0x0F

        # auth frame exactly like dachsweb sendAuthLevel(password, level)
        pw4 = args.auth_pass4
        apayload = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), args.auth_level & 0xFF])
        tx, ack, rx, dt = dc.send_service(ser, apayload, pn, args.timeout); log_step('auth', tx, ack, rx, dt); pn = (pn + 1) & 0x0F

        # re-sync and read target block with datamap read cmd
        pn = 0
        tx, ack, rx, dt = dc.send_service(ser, b'', pn, args.timeout); log_step('resync', tx, ack, rx, dt); pn = (pn + 1) & 0x0F

        rsvc = build_cmd(read_cmd, blen)
        tx, ack, rx, dt = dc.send_service(ser, rsvc, pn, args.timeout); log_step('read_before', tx, ack, rx, dt); pn = (pn + 1) & 0x0F
        cur = decode_payload(rx, read_offset)
        if cur is None:
            raise SystemExit('no payload on read_before')

        dec = dc._decode_fields(cur, layout)
        print(f"before[{key}]={dec.get(key)} read_cmd={read_cmd} write_cmd={write_cmd} read_offset={read_offset}")

        nb = bytearray(cur)
        set_value(nb, fmap[key], args.value)

        if args.dry_run:
            print('DRY_RUN stop before write')
            return 0

        wsvc = build_cmd(write_cmd, blen, bytes(nb))
        tx, ack, rx, dt = dc.send_service(ser, wsvc, pn, args.timeout); log_step('write', tx, ack, rx, dt); pn = (pn + 1) & 0x0F

        tx, ack, rx, dt = dc.send_service(ser, rsvc, pn, args.timeout); log_step('read_after', tx, ack, rx, dt); pn = (pn + 1) & 0x0F
        aft = decode_payload(rx, read_offset)
        if aft is not None:
            adec = dc._decode_fields(aft, layout)
            print(f"after[{key}]={adec.get(key)}")


if __name__ == '__main__':
    main()
