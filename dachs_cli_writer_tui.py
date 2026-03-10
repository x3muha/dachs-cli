#!/usr/bin/env python3
import argparse
import curses
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

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
            i += int(f.get('length', 0) or 0); continue
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
    if t == 'byte': return int.from_bytes(payload[o:o+1], 'little', signed=not u)
    if t == 'short': return int.from_bytes(payload[o:o+2], 'little', signed=not u)
    if t == 'long': return int.from_bytes(payload[o:o+4], 'little', signed=not u)
    if t == 'string':
        n = int(meta.get('size', 0) or 0)
        return payload[o:o+n].split(b'\x00', 1)[0].decode('latin-1', errors='ignore')
    return None


def set_raw(payload, meta, raw):
    o = meta['offset']; t = meta['type']; u = meta['unsigned']
    if t == 'byte': payload[o:o+1] = int(raw).to_bytes(1, 'little', signed=not u)
    elif t == 'short': payload[o:o+2] = int(raw).to_bytes(2, 'little', signed=not u)
    elif t == 'long': payload[o:o+4] = int(raw).to_bytes(4, 'little', signed=not u)
    elif t == 'string':
        n = int(meta.get('size', 0) or 0)
        b = str(raw).encode('latin-1', errors='ignore')[:n]
        payload[o:o+n] = b + (b'\x00' * max(0, n-len(b)))


def to_raw(val, key, meta, formats, raw_mode):
    if meta['type'] == 'string':
        return str(val)
    if isinstance(val, str) and '.' in val and len(val) == 10 and val[2] == '.' and val[5] == '.':
        dt = datetime.strptime(val, '%d.%m.%Y').replace(tzinfo=timezone.utc)
        base = datetime(2000, 1, 1, tzinfo=timezone.utc)
        return int((dt - base).total_seconds())
    x = float(val)
    if raw_mode:
        return int(round(x))
    fmt = formats.get(meta['base_key'], {})
    div = float(fmt.get('divisor', 1) or 1)
    add = float(fmt.get('adder', 0) or 0)
    return int(round((x - add) * div))


def read_block(ser, block, pn, timeout):
    _tx,_ack,rx,_dt = dc.send_service(ser, bytes([block & 0xFF]), pn, timeout)
    if not rx or rx[0] != 0x02 or len(rx) < 8: return None
    d = rx[5:-2]
    return d[1:] if d else None


def msr_pw4(serial_no, bstd):
    n = int(str(serial_no)[-3:]) if str(serial_no)[-3:].isdigit() else 0
    return f"{(n + 2749 + ((int(bstd) % 10000)//2)) & 0xFFFF:04d}"


def auth_and_load(args):
    layouts, formats = load_pack(args.pack_file)
    layout = layouts.get(str(args.block), [])
    if not layout: raise SystemExit('no layout for block')
    fmap = field_map(layout)
    keys = list(fmap.keys())
    ser = dc.open_port(args.port, args.baud)
    if not ser: raise SystemExit(2)
    pn = 0
    with ser:
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        p20 = read_block(ser, 20, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        p22 = read_block(ser, 22, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if not p20 or not p22: raise SystemExit('cannot read auth inputs')
        d20 = dc._decode_fields(p20, layouts.get('20', []))
        d22 = dc._decode_fields(p22, layouts.get('22', []))
        serial = str(d20.get('Hka_Bd_Stat.uchSeriennummer', '')).strip()
        bstd = int(d22.get('Hka_Bd.ulBetriebssekunden', 0) or 0) // 3600
        pw4 = args.auth_pass4.strip() if args.auth_pass4 else msr_pw4(serial, bstd)
        auth = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), int(args.auth_level) & 0xFF])
        txa, acka, rxa, _ = dc.send_service(ser, auth, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        pn = 0
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        payload = read_block(ser, args.block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if payload is None: raise SystemExit('cannot read target block')
        return {'layouts':layouts,'formats':formats,'layout':layout,'fmap':fmap,'keys':keys,'payload':bytearray(payload),'pn':pn,'auth_line':f"AUTH pw4={pw4} ack={dc.to_hex(acka) if acka else '-'} rx={dc.to_hex(rxa) if rxa else '-'}"}


def _read_key(stdscr):
    ch = stdscr.getch()
    if ch != 27:
        return ch
    # parse common escape sequences for function keys
    stdscr.nodelay(True)
    seq=[]
    for _ in range(5):
        c = stdscr.getch()
        if c == -1:
            break
        seq.append(c)
    stdscr.nodelay(False)
    # F2 variants: ESC O Q  or ESC [ 1 2 ~
    if seq[:2] == [79, 81] or seq[:4] == [91, 49, 50, 126]:
        return curses.KEY_F2
    # F4 variants: ESC O S  or ESC [ 1 4 ~
    if seq[:2] == [79, 83] or seq[:4] == [91, 49, 52, 126]:
        return curses.KEY_F4
    # F10 variants: ESC [ 2 1 ~  (common)
    if seq[:4] == [91, 50, 49, 126]:
        return curses.KEY_F10
    return 27

def run_tui(stdscr, state, args):
    curses.curs_set(0)
    stdscr.keypad(True)
    idx = 0
    top = 0
    raw_mode = False
    msg = state['auth_line']
    keys = state['keys']; fmap = state['fmap']; payload = state['payload']; layout = state['layout']
    changed = set()

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        title = f"dachs writer tui | block {args.block} | raw_mode={'ON' if raw_mode else 'OFF'}"
        help1 = 'Arrows: navigate  Enter:edit  F2/s:save  F4/r:reload  F6:raw-toggle  F10/Esc/q:quit'
        stdscr.addnstr(0, 0, title, w-1)
        stdscr.addnstr(1, 0, help1, w-1)
        stdscr.addnstr(2, 0, msg, w-1)

        visible = h - 4
        if idx < top: top = idx
        if idx >= top + visible: top = idx - visible + 1

        dec = dc._decode_fields(bytes(payload), layout)
        for i in range(top, min(len(keys), top + visible)):
            k = keys[i]
            marker = '*' if k in changed else ' '
            line = f"{marker} {k} = {dec.get(k)} (raw={raw_from_payload(bytes(payload), fmap[k])})"
            if i == idx:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addnstr(3 + (i-top), 0, line, w-1)
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addnstr(3 + (i-top), 0, line, w-1)

        ch = _read_key(stdscr)
        if ch in (27, curses.KEY_F10, ord('q'), ord('Q')):
            break
        elif ch == curses.KEY_UP:
            idx = max(0, idx-1)
        elif ch == curses.KEY_DOWN:
            idx = min(len(keys)-1, idx+1)
        elif ch == curses.KEY_NPAGE:
            idx = min(len(keys)-1, idx + max(1, visible-1))
        elif ch == curses.KEY_PPAGE:
            idx = max(0, idx - max(1, visible-1))
        elif ch == curses.KEY_F6:
            raw_mode = not raw_mode
            msg = f"raw_mode={'ON' if raw_mode else 'OFF'}"
        elif ch in (10,13):
            k = keys[idx]
            meta = fmap[k]
            curses.echo(); curses.curs_set(1)
            stdscr.move(h-1,0); stdscr.clrtoeol(); stdscr.addstr(h-1,0,f'new value for {k}: ')
            val = stdscr.getstr(h-1, len(f'new value for {k}: '), max(1, w-len(k)-20)).decode('latin-1','ignore')
            curses.noecho(); curses.curs_set(0)
            try:
                raw = to_raw(val, k, meta, state['formats'], raw_mode)
                set_raw(payload, meta, raw)
                changed.add(k)
                msg = f'OK {k} -> raw={raw}'
            except Exception as e:
                msg = f'ERR {e}'
        elif ch in (curses.KEY_F4, ord('r'), ord('R')):
            # reload from device
            try:
                ser = dc.open_port(args.port, args.baud)
                with ser:
                    pn = 0
                    dc.send_service(ser,b'',pn,args.rx_timeout); pn=(pn+1)&0x0F
                    p = read_block(ser,args.block,pn,args.rx_timeout)
                if p is not None:
                    payload[:] = p
                    changed.clear()
                    msg = 'reloaded from device'
                else:
                    msg = 'reload failed'
            except Exception as e:
                msg = f'reload err: {e}'
        elif ch in (curses.KEY_F2, ord('s'), ord('S')):
            if not changed:
                msg = 'nothing changed'
                continue
            if args.dry_run:
                msg = 'dry-run: changes staged (not written)'
                continue
            try:
                ser = dc.open_port(args.port, args.baud)
                with ser:
                    pn = 0
                    dc.send_service(ser,b'',pn,args.rx_timeout); pn=(pn+1)&0x0F
                    svc = bytes([(args.block+1)&0xFF]) + bytes(payload)
                    tx,ack,rx,_ = dc.send_service(ser,svc,pn,args.rx_timeout)
                msg = f"SAVED ack={dc.to_hex(ack) if ack else '-'} rx={dc.to_hex(rx) if rx else '-'}"
                changed.clear()
            except Exception as e:
                msg = f'save err: {e}'


def main():
    ap = argparse.ArgumentParser(prog='dachs_cli_writer_tui')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--block', type=int, required=True)
    ap.add_argument('--auth-level', type=int, default=2)
    ap.add_argument('--auth-pass4', default=None)
    ap.add_argument('--rx-timeout', type=float, default=2.0)
    ap.add_argument('--pack-file', default='/root/senertec/dachs-cli/msr2_pack_master.json')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    st = auth_and_load(args)
    curses.wrapper(run_tui, st, args)


if __name__ == '__main__':
    main()
