#!/usr/bin/env python3
import argparse
import curses
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import time
import threading

from core import dachs_core as dc
import dachs_cli_v2 as v2


def known_blocks_from_pack(p):
    obj = json.loads(Path(p).read_text())
    if isinstance(obj.get('layouts'), dict):
        out=[]
        for k in obj.get('layouts', {}).keys():
            try: out.append(int(k))
            except Exception: pass
        return sorted(set(out))
    if isinstance(obj.get('blocks'), dict):
        out=[]
        for k in obj.get('blocks', {}).keys():
            try: out.append(int(k))
            except Exception: pass
        return sorted(set(out))
    return []


def block_names_from_pack(p):
    try:
        obj = json.loads(Path(p).read_text())
    except Exception:
        return {}
    out = {}
    if isinstance(obj.get('blocks'), dict):
        for k,v in obj.get('blocks', {}).items():
            try:
                bi = int(k)
            except Exception:
                continue
            if isinstance(v, dict):
                nm = v.get('block_name_de') or v.get('name_de') or v.get('title_de')
                if isinstance(nm, str) and nm.strip():
                    out[bi] = nm.strip()
    return out


def load_pack(p, blocks=None, pack_rev='50'):
    obj = json.loads(Path(p).read_text())
    if isinstance(obj.get('layouts'), dict):
        return obj.get('layouts', {}), obj.get('formats', {})
    if isinstance(obj.get('blocks'), dict):
        blocks = sorted(set(blocks or []))
        tmp_pack, _tmp_labels = v2._materialize_pack_for_blocks(Path(p), blocks, str(pack_rev), fallback_formats=(Path('msr2_formats_v2.json') if Path('msr2_formats_v2.json').exists() else Path('core/msr2_formats_v2.json')))
        x = json.loads(Path(tmp_pack).read_text())
        return x.get('layouts', {}), x.get('formats', {})
    return {}, obj.get('formats', {})


def expected_len_from_layout(layout):
    m = 0
    for f in (layout or []):
        if not isinstance(f, dict):
            continue
        if f.get('kind') != 'data':
            continue
        off = int(f.get('offset', 0) or 0)
        t = (f.get('type') or 'Byte').lower()
        rep = int(f.get('repeat', 1) or 1)
        ln = int(f.get('length', 0) or 0)
        if t == 'byte': sz = 1
        elif t == 'short': sz = 2
        elif t == 'long': sz = 4
        elif t == 'string': sz = max(1, ln)
        else: sz = 1
        n = 1 if t == 'string' else (rep if rep > 1 else (ln if ln > 1 else 1))
        end = off + (sz * n)
        if end > m:
            m = end
    return m


def load_local_label_overrides():
    p = (Path('labels_master.properties') if Path('labels_master.properties').exists() else Path('core/labels_master.properties'))
    if p.exists():
        try:
            return dc._load_labels(p)
        except Exception:
            return {}
    return {}


def labels_from_layout(layout):
    out = {}
    for e in (layout or []):
        if isinstance(e, dict) and e.get('key') and e.get('label_de'):
            out[e.get('key')] = e.get('label_de')
    return out


def field_map(layout):
    out = {}
    i = 0
    for f in layout:
        if f.get('kind') == 'space':
            i += int(f.get('length', 0) or 0)
            continue
        if f.get('kind') != 'data':
            continue

        # Prefer explicit offset from pack/layout; fallback to running index
        off = f.get('offset', None)
        if off is None:
            off = i
        else:
            off = int(off)
            i = off

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
            out[kk] = {'offset': off + (idx * sz), 'type': t, 'unsigned': u, 'size': sz, 'base_key': k}

        i = off + (sz * n)
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




def _resolve_pack_file(pack_file_arg: str | None) -> Path:
    if pack_file_arg:
        p = Path(pack_file_arg)
        if p.exists():
            return p
    cands = [
        Path('core/msr2_pack_master_version.json'),
        Path('msr2_pack_master_version.json'),
        Path('core/msr2_pack_master.json'),
        Path('msr2_pack_master.json'),
    ]
    for c in cands:
        if c.exists():
            return c
    return cands[0]

def auth_and_load(args):
    pack_file = _resolve_pack_file(getattr(args, "pack_file", ""))
    args.pack_file = str(pack_file)
    known_blocks = known_blocks_from_pack(pack_file)
    block_names = block_names_from_pack(pack_file)
    if args.all_blocks and known_blocks:
        wanted = sorted(set([20,22] + known_blocks))
    else:
        wanted = [20,22,args.block]
    layouts, formats = load_pack(pack_file, blocks=wanted, pack_rev=getattr(args, 'pack_rev', '50'))
    layout = layouts.get(str(args.block), [])
    if not layout: raise SystemExit('no layout for block')
    fmap = field_map(layout)
    keys = [k for k in fmap.keys() if args.show_reserved or not dc._is_reserved_key(k)]
    ser = dc.open_port(args.port, args.baud)
    if not ser: raise SystemExit(2)
    pn = 0
    with ser:
        # read auth input blocks on the SAME serial session (no nested port open)
        def _read_with_retry(block_id, retries=3):
            nonlocal pn
            for _ in range(max(0, int(retries)) + 1):
                try:
                    ser.reset_input_buffer()
                except Exception:
                    pass
                pld = read_block(ser, int(block_id), pn, args.rx_timeout)
                pn = (pn + 1) & 0x0F
                if pld is not None:
                    return pld
                pn = 0
                dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F
            return None

        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        p20 = _read_with_retry(20, 3)
        p22 = _read_with_retry(22, 3)
        if not p20 or not p22:
            raise SystemExit('cannot read auth inputs')
        d20 = dc._decode_fields(p20, layouts.get('20', []))
        d22 = dc._decode_fields(p22, layouts.get('22', []))
        serial = str(d20.get('Hka_Bd_Stat.uchSeriennummer', '')).strip()
        bstd = int(d22.get('Hka_Bd.ulBetriebssekunden', 0) or 0) // 3600
        pw4 = args.auth_pass4.strip() if args.auth_pass4 else msr_pw4(serial, bstd)
        auth = bytes([126, ord(pw4[0]), ord(pw4[1]), ord(pw4[2]), ord(pw4[3]), int(args.auth_level) & 0xFF])
        txa, acka, rxa, _ = dc.send_service(ser, auth, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        granted = None
        if rxa and len(rxa) >= 8 and rxa[0] == 0x02:
            data = rxa[5:-2]
            if len(data) >= 2 and data[0] == 0xFE:
                granted = int(data[1])
        # initial target payload
        pn = 0
        dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        payload = read_block(ser, args.block, pn, args.rx_timeout); pn = (pn + 1) & 0x0F
        if payload is None: raise SystemExit('cannot read target block')

        # start with current block only; preload remaining blocks asynchronously in UI loop
        payload_cache = {int(args.block): bytes(payload)}
        preload_blocks = [int(b) for b in (known_blocks or []) if int(b) != int(args.block)] if args.all_blocks else []

        labels = labels_from_layout(layout)
        labels.update(load_local_label_overrides())
        return {'layouts':layouts,'formats':formats,'labels':labels,'layout':layout,'fmap':fmap,'keys':keys,'payload':bytearray(payload),'pn':pn,'auth_requested':int(args.auth_level),'auth_granted':granted,'auth_line':f"AUTH pw4={pw4} ack={dc.to_hex(acka) if acka else '-'} rx={dc.to_hex(rxa) if rxa else '-'}",'known_blocks':known_blocks,'block_names':block_names,'payload_cache':payload_cache,'preload_blocks':preload_blocks}


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





def _safe_text(v) -> str:
    t = '' if v is None else str(v)
    # curses.addnstr rejects embedded NUL
    t = t.replace('\x00', ' ')
    return t

def _ui_name_obj_val_raw(full_key: str, decoded_raw, fallback_raw, formats: dict, labels: dict):
    base = full_key.split('[', 1)[0]
    label = dc._label_for_key(base, labels or {})
    obj = base.split('.')[-1]
    raw = decoded_raw if decoded_raw is not None else fallback_raw
    vtxt, unit = dc._apply_format(base, raw, formats or {})
    if unit:
        vtxt = f"{vtxt} {unit}".rstrip()
    return _safe_text(label), _safe_text(obj), _safe_text(vtxt), '' if raw is None else _safe_text(raw)

VERSION_BASES = {
    'Hka_Bd_Stat.bSoftwareVersionUeberw',
    'Hka_Bd_Stat.bSoftwareVersionMessen',
    'Hka_Bd_Stat.bSoftwareVersionRegler',
}


def _build_ui_rows(keys, fmap):
    rows = []
    used = set()

    # collect indexed groups by base
    by_base = {}
    for k in keys:
        base = k.split('[', 1)[0]
        if '[' in k and k.endswith(']'):
            by_base.setdefault(base, []).append(k)

    # prepare generic candidates: indexed byte arrays (>=2)
    generic_group = set()
    for base, arr in by_base.items():
        # keep MeldeHIST arrays ungrouped (better readability and correct per-field formatting)
        if base.startswith('MeldeHIST.'):
            continue
        arrs = sorted(arr, key=lambda x: int(x.split('[')[1].split(']')[0]))
        if len(arrs) < 2:
            continue
        ok = True
        for kk in arrs:
            m = fmap.get(kk) or {}
            if (m.get('type') or '').lower() != 'byte':
                ok = False
                break
        if ok:
            generic_group.add(base)

    for k in keys:
        if k in used:
            continue
        base = k.split('[', 1)[0]

        if ('[' in k and k.endswith(']')) and (base in VERSION_BASES or base in generic_group):
            # only start group at [0]
            if not k.endswith('[0]'):
                used.add(k)
                continue
            comps = sorted([kk for kk in keys if kk.startswith(base + '[')], key=lambda x: int(x.split('[')[1].split(']')[0]))
            for c in comps:
                used.add(c)
            rows.append({'kind': 'version', 'base': base, 'keys': comps, 'key': comps[0] if comps else k})
            continue

        rows.append({'kind': 'normal', 'key': k, 'base': base, 'keys': [k]})

    return rows


def _read_version_from_payload(payload: bytes, comp_keys, fmap):
    vals = []
    for kk in comp_keys:
        m = fmap.get(kk)
        if not m:
            vals.append(0)
            continue
        rv = raw_from_payload(payload, m)
        try:
            vals.append(int(rv))
        except Exception:
            vals.append(0)
    return vals

def _hex_line(b: bytes):
    return ' '.join(f"{x:02X}" for x in b)


def _draw_hex_diff(stdscr, y, x, w, cur_b: bytes, base_b: bytes, attr_norm, attr_diff):
    max_bytes = max(1, (w + 1) // 3)
    n = min(max_bytes, len(cur_b))
    for i in range(n):
        tok = f"{cur_b[i]:02X}"
        a = attr_diff if (i >= len(base_b) or cur_b[i] != base_b[i]) else attr_norm
        xx = x + (i * 3)
        if xx + 1 >= x + w:
            break
        try:
            stdscr.addnstr(y, xx, tok, 2, a)
            if xx + 2 < x + w:
                stdscr.addch(y, xx + 2, ord(' '), attr_norm)
        except Exception:
            pass


def _draw_diff_text(stdscr, y, x, w, cur: str, base: str, attr_norm, attr_diff):
    cur = _safe_text(cur)
    base = _safe_text(base)
    maxw = max(1, w)
    # clear cell first
    stdscr.addnstr(y, x, ' ' * maxw, maxw, attr_norm)
    for i, ch in enumerate(cur[:maxw]):
        a = attr_diff if (i >= len(base) or ch != base[i]) else attr_norm
        try:
            stdscr.addch(y, x+i, ch, a)
        except Exception:
            pass


def _inline_edit(stdscr, y, x, w, initial: str):
    buf = list(initial)
    pos = len(buf)
    curses.curs_set(1)
    while True:
        txt = ''.join(buf)
        stdscr.addnstr(y, x, ' ' * max(1, w), max(1, w))
        stdscr.addnstr(y, x, txt, max(1, w))
        stdscr.move(y, x + min(pos, max(0, w-1)))
        ch = stdscr.getch()
        if ch in (10, 13):
            curses.curs_set(0)
            return ''.join(buf), True
        if ch in (27,):
            curses.curs_set(0)
            return initial, False
        if ch in (curses.KEY_LEFT,):
            pos = max(0, pos-1); continue
        if ch in (curses.KEY_RIGHT,):
            pos = min(len(buf), pos+1); continue
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if pos > 0:
                del buf[pos-1]; pos -= 1
            continue
        if ch in (curses.KEY_DC,):
            if pos < len(buf):
                del buf[pos]
            continue
        if 32 <= ch <= 126:
            if len(buf) < max(1, w):
                buf.insert(pos, chr(ch)); pos += 1
            elif pos < len(buf):
                buf[pos] = chr(ch); pos += 1
            continue


def run_tui(stdscr, state, args):
    curses.curs_set(0)
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # normal
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLUE)    # selected
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_BLACK)   # black bar
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLUE)      # red
        curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLUE)   # amber
        curses.init_pair(6, curses.COLOR_GREEN, curses.COLOR_BLUE)    # green
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLACK)   # white on black
        stdscr.bkgd(' ', curses.color_pair(1))

    # fixed rows
    TITLE_Y = 0
    BLOCK_Y = 2
    BLOCK_NAME_Y = 3
    STATUS_Y = 4
    AUTH_Y = 6
    INFO_Y = 8
    TABLE_Y = 10

    idx = 0
    top = 0
    raw_mode = False
    auth_msg = state.get('auth_line', '')
    msg = ''

    keys = state['keys']
    fmap = state['fmap']
    payload = state['payload']
    layout = state['layout']
    ui_rows = _build_ui_rows(keys, fmap)
    baseline_payload = bytearray(payload)

    known = sorted(set(state.get('known_blocks') or []))
    if args.all_blocks and known:
        block_list = known
    else:
        block_list = [int(args.block)]
    if int(args.block) not in block_list:
        block_list.append(int(args.block))
        block_list = sorted(set(block_list))
    block_idx = block_list.index(int(args.block)) if block_list else 0
    block_select_mode = False

    payload_cache = dict(state.get('payload_cache') or {int(args.block): bytes(payload)})
    preload_blocks = list(state.get('preload_blocks') or [])
    preload_pos = 0
    preload_done = (len(preload_blocks) == 0)
    cache_lock = threading.Lock()
    stop_bg = {'stop': False}

    def _bg_preload_worker():
        nonlocal preload_pos, preload_done, msg
        CHUNK = 8
        while (not stop_bg['stop']) and preload_pos < len(preload_blocks):
            chunk = []
            while preload_pos < len(preload_blocks) and len(chunk) < CHUNK:
                bpre = int(preload_blocks[preload_pos])
                preload_pos += 1
                with cache_lock:
                    if bpre in payload_cache:
                        continue
                chunk.append(bpre)
            if not chunk:
                continue
            try:
                res = dc.read_blocks_batch(args.port, args.baud, chunk, args.rx_timeout,
                                           wait_between_blocks=args.wait_between_blocks,
                                           flush_before_read=True, retry_on_timeout=0)
                with cache_lock:
                    for bb, pld in (res or {}).items():
                        if pld is not None:
                            payload_cache[int(bb)] = bytes(pld)
            except Exception:
                pass
        preload_done = True

    bg_thread = None
    if args.all_blocks and preload_blocks:
        bg_thread = threading.Thread(target=_bg_preload_worker, daemon=True)
        bg_thread.start()

    stdscr.timeout(80)
    changed = set()
    hide_name = bool(getattr(args, 'hide_name', False))
    hide_object = bool(getattr(args, 'hide_object', False))

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        exp_len = expected_len_from_layout(layout)
        cur_len = len(payload)

        # title black bar
        title = 'DACHS WRITER TUI'
        tx = max(0, (w - len(title)) // 2)
        if curses.has_colors():
            stdscr.addnstr(TITLE_Y, 0, ' ' * max(1, w-1), max(1, w-1), curses.color_pair(8))
            stdscr.addnstr(TITLE_Y, tx, title, max(1, w-tx-1), curses.color_pair(8) | curses.A_BOLD)
        else:
            stdscr.addnstr(TITLE_Y, tx, title, max(1, w-tx-1), curses.A_BOLD)

        # block line
        cur_block = block_list[block_idx] if block_list else args.block
        args.block = cur_block
        block_left = 'BLOCK '
        block_num = str(cur_block)
        block_tail = f' ({block_idx+1}/{len(block_list)})' if block_list else ''
        block_line = block_left + block_num + block_tail
        bx = max(0, (w - len(block_line)) // 2)
        if curses.has_colors():
            stdscr.addnstr(BLOCK_Y, bx, block_left, max(1, w-bx-1), curses.color_pair(1) | curses.A_BOLD)
            stdscr.addnstr(BLOCK_Y, bx + len(block_left), block_num, max(1, w-(bx+len(block_left))-1), curses.color_pair(4) | curses.A_BOLD)
            stdscr.addnstr(BLOCK_Y, bx + len(block_left) + len(block_num), block_tail, max(1, w-(bx+len(block_left)+len(block_num))-1), curses.color_pair(1) | curses.A_BOLD)
        else:
            stdscr.addnstr(BLOCK_Y, bx, block_line, max(1, w-bx-1), curses.A_BOLD)

        # block name line (from pack metadata)
        bname = (state.get('block_names') or {}).get(int(cur_block), '')
        if bname:
            bline = f'[{bname}]'
            bnx = max(0, (w - len(bline)) // 2)
            if curses.has_colors():
                stdscr.addnstr(BLOCK_NAME_Y, bnx, bline, max(1, w-bnx-1), curses.color_pair(6) | curses.A_BOLD)
            else:
                stdscr.addnstr(BLOCK_NAME_Y, bnx, bline, max(1, w-bnx-1), curses.A_BOLD)

        # status line
        req = state.get('auth_requested')
        grd = state.get('auth_granted')
        ok_auth = (grd is not None and req is not None and int(grd) == int(req))
        raw_on = bool(raw_mode)

        prefix = '| '
        p3 = ' | '
        p5 = ' | '
        suffix = ' |'
        status_plain = f"| auth_request={req} auth={grd if grd is not None else '?'} | raw_mode={'ON' if raw_on else 'OFF'} | payload={cur_len}B expected={exp_len}B |"
        sx = max(0, (w - len(status_plain)) // 2)

        if curses.has_colors():
            x = sx
            base = curses.color_pair(1)
            g = curses.color_pair(6) | curses.A_BOLD
            r = curses.color_pair(4) | curses.A_BOLD
            y = curses.color_pair(5) | curses.A_BOLD

            stdscr.addnstr(STATUS_Y, x, prefix, max(1, w-x-1), base); x += len(prefix)
            stdscr.addnstr(STATUS_Y, x, 'auth_request=', max(1, w-x-1), base); x += len('auth_request=')
            stdscr.addnstr(STATUS_Y, x, str(req), max(1, w-x-1), g); x += len(str(req))
            stdscr.addnstr(STATUS_Y, x, ' ', max(1, w-x-1), base); x += 1
            stdscr.addnstr(STATUS_Y, x, 'auth=', max(1, w-x-1), base); x += len('auth=')
            auth_val = str(grd if grd is not None else '?')
            stdscr.addnstr(STATUS_Y, x, auth_val, max(1, w-x-1), (g if ok_auth else r)); x += len(auth_val)
            stdscr.addnstr(STATUS_Y, x, p3, max(1, w-x-1), base); x += len(p3)

            stdscr.addnstr(STATUS_Y, x, 'raw_mode=', max(1, w-x-1), base); x += len('raw_mode=')
            rv = 'ON' if raw_on else 'OFF'
            stdscr.addnstr(STATUS_Y, x, rv, max(1, w-x-1), (g if raw_on else r)); x += len(rv)
            stdscr.addnstr(STATUS_Y, x, p5, max(1, w-x-1), base); x += len(p5)

            stdscr.addnstr(STATUS_Y, x, 'payload=', max(1, w-x-1), base); x += len('payload=')
            pv = f'{cur_len}B'
            stdscr.addnstr(STATUS_Y, x, pv, max(1, w-x-1), y); x += len(pv)
            stdscr.addnstr(STATUS_Y, x, ' ', max(1, w-x-1), base); x += 1
            stdscr.addnstr(STATUS_Y, x, 'expected=', max(1, w-x-1), base); x += len('expected=')
            ev = f'{exp_len}B'
            stdscr.addnstr(STATUS_Y, x, ev, max(1, w-x-1), y); x += len(ev)
            stdscr.addnstr(STATUS_Y, x, suffix, max(1, w-x-1), base)
        else:
            stdscr.addnstr(STATUS_Y, sx, status_plain, max(1, w-sx-1), curses.A_BOLD)

        # auth row always persistent
        cx_auth = max(0, (w - len(auth_msg)) // 2) if len(auth_msg) < w else 0
        if auth_msg.startswith('AUTH ') and curses.has_colors():
            x = cx_auth
            base_attr = curses.color_pair(1) | curses.A_BOLD
            val_g = curses.color_pair(6) | curses.A_BOLD
            val_y = curses.color_pair(5) | curses.A_BOLD
            stdscr.addnstr(AUTH_Y, x, 'AUTH ', max(1, w-x-1), base_attr); x += 5
            pw = auth_msg.split('pw4=',1)[1].split(' ',1)[0] if 'pw4=' in auth_msg else ''
            stdscr.addnstr(AUTH_Y, x, 'pw4=', max(1, w-x-1), base_attr); x += 4
            stdscr.addnstr(AUTH_Y, x, pw, max(1, w-x-1), val_g); x += len(pw)
            stdscr.addnstr(AUTH_Y, x, ' ', max(1, w-x-1), base_attr); x += 1
            ack = auth_msg.split('ack=',1)[1].split(' rx=',1)[0].strip() if 'ack=' in auth_msg else ''
            stdscr.addnstr(AUTH_Y, x, 'ack=', max(1, w-x-1), base_attr); x += 4
            stdscr.addnstr(AUTH_Y, x, ack, max(1, w-x-1), val_y); x += len(ack)
            stdscr.addnstr(AUTH_Y, x, ' ', max(1, w-x-1), base_attr); x += 1
            rx = auth_msg.split('rx=',1)[1].strip() if 'rx=' in auth_msg else ''
            stdscr.addnstr(AUTH_Y, x, 'rx=', max(1, w-x-1), base_attr); x += 3
            stdscr.addnstr(AUTH_Y, x, rx, max(1, w-x-1), val_y)
        else:
            stdscr.addnstr(AUTH_Y, cx_auth, auth_msg, max(1, w-cx_auth-1), curses.A_BOLD)

        # block picker overlay (via 'b')
        if block_select_mode and block_list:
            picker_items = []
            for i,b in enumerate(block_list):
                t = f"[{b}]" if i == block_idx else str(b)
                picker_items.append(t)
            picker = 'Blocks: ' + ' '.join(picker_items)
            px = max(0, (w - len(picker)) // 2)
            py = max(0, INFO_Y - 1)
            if curses.has_colors():
                stdscr.addnstr(py, 0, ' ' * max(1, w-1), max(1, w-1), curses.color_pair(3))
                stdscr.addnstr(py, px, picker, max(1, w-px-1), curses.color_pair(1) | curses.A_BOLD)
            else:
                stdscr.addnstr(py, px, picker, max(1, w-px-1), curses.A_BOLD)

        # info row (save/reload/errors)
        info_txt = msg
        if (not info_txt) and (not preload_done):
            with cache_lock:
                cached_n = len(payload_cache)
            info_txt = f'preloading blocks... {preload_pos}/{len(preload_blocks)} cached={cached_n}'
        cx_info = max(0, (w - len(info_txt)) // 2) if len(info_txt) < w else 0
        if curses.has_colors():
            if info_txt.lower().startswith('err') or 'save err' in info_txt.lower() or 'reload err' in info_txt.lower() or 'failed' in info_txt.lower():
                ia = curses.color_pair(4) | curses.A_BOLD  # red on error
            else:
                ia = curses.color_pair(6) | curses.A_BOLD  # green on normal info
            stdscr.addnstr(INFO_Y, cx_info, info_txt, max(1, w-cx_info-1), ia)
        else:
            stdscr.addnstr(INFO_Y, cx_info, info_txt, max(1, w-cx_info-1))

        # table
        y0 = TABLE_Y
        y1 = h - 1
        if y1 <= y0 + 2:
            stdscr.refresh()
            ch = _read_key(stdscr)
            if ch in (27, curses.KEY_F10, 274, ord('q'), ord('Q')):
                break
            continue

        # precompute decoded maps for dynamic width sizing
        dec = dc._decode_fields(bytes(payload), layout)
        dec_base = dc._decode_fields(bytes(baseline_payload), layout)

        # estimate dynamic content widths (Raw/Wert)
        raw_need = 10
        val_need = 16
        name_need = 12
        obj_need = 12
        sample_rows = ui_rows[:min(len(ui_rows), 120)]
        for rr in sample_rows:
            try:
                if rr.get('kind') == 'version':
                    base_k = rr.get('base','')
                    label = dc._label_for_key(base_k, state.get('labels', {}))
                    obj = base_k.split('.')[-1] if base_k else ''
                    vals = _read_version_from_payload(bytes(payload), rr.get('keys', []), fmap)
                    if ('version' in str(base_k).lower()) or (base_k in VERSION_BASES):
                        vtxt = '.'.join(str(int(x)) for x in vals)
                    else:
                        vtxt = ','.join(str(int(x)) for x in vals)
                    rtxt = vtxt
                    name = f"  {label}"
                else:
                    kk = rr.get('key')
                    if not kk or kk not in fmap:
                        continue
                    base_k = kk.split('[', 1)[0]
                    decoded_raw = dec.get(kk)
                    if decoded_raw is None:
                        decoded_raw = dec.get(base_k)
                    rv = raw_from_payload(bytes(payload), fmap[kk])
                    name, obj, vtxt, rtxt = _ui_name_obj_val_raw(kk, decoded_raw, rv, state.get('formats', {}), state.get('labels', {}))
                    name = f"  {name}"

                    # block 18 raw/value preview tweaks
                    if int(args.block) == 18 and kk.startswith('MeldeHIST.ulZeitstempel['):
                        try:
                            ii = int(kk.split('[',1)[1].split(']',1)[0])
                            bo = 10 + ii * 6
                            if bo + 6 <= len(payload):
                                ts = int.from_bytes(bytes(payload)[bo+2:bo+6], 'little', signed=False)
                                we = int(bytes(payload)[bo])
                                mix = int(bytes(payload)[bo+1])
                                ty = (mix >> 4) & 0x0F
                                mo = mix & 0x0F
                                tlabel = dc._melde_type_label(ty, state.get('labels', {}))
                                code = dc._apply_meldecode_modifier(ty, we)
                                mlabel = 'Dachs' if mo == 1 else '-'
                                ztxt, _ = dc._apply_format('MeldeHIST.ulZeitstempel', ts, state.get('formats', {}))
                                vtxt = f"{ztxt} | Typ={ty} ({tlabel}) | Wert={we} ({dc._value_text_from_servicecode(we)}) | Code={code} | Modul={mo} ({mlabel})"
                                rtxt = f"{ts};{ty};{we};{mo}"
                        except Exception:
                            pass

                name_need = max(name_need, len(str(name)))
                obj_need  = max(obj_need, len(str(obj)))
                val_need  = max(val_need, len(str(vtxt)))
                raw_need  = max(raw_need, len(str(rtxt)))
            except Exception:
                pass

        # optional column visibility
        if hide_name:
            name_need = 0
        if hide_object:
            obj_need = 0

        # caps to avoid absurd outliers
        name_need = min(name_need + (0 if hide_name else 1), 40)
        obj_need  = min(obj_need + (0 if hide_object else 1), 40)
        val_need  = min(val_need + 1, 120)
        raw_need  = min(raw_need + 1, 120)

        # cap growth: max need + 5 chars
        max_name = name_need + 5
        max_obj  = obj_need + 5
        max_val  = val_need + 5
        max_raw  = raw_need + 5

        inner_target = max(44, w - 6)
        sep = 3

        # start with "as needed"
        name_w = min(name_need, max_name)
        obj_w  = min(obj_need, max_obj)
        val_w  = min(val_need, max_val)
        raw_w  = min(raw_need, max_raw)

        # minimums
        min_name = 0 if hide_name else 8
        min_obj  = 0 if hide_object else 8
        min_val  = 10
        min_raw  = 10

        # if too wide: shrink Name+Objekt first (as requested)
        while (name_w + obj_w + val_w + raw_w + sep) > inner_target and (name_w > min_name or obj_w > min_obj):
            if name_w >= obj_w and name_w > min_name:
                name_w -= 1
            elif obj_w > min_obj:
                obj_w -= 1
            elif name_w > min_name:
                name_w -= 1
            else:
                break

        # if still too wide, shrink Wert/Raw only as needed
        while (name_w + obj_w + val_w + raw_w + sep) > inner_target and (val_w > min_val or raw_w > min_raw):
            if raw_w >= val_w and raw_w > min_raw:
                raw_w -= 1
            elif val_w > min_val:
                val_w -= 1
            elif raw_w > min_raw:
                raw_w -= 1
            else:
                break

        # if there is free space: give it to current mode focus, then the other dynamic column
        free = inner_target - (name_w + obj_w + val_w + raw_w + sep)
        if free > 0:
            if raw_mode:
                add = min(free, max(0, min(raw_need, max_raw) - raw_w)); raw_w += add; free -= add
                add = min(free, max(0, min(val_need, max_val) - val_w)); val_w += add; free -= add
            else:
                add = min(free, max(0, min(val_need, max_val) - val_w)); val_w += add; free -= add
                add = min(free, max(0, min(raw_need, max_raw) - raw_w)); raw_w += add; free -= add
            # remaining free width goes to obj/name (capped at need+5)
            if free > 0:
                add_obj = min(free // 2, max(0, max_obj - obj_w)); obj_w += add_obj; free -= add_obj
                add_name = min(free, max(0, max_name - name_w)); name_w += add_name; free -= add_name

        table_w = name_w + obj_w + val_w + raw_w + 3
        x0 = max(0, (w - table_w) // 2)
        x1 = x0 + name_w + 1
        x2 = x1 + obj_w + 1
        x3 = x2 + val_w + 1

        h_attr = (curses.color_pair(1) | curses.A_BOLD) if curses.has_colors() else curses.A_BOLD
        if name_w > 0:
            stdscr.addnstr(y0, x0+1, 'Name', max(1, name_w-1), h_attr)
        if obj_w > 0:
            stdscr.addnstr(y0, x1+1, 'Objekt', max(1, obj_w-1), h_attr)
        stdscr.addnstr(y0, x2+1, 'Wert', max(1, val_w-1), h_attr)
        stdscr.addnstr(y0, x3+1, 'Raw', max(1, raw_w-1), h_attr)

        visible = y1 - (y0 + 2)
        visible_rows = max(0, min(len(ui_rows)-top, visible))
        sep_end = y0 + 2 + visible_rows

        left = x0
        right = min(w-1, x3 + raw_w)
        topb = max(0, y0 - 1)
        bott = max(topb+1, sep_end)
        if right > left + 2 and bott > topb + 1:
            stdscr.addch(topb, left, ord('+'))
            stdscr.addch(topb, right, ord('+'))
            stdscr.addch(bott, left, ord('+'))
            stdscr.addch(bott, right, ord('+'))
            for xx in range(left+1, right):
                stdscr.addch(topb, xx, ord('-'))
                stdscr.addch(bott, xx, ord('-'))
            for yy in range(topb+1, bott):
                stdscr.addch(yy, left, ord('|'))
                stdscr.addch(yy, right, ord('|'))
            hdr_sep = y0 + 1
            if hdr_sep < bott:
                stdscr.addch(hdr_sep, left, ord('+'))
                stdscr.addch(hdr_sep, right, ord('+'))
                for xx in range(left+1, right):
                    stdscr.addch(hdr_sep, xx, ord('-'))

        for yy in range(y0, sep_end):
            if name_w > 0 and x1 < right: stdscr.addch(yy, x1, ord('|'))
            if obj_w > 0 and x2 < right: stdscr.addch(yy, x2, ord('|'))
            if x3 < right: stdscr.addch(yy, x3, ord('|'))

        if idx < top: top = idx
        if idx >= top + visible: top = idx - visible + 1

        # block 18 helper: map idx -> compact melde event fields for inline row rendering
        hist_map = {}
        hist_cur = None
        if int(args.block) == 18:
            try:
                hist_cur, hist_entries = dc._parse_block18_history(bytes(payload))
                for e in (hist_entries or []):
                    i = int(e.get('idx', -1))
                    if i < 0:
                        continue
                    t = e.get('typ')
                    wv = e.get('wert')
                    m = e.get('modul')
                    z = e.get('zeit')
                    ztxt, _ = dc._apply_format('MeldeHIST.ulZeitstempel', z, state.get('formats', {}))
                    code = dc._apply_meldecode_modifier(t, wv)
                    tlabel = dc._melde_type_label(t, state.get('labels', {}))
                    mlabel = 'Dachs' if int(m) == 1 else '-'
                    vtxt = f"{ztxt} | Typ={t} ({tlabel}) | Wert={wv} ({dc._value_text_from_servicecode(wv)}) | Code={code} | Modul={m} ({mlabel})"
                    hist_map[i] = {
                        'vtxt': vtxt,
                        'rawtxt': f"{int(z) if z is not None else 0};{int(t) if t is not None else 0};{int(wv) if wv is not None else 0};{int(m) if m is not None else 0}",
                    }
            except Exception:
                hist_map = {}
                hist_cur = None

        row_y = y0 + 2
        for i in range(top, min(len(ui_rows), top + visible)):
            row = ui_rows[i]
            k = row['key']
            row_changed = any((kk in changed) for kk in row.get('keys', [k]))
            marker = '*' if row_changed else ' '
            if row['kind'] == 'version':
                vals = _read_version_from_payload(bytes(payload), row['keys'], fmap)
                base_k = row['base']
                label = dc._label_for_key(base_k, state.get('labels', {}))
                obj = base_k.split('.')[-1]
                name = f"{marker} {label}"
                vals_base = _read_version_from_payload(bytes(baseline_payload), row['keys'], fmap)
                if ('version' in base_k.lower()) or (base_k in VERSION_BASES):
                    vtxt = '.'.join(str(int(x)) for x in vals)
                    base_vtxt = '.'.join(str(int(x)) for x in vals_base)
                    rawtxt = vtxt
                else:
                    vtxt = ','.join(str(int(x)) for x in vals)
                    base_vtxt = ','.join(str(int(x)) for x in vals_base)
                    rawtxt = vtxt
            else:
                base_k = k.split('[', 1)[0]
                decoded_raw = dec.get(k)
                if decoded_raw is None:
                    decoded_raw = dec.get(base_k)
                raw_i = raw_from_payload(bytes(payload), fmap[k])
                name, obj, vtxt, rawtxt = _ui_name_obj_val_raw(k, decoded_raw, raw_i, state.get('formats', {}), state.get('labels', {}))
                decoded_base = dec_base.get(k)
                if decoded_base is None:
                    decoded_base = dec_base.get(base_k)
                raw_base = raw_from_payload(bytes(baseline_payload), fmap[k])
                _n2, _o2, base_vtxt, _r2 = _ui_name_obj_val_raw(k, decoded_base, raw_base, state.get('formats', {}), state.get('labels', {}))
                name = f"{marker} {name}"

                # block 18: keep table layout, but render event summary on timestamp rows
                if int(args.block) == 18 and k.startswith('MeldeHIST.ulZeitstempel['):
                    try:
                        ii = int(k.split('[',1)[1].split(']',1)[0])
                    except Exception:
                        ii = None
                    if ii is not None and ii in hist_map:
                        vtxt = hist_map[ii]['vtxt']
                        rawtxt = hist_map[ii]['rawtxt']
                        if hist_cur is not None and int(hist_cur) == ii:
                            name = f"{marker} <= aktuell {name}"

            attr = curses.color_pair(2) if (curses.has_colors() and i == idx) else (curses.color_pair(1) if curses.has_colors() else 0)
            if curses.has_colors() and row_changed:
                val_attr = curses.color_pair(4) | curses.A_BOLD   # changed values red
            else:
                val_attr = attr

            if (not curses.has_colors()) and i == idx:
                stdscr.attron(curses.A_REVERSE)

            if name_w > 0:
                stdscr.addnstr(row_y, x0+1, _safe_text(name), max(1, name_w-1), attr)
            if obj_w > 0:
                stdscr.addnstr(row_y, x1+1, _safe_text(obj), max(1, obj_w-1), attr)
            if curses.has_colors() and row_changed:
                _draw_diff_text(stdscr, row_y, x2+1, max(1, val_w-1), vtxt, base_vtxt, attr, curses.color_pair(4) | curses.A_BOLD)
                stdscr.addnstr(row_y, x3+1, _safe_text(rawtxt), max(1, raw_w-1), attr)
            else:
                stdscr.addnstr(row_y, x2+1, _safe_text(vtxt), max(1, val_w-1), val_attr)
                stdscr.addnstr(row_y, x3+1, _safe_text(rawtxt), max(1, raw_w-1), val_attr)

            if (not curses.has_colors()) and i == idx:
                stdscr.attroff(curses.A_REVERSE)

            row_y += 1

        # hex section under table (toggle + wrapped to table width)
        if not args.no_hex:
            hex_y0 = row_y + 1
            table_left = x0
            table_right = min(w-1, x3 + raw_w)
            table_w = max(1, table_right - table_left)
            bytes_per_line = max(1, (table_w + 1) // 3)

            cur_b = bytes(payload)
            base_b = bytes(baseline_payload)

            if hex_y0 < h - 2:
                stdscr.addnstr(hex_y0, table_left, 'HEX current:', max(1, table_w), curses.A_BOLD if not curses.has_colors() else (curses.color_pair(1) | curses.A_BOLD))

            # current hex wrapped with red diff bytes
            lines_max = max(0, (h - 1) - (hex_y0 + 1))
            needed_cur = (len(cur_b) + bytes_per_line - 1) // bytes_per_line
            cur_lines = min(lines_max, needed_cur)
            for li in range(cur_lines):
                y = hex_y0 + 1 + li
                st = li * bytes_per_line
                en = min(len(cur_b), st + bytes_per_line)
                if curses.has_colors() and (cur_b != base_b):
                    _draw_hex_diff(stdscr, y, table_left, table_w, cur_b[st:en], base_b[st:en], curses.color_pair(1), curses.color_pair(4) | curses.A_BOLD)
                else:
                    txt = _hex_line(cur_b[st:en])
                    stdscr.addnstr(y, table_left, txt, max(1, table_w), curses.color_pair(1) if curses.has_colors() else 0)

            y_next = hex_y0 + 1 + cur_lines
            if y_next < h - 1:
                stdscr.addnstr(y_next, table_left, 'HEX baseline:', max(1, table_w), curses.A_BOLD if not curses.has_colors() else (curses.color_pair(1) | curses.A_BOLD))
                y_next += 1

            lines_max2 = max(0, (h - 1) - y_next)
            needed_base = (len(base_b) + bytes_per_line - 1) // bytes_per_line
            base_lines = min(lines_max2, needed_base)
            for li in range(base_lines):
                y = y_next + li
                st = li * bytes_per_line
                en = min(len(base_b), st + bytes_per_line)
                txt = _hex_line(base_b[st:en])
                stdscr.addnstr(y, table_left, txt, max(1, table_w), curses.color_pair(1) if curses.has_colors() else 0)

        # bottom centered key help in black bar
        help1 = 'Up/Down: navigate   Left/Right: block   Enter:edit   b:block-select   n:name on/off   o:objekt on/off   F2/s:save   F4/r:reload   F6:raw-toggle   F10/Esc/q:quit'
        hx = max(0, (w - len(help1)) // 2)
        if curses.has_colors():
            stdscr.addnstr(h-1, 0, ' ' * max(1, w-1), max(1, w-1), curses.color_pair(8))
            stdscr.addnstr(h-1, hx, help1, max(1, w-hx-1), curses.color_pair(8) | curses.A_BOLD)
        else:
            stdscr.addnstr(h-1, hx, help1, max(1, w-hx-1))

        def _reload_current_block():
            nonlocal layout, fmap, keys, ui_rows, payload, baseline_payload, changed, msg
            bk = args.block
            new_layout = state['layouts'].get(str(bk), [])
            if not new_layout:
                msg = f'no layout for block {bk}'
                return
            fmap = field_map(new_layout)
            keys = [k for k in fmap.keys() if args.show_reserved or not dc._is_reserved_key(k)]
            ui_rows = _build_ui_rows(keys, fmap)
            with cache_lock:
                pld = payload_cache.get(int(bk))
            if pld is None:
                res = dc.read_blocks_batch(args.port, args.baud, [int(bk)], args.rx_timeout,
                                           wait_between_blocks=args.wait_between_blocks,
                                           flush_before_read=True, retry_on_timeout=0)
                pld = res.get(int(bk))
                if pld is None:
                    msg = f'cannot read block {bk}'
                    return
                with cache_lock:
                    payload_cache[int(bk)] = bytes(pld)
            payload = bytearray(pld)
            baseline_payload = bytearray(payload)
            changed.clear()
            layout = new_layout
            state['layout'] = layout
            _lb = labels_from_layout(layout)
            _lb.update(load_local_label_overrides())
            state['labels'] = _lb
            state['fmap'] = fmap
            state['keys'] = keys
            state['payload'] = payload
            with cache_lock:
                in_cache = int(bk) in payload_cache
            msg = f'block switched to {bk} (cache)' if in_cache else f'block switched to {bk}'

        ch = _read_key(stdscr)
        if ch in (27, curses.KEY_F10, 274, ord('q'), ord('Q')):
            if block_select_mode and ch == 27:
                block_select_mode = False
                msg = 'block-select cancelled'
                continue
            break
        elif ch in (ord('b'), ord('B')):
            block_select_mode = not block_select_mode
            msg = 'block-select ON: UP/DOWN wählen, Enter laden, Esc abbrechen' if block_select_mode else 'block-select OFF'
        elif block_select_mode and ch == curses.KEY_UP:
            block_idx = max(0, block_idx-1)
            args.block = block_list[block_idx]
        elif block_select_mode and ch == curses.KEY_DOWN:
            block_idx = min(len(block_list)-1, block_idx+1)
            args.block = block_list[block_idx]
        elif block_select_mode and ch in (10,13):
            _reload_current_block()
            block_select_mode = False
            idx = 0
            top = 0
        elif ch == curses.KEY_LEFT:
            if block_list:
                block_idx = max(0, block_idx-1)
                args.block = block_list[block_idx]
                _reload_current_block()
                idx = 0
                top = 0
        elif ch == curses.KEY_RIGHT:
            if block_list:
                block_idx = min(len(block_list)-1, block_idx+1)
                args.block = block_list[block_idx]
                _reload_current_block()
                idx = 0
                top = 0
        elif ch == curses.KEY_UP:
            idx = max(0, idx-1)
        elif ch == curses.KEY_DOWN:
            idx = min(len(ui_rows)-1, idx+1)
        elif ch == curses.KEY_NPAGE:
            idx = min(len(ui_rows)-1, idx + max(1, visible-1))
        elif ch == curses.KEY_PPAGE:
            idx = max(0, idx - max(1, visible-1))
        elif ch in (ord('n'), ord('N')):
            hide_name = not hide_name
            msg = f"name column {'OFF' if hide_name else 'ON'}"
        elif ch in (ord('o'), ord('O')):
            hide_object = not hide_object
            msg = f"objekt column {'OFF' if hide_object else 'ON'}"
        elif ch in (curses.KEY_F6, 270):
            raw_mode = not raw_mode
            msg = f"raw_mode={'ON' if raw_mode else 'OFF'}"
        elif ch in (10, 13):
            row = ui_rows[idx]
            k = row['key']
            edit_y = y0 + 2 + (idx - top)
            if edit_y < (y0 + 2) or edit_y >= h-1:
                msg = 'row not visible'
                continue
            hist_edit_idx = None
            if row['kind'] == 'version':
                vals = _read_version_from_payload(bytes(payload), row['keys'], fmap)
                current_val = '.'.join(str(int(x)) for x in vals)
            else:
                base_k = k.split('[', 1)[0]
                decoded_raw = dec.get(k)
                if decoded_raw is None:
                    decoded_raw = dec.get(base_k)
                raw_i = raw_from_payload(bytes(payload), fmap[k])
                _n, _o, current_val, _r = _ui_name_obj_val_raw(k, decoded_raw, raw_i, state.get('formats', {}), state.get('labels', {}))
                if raw_mode:
                    current_val = str(raw_i if raw_i is not None else '')

                # block 18 timestamp rows: raw-mode edits raw ts, normal mode edits event tuple
                if int(args.block) == 18 and k.startswith('MeldeHIST.ulZeitstempel['):
                    try:
                        hist_edit_idx = int(k.split('[',1)[1].split(']',1)[0])
                    except Exception:
                        hist_edit_idx = None
                    if raw_mode and hist_edit_idx is not None:
                        base_off = 10 + (int(hist_edit_idx) * 6)
                        if base_off + 6 <= len(payload):
                            ts_raw = int.from_bytes(bytes(payload)[base_off+2:base_off+6], 'little', signed=False)
                            wert_raw = int(bytes(payload)[base_off])
                            mix_raw = int(bytes(payload)[base_off+1])
                            typ_raw = (mix_raw >> 4) & 0x0F
                            modul_raw = mix_raw & 0x0F
                            # raw tuple: ts;typ;wert;modul
                            current_val = f"{ts_raw};{typ_raw};{wert_raw};{modul_raw}"
                        else:
                            current_val = str(int(raw_i) if raw_i is not None else 0)
                    elif hist_edit_idx is not None and hist_edit_idx in hist_map:
                        ee = hist_map[hist_edit_idx]
                        # editable format: "DD.MM.YYYY HH:MM:SS;typ;wert;modul"
                        v = ee.get('vtxt','')
                        dt = v.split(' | ',1)[0] if ' | ' in v else current_val
                        typ = v.split('Typ=',1)[1].split(' ',1)[0] if 'Typ=' in v else '0'
                        wert = v.split('Wert=',1)[1].split(' ',1)[0] if 'Wert=' in v else '0'
                        modul = v.split('Modul=',1)[1].split(' ',1)[0] if 'Modul=' in v else '0'
                        current_val = f"{dt};{typ};{wert};{modul}"

            edit_x = x3+1 if raw_mode else x2+1
            edit_w = max(1, raw_w-1) if raw_mode else max(1, val_w-1)
            val, ok = _inline_edit(stdscr, edit_y, edit_x, edit_w, str(current_val))
            if not ok:
                msg = 'edit cancelled'
                continue
            try:
                if row['kind'] == 'version':
                    tmp = val.replace(',', '.')
                    parts = [x.strip() for x in tmp.split('.') if x.strip() != '']
                    if len(parts) != len(row['keys']):
                        raise ValueError(f"version needs {len(row['keys'])} parts")
                    vals = [int(x) for x in parts]
                    for rv in vals:
                        if rv < 0 or rv > 255:
                            raise ValueError('version byte out of range 0..255')
                    for kk, rv in zip(row['keys'], vals):
                        set_raw(payload, fmap[kk], rv)
                        changed.add(kk)
                    msg = f"OK {row['base']} -> " + '.'.join(str(x) for x in vals)
                else:
                    # block 18 timestamp rows: raw-mode edits raw timestamp directly
                    if raw_mode and int(args.block) == 18 and hist_edit_idx is not None and k.startswith('MeldeHIST.ulZeitstempel['):
                        txt = str(val).strip()
                        parts = [x.strip() for x in txt.split(';') if x.strip() != '']
                        base_off = 10 + (int(hist_edit_idx) * 6)
                        if base_off + 6 > len(payload):
                            raise ValueError('event offset out of payload range')

                        if len(parts) == 1:
                            # backward-compatible: only timestamp raw
                            raw_ts = int(parts[0])
                            if not (0 <= raw_ts <= 0xFFFFFFFF):
                                raise ValueError('raw timestamp out of range 0..4294967295')
                            old_ts = int.from_bytes(bytes(payload)[base_off+2:base_off+6], 'little', signed=False)
                            if raw_ts != old_ts:
                                payload[base_off + 2:base_off + 6] = int(raw_ts).to_bytes(4, 'little', signed=False)
                                changed.add(k)
                            msg = f"OK raw {k} -> {raw_ts}"
                        elif len(parts) == 4:
                            # raw tuple: ts;typ;wert;modul
                            raw_ts = int(parts[0]); raw_ty = int(parts[1]); raw_we = int(parts[2]); raw_mo = int(parts[3])
                            if not (0 <= raw_ts <= 0xFFFFFFFF):
                                raise ValueError('raw timestamp out of range 0..4294967295')
                            if not (0 <= raw_ty <= 15 and 0 <= raw_we <= 255 and 0 <= raw_mo <= 15):
                                raise ValueError('raw tuple range: ts(0..4294967295); typ/modul(0..15); wert(0..255)')
                            old = bytes(payload)[base_off:base_off+6]
                            mix = ((raw_ty & 0x0F) << 4) | (raw_mo & 0x0F)
                            payload[base_off] = raw_we & 0xFF
                            payload[base_off+1] = mix & 0xFF
                            payload[base_off+2:base_off+6] = int(raw_ts).to_bytes(4, 'little', signed=False)
                            if bytes(payload)[base_off:base_off+6] != old:
                                changed.add(k)
                            msg = f"OK raw event[{hist_edit_idx}] -> {raw_ts};{raw_ty};{raw_we};{raw_mo}"
                        else:
                            raise ValueError('Raw-Format: ts ODER ts;typ;wert;modul')

                    # block 18 timestamp rows: edit tuple date/time + typ + wert + modul
                    elif (not raw_mode) and int(args.block) == 18 and hist_edit_idx is not None and k.startswith('MeldeHIST.ulZeitstempel['):
                        txt = val.strip()
                        parts = [x.strip() for x in txt.split(';')]
                        if len(parts) != 4:
                            raise ValueError('Format: DD.MM.YYYY HH:MM:SS;typ;wert;modul')
                        dtxt, ttxt, wtxt, mtxt = parts
                        raw_ty = int(ttxt)
                        raw_we = int(wtxt)
                        raw_mo = int(mtxt)
                        if not (0 <= raw_ty <= 15 and 0 <= raw_we <= 255 and 0 <= raw_mo <= 15):
                            raise ValueError('typ/modul 0..15, wert 0..255')

                        # block18 wire layout: byte0 current, byte1..9 reserved, then 10 entries x 6 bytes
                        base_off = 10 + (int(hist_edit_idx) * 6)
                        if base_off + 6 > len(payload):
                            raise ValueError('event offset out of payload range')

                        # timestamp: explicit parse (format includes time)
                        from datetime import datetime, timezone
                        k_ts = f"MeldeHIST.ulZeitstempel[{hist_edit_idx}]"
                        dt_obj = datetime.strptime(dtxt, '%d.%m.%Y %H:%M:%S').replace(tzinfo=timezone.utc)
                        base = datetime(2000, 1, 1, tzinfo=timezone.utc)
                        raw_ts = int((dt_obj - base).total_seconds())

                        payload[base_off] = int(raw_we) & 0xFF
                        payload[base_off + 1] = ((int(raw_ty) & 0x0F) << 4) | (int(raw_mo) & 0x0F)
                        payload[base_off + 2:base_off + 6] = int(raw_ts).to_bytes(4, 'little', signed=False)

                        changed.add(k_ts)
                        code = dc._apply_meldecode_modifier(raw_ty, raw_we)
                        msg = f"OK event[{hist_edit_idx}] -> {dtxt};{raw_ty};{raw_we};{raw_mo} (code={code})"
                    else:
                        meta = fmap[k]
                        raw = to_raw(val, k, meta, state['formats'], raw_mode)
                        set_raw(payload, meta, raw)
                        changed.add(k)
                        msg = f"OK {k} -> raw={raw}"
            except Exception as e:
                msg = f"ERR {e}"
        elif ch in (curses.KEY_F4, 268, ord('r'), ord('R')):
            try:
                res = dc.read_blocks_batch(args.port, args.baud, [int(args.block)], args.rx_timeout,
                                           wait_between_blocks=args.wait_between_blocks,
                                           flush_before_read=True, retry_on_timeout=0)
                pld = res.get(int(args.block))
                if pld is not None:
                    payload[:] = pld
                    baseline_payload[:] = payload
                    with cache_lock:
                        payload_cache[int(args.block)] = bytes(payload)
                    changed.clear()
                    msg = 'reloaded from device'
                else:
                    msg = 'reload failed'
            except Exception as e:
                msg = f"reload err: {e}"
        elif ch in (curses.KEY_F2, 266, ord('s'), ord('S')):
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
                    dc.send_service(ser, b'', pn, args.rx_timeout); pn = (pn+1) & 0x0F
                    svc = bytes([(args.block+1) & 0xFF]) + bytes(payload)
                    _tx, ack, rx, _ = dc.send_service(ser, svc, pn, args.rx_timeout)
                msg = f"SAVED ack={dc.to_hex(ack) if ack else '-'} rx={dc.to_hex(rx) if rx else '-'}"
                baseline_payload[:] = payload
                changed.clear()
            except Exception as e:
                msg = f"save err: {e}"


def main():
    ap = argparse.ArgumentParser(prog='dachs_cli_writer_tui_v2')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--block', type=int, required=True)
    ap.add_argument('--all-blocks', action='store_true', help='load all known blocks for quick switching')
    ap.add_argument('--auth-level', type=int, default=5)
    ap.add_argument('--auth-pass4', default=None)
    ap.add_argument('--rx-timeout', type=float, default=2.0)
    ap.add_argument('--wait-between-blocks', type=float, default=0.0)
    ap.add_argument('--pack-file', default='', help='optional pack file override (otherwise auto-detect)')
    ap.add_argument('--pack-rev', default='50')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--show-reserved', action='store_true')
    ap.add_argument('--hide-name', action='store_true', help='hide Name column')
    ap.add_argument('--hide-object', '--hide-objekt', dest='hide_object', action='store_true', help='hide Objekt column')
    ap.add_argument('--no-hex', action='store_true', help='disable hex section under table')
    args = ap.parse_args()

    st = auth_and_load(args)
    curses.wrapper(run_tui, st, args)


if __name__ == '__main__':
    main()
