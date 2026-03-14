#!/usr/bin/env python3
import argparse
import json
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import dachs_core as dc
import dachs_cli_v2 as v2

DEFAULT_BACKUP_BLOCKS = [0,18,20,22,24,26,28,30,31,32,34,36,44,46,50,52,54,56,60,62,66,70,76,80,82,84,86,88,90,92,94,100,102,104,110,112,114]


def parse_blocks_csv(s: str):
    return [int(x.strip()) for x in s.split(',') if x.strip()] if s else []


def blocks_from_pack(pack_file: Path, pack_rev: str = '50'):
    obj = json.loads(pack_file.read_text())
    if isinstance(obj.get('layouts'), dict):
        layouts = obj.get('layouts', {})
        blocks = []
        for k in layouts.keys():
            try:
                blocks.append(int(k))
            except Exception:
                pass
        return sorted(set(blocks)), layouts
    if isinstance(obj.get('blocks'), dict):
        blocks=[]
        for k in obj.get('blocks',{}).keys():
            try:
                blocks.append(int(k))
            except Exception:
                pass
        blocks=sorted(set(blocks))
        tmp_pack, _tmp_labels = v2._materialize_pack_for_blocks(pack_file, blocks, str(pack_rev), fallback_formats=Path('/root/senertec/dachs-cli/msr2_formats_v2.json'))
        x = json.loads(Path(tmp_pack).read_text())
        return blocks, x.get('layouts', {})
    return [], {}


def read_block_payload(ser, block: int, pn: int, timeout: float):
    _tx, ack, rx, dt = dc.send_service(ser, bytes([block & 0xFF]), pn, timeout)
    rec = {
        'block': block,
        'packet': pn,
        'rtt_ms': round(dt, 1),
        'ack': dc.to_hex(ack) if ack else None,
        'rx': dc.to_hex(rx) if rx else None,
    }
    if not rx or rx[0] != 0x02 or len(rx) < 8:
        rec.update({'ok': False, 'status': None, 'payload_hex': None, 'payload_len': 0})
        return rec

    data = rx[5:-2]
    payload = data[1:] if len(data) > 1 else b''
    rec.update({'ok': True, 'status': data[0] if data else None, 'payload_hex': payload.hex().upper(), 'payload_len': len(payload)})
    return rec




def layout_expected_len(layout):
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


def color_payload(actual, expected):
    txt = f"payload={actual:3d}B"
    if expected and expected > 0:
        txt += f" exp={expected:3d}B"
    if actual <= 0:
        return f"[31m{txt}[0m"
    if expected and actual == expected:
        return f"[32m{txt}[0m"
    if expected and actual != expected:
        return f"[33m{txt}[0m"
    return txt

def run_pass(ser, blocks, timeout, layouts, decode=True, pass_name='pass', pause_between_blocks=0.0, flush_before_read=True, retry_on_timeout=3):
    out = []
    pn = 0
    dc.send_service(ser, b'', pn, timeout); pn = (pn + 1) & 0x0F

    total = len(blocks)
    for i, b in enumerate(blocks, start=1):
        attempt = 0
        rec = None
        while attempt <= retry_on_timeout:
            if flush_before_read:
                try:
                    ser.reset_input_buffer()
                except Exception:
                    pass
            rec = read_block_payload(ser, b, pn, timeout)
            pn = (pn + 1) & 0x0F
            timeout_like = (not rec.get('ok')) or rec.get('status') is None or rec.get('rtt_ms', 0) >= (timeout * 1000 - 5)
            if not timeout_like:
                break
            attempt += 1
            if attempt <= retry_on_timeout:
                pn = 0
                dc.send_service(ser, b'', pn, timeout); pn = (pn + 1) & 0x0F

        if decode and rec.get('ok') and rec.get('payload_hex'):
            layout = layouts.get(str(b), [])
            if layout:
                try:
                    rec['decoded'] = dc._decode_fields(bytes.fromhex(rec['payload_hex']), layout)
                except Exception as e:
                    rec['decode_error'] = str(e)

        out.append(rec)
        st = rec.get('status')
        st_txt = f"0x{st:02X}" if st is not None else '-'
        plen = rec.get('payload_len') or 0
        exp = layout_expected_len(layouts.get(str(b), []))
        payload_txt = color_payload(plen, exp)
        retry_txt = f" retries={attempt}" if attempt else ''
        print(f"[{pass_name}] {i:02d}/{total} block={b:3d} status={st_txt} {payload_txt} rtt={rec.get('rtt_ms',0):5.1f}ms{retry_txt}")

        if pause_between_blocks > 0:
            time.sleep(pause_between_blocks)

    return out


def _split_hex_pairs(h: str | None):
    if not h:
        return []
    h = ''.join(h.split()).upper()
    return [h[i:i+2] for i in range(0, len(h), 2)]


def _color_hex_diff(h1: str | None, h2: str | None):
    A = _split_hex_pairs(h1)
    B = _split_hex_pairs(h2)
    n = max(len(A), len(B))
    RED = '\x1b[31m'
    GRN = '\x1b[32m'
    DIM = '\x1b[2m'
    RST = '\x1b[0m'

    o1, o2 = [], []
    for i in range(n):
        a = A[i] if i < len(A) else '--'
        b = B[i] if i < len(B) else '--'
        changed = a != b
        if changed:
            o1.append(f"{RED}{a}{RST}")
            o2.append(f"{GRN}{b}{RST}")
        else:
            o1.append(f"{DIM}{a}{RST}")
            o2.append(f"{DIM}{b}{RST}")
    return ' '.join(o1), ' '.join(o2)


def summarize_changes(p1, p2):
    d1 = {r['block']: r for r in p1}
    d2 = {r['block']: r for r in p2}
    changes = []
    for b in sorted(set(d1) | set(d2)):
        a, c = d1.get(b), d2.get(b)
        if not a or not c:
            changes.append({'block': b, 'type': 'missing_in_one_pass'})
            continue
        if a.get('payload_hex') != c.get('payload_hex'):
            item = {
                'block': b,
                'type': 'payload_changed',
                'pass1_payload_hex': a.get('payload_hex'),
                'pass2_payload_hex': c.get('payload_hex'),
                'pass1_ok': a.get('ok'),
                'pass2_ok': c.get('ok'),
                'pass1_decode_error': a.get('decode_error'),
                'pass2_decode_error': c.get('decode_error'),
            }
            if isinstance(a.get('decoded'), dict) and isinstance(c.get('decoded'), dict):
                key_changes = []
                for k in sorted(set(a['decoded']) | set(c['decoded'])):
                    if a['decoded'].get(k) != c['decoded'].get(k):
                        key_changes.append({'key': k, 'pass1': a['decoded'].get(k), 'pass2': c['decoded'].get(k)})
                item['decoded_changes'] = key_changes
            changes.append(item)
    return changes


def print_change_summary(changes):
    if not changes:
        print('No changes between pass1/pass2')
        return
    print('Changed blocks between pass1/pass2:')
    for ch in changes:
        b = ch.get('block')
        if ch.get('type') != 'payload_changed':
            print(f" - block {b}: {ch.get('type')}")
            continue

        dcg = ch.get('decoded_changes') or []
        if dcg:
            print(f" - block {b}: {len(dcg)} decoded field(s) changed")
            for item in dcg[:8]:
                print(f"    {item['key']}: {item['pass1']} -> {item['pass2']}")
            if len(dcg) > 8:
                print(f"    ... and {len(dcg)-8} more")
            continue

        # No decoded diff possible -> show raw HEX side by side, colorized
        p1 = ch.get('pass1_payload_hex')
        p2 = ch.get('pass2_payload_hex')
        print(f" - block {b}: payload changed (no decoded diff available)")
        if ch.get('pass1_decode_error') or ch.get('pass2_decode_error'):
            print(f"    decode_error pass1={ch.get('pass1_decode_error')} pass2={ch.get('pass2_decode_error')}")
        l1, l2 = _color_hex_diff(p1, p2)
        print(f"    pass1 HEX: {l1 if l1 else '-'}")
        print(f"    pass2 HEX: {l2 if l2 else '-'}")


def main():
    ap = argparse.ArgumentParser(prog='msr_backup_v2')
    ap.add_argument('--port', default='/dev/ttyUSB0', help='serial port path')
    ap.add_argument('--baud', type=int, default=19200)
    ap.add_argument('--rx-timeout', type=float, default=2.0)
    ap.add_argument('--pause-between-passes', type=float, default=1.0)
    ap.add_argument('--pause-between-blocks', type=float, default=0.0)
    ap.add_argument('--wait-between-blocks', type=float, default=None, help='alias for pause-between-blocks')
    ap.add_argument('--blocks', default='', help='CSV block list override; default: all known blocks from pack')
    ap.add_argument('--pack-file', default='/root/senertec/dachs-cli/msr2_pack_master_version.json')
    ap.add_argument('--pack-rev', default='50')
    ap.add_argument('--output', default='')
    ap.add_argument('--no-decode', action='store_true')
    ap.add_argument('--auth-level', type=int, default=5, help='set <0 to skip auth, default=5')
    ap.add_argument('--auth-pass4', default='', help='optional 4-digit auth pass override')
    ap.add_argument('--no-flush-before-read', action='store_true', help='disable input buffer flush before each block read')
    ap.add_argument('--retry-on-timeout', type=int, default=3, help='retry count per block on timeout/empty response')
    args = ap.parse_args()

    _auto, layouts = blocks_from_pack(Path(args.pack_file), args.pack_rev)
    if not _auto:
        _auto = list(DEFAULT_BACKUP_BLOCKS)
    # default: all known blocks from pack; optional override via --blocks
    blocks = parse_blocks_csv(args.blocks) if args.blocks else list(_auto)

    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    out_path = Path(args.output) if args.output else Path(f'msr_backup_{ts}.json')

    auth_info = None
    if args.auth_level >= 0:
        cmd = [
            'python3', 'auth_v2.py',
            '--port', args.port,
            '--baud', str(args.baud),
            '--rx-timeout', str(args.rx_timeout),
            '--auth-level', str(args.auth_level),
            '--retries', '3',
            '--json',
        ]
        if args.auth_pass4:
            cmd += ['--auth-pass4', args.auth_pass4]
        cp = subprocess.run(cmd, cwd='/root/senertec/dachs-cli', capture_output=True, text=True)
        stdout = (cp.stdout or '').strip()
        line = stdout.splitlines()[-1] if stdout else ''
        if not line:
            raise RuntimeError(f'auth.py returned no output (rc={cp.returncode}) stderr={cp.stderr.strip()}')
        auth_info = json.loads(line)
        if not auth_info.get('ok'):
            raise RuntimeError(f"auth failed: {auth_info}")
        print(
            f"AUTH serial={auth_info.get('serial')} bstd={auth_info.get('bstd_hours')} requested={auth_info.get('requested')} "
            f"granted={auth_info.get('granted')} pw4={auth_info.get('pw4_used')} computed_pw4={auth_info.get('computed_pw4')} "
            f"ack={auth_info.get('ack') or '-'} rx={auth_info.get('rx') or '-'}"
        )
    else:
        print('AUTH skipped (--auth-level < 0)')

    ser = dc.open_port(args.port, args.baud)
    if not ser:
        raise SystemExit(2)

    wait_between = args.wait_between_blocks if args.wait_between_blocks is not None else args.pause_between_blocks

    with ser:
        pass1 = run_pass(ser, blocks, args.rx_timeout, layouts, decode=not args.no_decode,
                         pass_name='pass1', pause_between_blocks=wait_between,
                         flush_before_read=not args.no_flush_before_read,
                         retry_on_timeout=max(0, int(args.retry_on_timeout)))

        if args.pause_between_passes > 0:
            time.sleep(args.pause_between_passes)

        pass2 = run_pass(ser, blocks, args.rx_timeout, layouts, decode=not args.no_decode,
                         pass_name='pass2', pause_between_blocks=wait_between,
                         flush_before_read=not args.no_flush_before_read,
                         retry_on_timeout=max(0, int(args.retry_on_timeout)))

    changes = summarize_changes(pass1, pass2)
    result = {
        'tool': 'msr_backup',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'port': args.port,
        'baud': args.baud,
        'rx_timeout': args.rx_timeout,
        'auth': auth_info,
        'blocks': blocks,
        'pass1': pass1,
        'pass2': pass2,
        'changes_between_passes': changes,
    }
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f'Backup written: {out_path}')
    print(f'Port: {args.port} | Blocks: {len(blocks)} | changed blocks between pass1/pass2: {len(changes)}')
    print_change_summary(changes)

if __name__ == '__main__':
    raise SystemExit(main())
