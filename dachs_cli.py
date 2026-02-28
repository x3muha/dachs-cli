#!/usr/bin/env python3
import argparse
import json
import sys
import time
import re
import os
import locale
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

try:
    import serial
except Exception:
    serial = None


def to_hex(bs: bytes) -> str:
    return ' '.join(f'{b:02X}' for b in bs)


def crc16_msr(data: bytes) -> int:
    poly = 0x1021
    table = []
    for i in range(256):
        rem = i << 8
        for _ in range(8):
            rem = ((rem << 1) ^ poly) if (rem & 0x8000) else (rem << 1)
        table.append(rem & 0xFFFF)
    v = 0
    for b in data:
        d = (b ^ (v >> 8)) & 0xFF
        v = (table[d] ^ ((v << 8) & 0xFFFF)) & 0xFFFF
    return v


def mk_send_telegram(data: bytes, packet_number: int, src=0x00, dst=0x10) -> bytes:
    ln = len(data)
    b0 = ((packet_number & 0x0F) << 4) | ((ln >> 8) & 0x0F)
    b1 = ln & 0xFF
    pkt = bytearray([0x02, src, dst, b0, b1]) + bytearray(data)
    c = crc16_msr(pkt)
    # Java impl writes CRC high byte first, then low byte.
    pkt.extend([(c >> 8) & 0xFF, c & 0xFF])
    return bytes(pkt)


def _parse_first_frame(buf: bytes):
    i = 0
    n = len(buf)
    while i < n and buf[i] not in (0x02, 0x06, 0x15):
        i += 1
    if i >= n:
        return b'', b''
    b0 = buf[i]
    if b0 in (0x06, 0x15):
        if i + 5 <= n:
            return buf[i:i+5], buf[i+5:]
        return b'', buf[i:]
    if i + 5 <= n:
        ln = ((buf[i+3] & 0x0F) << 8) | buf[i+4]
        total = 5 + ln + 2
        if i + total <= n:
            return buf[i:i+total], buf[i+total:]
    return b'', buf[i:]


def _parse_all_frames(buf: bytes):
    out = []
    i = 0
    n = len(buf)
    while i < n:
        while i < n and buf[i] not in (0x02, 0x06, 0x15):
            i += 1
        if i >= n:
            break
        b0 = buf[i]
        if b0 in (0x06, 0x15):
            if i + 5 <= n:
                out.append(buf[i:i+5])
                i += 5
            else:
                break
        else:
            if i + 5 > n:
                break
            ln = ((buf[i+3] & 0x0F) << 8) | buf[i+4]
            total = 5 + ln + 2
            if i + total <= n:
                out.append(buf[i:i+total])
                i += total
            else:
                break
    return out


def send_service(ser, service_data: bytes, pn: int, timeout_s: float):
    tx = mk_send_telegram(service_data, pn)
    t0 = time.time()
    ser.write(tx)
    deadline = time.time() + timeout_s
    raw = bytearray()
    ack = b''
    data = b''
    while time.time() < deadline:
        b = ser.read(512)
        if not b:
            continue
        raw.extend(b)
        frames = _parse_all_frames(bytes(raw))
        for f in frames:
            if f[0] in (0x06, 0x15) and ((f[1] >> 4) & 0x0F) == pn:
                ack = f
            if f[0] == 0x02:
                # some devices emit data with shifted packet numbers; keep latest data frame
                data = f
        if data:
            break
    return tx, ack, data, (time.time() - t0) * 1000.0


def open_port(port: str, baud: int):
    if serial is None:
        print('pyserial missing. Install with: pip install pyserial', file=sys.stderr)
        return None
    return serial.Serial(port=port, baudrate=baud, bytesize=8, parity='N', stopbits=1, timeout=0.02)


def watch_link(port: str, baud: int, count: int, interval: float, rx_timeout: float):
    ser = open_port(port, baud)
    if not ser:
        return 2
    rtts = []
    pn = 0
    print('time\tpn\tstatus\trtt_ms\trx')
    with ser:
        for _ in range(count):
            tx, ack, _, rtt = send_service(ser, b'', pn, rx_timeout)
            if ack:
                rtts.append(rtt)
                st = 'ACK+' if ack[0] == 0x06 else 'ACK-'
                print(f"{time.strftime('%H:%M:%S')}\t{pn:X}\t{st}\t{rtt:6.1f}\t{to_hex(ack)}")
            else:
                print(f"{time.strftime('%H:%M:%S')}\t{pn:X}\tTIMEOUT\t-\t-")
            pn = (pn + 1) & 0x0F
            time.sleep(interval)

    if rtts:
        print(f"summary ok={len(rtts)} fail={count-len(rtts)} avg_ms={sum(rtts)/len(rtts):.1f}")
    return 0


def read_block(port: str, baud: int, block: int, packet: int, rx_timeout: float):
    ser = open_port(port, baud)
    if not ser:
        return 2
    with ser:
        try:
            ser.reset_input_buffer()
        except Exception:
            pass
        # sync/init frame first
        send_service(ser, b'', packet, rx_timeout)
        packet = (packet + 1) & 0x0F
        tx, ack, rx, dt = send_service(ser, bytes([block & 0xFF]), packet, rx_timeout)
    print(f"TX: {to_hex(tx)}")
    print(f"ACK: {to_hex(ack) if ack else '-'}")
    print(f"RX: {to_hex(rx) if rx else '-'}")
    print(f"RTT_MS: {dt:.1f}")
    if rx and rx[0] == 0x02 and len(rx) >= 8:
        data = rx[5:-2]
        if data:
            status = data[0]
            payload = data[1:]
            print(f"STATUS: 0x{status:02X}")
            print(f"PAYLOAD_LEN: {len(payload)}")
            print(f"PAYLOAD_HEX: {to_hex(payload[:120])}")
    return 0


def readall(port: str, baud: int, blocks: list[int], interval: float, loops: int, rx_timeout: float):
    ser = open_port(port, baud)
    if not ser:
        return 2
    pn = 0
    with ser:
        for lp in range(loops):
            print(f"# loop {lp+1}/{loops} @ {time.strftime('%H:%M:%S')}")
            # sync/init once per loop
            send_service(ser, b'', pn, rx_timeout)
            pn = (pn + 1) & 0x0F
            for b in blocks:
                try:
                    ser.reset_input_buffer()
                except Exception:
                    pass
                tx, ack, rx, dt = send_service(ser, bytes([b & 0xFF]), pn, rx_timeout)
                if ack and ack[0] != 0x06:
                    print(f"block={b:3d} pn={pn:X} rtt={dt:6.1f}ms ack=NEG {to_hex(ack)}")
                elif rx and rx[0] == 0x02 and len(rx) >= 8:
                    data = rx[5:-2]
                    st = data[0] if data else None
                    payload = data[1:] if len(data) > 1 else b''
                    print(f"block={b:3d} pn={pn:X} rtt={dt:6.1f}ms status=0x{st:02X} payload={len(payload):3d}B")
                else:
                    print(f"block={b:3d} pn={pn:X} rtt={dt:6.1f}ms ack={to_hex(ack) if ack else '-'} rx={to_hex(rx) if rx else '-'}")
                pn = (pn + 1) & 0x0F
                time.sleep(max(0.02, interval))
    return 0


def _resolve_entities(text: str, struct_dir: Path, depth: int = 0) -> str:
    if depth > 8:
        return text
    pat = re.compile(r'&([A-Za-z0-9_]+);')

    def repl(m):
        name = m.group(1)
        p = struct_dir / f"{name}.xml"
        if not p.exists():
            return ''
        t = p.read_text(errors='ignore')
        return _resolve_entities(t, struct_dir, depth + 1)

    return pat.sub(repl, text)


def _load_block_layout(data_xml: Path, struct_dir: Path, block_id: int):
    txt = _resolve_entities(data_xml.read_text(errors='ignore'), struct_dir)
    root = ET.fromstring(txt)
    block = None
    for b in root.findall('.//block'):
        if int(b.attrib.get('id', '-1')) == block_id:
            block = b
            break
    if block is None:
        return []

    fields = []

    def walk(node, prefix='', repeat=1):
        tag = node.tag.lower()
        if tag == 'data':
            key = node.attrib.get('key', '')
            typ = node.attrib.get('type', 'Byte')
            unsigned = node.attrib.get('unsigned', '0') == '1'
            length = int(node.attrib.get('length', '0') or '0')
            fields.append({'kind': 'data', 'key': prefix + key, 'type': typ, 'unsigned': unsigned, 'length': length, 'repeat': repeat})
            return
        if tag == 'space':
            fields.append({'kind': 'space', 'length': int(node.attrib.get('length', '0') or '0') * max(1, repeat)})
            return
        if tag in ('struct', 'union'):
            pfx = prefix + node.attrib.get('key', '') + '.' if node.attrib.get('key') else prefix
            for ch in list(node):
                walk(ch, pfx, repeat)
            return
        if tag == 'field':
            size = int(node.attrib.get('size', '1') or '1')
            for ch in list(node):
                walk(ch, prefix, repeat=size)
            return
        for ch in list(node):
            walk(ch, prefix, repeat)

    for ch in list(block):
        walk(ch, '')
    return fields


def _short_endian_for_key(key: str) -> str:
    return 'little'


def _needs_pre_motor_pad(key: str) -> bool:
    b = _base_key(key)
    # MSR2 quirk on this controller: one pad byte appears before Hka_Mw1.Temp.sbMotor
    # in block 24 payloads.
    return bool(
        b == 'Hka_Mw1.Temp.sbMotor'
        or re.match(r'^Hka_BZbeiSC_Mw1_\d+L\.Temp\.sbMotor$', b)
    )


def _decode_fields(payload: bytes, fields):
    out = {}
    i = 0
    temp_motor_pad_applied = False
    for f in fields:
        if f['kind'] == 'space':
            i += f['length']
            continue
        typ = f['type'].lower()
        key = f['key']
        arr_len = f.get('length', 0) or 0
        rep = f.get('repeat', 1) or 1

        def put_value(k, v):
            out[k] = v

        if typ == 'byte':
            n = rep if rep > 1 else (arr_len if arr_len > 1 else 1)
            for idx in range(n):
                k2 = f"{key}[{idx}]" if n > 1 else key
                if _needs_pre_motor_pad(k2) and (not temp_motor_pad_applied):
                    if i + 1 <= len(payload):
                        i += 1
                        temp_motor_pad_applied = True
                if i + 1 > len(payload):
                    break
                v = payload[i]
                if not f['unsigned'] and v >= 128:
                    v -= 256
                put_value(k2, v)
                i += 1
        elif typ == 'short':
            n = rep if rep > 1 else (arr_len if arr_len > 1 else 1)
            for idx in range(n):
                k2 = f"{key}[{idx}]" if n > 1 else key
                if i + 2 > len(payload):
                    break
                endian = _short_endian_for_key(k2)
                raw = int.from_bytes(payload[i:i+2], endian, signed=not f['unsigned'])
                put_value(k2, raw)
                i += 2
        elif typ == 'long':
            n = rep if rep > 1 else (arr_len if arr_len > 1 else 1)
            for idx in range(n):
                if i + 4 > len(payload):
                    break
                raw = int.from_bytes(payload[i:i+4], 'little', signed=not f['unsigned'])
                put_value(f"{key}[{idx}]" if n > 1 else key, raw)
                i += 4
        elif typ == 'string':
            ln = f['length'] if f['length'] > 0 else 1
            if i + ln > len(payload):
                break
            s = payload[i:i+ln].decode('latin1', errors='ignore').rstrip('\x00').strip()
            put_value(key, s)
            i += ln
        else:
            if i + 1 > len(payload):
                break
            put_value(key, payload[i])
            i += 1
    return out


def _load_format_map(lib_dir: Path):
    fmap = {}
    refs = {}
    for p in lib_dir.glob('*.xml'):
        txt = p.read_text(errors='ignore')
        try:
            r = ET.fromstring(txt)
        except Exception:
            continue
        for e in r.findall('.//msrdata'):
            k = e.attrib.get('key')
            if not k:
                continue
            div = float(e.attrib.get('divisor', '1') or '1')
            add = float(e.attrib.get('adder', '0') or '0')
            fmt = e.attrib.get('format', '')
            ref = e.attrib.get('refkey')
            invalid_vals = [v.strip() for v in (e.attrib.get('invalidvals', '') or '').split(',') if v.strip()]
            invalid_display = e.attrib.get('invaliddisplay', '')
            unit = ''
            m = re.search(r'\}\s*(.+)$', fmt)
            if m:
                unit = m.group(1).strip()
            fmap[k] = {
                'divisor': div,
                'adder': add,
                'unit': unit,
                'format': fmt,
                'invalidvals': invalid_vals,
                'invaliddisplay': invalid_display,
            }
            if ref:
                refs[k] = ref
    # recursive inherit from refkey chains
    changed = True
    guard = 0
    while changed and guard < 20:
        changed = False
        guard += 1
        for k, ref in refs.items():
            if ref not in fmap:
                continue
            cur = dict(fmap.get(k, {}))
            src = fmap[ref]
            before = cur.copy()
            if (cur.get('divisor', 1) == 1) and (src.get('divisor', 1) != 1):
                cur['divisor'] = src['divisor']
            if (cur.get('adder', 0) == 0) and (src.get('adder', 0) != 0):
                cur['adder'] = src['adder']
            if not cur.get('format') and src.get('format'):
                cur['format'] = src['format']
            if not cur.get('unit') and src.get('unit'):
                cur['unit'] = src['unit']
            if (not cur.get('invalidvals')) and src.get('invalidvals'):
                cur['invalidvals'] = src['invalidvals']
            if (not cur.get('invaliddisplay')) and src.get('invaliddisplay'):
                cur['invaliddisplay'] = src['invaliddisplay']
            if cur != before:
                changed = True
            fmap[k] = cur
    return fmap


def _base_key(key: str) -> str:
    return re.sub(r'\[\d+\]$', '', key)


def _humanize_key(key: str) -> str:
    k = _base_key(key).split('.')[-1]
    # strip common type prefixes (b/sb/us/ul/uch/a) for readability
    k = re.sub(r'^(sb|us|ul|uch|b|a)(?=[A-Z])', '', k)
    k = k.replace('_', ' ')
    k = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', k)
    return k.strip()




def _bundled_file_candidates(name: str):
    script_dir = Path(__file__).resolve().parent
    cands = [
        Path.cwd() / name,
        script_dir / name,
    ]
    out = []
    seen = set()
    for c in cands:
        k = str(c)
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
    return out


def _cleanup_label_for_display(key: str, label: str) -> str:
    kb = _base_key(key)
    l = (label or '').strip()

    # snapshots in blocks 84/86/88/90/92/94: prefix label with MW1/MW2 for clarity
    if re.match(r'^Hka_BZbeiSC_Mw1_\d+L\.', kb):
        if not l.startswith('MW1 '):
            l = 'MW1 ' + l
    elif re.match(r'^Hka_BZbeiSC_Mw2_\d+L\.', kb):
        if not l.startswith('MW2 '):
            l = 'MW2 ' + l

    # explicit rename: Kapseltemperatur without condenser suffix
    if kb.endswith('.Temp.sKapsel'):
        if re.match(r'^Hka_BZbeiSC_Mw1_\d+L\.', kb):
            return 'MW1 Kapseltemperatur' + _phase_suffix(key)
        if re.match(r'^Hka_BZbeiSC_Mw2_\d+L\.', kb):
            return 'MW2 Kapseltemperatur' + _phase_suffix(key)
        return 'Kapseltemperatur' + _phase_suffix(key)
    if kb.endswith('.MaxTemp.sKapsel'):
        return 'Maximale Kapseltemperatur' + _phase_suffix(key)

    # targeted cleanup for technical/cryptic labels
    suffix_overrides = {
        '.Hka_UC.ubFehlerGrundMc1': 'Fehlergrund MC1',
        '.Hka_UC.ubFehlerCodeMc1': 'Fehlercode MC1',
        '.Hka_UC.ubFehlerGrundMc2': 'Fehlergrund MC2',
        '.Hka_UC.ubFehlerCodeMc2': 'Fehlercode MC2',
        '.Hka_UC.ubSchutzartMc1': 'Schutzart MC1',
        '.Hka_UC.ubSchutzartMc2': 'Schutzart MC2',
        '.Hka_UC.ausPhi': 'Phi',
    }
    for suf, txt in suffix_overrides.items():
        if kb.endswith(suf):
            return txt + _phase_suffix(key)

    # generic polish
    l = re.sub(r'^(ub|aus|sb|us|ul|uch|s|b|a)\s+', '', l)
    l = l.replace(' Mc1', ' MC1').replace(' Mc2', ' MC2')
    l = l.replace(' / ', ' ')
    l = l.replace('Stoerungbei', 'Störung bei').replace('Startsbei', 'Starts bei')
    replacements = {
        'Regelungsgrundlage / Programmwahl': 'Regelungsgrundlage Programmwahl',
        'Max. Rücklauftemp für / Dachs-Betrieb': 'Max. Rücklauftemp für Dachs-Betrieb',
        'Hydaulische Einbindung': 'Hydraulische Einbindung',
        'Laufzeit bei / Tastbetätigung': 'Laufzeit bei Tastbetätigung',
        'Wi bei Tagbetrieb wenn Aussentemp <': 'Wi bei Tagbetrieb wenn Außentemp <',
        'Wi bei Nachtbetrieb wenn Aussentemp <': 'Wi bei Nachtbetrieb wenn Außentemp <',
        'Vorlaufsollwert bei +15C Aussentemperatur': 'Vorlaufsollwert bei +15°C Außentemperatur',
        'Vorlaufsollwert bei -10C Aussentemperatur': 'Vorlaufsollwert bei -10°C Außentemperatur',
        'Uhrzeit NT-Zeit aus': 'Uhrzeit NT-Zeit Ende',
        'fuer': 'für',
        'Ruecklauf': 'Rücklauf',
        'Aussen': 'Außen',
        'Fuehler': 'Fühler',
        'Stoerung': 'Störung',
        'Waerm': 'Wärme',
        'WIntvall': 'W-Intervall',
        'beiSC': 'bei SC',
        'Tel.-Nr.1 für Meldung Service: Tel.-Nr. 1': 'Tel.-Nr.1 für Meldung/Service',
        'Tel.-Nr.2 für Meldung Service: Tel.-Nr. 2': 'Tel.-Nr.2 für Meldung/Service',
    }
    for a, b in replacements.items():
        l = l.replace(a, b)
    l = re.sub(r'\s{2,}', ' ', l).strip()
    return l

def _label_for_key(key: str, labels: dict) -> str:
    kb = _base_key(key)

    # try exact/base keys first
    cands = [
        key, key + '.presenter', key + '.Short',
        kb, kb + '.presenter', kb + '.Short',
    ]

    # alias variant: same path, but last token forced to 'ul...' (many labels use ul*)
    last = kb.split('.')[-1]
    parent = kb.rsplit('.', 1)[0] if '.' in kb else ''
    stem = re.sub(r'^(sb|us|ul|uch|b|a)(?=[A-Z])', '', last)
    if stem and parent:
        ulk = parent + '.ul' + stem
        cands += [ulk, ulk + '.presenter', ulk + '.Short']

    # normalize servicecode snapshot prefixes to live-equivalent keys for label lookup
    n = kb
    n = re.sub(r'^Hka_BZbeiSC_Mw1_\d+L\.', 'Hka_Mw1.', n)
    n = re.sub(r'^Hka_BZbeiSC_Mw2_\d+L\.', 'Hka_Mw2.', n)
    n_key = key
    n_key = re.sub(r'^Hka_BZbeiSC_Mw1_\d+L\.', 'Hka_Mw1.', n_key)
    n_key = re.sub(r'^Hka_BZbeiSC_Mw2_\d+L\.', 'Hka_Mw2.', n_key)
    if n != kb or n_key != key:
        cands += [n_key, n_key + '.presenter', n_key + '.Short', n, n + '.presenter', n + '.Short']

    for c in cands:
        if c in labels and str(labels[c]).strip():
            return _cleanup_label_for_display(key, _strip_html_label(labels[c]) + _phase_suffix(key))

    return _cleanup_label_for_display(key, _strip_html_label(_humanize_key(key)) + _phase_suffix(key))


def _format_lookup_key(key: str, fmap):
    b = _base_key(key)
    if b in fmap:
        return b

    # normalize common history prefixes to live-equivalent keys
    n = b
    n = re.sub(r'^BD3112\.', '', n)
    n = re.sub(r'^Hka_BZbeiSC_Mw1_\d+L\.', 'Hka_Mw1.', n)
    n = re.sub(r'^Hka_BZbeiSC_Mw2_\d+L\.', 'Hka_Mw2.', n)
    n = re.sub(r'^Hka_BZbeiSC_Mw1_XXL\.', 'Hka_Mw1.', n)
    n = re.sub(r'^Hka_BZbeiSC_Hist_\d+L\.', 'Hka_Bd.', n)
    n = re.sub(r'^Hka_BzbeiWarnHist_\d+L\.', 'Hka_Bd.', n)
    if n in fmap:
        return n

    # suffix fallback: longest matching tail
    best = None
    for fk in fmap.keys():
        if b.endswith(fk) or n.endswith(fk):
            if best is None or len(fk) > len(best):
                best = fk
    return best


MOTOR_STATUS_MAP = {
    0: 'OK',
    10: 'Störabschaltung',
    11: 'Abschaltroutine 1',
    12: 'Abschaltroutine 2',
    13: 'Drehz. 200 U/min',
    14: 'Drehz 200 U/min NICHT erreicht',
    15: 'Dachs >1 Minute AUS',
    16: 'Dachs >4 Minuten AUS',
    20: 'Startvorbereitung',
    21: 'Starteinleitung',
    22: 'Anlasser ein',
    23: 'Anlasser läuft 1,5 Sekunden',
    24: 'Anlasser aus',
    30: 'Dachs läuft hoch',
    31: 'Dachs im Synchrondrehzahlfenster',
    32: 'Generator am Netz',
    33: 'Stellmotorbewegung ZU',
    34: 'Stellmotorbewegung AUF',
    35: 'KEINE Stellmotorbewegung',
}

def _collect_indexed(decoded: dict, base_key: str) -> dict:
    out = {}
    pat = re.compile(r'^' + re.escape(base_key) + r'\[(\d+)\]$')
    for k, v in decoded.items():
        m = pat.match(k)
        if m:
            out[int(m.group(1))] = v
    return out



_SRC_MELDETYPE_LABELS = None
_SRC_SERVICECODE_LABELS = None


def _load_java_properties(path: Path) -> dict:
    out = {}
    if not path.exists():
        return out
    for ln in path.read_text(encoding='latin-1', errors='ignore').splitlines():
        t = ln.strip()
        if not t or t.startswith('#') or '=' not in t:
            continue
        k, v = t.split('=', 1)
        out[k.strip()] = _decode_java_properties_escapes(v.strip())
    return out


def _load_meldehist_source_labels():
    global _SRC_MELDETYPE_LABELS, _SRC_SERVICECODE_LABELS
    if _SRC_MELDETYPE_LABELS is not None and _SRC_SERVICECODE_LABELS is not None:
        return _SRC_MELDETYPE_LABELS, _SRC_SERVICECODE_LABELS

    melde = {}
    sc = {}

    # bundled, repo-local fallback files (no external source tree required)
    for p in _bundled_file_candidates('meldehist_types_de.properties'):
        if p.exists():
            melde = _load_java_properties(p)
            break
    for p in _bundled_file_candidates('servicecodes_de.properties'):
        if p.exists():
            sc = _load_java_properties(p)
            break

    _SRC_MELDETYPE_LABELS = melde
    _SRC_SERVICECODE_LABELS = sc
    return melde, sc


def _melde_type_label(t: int, labels: dict) -> str:
    key = f'MeldeHIST.bMeldecodeTyp.option.{int(t)}'
    v = labels.get(key)
    if v:
        return _strip_html_label(v)
    melde, _ = _load_meldehist_source_labels()
    return melde.get(key, str(t))


def _service_code_label(code) -> str:
    try:
        c = int(code)
    except Exception:
        return '-'
    _, sc = _load_meldehist_source_labels()
    return sc.get(f'sc.{c}', '-')


def _value_text_from_servicecode(raw_wert):
    # show human text for raw value when available as servicecode label
    try:
        w = int(raw_wert)
    except Exception:
        return '-'
    return _service_code_label(w)

def _apply_meldecode_modifier(melde_typ, raw_wert):
    # For classic Dachs product group the Java implementation (StoerCodeDataMapAttributeAction)
    # maps historical fault value to code as: if w>0 => w+100 else w.
    try:
        w = int(raw_wert)
    except Exception:
        return None
    if w > 0:
        return w + 100
    return w



def _parse_block18_history(payload: bytes):
    out = []
    if not payload:
        return None, out
    current = payload[0]
    off = 10  # 1 byte ring index + 9 bytes reserved
    for i in range(10):
        if off + 6 > len(payload):
            break
        b_wert = payload[off]
        b_mix = payload[off + 1]
        b_modul = b_mix & 0x0F
        b_typ = (b_mix >> 4) & 0x0F
        ts = int.from_bytes(payload[off + 2:off + 6], 'little', signed=False)
        out.append({
            'idx': i,
            'zeit': ts,
            'typ': b_typ,
            'wert': b_wert,
            'modul': b_modul,
        })
        off += 6
    return current, out


def _render_meldehist(decoded: dict, labels: dict, fmap: dict, payload: bytes | None = None) -> list[str]:
    lines = []

    if payload is not None:
        cur, entries = _parse_block18_history(payload)
        for e in entries:
            i = e['idx']
            t = e['typ']
            w = e['wert']
            m = e['modul']
            z = e['zeit']
            ztxt, _ = _apply_format('MeldeHIST.ulZeitstempel', z, fmap)
            tlabel = _melde_type_label(t, labels)
            code = _apply_meldecode_modifier(t, w)
            mlabel = 'Dachs' if int(m) == 1 else '-'
            mark = ' <= aktuell' if cur is not None and int(cur) == i else ''
            lines.append(
                f"  [{i:02d}]{mark} {ztxt} Typ={t} ({tlabel}) Wert={w} ({_value_text_from_servicecode(w)}) Code(calc-num)={code} Modul={m} ({mlabel})"
            )
        return lines

    # fallback via decoded map (if payload parser is unavailable)
    types = _collect_indexed(decoded, 'MeldeHIST.bMeldecodeTyp')
    werte = _collect_indexed(decoded, 'MeldeHIST.bWert')
    module = _collect_indexed(decoded, 'MeldeHIST.bModul_Nr')
    zeit = _collect_indexed(decoded, 'MeldeHIST.ulZeitstempel')
    idxs = sorted(set(types) | set(werte) | set(module) | set(zeit))
    cur = decoded.get('AktuelleRingnummer_MeldeHist')
    for i in idxs:
        t = types.get(i)
        w = werte.get(i)
        m = module.get(i)
        z = zeit.get(i)
        ztxt, _ = _apply_format('MeldeHIST.ulZeitstempel', z if z is not None else 0, fmap)
        try:
            ti = int(t) if t is not None else None
        except Exception:
            ti = None
        tlabel = _melde_type_label(ti if ti is not None else -1, labels)
        code = _apply_meldecode_modifier(t, w)
        mlabel = 'Dachs' if (m is not None and int(m) == 1) else '-'
        mark = ' <= aktuell' if cur is not None and int(cur) == i else ''
        lines.append(
            f"  [{i:02d}]{mark} {ztxt} Typ={t} ({tlabel}) Wert={w} ({_value_text_from_servicecode(w)}) Code(calc-num)={code} Modul={m} ({mlabel})"
        )
    return lines






# threshold/operator-based textual interpretations for selected status fields
SPECIAL_THRESHOLD_TEXT = {
    # value < threshold => first text ; else => second text
    'Hka_Bd.UHka_Frei.usFreigabe': (65535, 'nein', 'ja'),
    'Hka_Bd.UBrenner_Frei.bFreigabe': (255, 'nein', 'ja'),
    'Hka_Bd.UStromF_Frei.bFreigabe': (255, 'nein', 'ja'),
}


def _special_text_for_key(key: str, val):
    kb = _base_key(key)
    rule = SPECIAL_THRESHOLD_TEXT.get(kb)
    if not rule:
        return None
    try:
        iv = int(val)
    except Exception:
        return None
    thr, t_low, t_eq = rule
    return t_low if iv < thr else t_eq

def _format_hist_timestamp(ts):
    try:
        iv = int(ts)
    except Exception:
        return '-', False
    if iv == 0:
        return 'leer', False
    dt = datetime(2000, 1, 1) + timedelta(seconds=iv)
    now = datetime.now()
    plausible = (datetime(2010, 1, 1) <= dt <= (now + timedelta(days=365*3)))
    txt = dt.strftime('%d.%m.%Y %H:%M:%S')
    if not plausible:
        txt += ' (!)'
    return txt, plausible




def _parse_block80_hist(payload: bytes):
    if not payload or len(payload) < 6:
        return None, []
    cur_sc = payload[0]
    cur_bls = payload[1]
    cur_w = payload[2]
    entries = []
    off = 6
    for idx in range(1, 9):
        if off + 8 > len(payload):
            break
        raw = payload[off]
        _res = payload[off + 1]
        ts = int.from_bytes(payload[off + 2:off + 6], 'little', signed=False)
        delta = payload[off + 6]
        flags = payload[off + 7]
        ent = flags & 0x01
        auto = (flags >> 1) & 0x01
        entries.append({'idx': idx, 'raw': raw, 'ts': ts, 'delta': delta, 'ent': ent, 'auto': auto})
        off += 8
    return {'cur_sc': cur_sc, 'cur_bls': cur_bls, 'cur_w': cur_w}, entries


def _parse_block82_hist(payload: bytes):
    if not payload:
        return [], []
    sc = []
    w = []
    off = 0
    # SC 9..13
    for idx in range(9, 14):
        if off + 8 > len(payload):
            return sc, w
        raw = payload[off]
        _res = payload[off + 1]
        ts = int.from_bytes(payload[off + 2:off + 6], 'little', signed=False)
        delta = payload[off + 6]
        flags = payload[off + 7]
        ent = flags & 0x01
        auto = (flags >> 1) & 0x01
        sc.append({'idx': idx, 'raw': raw, 'ts': ts, 'delta': delta, 'ent': ent, 'auto': auto})
        off += 8
    # Warn 1..5
    for idx in range(1, 6):
        if off + 6 > len(payload):
            break
        raw = payload[off]
        mix = payload[off + 1]
        modul = mix & 0x0F
        typ = (mix >> 4) & 0x0F
        ts = int.from_bytes(payload[off + 2:off + 6], 'little', signed=False)
        w.append({'idx': idx, 'raw': raw, 'modul': modul, 'typ': typ, 'ts': ts})
        off += 6
    return sc, w


def _render_scwarn_hist_from_payload(b: int, payload: bytes, ring=None) -> list[str]:
    lines = []
    if b == 80:
        ring, sc = _parse_block80_hist(payload)
        for e in sc:
            code = e['raw'] + 100 if e['raw'] > 0 else 0
            ztxt, _ = _format_hist_timestamp(e['ts'])
            clabel = _service_code_label(code)
            mark = ' <= aktuell' if ring and int(ring.get('cur_sc', -1)) == e['idx'] else ''
            ent = '#Auto' if e['ent'] else '#Manuell'
            lines.append(f"  [SC {e['idx']:02d}]{mark} {ztxt} Code={code} ({clabel}) ΔBh={e['delta']} Entstörart={ent}")
    elif b == 82:
        sc, w = _parse_block82_hist(payload)
        for e in sc:
            code = e['raw'] + 100 if e['raw'] > 0 else 0
            ztxt, _ = _format_hist_timestamp(e['ts'])
            clabel = _service_code_label(code)
            ent = '#Auto' if e['ent'] else '#Manuell'
            lines.append(f"  [SC {e['idx']:02d}] {ztxt} Code={code} ({clabel}) ΔBh={e['delta']} Entstörart={ent}")
        for e in w:
            code = e['raw'] + 600 if e['raw'] > 0 else 0
            ztxt, _ = _format_hist_timestamp(e['ts'])
            clabel = _service_code_label(code)
            lines.append(f"  [W  {e['idx']:02d}] {ztxt} Code={code} ({clabel}) Modul={e['modul']} Typ={e['typ']}")
    return lines

def _render_abschalt_hist(decoded: dict, fmap: dict) -> list[str]:
    lines = []
    for i in range(1, 6):
        k_code = f'Hka_Abschaltgrund_{i}L.usAbschaltcode'
        k_ts = f'Hka_Abschaltgrund_{i}L.ulZeitstempel'
        code = decoded.get(k_code)
        ts = decoded.get(k_ts)
        if code is None and ts is None:
            continue
        ztxt, _ = _format_hist_timestamp(ts)
        lines.append(f"  [{i:02d}] {ztxt} Abschaltcode=0x{int(code):04X} ({code})")
    return lines


def _render_scwarn_hist(decoded: dict, fmap: dict) -> list[str]:
    lines = []

    cur_sc = decoded.get('AktuelleRingnummer_SCHist')
    cur_w = decoded.get('AktuelleRingnummer_WHist')

    # Service/Fault history 1..13
    for i in range(1, 14):
        k_code = f'Hka_BZbeiSC_Hist_{i}L.bStoercode'
        k_ts = f'Hka_BZbeiSC_Hist_{i}L.ulZeitstempel'
        k_delta = f'Hka_BZbeiSC_Hist_{i}L.bDeltaMotorlaufZeitServiceCode'
        code = decoded.get(k_code)
        ts = decoded.get(k_ts)
        delta = decoded.get(k_delta)
        if code is None and ts is None and delta is None:
            continue
        ztxt, _ = _format_hist_timestamp(ts)
        clabel = _service_code_label(code)
        mark = ' <= aktuell' if cur_sc is not None and int(cur_sc) == i else ''
        lines.append(f"  [SC {i:02d}]{mark} {ztxt} Störcode={code} ({clabel}) ΔBh={delta}")

    # Warning history 1..5
    for i in range(1, 6):
        k_code = f'Hka_BzbeiWarnHist_{i}L.bWarncode'
        k_ts = f'Hka_BzbeiWarnHist_{i}L.ulZeitstempel'
        code = decoded.get(k_code)
        ts = decoded.get(k_ts)
        if code is None and ts is None:
            continue
        ztxt, _ = _format_hist_timestamp(ts)
        # no dedicated warncode text table in current bundle; keep numeric-only label when unknown
        clabel = _service_code_label(code)
        mark = ' <= aktuell' if cur_w is not None and int(cur_w) == i else ''
        lines.append(f"  [W  {i:02d}]{mark} {ztxt} Warncode={code} ({clabel})")

    return lines


def _format_usdatum(val):
    """Decode packed day/month short used in some schedule date fields.
    Format is little-endian: low byte=day, high byte=month.
    Returns None when value does not look like a valid day/month pair.
    """
    try:
        iv = int(val) & 0xFFFF
    except Exception:
        return None
    day = iv & 0xFF
    month = (iv >> 8) & 0xFF
    if day == 0 and month == 0:
        return '--.--'
    if 1 <= day <= 31 and 1 <= month <= 12:
        return f"{day:02d}.{month:02d}"
    return None


def _format_msr2000_timestamp(seconds: int, date_only: bool = False):
    dt = datetime(2000, 1, 1) + timedelta(seconds=int(seconds))
    return dt.strftime('%d.%m.%Y' if date_only else '%d.%m.%Y %H:%M:%S')

def _apply_format(key: str, val, fmap):
    lk = _format_lookup_key(key, fmap)
    f = fmap.get(lk) if lk else None

    # allow date rendering even when no mapping entry exists
    if isinstance(val, str):
        return val, ''

    kb = _base_key(key)
    kb_mw = re.sub(r'^Hka_BZbeiSC_Mw1_\d+L\.', 'Hka_Mw1.', kb)
    if kb_mw == 'Hka_Mw1.bMotorStatus':
        try:
            iv = int(val)
            if iv in MOTOR_STATUS_MAP:
                return f"{iv} ({MOTOR_STATUS_MAP[iv]})", ''
            return f"{iv} (unbekannt)", ''
        except Exception:
            pass

    if not f:
        f = {'divisor': 1, 'adder': 0, 'unit': '', 'format': ''}

    kb = _base_key(key).lower()
    kb_live = re.sub(r'^hka_bzbeisc_mw1_\d+l\.', 'hka_mw1.', kb)
    kb_live = re.sub(r'^hka_bzbeisc_mw2_\d+l\.', 'hka_mw2.', kb_live)

    # invalid value handling first (raw domain)
    raw = val
    invalid_vals = f.get('invalidvals') or []
    if invalid_vals:
        for iv in invalid_vals:
            try:
                if float(raw) == float(iv):
                    # special handling: code fields should show explicit no-code text
                    if kb_live in ('hka_bd.bstoerung', 'hka_bd.bwarnung'):
                        return '0 (-)', ''
                    inv = f.get('invaliddisplay', '')
                    if inv != '':
                        return inv, f.get('unit', '')
                    return 'n.a.', f.get('unit', '')
            except Exception:
                pass

    v = float(raw) + f.get('adder', 0.0)
    d = f.get('divisor', 1.0)
    if d != 0 and d != 1:
        v = v / d

    # formatting hint
    fmt = f.get('format', '') or ''

    # packed day/month short fields (usDatum)
    if kb_live.endswith('.usdatum'):
        dm = _format_usdatum(v)
        if dm is not None:
            return dm, ''

    # Date/timestamp fields (MSR source logic: seconds since 2000-01-01)
    is_date_like = ('{0,date}' in fmt) or ('inbetriebnahmedatum' in kb_live) or ('ulzeitstempel' in kb_live) or kb_live.endswith('.uldatum')
    if is_date_like:
        try:
            ts = int(round(v))
            date_only = ('inbetriebnahmedatum' in kb)
            return _format_msr2000_timestamp(ts, date_only=date_only), ''
        except Exception:
            pass


    # selected threshold/adder text mappings from source XML
    if kb_live == 'hka_bd.uhka_frei.usfreigabe':
        try:
            iv = int(round(v))
            txt = 'ja' if iv >= 65535 else 'nein'
            return f"{iv} ({txt})", ''
        except Exception:
            pass
    if kb_live in ('hka_bd.ubrenner_frei.bfreigabe', 'hka_bd.ustromf_frei.bfreigabe'):
        try:
            iv = int(round(v))
            txt = 'ja' if iv >= 255 else 'nein'
            return f"{iv} ({txt})", ''
        except Exception:
            pass
    if kb_live == 'hka_mw1.temp.sbfreigabemodul':
        try:
            iv = int(round(v))
            txt = 'ja' if iv >= 127 else 'nein'
            return f"{iv} ({txt})", ''
        except Exception:
            pass
    if kb_live == 'hka_bd.bstoerung':
        try:
            iv = int(round(v))
            if iv == 0:
                return '0 (-)', ''
            code = iv + 100
            return f"{iv} (Code {code}: {_service_code_label(code)})", ''
        except Exception:
            pass
    if kb_live == 'hka_bd.bwarnung':
        try:
            iv = int(round(v))
            if iv == 0:
                return '0 (-)', ''
            code = iv + 600
            return f"{iv} (Code {code}: {_service_code_label(code)})", ''
        except Exception:
            pass
    if kb_live == 'hka_mw1.bkraftstofftyp':
        try:
            iv = int(round(v))
            if iv in (8, 9, 10, 11):
                t = 'Öl'
            elif iv in (128, 144, 160, 176, 192, 208):
                t = 'Gas'
            elif iv == 0:
                t = '-'
            else:
                t = 'unbekannt'
            return f"{iv} ({t})", ''
        except Exception:
            pass
    if kb_live == 'hka_ew.uchprogrammwahl':
        try:
            iv = int(round(v))
            m = {65: 'A', 66: 'B', 69: 'E', 83: 'S'}
            t = m.get(iv, 'unbekannt')
            return f"{iv} ({t})", ''
        except Exception:
            pass
    if 'integer' in fmt:
        v = int(round(v))
    elif '#.##' in fmt:
        v = round(v, 2)
        if abs(v - int(v)) < 1e-9:
            v = int(v)
    elif abs(v - int(v)) < 1e-9:
        v = int(v)

    return v, f.get('unit', '')


def _decode_java_properties_escapes(s: str) -> str:
    # Decode Java .properties escapes without unicode_escape deprecation warnings.
    if s is None:
        return ''
    try:
        s = re.sub(r'\\u([0-9A-Fa-f]{4})', lambda m: chr(int(m.group(1), 16)), s)
        s = s.replace('\\t', '\t').replace('\\n', '\n').replace('\\r', '\r')
        s = s.replace('\\:', ':').replace('\\=', '=').replace('\\\\', '\\')
        return s
    except Exception:
        return s


def _strip_html_label(s: str) -> str:
    s = re.sub(r'(?i)</?html>', '', s)
    s = re.sub(r'(?i)<br\s*/?>', ' / ', s)
    s = re.sub(r'<[^>]+>', '', s)
    return ' '.join(s.split()).strip()


def _is_reserved_key(key: str) -> bool:
    b = _base_key(key).lower()
    return (
        '.bres' in b
        or '.reserve' in b
        or b.endswith('.res')
        or b.endswith('.res1')
        or b.endswith('.res2')
        or 'reserve' in b
    )


def _phase_suffix(key: str) -> str:
    m = re.match(r'^(.*)\[(\d+)\]$', key)
    if not m:
        return ''
    base = m.group(1)
    # normalize snapshot prefixes to live keys
    base = re.sub(r'^Hka_BZbeiSC_Mw2_\d+L\.', 'Hka_Mw2.', base)
    idx = int(m.group(2))
    phase_map = {0: 'L1', 1: 'L2', 2: 'L3'}
    if idx not in phase_map:
        return ''
    phase_keys = {
        'Hka_Mw2.Hka_UC.ausVoltage1',
        'Hka_Mw2.Hka_UC.ausCurrent1',
        'Hka_Mw2.Hka_UC.ausImpedanz',
        'Hka_Mw2.Hka_UC.ausPhi',
    }
    if base in phase_keys:
        return f" ({phase_map[idx]})"
    return ''


def _load_labels(properties_file: Path):
    labels = {}
    if not properties_file.exists():
        return labels
    for line in properties_file.read_text(errors='ignore').splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if '=' not in s:
            continue
        k, v = s.split('=', 1)
        k = k.strip()
        v = _decode_java_properties_escapes(v.strip())
        if not k:
            continue
        labels[k] = v
    return labels


def _collapse_version_fields(decoded: dict):
    """Merge software version byte arrays into dotted version strings."""
    targets = {
        'Hka_Bd_Stat.bSoftwareVersionUeberw',
        'Hka_Bd_Stat.bSoftwareVersionMessen',
        'Hka_Bd_Stat.bSoftwareVersionRegler',
    }
    grouped = {}
    for k, v in decoded.items():
        m = re.match(r'^(.*)\[(\d+)\]$', k)
        if not m:
            continue
        base = m.group(1)
        if base not in targets:
            continue
        idx = int(m.group(2))
        grouped.setdefault(base, {})[idx] = v

    merged = {}
    consumed = set()
    for base, idx_map in grouped.items():
        vals = [idx_map[i] for i in sorted(idx_map.keys())]
        # keep only numeric byte-like values
        if all(isinstance(x, (int, float)) for x in vals):
            merged[base] = '.'.join(str(int(x)) for x in vals)
            for i in idx_map.keys():
                consumed.add(f"{base}[{i}]")

    return merged, consumed


def _resolve_optional_file(preferred: Path | None, candidates: list[Path]) -> Path | None:
    if preferred and preferred.exists():
        return preferred
    for c in candidates:
        if c and c.exists():
            return c
    return preferred




def _render_field_name(label: str, key: str, mode: str = 'both') -> str:
    m = (mode or 'both').lower()
    if m == 'text':
        return f"{label:40}"
    if m == 'key':
        return f"[{key}]"
    return f"{label:40} [{key}]"

def readall_decoded(port: str, baud: int, blocks: list[int], interval: float, loops: int, rx_timeout: float,
                    data_xml: Path, struct_dir: Path, format_dir: Path, pack_file: Path | None = None,
                    labels_file: Path | None = None, show_reserved: bool = False, display_mode: str = "both"):
    ser = open_port(port, baud)
    if not ser:
        return 2
    fmap = {}
    layouts = {}

    script_dir = Path(__file__).resolve().parent
    cwd = Path.cwd()

    pack_file = _resolve_optional_file(
        pack_file,
        [
            cwd / 'msr2_pack_master.json',
            script_dir / 'msr2_pack_master.json',
            cwd / 'msr2_pack_dachs.json',
            script_dir / 'msr2_pack_dachs.json',
            cwd / 'msr2_pack_subset.json',
            script_dir / 'msr2_pack_subset.json',
        ],
    )
    labels_file = _resolve_optional_file(
        labels_file,
        [
            cwd / 'labels_merged.properties',
            script_dir / 'labels_merged.properties',
            cwd / 'labels_master.properties',
            script_dir / 'labels_master.properties',
            cwd / 'labels_subset.properties',
            script_dir / 'labels_subset.properties',
        ],
    )

    labels = _load_labels(labels_file) if labels_file else {}
    if pack_file and pack_file.exists():
        p = json.loads(pack_file.read_text())
        fmap = p.get('formats', {})
        for b in blocks:
            layouts[b] = p.get('layouts', {}).get(str(b), [])
    else:
        fmap = _load_format_map(format_dir)
        layouts = {b: _load_block_layout(data_xml, struct_dir, b) for b in blocks}
    pn = 0
    with ser:
        try:
            ser.reset_input_buffer()
        except Exception:
            pass
        for lp in range(loops):
            print(f"# decoded loop {lp+1}/{loops} @ {time.strftime('%H:%M:%S')}")
            send_service(ser, b'', pn, rx_timeout)
            pn = (pn + 1) & 0x0F
            for b in blocks:
                try:
                    ser.reset_input_buffer()
                except Exception:
                    pass
                tx, ack, rx, dt = send_service(ser, bytes([b & 0xFF]), pn, rx_timeout)
                pn = (pn + 1) & 0x0F
                if not rx or rx[0] != 0x02:
                    print(f"block={b} no-data ack={to_hex(ack) if ack else '-'}")
                    continue
                data = rx[5:-2]
                status = data[0] if data else 0
                payload = data[1:] if len(data) > 1 else b''
                print(f"\n[block {b}] status=0x{status:02X} payload={len(payload)}B rtt={dt:.1f}ms")
                decoded = _decode_fields(payload, layouts.get(b, []))
                merged_versions, consumed = _collapse_version_fields(decoded)

                if b == 18:
                    print('  -- MeldeHIST (kompakt) --')
                    for ln in _render_meldehist(decoded, labels, fmap, payload=payload):
                        print(ln)
                    consumed.update(k for k in decoded.keys() if k.startswith('MeldeHIST.'))
                    if 'AktuelleRingnummer_MeldeHist' in decoded:
                        consumed.add('AktuelleRingnummer_MeldeHist')

                if b == 30:
                    print('  -- Abschalt-Historie (kompakt) --')
                    for ln in _render_abschalt_hist(decoded, fmap):
                        print(ln)
                    for i in range(1, 6):
                        consumed.add(f'Hka_Abschaltgrund_{i}L.usAbschaltcode')
                        consumed.add(f'Hka_Abschaltgrund_{i}L.ulZeitstempel')

                if b in (80, 82):
                    print('  -- Service/Warn-Historie (kompakt) --')
                    if b == 80:
                        ring, _ = _parse_block80_hist(payload)
                        if ring:
                            print(f"  -- Hist-Ringzeiger SC={ring['cur_sc']} W={ring['cur_w']} BLS={ring['cur_bls']} --")
                    for ln in _render_scwarn_hist_from_payload(b, payload):
                        print(ln)
                    consumed.update(k for k in decoded.keys() if k.startswith('Hka_BZbeiSC_Hist_'))
                    consumed.update(k for k in decoded.keys() if k.startswith('Hka_BzbeiWarnHist_'))
                    consumed.update(k for k in ['AktuelleRingnummer_SCHist','AktuelleRingnummer_BLS','AktuelleRingnummer_WHist'] if k in decoded)

                # print merged version fields first
                for k, vv in merged_versions.items():
                    label = _label_for_key(k, labels)
                    if (not show_reserved) and _is_reserved_key(k):
                        continue
                    name = _render_field_name(label, k, display_mode)
                    print(f"  {name} = {vv}")

                for k, v in decoded.items():
                    if k in consumed:
                        continue
                    vv, unit = _apply_format(k, v, fmap)
                    label = _label_for_key(k, labels)
                    if (not show_reserved) and _is_reserved_key(k):
                        continue
                    name = _render_field_name(label, k, display_mode)
                    print(f"  {name} = {vv} {unit}".rstrip())
                time.sleep(max(0.02, interval))
    return 0


def list_keys(mapping_path: Path, limit: int):
    rows = json.loads(mapping_path.read_text())
    rows = sorted(rows, key=lambda r: (str(r.get('block')), r.get('key', '')))
    for r in rows[:limit]:
        print(f"{r.get('key')}\tblock={r.get('block')}\tread={r.get('read')}")
    print(f"# total_keys={len(rows)}")


def parse_blocks(s: str) -> list[int]:
    out = []
    for p in s.split(','):
        p = p.strip()
        if not p:
            continue
        out.append(int(p, 0))
    return out


def _ensure_utf8_runtime():
    enc = (getattr(sys.stdout, 'encoding', None) or '').lower()
    loc = (locale.getpreferredencoding(False) or '').lower()
    ok = 'utf' in enc or 'utf' in loc
    if not ok:
        # best-effort override for this process
        os.environ.setdefault('LANG', 'C.UTF-8')
        os.environ.setdefault('LC_ALL', 'C.UTF-8')
        os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
        print('WARN: Non-UTF8 terminal detected. For umlauts use: LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONIOENCODING=utf-8', file=sys.stderr)




def _default_decode_source_paths():
    """Default source paths (only used when no pack file is available)."""
    return (
        'source/senertec/dachsweb/msr/xml/regler/5/data.xml',
        'source/senertec/dachsweb/msr/xml/regler/5/struct',
        'source/senertec/dachsweb/library/xml/dachs',
    )

def main():
    _ensure_utf8_runtime()
    ap = argparse.ArgumentParser(prog='dachs-cli')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=19200)

    sub = ap.add_subparsers(dest='cmd', required=True)

    p_link = sub.add_parser('watch-link', help='MSR2 link keepalive monitor (interval table)')
    p_link.add_argument('--count', type=int, default=20)
    p_link.add_argument('--interval', type=float, default=0.5)
    p_link.add_argument('--rx-timeout', type=float, default=0.8)

    p_rb = sub.add_parser('read-block', help='Read one MSR2 block id (0..255)')
    p_rb.add_argument('--block', required=True, type=lambda x: int(x, 0))
    p_rb.add_argument('--packet', type=lambda x: int(x, 0), default=0)
    p_rb.add_argument('--rx-timeout', type=float, default=0.9)

    p_ra = sub.add_parser('readall', help='Cycle through default block list (MSR2 transport baseline)')
    p_ra.add_argument('--blocks', default='20,22,24,26,28,30,50,62,70,76')
    p_ra.add_argument('--interval', type=float, default=3.5)
    p_ra.add_argument('--loops', type=int, default=1)
    p_ra.add_argument('--rx-timeout', type=float, default=0.9)

    p_rd = sub.add_parser('readall-decoded', help='MSR2 decoded values (layout+units/multipliers)')
    p_rd.add_argument('--blocks', default='20,22,24,26')
    p_rd.add_argument('--interval', type=float, default=3.5)
    p_rd.add_argument('--loops', type=int, default=1)
    p_rd.add_argument('--rx-timeout', type=float, default=0.9)
    d_data, d_struct, d_fmt = _default_decode_source_paths()
    p_rd.add_argument('--data-xml', default=d_data)
    p_rd.add_argument('--struct-dir', default=d_struct)
    p_rd.add_argument('--format-dir', default=d_fmt)
    p_rd.add_argument('--pack-file', default='')
    p_rd.add_argument('--labels-file', default='')
    p_rd.add_argument('--show-reserved', action='store_true', help='Show reserve/res fields (hidden by default)')
    p_rd.add_argument('--text-only', action='store_true', help='Show only text labels (no [key])')
    p_rd.add_argument('--key-only', action='store_true', help='Show only [key] (no text label)')

    p_keys = sub.add_parser('list-keys', help='List extracted XML keys')
    p_keys.add_argument('--mapping', default=str(Path(__file__).resolve().parent.parent / 'bhkw-mapping.json'))
    p_keys.add_argument('--limit', type=int, default=200)

    args = ap.parse_args()

    if args.cmd == 'watch-link':
        return watch_link(args.port, args.baud, args.count, args.interval, args.rx_timeout)
    if args.cmd == 'read-block':
        return read_block(args.port, args.baud, args.block, args.packet, args.rx_timeout)
    if args.cmd == 'readall':
        return readall(args.port, args.baud, parse_blocks(args.blocks), args.interval, args.loops, args.rx_timeout)
    if args.cmd == 'readall-decoded':
        if args.text_only and args.key_only:
            print('ERROR: --text-only and --key-only are mutually exclusive', file=sys.stderr)
            return 2
        mode = 'both'
        if args.text_only:
            mode = 'text'
        elif args.key_only:
            mode = 'key'
        return readall_decoded(
            args.port,
            args.baud,
            parse_blocks(args.blocks),
            args.interval,
            args.loops,
            args.rx_timeout,
            Path(args.data_xml),
            Path(args.struct_dir),
            Path(args.format_dir),
            Path(args.pack_file) if args.pack_file else None,
            Path(args.labels_file) if args.labels_file else None,
            args.show_reserved,
            mode,
        )
    if args.cmd == 'list-keys':
        return list_keys(Path(args.mapping), args.limit) or 0
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
