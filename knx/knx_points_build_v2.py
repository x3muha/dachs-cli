#!/usr/bin/env python3
import argparse
import re
import json
from pathlib import Path


DEFAULT_PACK = Path('core/msr2_pack_master_version.json')
DEFAULT_FORMATS = Path('core/msr2_formats_v2.json')
DEFAULT_OUT = Path('knx/config/knx_points_v2.json')
DEFAULT_REV = '50'

# Profil B: Software-Versionen + Schaltzeiten/Laufraster (ohne Reserve/Res)
DEFAULT_AGGREGATE_BASES = [
    'Hka_Bd_Stat.bSoftwareVersionUeberw',
    'Hka_Bd_Stat.bSoftwareVersionMessen',
    'Hka_Bd_Stat.bSoftwareVersionRegler',
]
DEFAULT_AGGREGATE_PREFIXES = [
    'Schaltzeiten1.',
    'Schaltzeiten2.',
    'Schaltzeiten3.',
    'Laufraster15Min_',
    'Laufraster15MinZB_',
]



PRESERVE_FIELDS = [
    'knx_adresse',
    'schreiben',
    'lesen',
    'zyklisch_senden_s',
    'senden_als_text',
    'knx_dpt',
    'senden_bei_wertaenderung',
    'bei_wertaenderung_prozent',
    'bei_wertaenderung_delta',
    'aggregate_separator',
    'aktiv',
    'note',
]


def pick_layout(block_def: dict, rev: str):
    out = list(block_def.get('base') or [])
    for var in (block_def.get('variants') or []):
        picked = None
        for ch in (var.get('choices') or []):
            versions = [str(v) for v in (ch.get('versions') or [])]
            if rev in versions:
                picked = ch.get('entry')
                break
        if picked is None and len(var.get('choices') or []) == 1:
            picked = (var.get('choices') or [])[0].get('entry')
        if isinstance(picked, dict):
            out.append(picked)
    return out


def dpt_for(field: dict):
    t = (field.get('type') or 'Byte').lower()
    unsigned = bool(field.get('unsigned'))
    if t in ('bool', 'boolean'):
        return 'DPT1', 'bool'
    if t == 'byte':
        return ('DPT5' if unsigned else 'DPT6'), ('u8' if unsigned else 'i8')
    if t == 'short':
        return ('DPT7' if unsigned else 'DPT8'), ('u16' if unsigned else 'i16')
    if t == 'long':
        return ('DPT12' if unsigned else 'DPT13'), ('u32' if unsigned else 'i32')
    if t == 'string':
        return 'DPT16', 'string'
    return 'DPT5', 'u8'


def _resolve(path_arg: str | None, default_path: Path) -> Path:
    if path_arg:
        p = Path(path_arg)
        if p.exists() or str(path_arg):
            return p
    return default_path


def _load_existing(path: Path):
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text())
    except Exception:
        return {}
    out = {}
    for p in (obj.get('points') or []):
        if isinstance(p, dict) and p.get('key'):
            out[p['key']] = p
    return out


def _merged_point(base_point: dict, old_point: dict | None):
    if not old_point:
        return base_point
    merged = dict(base_point)
    for f in PRESERVE_FIELDS:
        if f in old_point:
            merged[f] = old_point[f]
    return merged

def _is_aggregate_candidate(base: str, aggregate_allow: set[str], aggregate_prefixes: list[str], aggregate_all: bool) -> bool:
    b = str(base or '')
    low = b.lower()
    # never aggregate reserve-like fields
    if 'reserve' in low or low.endswith('.res') or '.res.' in low or '.bres' in low:
        return False
    if aggregate_all:
        return True
    if b in aggregate_allow:
        return True
    for pref in aggregate_prefixes:
        if b.startswith(pref):
            return True
    return False



def build_points(pack_path: Path, formats_path: Path, out_path: Path, rev: str, keep_removed=False, aggregate_bases=None, aggregate_all=False):
    pack = json.loads(pack_path.read_text())
    formats = json.loads(formats_path.read_text()) if formats_path.exists() else {}
    blocks = pack.get('blocks') or {}
    existing = _load_existing(out_path)

    points = []
    seen = set()
    for b in sorted(blocks.keys(), key=lambda x: int(x) if str(x).isdigit() else 10**9):
        bd = blocks[b]
        layout = pick_layout(bd, rev)
        bname = bd.get('block_name_de', '')
        for f in layout:
            if not isinstance(f, dict) or f.get('kind') != 'data':
                continue
            key = f.get('key')
            if not key:
                continue
            rep = int(f.get('repeat', 1) or 1)
            arr = int(f.get('length', 0) or 0)
            n = rep if rep > 1 else (1 if (f.get('type') or '').lower() == 'string' else (arr if arr > 1 else 1))
            dpt, raw_type = dpt_for(f)
            unit = f.get('unit') or (formats.get(key, {}) or {}).get('unit') or ''
            for i in range(n):
                k = f"{key}[{i}]" if n > 1 else key
                if k in seen:
                    continue
                seen.add(k)
                base_point = {
                    'key': k,
                    'base_key': key,
                    'block': int(b),
                    'block_name_de': bname,
                    'label_de': f.get('label_de', ''),
                    'type': f.get('type', 'Byte'),
                    'raw_type': raw_type,
                    'unsigned': bool(f.get('unsigned')),
                    'unit': unit,
                    'dpt': dpt,
                    'knx_adresse': '',
                    'schreiben': False,
                    'lesen': False,
                    'zyklisch_senden_s': 0,
                    'senden_als_text': False,
                    'knx_dpt': '',
                    'senden_bei_wertaenderung': True,
                    'bei_wertaenderung_prozent': 10.0,
                    'bei_wertaenderung_delta': 0.0,
                    'aktiv': False,
                    'note': ''
                }
                points.append(_merged_point(base_point, existing.get(k)))

    # synthetic aggregated points for indexed byte arrays (>=2), one GA per base key
    by_base = {}
    for pt in points:
        k = pt.get('key','')
        m = re.match(r'^(.*)\[(\d+)\]$', k)
        if not m:
            continue
        base = m.group(1)
        try:
            idx = int(m.group(2))
        except Exception:
            continue
        if str(pt.get('type','')).lower() != 'byte':
            continue
        by_base.setdefault(base, []).append((idx, pt))

    aggregate_allow = set(aggregate_bases or DEFAULT_AGGREGATE_BASES)
    aggregate_prefixes = DEFAULT_AGGREGATE_PREFIXES

    for base, arr in by_base.items():
        arr = sorted(arr, key=lambda x: x[0])
        if len(arr) < 2:
            continue
        if not _is_aggregate_candidate(base, aggregate_allow, aggregate_prefixes, aggregate_all):
            continue
        old = existing.get(base)
        p0 = arr[0][1]
        syn = {
            'key': base,
            'base_key': base,
            'block': p0.get('block'),
            'block_name_de': p0.get('block_name_de', ''),
            'label_de': p0.get('label_de', base.split('.')[-1]),
            'type': 'String',
            'raw_type': 'string',
            'unsigned': False,
            'unit': '',
            'dpt': 'DPT16.001',
            'knx_adresse': '',
            'schreiben': False,
            'lesen': True,
            'zyklisch_senden_s': 0,
            'senden_als_text': True,
            'knx_dpt': 'DPT16.001',
            'senden_bei_wertaenderung': True,
            'bei_wertaenderung_prozent': 0.0,
            'bei_wertaenderung_delta': 0.0,
            'aktiv': False,
            'aggregate_separator': '.',
            'note': 'aggregiert aus Bytes [0..n], Darstellung wie TUI'
        }
        points.append(_merged_point(syn, old))

    if keep_removed:
        for k, oldp in existing.items():
            if k in seen:
                continue
            p = dict(oldp)
            p['deprecated'] = True
            points.append(p)

    out = {
        'schema': 'dachs-knx-points/v2',
        'pack_file': str(pack_path),
        'pack_rev': str(rev),
        'description': 'KNX-Datenpunktvorlage (Merge-Update). Bestehende KNX-Zuordnungen bleiben erhalten.',
        'points': points,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
    return len(points), len(existing)


def main():
    ap = argparse.ArgumentParser(prog='knx_points_build_v2')
    ap.add_argument('--pack-file', default=str(DEFAULT_PACK), help='Pack source JSON (default: core/msr2_pack_master_version.json)')
    ap.add_argument('--formats-file', default=str(DEFAULT_FORMATS), help='Formats source JSON (default: core/msr2_formats_v2.json)')
    ap.add_argument('--out', default=str(DEFAULT_OUT), help='Output points JSON (default: knx/config/knx_points_v2.json)')
    ap.add_argument('--pack-rev', default=DEFAULT_REV, help='Pack revision (default: 50)')
    ap.add_argument('--keep-removed', action='store_true', help='Keep removed keys as deprecated entries')
    ap.add_argument('--aggregate-base', action='append', default=[], help='Extra whitelist base key for aggregation (repeatable)')
    ap.add_argument('--aggregate-all', action='store_true', help='Aggregate all eligible byte arrays [0..n]')
    args = ap.parse_args()

    pack = _resolve(args.pack_file, DEFAULT_PACK)
    formats = _resolve(args.formats_file, DEFAULT_FORMATS)
    out = _resolve(args.out, DEFAULT_OUT)

    agg = args.aggregate_base if args.aggregate_base else DEFAULT_AGGREGATE_BASES
    n, oldn = build_points(pack, formats, out, args.pack_rev, keep_removed=args.keep_removed, aggregate_bases=agg, aggregate_all=args.aggregate_all)
    print(f'written {out} with {n} points (merge from {oldn} existing entries)')


if __name__ == '__main__':
    main()
