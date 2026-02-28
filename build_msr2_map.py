#!/usr/bin/env python3
import argparse
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

BLOCKS = [18,20,22,24,26,28,30,31,32,34,36,50,52,54,56,60,62,66,70,76,80,82,84,86,88,90,92,94,100,102,104,110,112,114]

_DATA_XML = None
_STRUCT_DIR = None
_DACHS_XML_DIR = None
_LABELS_FILE = None


def resolve_base(base_arg: str = '', regler: str = '5') -> Path:
    env_root = (base_arg or '').strip() or os.environ.get('DACHSWEB_SOURCE', '').strip()
    script_dir = Path(__file__).resolve().parent
    cands = []
    if env_root:
        cands.append(Path(env_root))
    cands += [
        Path.cwd() / 'source' / 'senertec' / 'dachsweb',
        Path.cwd().parent / 'source' / 'senertec' / 'dachsweb',
        script_dir.parent / 'source' / 'senertec' / 'dachsweb',
    ]
    for b in cands:
        if (b / f'msr/xml/regler/{regler}/data.xml').exists():
            return b
    return cands[0]


def init_paths(base: Path, regler: str):
    data_xml = base / f'msr/xml/regler/{regler}/data.xml'
    struct_dir = base / f'msr/xml/regler/{regler}/struct'
    dachs_xml_dir = base / 'library/xml/dachs'
    labels_file = base / 'gui/desktop/MsrData_de.properties'
    return data_xml, struct_dir, dachs_xml_dir, labels_file


def resolve_struct_entities(text: str, depth: int = 0) -> str:
    if depth > 12:
        return text
    pat = re.compile(r'&([A-Za-z0-9_]+);')

    def repl(m):
        p = _STRUCT_DIR / f"{m.group(1)}.xml"
        if not p.exists():
            return ''
        return resolve_struct_entities(p.read_text(errors='ignore'), depth + 1)

    return pat.sub(repl, text)


def parse_layouts():
    root = ET.fromstring(resolve_struct_entities(_DATA_XML.read_text(errors='ignore')))
    layouts = {}

    def walk(node, fields, prefix='', repeat=1):
        tag = node.tag.lower()
        if tag == 'data':
            fields.append({
                'kind': 'data',
                'key': prefix + node.attrib.get('key', ''),
                'type': node.attrib.get('type', 'Byte'),
                'unsigned': node.attrib.get('unsigned', '0') == '1',
                'length': int(node.attrib.get('length', '0') or '0'),
                'repeat': repeat,
            })
            return
        if tag == 'space':
            fields.append({'kind': 'space', 'length': int(node.attrib.get('length', '0') or '0') * max(1, repeat)})
            return
        if tag in ('struct', 'union'):
            pfx = prefix + node.attrib.get('key', '') + '.' if node.attrib.get('key') else prefix
            for ch in list(node):
                walk(ch, fields, pfx, repeat)
            return
        if tag == 'field':
            size = int(node.attrib.get('size', '1') or '1')
            for ch in list(node):
                walk(ch, fields, prefix, size)
            return
        for ch in list(node):
            walk(ch, fields, prefix, repeat)

    for b in root.findall('.//block'):
        bid = int(b.attrib.get('id', '-1'))
        if bid not in BLOCKS:
            continue
        fields = []
        for ch in list(b):
            walk(ch, fields)
        layouts[str(bid)] = fields
    return layouts


def parse_formats():
    fmap = {}
    refs = {}
    entity_pat = re.compile(r'&([A-Za-z0-9_]+);')

    for p in _DACHS_XML_DIR.glob('*.xml'):
        txt = entity_pat.sub('', p.read_text(errors='ignore'))
        try:
            root = ET.fromstring(txt)
        except Exception:
            continue
        for e in root.findall('.//msrdata'):
            key = e.attrib.get('key')
            if not key:
                continue
            inv = [v.strip() for v in (e.attrib.get('invalidvals', '') or '').split(',') if v.strip()]
            fmt = e.attrib.get('format', '')
            m = re.search(r'\}\s*(.+)$', fmt)
            unit = m.group(1).strip() if m else ''
            fmap[key] = {
                'divisor': float(e.attrib.get('divisor', '1') or '1'),
                'adder': float(e.attrib.get('adder', '0') or '0'),
                'format': fmt,
                'unit': unit,
                'invalidvals': inv,
                'invaliddisplay': e.attrib.get('invaliddisplay', ''),
                'source': p.name,
            }
            ref = e.attrib.get('refkey')
            if ref:
                refs[key] = ref

    # recursive ref propagation
    for _ in range(30):
        changed = False
        for key, ref in refs.items():
            if key not in fmap or ref not in fmap:
                continue
            cur = dict(fmap[key])
            src = fmap[ref]
            if cur.get('divisor', 1) == 1 and src.get('divisor', 1) != 1:
                cur['divisor'] = src['divisor']
            if cur.get('adder', 0) == 0 and src.get('adder', 0) != 0:
                cur['adder'] = src['adder']
            if not cur.get('format') and src.get('format'):
                cur['format'] = src['format']
            if not cur.get('unit') and src.get('unit'):
                cur['unit'] = src['unit']
            if (not cur.get('invalidvals')) and src.get('invalidvals'):
                cur['invalidvals'] = src['invalidvals']
            if (not cur.get('invaliddisplay')) and src.get('invaliddisplay'):
                cur['invaliddisplay'] = src['invaliddisplay']
            if cur != fmap[key]:
                fmap[key] = cur
                changed = True
        if not changed:
            break

    return fmap


def parse_labels():
    labels = {}
    if not _LABELS_FILE.exists():
        return labels
    for ln in _LABELS_FILE.read_text(errors='ignore').splitlines():
        s = ln.strip()
        if not s or s.startswith('#') or '=' not in s:
            continue
        k, v = s.split('=', 1)
        labels[k.strip()] = v.strip()
    return labels


def main():
    ap = argparse.ArgumentParser(description='Build msr2 master map from dachsweb source tree')
    ap.add_argument('--base', default='', help='Path to source/senertec/dachsweb root (optional)')
    ap.add_argument('--regler', default='5', help='Regler id (default: 5)')
    ap.add_argument('--out', default='msr2_master_map.json', help='Output file path')
    args = ap.parse_args()

    base = resolve_base(args.base, args.regler)
    global _DATA_XML, _STRUCT_DIR, _DACHS_XML_DIR, _LABELS_FILE
    _DATA_XML, _STRUCT_DIR, _DACHS_XML_DIR, _LABELS_FILE = init_paths(base, args.regler)

    layouts = parse_layouts()
    formats = parse_formats()
    labels = parse_labels()

    used = set()
    for fs in layouts.values():
        for f in fs:
            if f.get('kind') == 'data' and f.get('key'):
                used.add(f['key'])

    master = {}
    for key in sorted(used):
        basek = re.sub(r'\[\d+\]$', '', key)
        master[key] = {
            'base': basek,
            'label': labels.get(key) or labels.get(key + '.presenter') or labels.get(key + '.Short')
                     or labels.get(basek) or labels.get(basek + '.presenter') or labels.get(basek + '.Short')
                     or '',
            'format': formats.get(key) or formats.get(basek) or {},
        }

    decode_hints = {
        'shortBigEndianKeys': [],
        'shortPadOnceKeys': [
            'Hka_Mw1.Temp.sAbgasMotor',
            'Hka_Mw1.Temp.sAbgasHKA',
            'Hka_Mw1.Temp.sKapsel',
            'Hka_BZbeiSC_Mw1_XXL.Temp.sAbgasMotor',
            'Hka_BZbeiSC_Mw1_XXL.Temp.sAbgasHKA',
            'Hka_BZbeiSC_Mw1_XXL.Temp.sKapsel',
        ],
    }

    out = {
        'blocks': BLOCKS,
        'layouts': layouts,
        'map': master,
        'decodeHints': decode_hints,
        'meta': {
            'source': f'msr/xml/regler/{args.regler} + library/xml/dachs + gui/desktop/MsrData_de.properties'
        }
    }
    op = Path(args.out)
    op.write_text(json.dumps(out))
    missing_labels = sum(1 for v in master.values() if not v['label'])
    print(f'wrote={op} keys={len(master)} missing_labels={missing_labels} base={base}')


if __name__ == '__main__':
    main()
