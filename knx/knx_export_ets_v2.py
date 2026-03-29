#!/usr/bin/env python3
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET

NS = 'http://knx.org/xml/ga-export/01'


def guess_better_dpt(point: dict) -> str:
    ov = (point.get('knx_dpt') or '').strip()
    if ov:
        return ov
    key = (point.get('base_key') or point.get('key') or '').lower()
    raw_type = (point.get('raw_type') or '').lower()

    if 'softwareversion' in key:
        return 'DPT16.001'

    if 'ulzeitstempel' in key or 'timestamp' in key:
        return 'DPT19.001'
    if key.endswith('datum') or '.uldatum' in key or '.usdatum' in key:
        return 'DPT11.001'
    if 'uhrzeit' in key or '.time' in key:
        return 'DPT10.001'
    if 'temp' in key or 'temperatur' in key:
        return 'DPT9.001'

    if raw_type == 'u8':
        return 'DPT5.001'
    if raw_type == 'i8':
        return 'DPT6.001'
    if raw_type == 'u16':
        return 'DPT7.001'
    if raw_type == 'i16':
        return 'DPT8.001'
    if raw_type == 'u32':
        return 'DPT12.001'
    if raw_type == 'i32':
        return 'DPT13.001'
    if key.endswith('_min') or 'betriebssekunden' in key or 'betriebsstunden' in key or 'laufzeit' in key:
        return 'DPT7.007' if raw_type == 'u16' else ('DPT12.001' if raw_type == 'u32' else (point.get('dpt') or 'DPT7.007'))

    return point.get('dpt') or 'DPT5.001'


def dpt_to_dpst(dpt: str) -> str:
    d = (dpt or '').upper().replace(' ', '')
    if d.startswith('DPST-'):
        return d
    if d.startswith('DPT'):
        d = d[3:]
    if d.startswith('-'):
        d = d[1:]
    if '.' in d:
        main, sub = d.split('.', 1)
        try:
            sub_i = int(sub)
        except Exception:
            sub_i = 1
        return f'DPST-{int(main)}-{sub_i}'
    try:
        return f'DPST-{int(d)}-1'
    except Exception:
        return 'DPST-5-1'


def ga_to_int(ga: str) -> int:
    a, b, c = [int(x) for x in ga.split('/')]
    return (a << 11) | (b << 8) | c


def group_name(point: dict) -> str:
    label = (point.get('label_de') or '').strip()
    key = point.get('key') or ''
    if label:
        return f"{label} [{key}]"
    return key


def export_csv(points, out_csv: Path):
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow(['Main', 'Middle', 'Name', 'Address', 'DatapointType', 'Description'])
        for p in points:
            ga = str(p.get('knx_adresse', '')).strip()
            if not ga:
                continue
            a, b, _ = [int(x) for x in ga.split('/')]
            main = f"{a:02d}"
            middle = f"{b:02d}_{p.get('block_name_de') or ('Block ' + str(p.get('block')))}"
            dpt = dpt_to_dpst(guess_better_dpt(p))
            desc = f"key={p.get('key')} block={p.get('block')} write={p.get('schreiben')} read={p.get('lesen')} cyc={p.get('zyklisch_senden_s')}"
            w.writerow([main, middle, group_name(p), ga, dpt, desc])


def export_csv_strict_ets(points, out_csv: Path):
    """ETS-like hierarchical CSV matching common KNX export style:
    "Main";"Middle";"Sub";"Address"
    "Area";;;"11/-/-"
    ;"Line";;"11/3/-"
    ;;"GA Name";"11/3/1"
    """
    by_main_mid = {}
    for p in points:
        ga = str(p.get('knx_adresse', '')).strip()
        if not ga:
            continue
        a, b, c = [int(x) for x in ga.split('/')]
        by_main_mid.setdefault(a, {}).setdefault(b, []).append((c, p))

    with out_csv.open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f, delimiter=';', quotechar='"', quoting=csv.QUOTE_ALL)
        w.writerow(['Main', 'Middle', 'Sub', 'Address'])
        for a in sorted(by_main_mid.keys()):
            w.writerow([f'Dachs Main {a}', '', '', f'{a}/-/-'])
            mids = by_main_mid[a]
            for b in sorted(mids.keys()):
                w.writerow(['', f'Blockgruppe {b}', '', f'{a}/{b}/-'])
                for c, p in sorted(mids[b], key=lambda x: x[0]):
                    ga = f'{a}/{b}/{c}'
                    w.writerow(['', '', group_name(p), ga])


def export_ets_xml(points, out_xml: Path):
    ET.register_namespace('', NS)
    root = ET.Element(f'{{{NS}}}GroupAddress-Export')

    ga_points = [p for p in points if str(p.get('knx_adresse', '')).strip()]
    if not ga_points:
        ET.ElementTree(root).write(out_xml, encoding='utf-8', xml_declaration=True)
        return

    ints = [ga_to_int(str(p['knx_adresse']).strip()) for p in ga_points]
    mains = sorted({int(str(p['knx_adresse']).split('/')[0]) for p in ga_points})
    top_start = (min(mains) << 11)
    top_end = (max(mains) << 11) + 2047
    top = ET.SubElement(root, f'{{{NS}}}GroupRange', {
        'Name': 'Dachs-CLI',
        'RangeStart': str(top_start),
        'RangeEnd': str(top_end),
        'Security': 'Off'
    })

    by_main = defaultdict(list)
    for p in ga_points:
        a, b, c = [int(x) for x in str(p['knx_adresse']).split('/')]
        by_main[a].append((b, c, p))

    for a in sorted(by_main.keys()):
        main_items = by_main[a]
        main_start = (a << 11)
        main_end = main_start + 2047
        gr_main = ET.SubElement(top, f'{{{NS}}}GroupRange', {
            'Name': f'Main {a}',
            'RangeStart': str(main_start),
            'RangeEnd': str(main_end)
        })

        by_mid = defaultdict(list)
        for b, c, p in main_items:
            by_mid[b].append((c, p))

        for b in sorted(by_mid.keys()):
            mid_start = (a << 11) | (b << 8)
            mid_end = mid_start + 255
            # use most common block name hint
            names = [x[1].get('block_name_de') for x in by_mid[b] if x[1].get('block_name_de')]
            mid_name = names[0] if names else f'Middle {b}'
            gr_mid = ET.SubElement(gr_main, f'{{{NS}}}GroupRange', {
                'Name': mid_name,
                'RangeStart': str(mid_start),
                'RangeEnd': str(mid_end)
            })

            for c, p in sorted(by_mid[b], key=lambda x: x[0]):
                ga = f"{a}/{b}/{c}"
                attrs = {
                    'Name': group_name(p),
                    'Address': ga,
                    'DPTs': dpt_to_dpst(guess_better_dpt(p)),
                }
                if p.get('lesen'):
                    attrs['Central'] = 'true'
                ET.SubElement(gr_mid, f'{{{NS}}}GroupAddress', attrs)

    ET.ElementTree(root).write(out_xml, encoding='utf-8', xml_declaration=True)


def main():
    ap = argparse.ArgumentParser(prog='knx_export_ets_v2')
    ap.add_argument('--points', default='knx/config/knx_points_v2.json')
    ap.add_argument('--out-csv', default='knx/exports/knx_ets_groups_v2.csv')
    ap.add_argument('--out-csv-strict', default='knx/exports/knx_ets_groups_v2_ets.csv')
    ap.add_argument('--out-xml', default='knx/exports/knx_ets_groups_v2.xml')
    ap.add_argument('--include-inactive', action='store_true')
    args = ap.parse_args()

    cfg = json.loads(Path(args.points).read_text())
    pts = [p for p in (cfg.get('points') or []) if isinstance(p, dict) and str(p.get('knx_adresse', '')).strip()]
    if not args.include_inactive:
        pts = [p for p in pts if p.get('aktiv')]

    export_csv(pts, Path(args.out_csv))
    export_csv_strict_ets(pts, Path(args.out_csv_strict))
    export_ets_xml(pts, Path(args.out_xml))
    print(f'written {args.out_csv}, {args.out_csv_strict} and {args.out_xml} with {len(pts)} mapped points')


if __name__ == '__main__':
    main()
