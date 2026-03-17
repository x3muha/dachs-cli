#!/usr/bin/env python3
import argparse
import json
import tempfile
from pathlib import Path
import dachs_core as core

# kept name for minimal code diff
v1 = core


def _build_layout_from_versioned_pack(pack_obj: dict, block: int, pack_rev: str | None):
    b = (pack_obj.get("blocks", {}) or {}).get(str(block))
    if not isinstance(b, dict):
        return []
    out = list(b.get("base", []) or [])
    rev = str(pack_rev) if pack_rev not in (None, "") else None
    for var in b.get("variants", []) or []:
        picked = None
        choices = var.get("choices", []) or []
        if rev is not None:
            for ch in choices:
                vv = [str(x) for x in (ch.get("versions", []) or [])]
                if rev in vv:
                    picked = ch.get("entry")
                    break
        if picked is None and len(choices) == 1:
            picked = choices[0].get("entry")
        if isinstance(picked, dict):
            out.append(picked)
    return out


def _materialize_pack_for_blocks(versioned_pack: Path, blocks: list[int], pack_rev: str, fallback_formats: Path | None):
    p = json.loads(versioned_pack.read_text())
    out = {"layouts": {}, "formats": p.get("formats", {})}
    if (not out["formats"]) and fallback_formats and fallback_formats.exists():
        out["formats"] = json.loads(fallback_formats.read_text()).get("formats", {})

    labels = {}
    for b in blocks:
        lay = _build_layout_from_versioned_pack(p, b, pack_rev)
        out["layouts"][str(b)] = lay
        for e in lay:
            if isinstance(e, dict) and e.get("key") and e.get("label_de"):
                labels[e["key"]] = e["label_de"]

    tmp_pack = Path(tempfile.mkstemp(prefix="dachs_v2_pack_", suffix=".json")[1])
    tmp_pack.write_text(json.dumps(out, ensure_ascii=False))

    tmp_labels = None
    if labels:
        tmp_labels = Path(tempfile.mkstemp(prefix="dachs_v2_labels_", suffix=".properties")[1])
        tmp_labels.write_text("\n".join(f"{k}={v}" for k, v in sorted(labels.items())))

    return tmp_pack, tmp_labels


def _eff_port_baud(args):
    p = getattr(args, 'port_local', None) or getattr(args, 'port', '/dev/ttyUSB0')
    b = getattr(args, 'baud_local', None) or getattr(args, 'baud', 19200)
    return p, int(b)


def main():
    ap = argparse.ArgumentParser(prog="dachs-cli-v2")
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=19200)

    sub = ap.add_subparsers(dest="cmd", required=True)

    p_link = sub.add_parser("watch-link")
    p_link.add_argument("--count", type=int, default=20)
    p_link.add_argument("--interval", type=float, default=0.5)
    p_link.add_argument("--rx-timeout", type=float, default=0.8)
    p_link.add_argument("--port", dest="port_local", default=None)
    p_link.add_argument("--baud", dest="baud_local", type=int, default=None)

    p_rb = sub.add_parser("read-block")
    p_rb.add_argument("--block", required=True, type=lambda x: int(x, 0))
    p_rb.add_argument("--packet", type=lambda x: int(x, 0), default=0)
    p_rb.add_argument("--rx-timeout", type=float, default=0.9)
    p_rb.add_argument("--port", dest="port_local", default=None)
    p_rb.add_argument("--baud", dest="baud_local", type=int, default=None)

    p_ra = sub.add_parser("readall")
    p_ra.add_argument("--blocks", default="20,22,24,26,28,30,50,62,70,76")
    p_ra.add_argument("--interval", type=float, default=3.5)
    p_ra.add_argument("--loops", type=int, default=1)
    p_ra.add_argument("--rx-timeout", type=float, default=0.9)
    p_ra.add_argument("--wait-between-blocks", type=float, default=None)
    p_ra.add_argument("--port", dest="port_local", default=None)
    p_ra.add_argument("--baud", dest="baud_local", type=int, default=None)

    p_rd = sub.add_parser("readall-decoded")
    p_rd.add_argument("--blocks", default="20,22,24,26")
    p_rd.add_argument("--interval", type=float, default=3.5)
    p_rd.add_argument("--loops", type=int, default=1)
    p_rd.add_argument("--rx-timeout", type=float, default=0.9)
    p_rd.add_argument("--wait-between-blocks", type=float, default=None)
    d_data, d_struct, d_fmt = v1._default_decode_source_paths()
    p_rd.add_argument("--data-xml", default=d_data)
    p_rd.add_argument("--struct-dir", default=d_struct)
    p_rd.add_argument("--format-dir", default=d_fmt)
    p_rd.add_argument("--pack-file", default="")
    p_rd.add_argument("--pack-rev", default="50")
    p_rd.add_argument("--labels-file", default="")
    p_rd.add_argument("--show-reserved", action="store_true")
    p_rd.add_argument("--text-only", action="store_true")
    p_rd.add_argument("--key-only", action="store_true")
    p_rd.add_argument("--show-msr-menu-code", action="store_true")
    p_rd.add_argument("--port", dest="port_local", default=None)
    p_rd.add_argument("--baud", dest="baud_local", type=int, default=None)

    p_keys = sub.add_parser("list-keys")
    p_keys.add_argument("--mapping", default=str(Path(__file__).resolve().parent / "msr2_master_map.json"))
    p_keys.add_argument("--limit", type=int, default=200)

    args = ap.parse_args()

    port, baud = _eff_port_baud(args)

    if args.cmd == "watch-link":
        return v1.watch_link(port, baud, args.count, args.interval, args.rx_timeout)
    if args.cmd == "read-block":
        return v1.read_block(port, baud, args.block, args.packet, args.rx_timeout)
    if args.cmd == "readall":
        _wb = args.wait_between_blocks if args.wait_between_blocks is not None else args.interval
        return v1.readall(port, baud, v1.parse_blocks(args.blocks), _wb, args.loops, args.rx_timeout)
    if args.cmd == "list-keys":
        return v1.list_keys(Path(args.mapping), args.limit) or 0

    if args.cmd == "readall-decoded":
        if args.text_only and args.key_only:
            print("ERROR: --text-only and --key-only are mutually exclusive")
            return 2
        mode = "text" if args.text_only else ("key" if args.key_only else "both")

        script_dir = Path(__file__).resolve().parent
        cwd = Path.cwd()
        pack = Path(args.pack_file) if args.pack_file else None
        if not pack:
            cands = [
                cwd / "msr2_pack_master_version.json",
                script_dir / "msr2_pack_master_version.json",
                cwd / "msr2_pack_master.json",
                script_dir / "msr2_pack_master.json",
            ]
            pack = next((c for c in cands if c.exists()), cands[0])

        blocks = v1.parse_blocks(args.blocks)
        labels_file = Path(args.labels_file) if args.labels_file else None

        if pack.exists() and json.loads(pack.read_text()).get("blocks"):
            tmp_pack, tmp_labels = _materialize_pack_for_blocks(
                pack, blocks, args.pack_rev,
                fallback_formats=(cwd / "msr2_formats_v2.json" if (cwd / "msr2_formats_v2.json").exists() else script_dir / "msr2_formats_v2.json")
            )
            if labels_file is None:
                labels_file = tmp_labels
            pack_use = tmp_pack
        else:
            pack_use = pack

        return v1.readall_decoded(
            port,
            baud,
            blocks,
            (args.wait_between_blocks if args.wait_between_blocks is not None else args.interval),
            args.loops,
            args.rx_timeout,
            Path(args.data_xml),
            Path(args.struct_dir),
            Path(args.format_dir),
            pack_use,
            labels_file,
            args.show_reserved,
            mode,
            args.show_msr_menu_code,
        )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
