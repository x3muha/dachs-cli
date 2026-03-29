from __future__ import annotations
#!/usr/bin/env python3
import argparse
import asyncio
import json
import signal
import sys
import subprocess
import time
from pathlib import Path

XKNX_IMPORT_ERROR = None
try:
    from xknx import XKNX
    from xknx.dpt import DPT2ByteFloat, DPTArray, DPTBinary, DPTString
    from xknx.io import ConnectionConfig, ConnectionType
    from xknx.telegram import Telegram
    from xknx.telegram.apci import GroupValueRead, GroupValueResponse, GroupValueWrite
    from xknx.telegram.address import GroupAddress
except Exception as _e:
    XKNX_IMPORT_ERROR = _e


def load_json(path):
    pp = Path(path)
    if not pp.exists():
        return {}
    return json.loads(pp.read_text())


def pct_change(old, new):
    try:
        o = float(old); n = float(new)
        if o == 0:
            return 100.0 if n != 0 else 0.0
        return abs((n - o) / o) * 100.0
    except Exception:
        return 0.0 if str(old) == str(new) else 100.0


def _software_version_text(values: dict, key: str):
    if '[' not in key or ']' not in key:
        return None
    base = key.split('[', 1)[0]
    if 'SoftwareVersion' not in base:
        return None
    parts = []
    i = 0
    while True:
        k = f"{base}[{i}]"
        if k not in values:
            break
        rv = values[k].get('raw')
        try:
            parts.append(str(int(rv)))
        except Exception:
            break
        i += 1
    if len(parts) >= 2:
        return '.'.join(parts)
    return None


def _guess_dpt_for_point(p: dict) -> str:
    ov = (p.get('knx_dpt') or '').strip()
    if ov:
        return ov
    key = (p.get('base_key') or p.get('key') or '').lower()
    rt = (p.get('raw_type') or '').lower()
    if 'softwareversion' in key:
        return 'DPT16.001'
    if 'ulzeitstempel' in key or 'timestamp' in key:
        return 'DPT19.001'
    if key.endswith('datum') or '.uldatum' in key or '.usdatum' in key:
        return 'DPT11.001'
    if 'temp' in key or 'temperatur' in key:
        return 'DPT9.001'
    m = {'u8': 'DPT5.001', 'i8': 'DPT6.001', 'u16': 'DPT7.001', 'i16': 'DPT8.001', 'u32': 'DPT12.001', 'i32': 'DPT13.001'}
    return m.get(rt, 'DPT16.001')


def _coerce_for_dpt(value, dpt: str):
    d = (dpt or '').upper()
    if d.startswith('DPT16'):
        return str(value)
    if d.startswith('DPT11') or d.startswith('DPT10') or d.startswith('DPT19'):
        return str(value)
    if isinstance(value, (int, float)):
        return value
    import re
    txt = str(value)
    m = re.match(r'^\s*([-+]?\d+(?:[\.,]\d+)?)', txt)
    if m:
        t = m.group(1).replace(',', '.')
        return float(t) if '.' in t else int(t)
    return str(value)




def current_value_for_key(vals: dict, key: str, point: dict | None = None):
    if key in vals:
        v = vals[key].get('value')
        sv = _software_version_text(vals, key)
        return sv if sv is not None else v
    # generic aggregated key without index: base[0..n] -> "x.y.z"
    if '[' not in key:
        parts = []
        i = 0
        while True:
            kk = f"{key}[{i}]"
            if kk not in vals:
                break
            raw = vals[kk].get('raw')
            val = vals[kk].get('value')
            candidate = raw if raw is not None else val
            if candidate is None:
                break
            try:
                parts.append(str(int(candidate)))
            except Exception:
                parts.append(str(candidate))
            i += 1
        if len(parts) >= 2:
            sep = '.'
            if isinstance(point, dict):
                sep = str(point.get('aggregate_separator') or '.')
            return sep.join(parts)
    return None

def encode_payload(value, dpt: str):
    d = (dpt or '').upper()
    if d.startswith('DPT1'):
        return DPTBinary(1 if bool(value) else 0)
    if d.startswith('DPT5'):
        return DPTArray(int(value).to_bytes(1, 'big', signed=False))
    if d.startswith('DPT6'):
        return DPTArray(int(value).to_bytes(1, 'big', signed=True))
    if d.startswith('DPT7'):
        return DPTArray(int(value).to_bytes(2, 'big', signed=False))
    if d.startswith('DPT8'):
        return DPTArray(int(value).to_bytes(2, 'big', signed=True))
    if d.startswith('DPT9'):
        return DPT2ByteFloat.to_knx(float(value))
    if d.startswith('DPT12'):
        return DPTArray(int(value).to_bytes(4, 'big', signed=False))
    if d.startswith('DPT13'):
        return DPTArray(int(value).to_bytes(4, 'big', signed=True))
    if d.startswith('DPT16'):
        return DPTString.to_knx(str(value))
    # fallback text
    return DPTString.to_knx(str(value))


def build_connection_config(tx: dict) -> ConnectionConfig:
    routing = tx.get('routing') or {}
    tunn = tx.get('tunneling') or {}
    individual_address = tx.get('individual_address') or None
    # priority: routing first, tunneling second
    if bool(routing.get('enabled', False)):
        return ConnectionConfig(
            connection_type=ConnectionType.ROUTING,
            multicast_group=routing.get('multicast_group') or '224.0.23.12',
            multicast_port=int(routing.get('multicast_port') or 3671),
            local_ip=routing.get('local_ip') or None,
            auto_reconnect=True,
            individual_address=individual_address,
        )
    if bool(tunn.get('enabled', False)):
        return ConnectionConfig(
            connection_type=ConnectionType.TUNNELING,
            gateway_ip=tunn.get('gateway_ip') or '127.0.0.1',
            gateway_port=int(tunn.get('gateway_port') or 3671),
            local_ip=tunn.get('local_ip') or None,
            auto_reconnect=True,
            individual_address=individual_address,
        )
    # fallback routing
    return ConnectionConfig(
        connection_type=ConnectionType.ROUTING,
        multicast_group=routing.get('multicast_group') or '224.0.23.12',
        multicast_port=int(routing.get('multicast_port') or 3671),
        local_ip=routing.get('local_ip') or None,
        auto_reconnect=True,
    )


def load_runtime(points_path: str):
    cfg = load_json(points_path)
    points = [
        p for p in (cfg.get('points') or [])
        if isinstance(p, dict) and p.get('aktiv') and str(p.get('knx_adresse', '')).strip()
    ]
    by_key = {p['key']: p for p in points if p.get('key')}
    by_ga = {}
    for p in points:
        by_ga[str(p.get('knx_adresse')).strip()] = p
    return points, by_key, by_ga


class DaemonState:
    def __init__(self):
        self.stop = False
        self.last_sent = {}
        self.cache_values = {}
        self.cache_reader_proc = None


async def main_async(args):
    cfg = load_json(args.config) if args.config else {}
    files = (cfg.get('files') or {}) if isinstance(cfg, dict) else {}
    rt = (cfg.get('runtime') or {}) if isinstance(cfg, dict) else {}
    tx = (cfg.get('transport') or {}) if isinstance(cfg, dict) else {}
    cr = (cfg.get('cache_reader') or {}) if isinstance(cfg, dict) else {}

    points_path = args.points or files.get('points_file') or 'knx/config/knx_points_v2.json'
    cache_path = args.cache or files.get('cache_file') or 'cache/dachs_cache_v2.json'
    interval = float(args.interval if args.interval is not None else (rt.get('interval_s', 1.0)))
    initial_send = bool(rt.get('initial_send', True))

    points, by_key, by_ga = load_runtime(points_path)
    if not points:
        print('Keine aktiven KNX-Punkte vorhanden.')
        return 1

    conn_cfg = build_connection_config(tx)
    mode = 'routing' if conn_cfg.connection_type == ConnectionType.ROUTING else 'tunneling'
    print(f'KNX mode={mode}')
    xknx = XKNX(connection_config=conn_cfg)
    state = DaemonState()

    cache_reader_proc = None
    cache_reader_mode = str(cr.get('mode', 'every')).lower()
    cache_reader_interval = float(cr.get('interval_s', 60.0) or 60.0)
    cache_reader_next_run = 0.0

    loop = asyncio.get_running_loop()

    def _on_sig(*_):
        state.stop = True
        p = state.cache_reader_proc
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_sig)
        except NotImplementedError:
            pass

    async def send_for_point(p: dict, cur, reason=''):
        ga = str(p.get('knx_adresse')).strip()
        k = p.get('key')
        dpt = _guess_dpt_for_point(p)
        val = _coerce_for_dpt(cur, dpt)
        payload = encode_payload(val, dpt)
        telegram = Telegram(destination_address=GroupAddress(ga), payload=GroupValueWrite(payload))
        await xknx.telegrams.put(telegram)
        state.last_sent[k] = {'value': val, 'ts': time.time()}
        print(f"SEND {ga} <= {k} = {val} ({dpt}) [{reason}]")

    async def send_response_for_ga(ga: str):
        p = by_ga.get(ga)
        if not p:
            return
        if not bool(p.get('lesen', False)):
            return
        k = p.get('key')
        vals = state.cache_values
        cur = current_value_for_key(vals, k, p)
        if cur is None:
            return
        dpt = _guess_dpt_for_point(p)
        val = _coerce_for_dpt(cur, dpt)
        payload = encode_payload(val, dpt)
        telegram = Telegram(destination_address=GroupAddress(ga), payload=GroupValueResponse(payload))
        await xknx.telegrams.put(telegram)
        print(f"RESP {ga} => {k} = {val} ({dpt}) [group-read]")

    def on_telegram(telegram):
        try:
            if isinstance(telegram.payload, GroupValueRead):
                ga = str(telegram.destination_address)
                asyncio.create_task(send_response_for_ga(ga))
        except Exception as e:
            print('WARN telegram handler:', e)

    xknx.telegram_queue.register_telegram_received_cb(on_telegram)

    # optional embedded cache reader
    if bool(cr.get('enabled', False)):
        cmd = cr.get('command') or []
        if not cmd:
            cmd = ['python3', 'dachs_cache_reader_v2.py']
        if isinstance(cmd, list) and cmd:
            cmd = list(cmd)
            if cmd and str(cmd[0]) in ('python', 'python3'):
                cmd[0] = sys.executable
            if '--cache' not in cmd:
                cmd += ['--cache', cache_path]
            if cache_reader_mode == 'loop':
                # read -> end -> read immediately
                if '--interval' not in cmd:
                    cmd += ['--interval', '0']
                if '--once' in cmd:
                    cmd = [x for x in cmd if x != '--once']
                try:
                    cache_reader_proc = subprocess.Popen(cmd, cwd=str(Path('.').resolve()))
                    state.cache_reader_proc = cache_reader_proc
                    print(f"cache_reader(loop) gestartet: {' '.join(cmd)} (pid={cache_reader_proc.pid})")
                except Exception as e:
                    print(f"WARN cache_reader(loop) start fehlgeschlagen: {e}")
            else:
                # every: read -> wait interval -> read
                cache_reader_next_run = 0.0
                print(f"cache_reader mode=every interval={cache_reader_interval}s")

    await xknx.start()
    print('KNX daemon gestartet.')

    try:
        while not state.stop:
            cache = load_json(cache_path)
            vals = (cache.get('values') or {}) if isinstance(cache, dict) else {}
            state.cache_values = vals
            now = time.time()

            # cache_reader mode=every supervision
            if bool(cr.get('enabled', False)) and cache_reader_mode != 'loop':
                proc_alive = (cache_reader_proc is not None and cache_reader_proc.poll() is None)
                if (not proc_alive) and (now >= cache_reader_next_run):
                    cmd = cr.get('command') or ['python3', 'dachs_cache_reader_v2.py']
                    cmd = list(cmd)
                    if cmd and str(cmd[0]) in ('python', 'python3'):
                        cmd[0] = sys.executable
                    if '--cache' not in cmd:
                        cmd += ['--cache', cache_path]
                    if '--once' not in cmd:
                        cmd += ['--once']
                    try:
                        cache_reader_proc = subprocess.Popen(cmd, cwd=str(Path('.').resolve()))
                        state.cache_reader_proc = cache_reader_proc
                        cache_reader_next_run = now + max(0.0, cache_reader_interval)
                        print(f"cache_reader(every) gestartet: {' '.join(cmd)} (pid={cache_reader_proc.pid})")
                    except Exception as e:
                        cache_reader_next_run = now + max(1.0, float(cr.get('restart_delay_s', 2.0) or 2.0))
                        print(f"WARN cache_reader(every) start fehlgeschlagen: {e}")

            for p in points:
                if not bool(p.get('schreiben', False)):
                    continue
                k = p.get('key')
                if not k:
                    continue

                cur = current_value_for_key(vals, k, p)
                if cur is None:
                    continue
                st = state.last_sent.get(k)

                do_send = False
                reason = ''

                cyc = float(p.get('zyklisch_senden_s') or 0)
                if cyc > 0 and (st is None or (now - st['ts']) >= cyc):
                    do_send = True
                    reason = f'zyklisch/{int(cyc)}s'

                if bool(p.get('senden_bei_wertaenderung', True)):
                    if st is None and initial_send:
                        do_send = True
                        reason = reason or 'initial'
                    else:
                        th = float(p.get('bei_wertaenderung_prozent', 10.0) or 10.0)
                        delta_th = float(p.get('bei_wertaenderung_delta', 0.0) or 0.0)
                        chg = pct_change(st['value'], cur)
                        delta_ok = False
                        if delta_th > 0:
                            try:
                                delta_ok = abs(float(cur) - float(st['value'])) >= delta_th
                            except Exception:
                                delta_ok = False
                        if chg >= th or delta_ok:
                            do_send = True
                            if delta_ok and chg < th:
                                reason = reason or f'änderung/Δ>={delta_th:g}'
                            else:
                                reason = reason or f'änderung/{chg:.1f}%>= {th:.1f}%'

                if do_send:
                    try:
                        await send_for_point(p, cur, reason)
                    except Exception as e:
                        print(f"WARN send {p.get('key')}: {e}")

            if args.once:
                break
            sleep_left = max(0.2, float(interval))
            while sleep_left > 0 and not state.stop:
                step = 0.2 if sleep_left > 0.2 else sleep_left
                await asyncio.sleep(step)
                sleep_left -= step
    finally:
        await xknx.stop()
        p = state.cache_reader_proc or cache_reader_proc
        if p is not None:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print('KNX daemon gestoppt.')

    return 0


def main():
    if XKNX_IMPORT_ERROR is not None:
        print('ERROR: xknx nicht verfügbar. Nutze venv: source .venv/bin/activate && python knx/knx_dachs_daemon_v2.py ...')
        print(f'Import-Fehler: {XKNX_IMPORT_ERROR}')
        return 2

    ap = argparse.ArgumentParser(prog='knx_dachs_daemon_v2')
    ap.add_argument('--config', default='knx/config/knx_dachs_daemon_config_v2.json')
    ap.add_argument('--points', default='')
    ap.add_argument('--cache', default='')
    ap.add_argument('--interval', type=float, default=None)
    ap.add_argument('--once', action='store_true')
    args = ap.parse_args()
    return asyncio.run(main_async(args))


if __name__ == '__main__':
    raise SystemExit(main())
