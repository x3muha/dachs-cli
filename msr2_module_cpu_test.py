#!/usr/bin/env python3
import argparse, time, sys
sys.path.insert(0, '/root/senertec/dachs-cli')
import dachs_cli as dc

def send_addr(ser, data: bytes, pn: int, timeout: float, src: int, dst: int):
    tx = dc.mk_send_telegram(data, pn, src=src, dst=dst)
    t0 = time.time()
    ser.write(tx)
    deadline = time.time() + timeout
    raw = bytearray(); ack=b''; rx=b''
    while time.time() < deadline:
        b = ser.read(512)
        if not b:
            continue
        raw.extend(b)
        for f in dc._parse_all_frames(bytes(raw)):
            if f[0] in (0x06,0x15) and ((f[1]>>4)&0x0F)==pn:
                ack=f
            if f[0]==0x02:
                rx=f
        if rx:
            break
    return tx,ack,rx,(time.time()-t0)*1000.0

def dst_from(module:int,cpu:int)->int:
    return ((module & 0x0F)<<4) | (cpu & 0x0F)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--port',default='/dev/ttyUSB0')
    ap.add_argument('--baud',type=int,default=19200)
    ap.add_argument('--module',type=int,default=1)
    ap.add_argument('--cpu',type=int,default=0)
    ap.add_argument('--timeout',type=float,default=2.0)
    ap.add_argument('--auth-level',type=int,default=2)
    ap.add_argument('--auth-pass4',default='5631')
    ap.add_argument('--write-name',default='TEST_X3')
    args=ap.parse_args()

    dst=dst_from(args.module,args.cpu)
    ser=dc.open_port(args.port,args.baud)
    pn=0
    with ser:
        tx,ack,rx,dt=send_addr(ser,b'',pn,args.timeout,0x00,dst); print('sync',dc.to_hex(tx),dc.to_hex(ack) if ack else '-',dc.to_hex(rx) if rx else '-'); pn=(pn+1)&0x0F
        tx,ack,rx,dt=send_addr(ser,bytes([110]),pn,args.timeout,0x00,dst); print('read110',dc.to_hex(tx),dc.to_hex(ack) if ack else '-',dc.to_hex(rx[:24]) if rx else '-'); pn=(pn+1)&0x0F
        if not rx or len(rx)<8:
            print('NO_RX_110'); return 2
        data=rx[5:-2]
        payload=bytearray(data[1:])

        pw=args.auth_pass4
        auth=bytes([126,ord(pw[0]),ord(pw[1]),ord(pw[2]),ord(pw[3]),args.auth_level & 0xFF])
        tx,ack,rx,dt=send_addr(ser,auth,pn,args.timeout,0x00,dst); print('auth',dc.to_hex(tx),dc.to_hex(ack) if ack else '-',dc.to_hex(rx) if rx else '-'); pn=(pn+1)&0x0F

        v=args.write_name.encode('latin-1',errors='ignore')[:20]
        payload[0:20]=v + b'\x00'*(20-len(v))
        wsvc=bytes([111])+bytes(payload)
        tx,ack,rx,dt=send_addr(ser,wsvc,pn,args.timeout,0x00,dst); print('write111',dc.to_hex(tx),dc.to_hex(ack) if ack else '-',dc.to_hex(rx) if rx else '-'); pn=(pn+1)&0x0F

        tx,ack,rx,dt=send_addr(ser,bytes([110]),pn,args.timeout,0x00,dst); print('read110_after',dc.to_hex(tx),dc.to_hex(ack) if ack else '-',dc.to_hex(rx[:40]) if rx else '-');

if __name__=='__main__':
    raise SystemExit(main())
