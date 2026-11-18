#!/usr/bin/env python3
"""Small standard-library UDP traffic endpoint for the disposable Phase-A lab."""
import argparse
import json
import socket
import time
from collections import defaultdict


def serve(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as ready:
            ready.write("ready\n")
    sock.settimeout(0.10)
    deadline = time.monotonic() + args.duration
    counts = defaultdict(lambda: {"packets": 0, "payload_bytes": 0})
    while time.monotonic() < deadline:
        try:
            payload, peer = sock.recvfrom(65535)
        except socket.timeout:
            continue
        counts[peer[0]]["packets"] += 1
        counts[peer[0]]["payload_bytes"] += len(payload)
    sock.close()
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(dict(counts), handle, sort_keys=True)


def send(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"RMA-PHASE-A-" + (b"x" * (args.payload_size - 12))
    for _ in range(args.count):
        sock.sendto(payload, (args.destination, args.port))
        if args.interval:
            time.sleep(args.interval)
    sock.close()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--bind", default="10.10.4.2")
    server.add_argument("--port", type=int, default=44000)
    server.add_argument("--duration", type=float, default=2.0)
    server.add_argument("--output", required=True)
    server.add_argument("--ready-file")
    client = sub.add_parser("send")
    client.add_argument("--destination", default="10.10.4.2")
    client.add_argument("--port", type=int, default=44000)
    client.add_argument("--count", type=int, default=30)
    client.add_argument("--payload-size", type=int, default=1200)
    client.add_argument("--interval", type=float, default=0.001)
    args = parser.parse_args()
    if args.mode == "serve":
        serve(args)
    else:
        send(args)


if __name__ == "__main__":
    main()
