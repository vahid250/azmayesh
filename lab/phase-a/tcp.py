#!/usr/bin/env python3
"""Small standard-library TCP endpoint for the disposable Phase-A lab."""
import argparse
import json
import socket
import time


def serve(args):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(4)
    listener.settimeout(0.2)
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as ready:
            ready.write("ready\n")
    deadline = time.monotonic() + args.duration
    connections = 0
    received = 0
    while time.monotonic() < deadline:
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        connections += 1
        conn.settimeout(0.2)
        try:
            while time.monotonic() < deadline:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                received += len(chunk)
        except OSError:
            pass
        finally:
            conn.close()
    listener.close()
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump({"connections": connections, "received_bytes": received}, handle, sort_keys=True)


def send(args):
    sent = 0
    outcome = "completed"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect((args.destination, args.port))
        block = b"RMA-TCP-PHASE-A-" + (b"x" * (args.chunk_size - 16))
        deadline = time.monotonic() + args.duration
        while sent < args.total_bytes and time.monotonic() < deadline:
            amount = min(len(block), args.total_bytes - sent)
            try:
                sock.sendall(block[:amount])
                sent += amount
            except (socket.timeout, OSError):
                outcome = "send_blocked_or_timed_out"
                break
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    except (socket.timeout, OSError) as exc:
        outcome = "connect_failed"
        print(f"TCP client: {outcome}: {exc}")
    finally:
        sock.close()
    print(json.dumps({"locally_accepted_bytes": sent, "outcome": outcome}, sort_keys=True))


def probe(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect((args.destination, args.port))
    except (socket.timeout, OSError):
        print("PASS: TCP connection could not be established after quota exhaustion.")
        return
    finally:
        sock.close()
    raise SystemExit("FAIL: TCP connection established after quota exhaustion")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--bind", default="10.10.4.2")
    server.add_argument("--port", type=int, default=44003)
    server.add_argument("--duration", type=float, default=6.0)
    server.add_argument("--output", required=True)
    server.add_argument("--ready-file")
    client = sub.add_parser("send")
    client.add_argument("--destination", default="10.10.4.2")
    client.add_argument("--port", type=int, default=44003)
    client.add_argument("--total-bytes", type=int, default=1048576)
    client.add_argument("--chunk-size", type=int, default=16384)
    client.add_argument("--duration", type=float, default=2.0)
    client.add_argument("--timeout", type=float, default=0.3)
    check = sub.add_parser("probe")
    check.add_argument("--destination", default="10.10.4.2")
    check.add_argument("--port", type=int, default=44004)
    check.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()
    if args.mode == "serve":
        serve(args)
    elif args.mode == "send":
        send(args)
    else:
        probe(args)


if __name__ == "__main__":
    main()
