#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import argparse
import websockets
import time
import functools
import json
import struct

async def server_handler(websocket, path, args):
    """处理单个客户端连接。"""
    print(f"Client connected from {websocket.remote_address}")
    
    async def sender(duration):
        chunk = b'\0' * 65536
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                await websocket.send(chunk)
            except websockets.exceptions.ConnectionClosed:
                break
        try:
            await websocket.send("EOT_S") # End of Transmission from Server
        except websockets.exceptions.ConnectionClosed:
            pass

    async def receiver():
        async for message in websocket:
            if message == "EOT_C": # End of Transmission from Client
                break

    try:
        # Authentication
        if args.token:
            client_token = await websocket.recv()
            if client_token != args.token:
                print(f"Authentication failed for {websocket.remote_address}. Closing connection.")
                await websocket.close(code=1008, reason="Invalid token")
                return

        initial_message = await websocket.recv()

        if initial_message == "BIDIR":
            print(f"Starting bidirectional test for {websocket.remote_address}")
            duration = args.time or 10 # Default to 10s if not specified
            sender_task = asyncio.create_task(sender(duration))
            receiver_task = asyncio.create_task(receiver())
            await asyncio.gather(sender_task, receiver_task)
            print(f"Bidirectional test finished for {websocket.remote_address}")

        elif initial_message == "UDP":
            # 模拟UDP测试 (Client -> Server)
            print(f"Starting UDP test for {websocket.remote_address}")
            jitter = 0
            last_transit_time = -1
            last_seq = -1
            lost_packets = 0
            total_packets = 0

            start_time = time.time()
            while time.time() - start_time < (args.time or 10) + 2: # Wait 2 extra secs for late packets
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    if message == "EOT_C":
                        break
                    
                    now_ns = time.time_ns()
                    seq, client_ts_ns = struct.unpack('!QL', message[:16])
                    total_packets += 1

                    if last_seq != -1 and seq > last_seq + 1:
                        lost_packets += seq - (last_seq + 1)
                    
                    transit_time = now_ns - client_ts_ns
                    if last_transit_time != -1:
                        d = abs(transit_time - last_transit_time)
                        jitter += (d - jitter) / 16.0
                    
                    last_transit_time = transit_time
                    last_seq = seq

                except asyncio.TimeoutError:
                    continue
            
            loss_percent = (lost_packets / (last_seq + 1)) * 100 if (last_seq + 1) > 0 else 0
            jitter_ms = jitter / 1_000_000
            report = {
                "jitter_ms": jitter_ms,
                "lost_packets": lost_packets,
                "total_packets": total_packets,
                "loss_percent": loss_percent
            }
            await websocket.send(json.dumps(report))
            print(f"UDP test finished for {websocket.remote_address}: Jitter={jitter_ms:.3f}ms, Lost={lost_packets}/{last_seq + 1} ({loss_percent:.2f}%)")

        elif initial_message == "REVERSE":
            # TCP 下载测试 (Server -> Client)
            print(f"Starting reverse test for {websocket.remote_address}")
            await sender(args.time or 10)
            print(f"Reverse test finished for {websocket.remote_address}")
        else: # UPLOAD
            # TCP 上传测试 (Client -> Server), server acts as a sink.
            print(f"Starting upload test for {websocket.remote_address}")
            await receiver()
            print(f"Upload test finished for {websocket.remote_address}")

    except websockets.exceptions.ConnectionClosed:
        print(f"Connection with {websocket.remote_address} closed unexpectedly.")
    finally:
        print(f"Client {websocket.remote_address} disconnected.")


async def start_server(host, port, args):
    """启动wperf服务端"""
    print(f"Starting wperf server on {host}:{port}")
    handler = functools.partial(server_handler, args=args)
    async with websockets.serve(handler, host, port):
        await asyncio.Future()  # run forever

async def reporter(start_time, stats, args):
    """定期报告带宽的协程，支持文本或JSON输出"""
    
    # In UDP mode, the server sends the final report. The client reporter just waits.
    if args.udp:
        while not stats['done']:
            await asyncio.sleep(0.2)
        
        # Wait for the final report to be populated by the worker
        await asyncio.sleep(0.5) 
        
        if 'udp_report' in stats and stats['udp_report']:
            report = stats['udp_report']
            if args.json:
                 print(json.dumps(report, indent=4))
            else:
                print("-" * 40)
                print(f"Jitter: {report['jitter_ms']:.3f} ms")
                print(f"Lost/Total: {report['lost_packets']}/{report['total_packets']} ({report['loss_percent']:.2f}%)")
                print("-" * 40)
        return

    # TCP Mode Reporting
    if args.json:
        result = {
            'start': {
                'timestamp': {'time': time.strftime('%Y-%m-%d %H:%M:%S %Z'), 'timesecs': start_time},
                'connecting_to': {'host': args.client, 'port': args.port},
                'test_parameters': {
                    'time': args.time,
                    'bytes': args.bytes,
                    'parallel': args.parallel,
                    'reverse': args.reverse,
                    'bidir': args.bidir,
                    'interval': args.interval
                }
            },
            'intervals': [],
            'end': {}
        }
    else:
        print("-" * 60)
        if args.bidir:
            print(f"Interval\tUpload (Transfer, Bandwidth)\tDownload (Transfer, Bandwidth)")
        else:
            print(f"Interval\tTransfer\tBandwidth")
        print(f"[SUM]\t{'[sec]':<8}\t{'[MBytes]':<8}\t{'[Mbits/sec]':<8}")
        print("-" * 60)

    last_report_time = start_time
    last_total_uploaded = 0
    last_total_downloaded = 0

    while not stats['done']:
        await asyncio.sleep(args.interval)
        
        now = time.time()
        if args.time and now - start_time > args.time:
            break
        
        total_uploaded = sum(stats['bytes_uploaded'])
        total_downloaded = sum(stats['bytes_downloaded'])
        if args.bytes and (total_uploaded >= args.bytes or total_downloaded >= args.bytes):
            break
        
        interval_duration = now - last_report_time
        interval_uploaded = total_uploaded - last_total_uploaded
        interval_downloaded = total_downloaded - last_total_downloaded
        upload_speed_mbps = (interval_uploaded * 8) / (interval_duration * 1_000_000) if interval_duration > 0 else 0
        download_speed_mbps = (interval_downloaded * 8) / (interval_duration * 1_000_000) if interval_duration > 0 else 0
        
        if args.json:
            # JSON reporting for bidir can be complex, skipping detailed interval for now
            pass
        else:
            if args.bidir:
                up_str = f"{interval_uploaded / 1_000_000:<8.2f}\t{upload_speed_mbps:<8.2f}"
                down_str = f"{interval_downloaded / 1_000_000:<8.2f}\t{download_speed_mbps:<8.2f}"
                print(f"[SUM]\t{last_report_time - start_time:.1f}-{now - start_time:.1f}\t{up_str}\t{down_str}")
            else:
                total_bytes = total_uploaded if not args.reverse else total_downloaded
                last_total_bytes = last_total_uploaded if not args.reverse else last_total_downloaded
                interval_bytes = total_bytes - last_total_bytes
                speed_mbps = (interval_bytes * 8) / (interval_duration * 1_000_000) if interval_duration > 0 else 0
                print(f"[SUM]\t{last_report_time - start_time:.1f}-{now - start_time:.1f}\t{interval_bytes / 1_000_000:<8.2f}\t{speed_mbps:<8.2f}")

        last_report_time = now
        last_total_uploaded = total_uploaded
        last_total_downloaded = total_downloaded

    # Final report
    end_time = time.time()
    total_duration = end_time - start_time
    total_uploaded = sum(stats['bytes_uploaded'])
    total_downloaded = sum(stats['bytes_downloaded'])
    upload_speed_mbps = (total_uploaded * 8) / (total_duration * 1_000_000) if total_duration > 0 else 0
    download_speed_mbps = (total_downloaded * 8) / (total_duration * 1_000_000) if total_duration > 0 else 0
    
    if args.json:
        # Simplified JSON end report for now
        result['end'] = {
            'sum_sent': {'bytes': total_uploaded, 'bits_per_second': upload_speed_mbps * 1_000_000},
            'sum_received': {'bytes': total_downloaded, 'bits_per_second': download_speed_mbps * 1_000_000}
        }
        print(json.dumps(result, indent=4))
    else:
        print("-" * 60)
        if args.bidir:
            print(f"[SUM]\t0.0-{total_duration:.1f} sec\tUpload: {total_uploaded / 1_000_000:.2f} MB {upload_speed_mbps:.2f} Mbps")
            print(f"[SUM]\t0.0-{total_duration:.1f} sec\tDownload: {total_downloaded / 1_000_000:.2f} MB {download_speed_mbps:.2f} Mbps")
        else:
            total_bytes = total_uploaded if not args.reverse else total_downloaded
            total_speed_mbps = upload_speed_mbps if not args.reverse else download_speed_mbps
            print(f"[SUM]\t0.0-{total_duration:.1f}\t{total_bytes / 1_000_000:<8.2f}\t{total_speed_mbps:<8.2f}")
        print("-" * 60)


async def client_worker(worker_id, uri, args, stats):
    """单个客户端工作流，负责一个连接"""
    
    async def sender(websocket):
        chunk = b'\0' * 65536
        start_time = time.time()
        bytes_to_send = args.bytes / args.parallel if args.bytes else None
        
        while True:
            if bytes_to_send and stats['bytes_uploaded'][worker_id] >= bytes_to_send:
                break
            if not bytes_to_send and args.time and time.time() - start_time >= args.time:
                break
            
            await websocket.send(chunk)
            stats['bytes_uploaded'][worker_id] += len(chunk)
        
        await websocket.send("EOT_C")

    async def receiver(websocket):
        bytes_to_receive = args.bytes / args.parallel if args.bytes else None
        start_time = time.time()
        while bytes_to_receive is None or stats['bytes_downloaded'][worker_id] < bytes_to_receive:
            try:
                message = await websocket.recv()
                if message == "EOT_S":
                    break
                stats['bytes_downloaded'][worker_id] += len(message)
                if bytes_to_receive is None and args.time and time.time() - start_time >= args.time:
                    break
            except websockets.exceptions.ConnectionClosed:
                break

    try:
        async with websockets.connect(uri) as websocket:
            # Authentication
            if args.token:
                await websocket.send(args.token)

            if args.bidir:
                await websocket.send("BIDIR")
                sender_task = asyncio.create_task(sender(websocket))
                receiver_task = asyncio.create_task(receiver(websocket))
                await asyncio.gather(sender_task, receiver_task)

            elif args.udp:
                await websocket.send("UDP")
                seq = 0
                packet_size_bytes = 1400
                target_bps = args.bandwidth * 1_000_000
                delay = (packet_size_bytes * 8) / target_bps if target_bps > 0 else 0
                payload = b'\0' * (packet_size_bytes - 16)
                start_time = time.time()

                while time.time() - start_time < (args.time or 10):
                    client_ts_ns = time.time_ns()
                    header = struct.pack('!QL', seq, client_ts_ns)
                    await websocket.send(header + payload)
                    stats['bytes_uploaded'][worker_id] += packet_size_bytes
                    seq += 1
                    if delay > 0:
                        await asyncio.sleep(delay)
                
                await websocket.send("EOT_C")
                report_str = await websocket.recv()
                stats['udp_report'] = json.loads(report_str)

            elif args.reverse:
                await websocket.send("REVERSE")
                await receiver(websocket)
            else: # TCP Upload
                await websocket.send("UPLOAD") # Explicitly state mode
                await sender(websocket)

    except Exception as e:
        print(f"Worker {worker_id} error: {e}")


async def start_client(uri, args):
    """启动wperf客户端并协调所有工作流"""
    if not args.json:
        print(f"Connecting to wperf server at {uri}, running {args.parallel} parallel streams")
    
    start_time = time.time()
    # Shared state for all workers and the reporter
    stats = {
        'bytes_uploaded': [0] * args.parallel,
        'bytes_downloaded': [0] * args.parallel,
        'done': False
    }
    if args.udp:
        stats['udp_report'] = {}

    reporter_task = asyncio.create_task(reporter(start_time, stats, args))
    
    worker_tasks = [
        client_worker(i, uri, args, stats) for i in range(args.parallel)
    ]

    try:
        await asyncio.gather(*worker_tasks)
    finally:
        # Signal the reporter to finish and print the final report
        stats['done'] = True
        await reporter_task

def main():
    """主函数，解析命令行参数并启动相应的模式"""
    parser = argparse.ArgumentParser(description="wperf: A simple network performance tool using WebSockets.")
    
    # 服务端模式参数
    parser.add_argument("-s", "--server", action="store_true", help="Run in server mode.")
    
    # 客户端模式参数
    parser.add_argument("-c", "--client", type=str, help="Run in client mode, connecting to the specified server address.")
    
    # 通用参数
    parser.add_argument("-p", "--port", type=int, default=8765, help="The port to listen on (server mode) or connect to (client mode).")
    parser.add_argument("--token", type=str, help="Authentication token for the server.")
    parser.add_argument("-i", "--interval", type=int, default=1, help="The interval in seconds to report bandwidth.")
    parser.add_argument("-t", "--time", type=int, help="The total duration of the test in seconds (TCP mode).")
    parser.add_argument("-n", "--bytes", type=str, help="Number of bytes to transmit (e.g., 10M, 1G).")
    
    # 客户端专用参数
    parser.add_argument("-R", "--reverse", action="store_true", help="Reverse mode (server sends, client receives).")
    parser.add_argument("--bidir", action="store_true", help="Bidirectional test (both send and receive).")
    parser.add_argument("-P", "--parallel", type=int, default=1, help="Number of parallel client streams to run.")
    parser.add_argument("-J", "--json", action="store_true", help="Output in JSON format.")
    parser.add_argument("--udp", action="store_true", help="Simulate UDP traffic and measure jitter/loss.")
    parser.add_argument("-b", "--bandwidth", type=float, default=1, help="Target bandwidth in Mbits/sec (for UDP mode).")

    args = parser.parse_args()

    if args.bytes:
        args.time = None # -n overrides -t
        size_str = args.bytes.upper()
        try:
            if size_str.endswith('K'):
                args.bytes = int(size_str[:-1]) * 1024
            elif size_str.endswith('M'):
                args.bytes = int(size_str[:-1]) * 1024 * 1024
            elif size_str.endswith('G'):
                args.bytes = int(size_str[:-1]) * 1024 * 1024 * 1024
            else:
                args.bytes = int(size_str)
        except ValueError:
            print("Error: Invalid format for --bytes. Use a number with an optional K, M, or G suffix.")
            return
    elif not args.udp and not args.bidir:
        args.bytes = None
        if not args.time:
            args.time = 10 # Default to 10 seconds if neither -t nor -n is given for TCP tests

    if args.server and args.client:
        print("Error: Cannot be both a server and a client.")
        return
    
    if args.client and not args.time and not args.bytes and not args.udp:
        print("Error: TCP test requires either --time or --bytes to be specified.")
        return
    
    if args.reverse and args.bidir:
        print("Error: Cannot use --reverse and --bidir at the same time.")
        return

    if args.server:
        # 在服务端模式下，我们监听所有接口
        host = '0.0.0.0'
        asyncio.run(start_server(host, args.port, args))
    elif args.client:
        uri = f"ws://{args.client}:{args.port}"
        asyncio.run(start_client(uri, args))
    else:
        print("Error: You must specify either server (-s) or client (-c) mode.")
        parser.print_help()

if __name__ == "__main__":
    main()