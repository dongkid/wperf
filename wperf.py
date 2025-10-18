#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import argparse
import websockets
import time
import functools
import json
import struct
import socket
import os
import sys
import urllib.request
import urllib.error


async def get_geoip_info(ip):
    """获取IP地址的地理位置和ASN信息"""
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return "", ""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode,as"
        with urllib.request.urlopen(url, timeout=2) as response:
            data = json.loads(response.read().decode())
            return data.get('countryCode', ''), data.get('as', '')
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError):
        return "", ""

async def run_traceroute(host, max_hops, timeout):
    """
    执行路由追踪。这是一个异步生成器，会为每一跳产出一个结果字典。
    如果权限不足或设置失败，会引发异常。
    """
    # 检查管理员权限
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        raise PermissionError("路由追踪功能需要管理员或 root 权限才能运行。")

    try:
        dest_addr = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"无法解析主机名 '{host}': {e}") from e

    # ICMP 协议号
    icmp = socket.getprotobyname('icmp')
    # UDP 协议号
    udp = socket.getprotobyname('udp')

    port = 33434  # Traceroute 使用的典型端口

    for ttl in range(1, max_hops + 1):
        hop_data = {"ttl": ttl, "ip": "*", "name": "*", "rtt": -1, "country": "", "asn": ""}
        curr_addr = None
        
        # 创建接收和发送套接字
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as recv_socket, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp) as send_socket:
            
            recv_socket.settimeout(timeout)
            send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # 绑定接收套接字并执行探测 (平台特定)
            try:
                if sys.platform == "win32":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.connect((dest_addr, port))
                        local_ip = s.getsockname()[0]
                    recv_socket.bind((local_ip, 0))
                    recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                else:
                    recv_socket.bind(("", port))
            except Exception as e:
                raise IOError(f"套接字设置失败 (TTL={ttl}): {e}") from e

            try:
                start_time = time.time()
                send_socket.sendto(b'', (dest_addr, port))
                # 等待 ICMP 响应 (使用更大的缓冲区以容纳完整的IP包)
                _, curr_addr_tuple = recv_socket.recvfrom(65535)
                end_time = time.time()
                curr_addr = curr_addr_tuple[0]
                
                hop_data["ip"] = curr_addr
                hop_data["rtt"] = (end_time - start_time) * 1000
                try:
                    hop_data["name"] = socket.gethostbyaddr(curr_addr)[0]
                except socket.herror:
                    hop_data["name"] = curr_addr
                
                country, asn = await get_geoip_info(curr_addr)
                hop_data["country"] = country
                hop_data["asn"] = asn

            except socket.timeout:
                pass # ip remains '*'
            finally:
                if sys.platform == "win32":
                    try:
                        recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception:
                        pass # Socket may already be closed or in a bad state
        
        yield hop_data

        if curr_addr == dest_addr:
            break


async def server_handler(websocket, args):
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

        # 首先尝试解析为JSON命令
        try:
            command_data = json.loads(initial_message)
            if isinstance(command_data, dict) and command_data.get('command') == 'reverse_traceroute':
                client_ip = websocket.remote_address[0]
                print(f"Starting reverse traceroute for {client_ip}")
                try:
                    async for hop in run_traceroute(client_ip, args.tr_max_hops, args.tr_timeout):
                        await websocket.send(json.dumps({"type": "hop", "data": hop}))
                except (PermissionError, ValueError, IOError) as e:
                    await websocket.send(json.dumps({"type": "error", "message": str(e)}))
                except Exception as e:
                    await websocket.send(json.dumps({"type": "error", "message": f"An unexpected error occurred: {e}"}))
                finally:
                    await websocket.send(json.dumps({"type": "end"}))
                return # 完成反向路由追踪，结束处理器
        except (json.JSONDecodeError, TypeError):
            # 不是JSON命令，继续执行旧的逻辑
            pass

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
                    seq, client_ts_ns = struct.unpack('!QQ', message[:16])
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
    async with websockets.serve(lambda ws: server_handler(ws, args), host, port):
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
                    header = struct.pack('!QQ', seq, client_ts_ns)
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


async def run_reverse_traceroute_client(uri, args):
    """客户端执行反向路由追踪的逻辑"""
    try:
        async with websockets.connect(uri) as websocket:
            print(f"Requesting reverse traceroute from server {args.client}...")
            if args.token:
                await websocket.send(args.token)
            
            await websocket.send(json.dumps({"command": "reverse_traceroute"}))
            
            client_ip = websocket.local_address[0]
            try:
                dest_addr = socket.gethostbyname(client_ip)
                print(f"traceroute to {client_ip} ({dest_addr}), {args.tr_max_hops} hops max, from server {args.client}")
            except Exception:
                 print(f"Starting reverse traceroute to this client from server {args.client}...")

            async for message in websocket:
                data = json.loads(message)
                if data['type'] == 'hop':
                    hop = data['data']
                    if hop.get('error'):
                        print(f"Error at TTL {hop['ttl']}: {hop['error']}")
                        break
                    if hop['ip'] == '*':
                        print(f"{hop['ttl']:<2} * * *")
                    else:
                        geo_info = f"[{hop['country']}, {hop['asn']}]" if hop['country'] and hop['asn'] else ""
                        print(f"{hop['ttl']:<2} {geo_info:<25} {hop['name']} ({hop['ip']}) {hop['rtt']:.3f} ms")
                elif data['type'] == 'end':
                    break
                elif data['type'] == 'error':
                    print(f"Server error: {data['message']}")
                    break
    except Exception as e:
        print(f"Connection error: {e}")


async def start_client(uri, args):
    """启动wperf客户端并协调所有工作流"""
    if args.reverse_traceroute:
        await run_reverse_traceroute_client(uri, args)
        return

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
    
    # Dynamically determine the program name for help messages
    is_frozen = getattr(sys, 'frozen', False)
    if is_frozen:
        prog_name = os.path.basename(sys.executable)
        sudo_prefix = "sudo " if os.name != 'nt' else ''
    else:
        prog_name = f"python {sys.argv[0]}"
        sudo_prefix = "sudo " if os.name != 'nt' else ''

    epilog_text = f"""
Examples:
  # Run a server on port 9000
  {prog_name} -s -p 9000

  # Run a 10-second TCP upload test
  {prog_name} -c <server_ip> -t 10

  # Run a TCP download test transferring 100MB of data with 4 parallel streams
  {prog_name} -c <server_ip> -n 100M -P 4 -R

  # Run a 20-second bidirectional test
  {prog_name} -c <server_ip> --bidir -t 20

  # Run a UDP test with a target bandwidth of 5 Mbps for 15 seconds
  {prog_name} -c <server_ip> --udp -b 5 -t 15

  # Run a standalone traceroute (requires administrator/root privileges)
  {sudo_prefix}{prog_name} --traceroute google.com
  
  # Request a reverse traceroute from the server (requires administrator/root privileges on client)
  {sudo_prefix}{prog_name} -c <server_ip> --reverse-traceroute
"""

    parser = argparse.ArgumentParser(
        description="wperf: A WebSocket-based network performance tool, similar to iperf3.",
        epilog=epilog_text,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Mode selection
    mode_group = parser.add_argument_group('Mode', 'Choose one of the operating modes. Only one mode can be selected.')
    mode_exclusive_group = mode_group.add_mutually_exclusive_group()
    mode_exclusive_group.add_argument("-s", "--server", action="store_true", help="Run in server mode, waiting for client connections.")
    mode_exclusive_group.add_argument("-c", "--client", type=str, metavar='<host>', help="Run in client mode, connecting to the specified server.")
    mode_exclusive_group.add_argument("--traceroute", type=str, metavar='<host>', help="Run in standalone traceroute mode. This does not connect to a wperf server.")

    # General options
    general_group = parser.add_argument_group('General Options', 'Parameters applicable to client, server, and traceroute modes')
    general_group.add_argument("-p", "--port", type=int, default=8765, help="The port to listen on (server) or connect to (client). Default: 8765.")
    general_group.add_argument("--token", type=str, help="Authentication token to secure the server. Must be the same on client and server.")
    
    # Client test options
    client_group = parser.add_argument_group('Client Test Options', 'Parameters for controlling client-side tests')
    client_group.add_argument("-i", "--interval", type=int, default=1, metavar='<sec>', help="The interval in seconds between periodic bandwidth reports. Default: 1.")
    client_group.add_argument("-t", "--time", type=int, metavar='<sec>', help="The duration of the test in seconds. Default is 10s for TCP/UDP tests. Incompatible with -n.")
    client_group.add_argument("-n", "--bytes", type=str, metavar='<size>', help="Number of bytes to transmit (e.g., 10M, 1G). This overrides the --time option.")
    client_group.add_argument("-R", "--reverse", action="store_true", help="Reverse mode (server sends, client receives). Tests download speed.")
    client_group.add_argument("--bidir", action="store_true", help="Bidirectional test (both send and receive simultaneously).")
    client_group.add_argument("-P", "--parallel", type=int, default=1, metavar='<n>', help="Number of parallel client streams to run to saturate the link. Default: 1.")
    client_group.add_argument("-J", "--json", action="store_true", help="Output results in machine-readable JSON format.")
    client_group.add_argument("--udp", action="store_true", help="Simulate UDP traffic to measure jitter and packet loss. Default is TCP.")
    client_group.add_argument("-b", "--bandwidth", type=float, default=1, metavar='<mbps>', help="Target bandwidth in Mbits/sec for UDP tests. Default: 1 Mbps.")

    # Traceroute options
    traceroute_group = parser.add_argument_group('Traceroute Options', 'Parameters for traceroute modes (require admin/root privileges)')
    traceroute_group.add_argument("--reverse-traceroute", action="store_true", help="Request a reverse traceroute from the server to this client. Must be used with -c.")
    traceroute_group.add_argument("--tr-max-hops", type=int, default=30, metavar='<n>', help="Set the max number of hops (TTL) for traceroute. Default: 30.")
    traceroute_group.add_argument("--tr-timeout", type=int, default=1, metavar='<sec>', help="Set the timeout in seconds for each traceroute hop. Default: 1.")

    # If no arguments are provided, print help. For compiled executables, wait for user input.
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        # When running as a compiled executable (e.g., via PyInstaller),
        # the console window may close immediately. This prevents that.
        if getattr(sys, 'frozen', False):
            input("\nPress Enter to exit...")
        sys.exit(1)

    args = parser.parse_args()

    # Validate modes and options
    if not args.server and not args.client and not args.traceroute:
        print("Error: You must specify a mode: -s, -c <host>, or --traceroute <host>", file=sys.stderr)
        sys.exit(1)

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
        except (ValueError, TypeError):
            print("Error: Invalid format for --bytes. Use a number with an optional K, M, or G suffix.", file=sys.stderr)
            sys.exit(1)
    
    # Set default test duration if not specified for client tests
    if args.client and not args.reverse_traceroute:
        if not args.bytes and not args.time:
            args.time = 10
    
    if args.reverse_traceroute and not args.client:
        print("Error: --reverse-traceroute must be used with -c <server_address>.", file=sys.stderr)
        sys.exit(1)
    
    if args.reverse and args.bidir:
        print("Error: Cannot use --reverse and --bidir at the same time.", file=sys.stderr)
        sys.exit(1)

    if args.server:
        # 在服务端模式下，我们监听所有接口
        host = '0.0.0.0'
        asyncio.run(start_server(host, args.port, args))
    elif args.client:
        uri = f"ws://{args.client}:{args.port}"
        asyncio.run(start_client(uri, args))
    elif args.traceroute:
        # 本地路由追踪现在也使用新的格式化逻辑
        async def run_and_print_traceroute():
            try:
                dest_addr = socket.gethostbyname(args.traceroute)
                print(f"traceroute to {args.traceroute} ({dest_addr}), {args.tr_max_hops} hops max")
                async for hop in run_traceroute(args.traceroute, args.tr_max_hops, args.tr_timeout):
                    if hop.get('error'):
                        print(f"Error at TTL {hop['ttl']}: {hop['error']}")
                        break
                    if hop['ip'] == '*':
                        print(f"{hop['ttl']:<2} * * *")
                    else:
                        geo_info = f"[{hop['country']}, {hop['asn']}]" if hop['country'] and hop['asn'] else ""
                        print(f"{hop['ttl']:<2} {geo_info:<25} {hop['name']} ({hop['ip']}) {hop['rtt']:.3f} ms")
            except (PermissionError, ValueError, IOError) as e:
                print(f"Error: {e}")

        asyncio.run(run_and_print_traceroute())

if __name__ == "__main__":
    main()