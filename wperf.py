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
import random


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

def calculate_checksum(source_string):
    """计算给定字节串的IP校验和"""
    countTo = (len(source_string) // 2) * 2
    sum = 0
    count = 0
    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff 
        count = count + 2
    if countTo < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff 
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


async def _probe_hop(dest_addr, ttl, timeout, proto):
    """执行单跳的探测"""
    hop_data = {"ttl": ttl, "ip": "*", "name": "*", "rtt": -1, "country": "", "asn": ""}
    curr_addr = None
    icmp = socket.getprotobyname('icmp')

    try:
        if proto == 'icmp':
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                sock.settimeout(timeout)
                packet_id = os.getpid() & 0xFFFF
                seq = ttl
                header = struct.pack("!BBHHH", 8, 0, 0, packet_id, seq)
                data = b'wperf_icmp_probe'
                my_checksum = calculate_checksum(header + data)
                header = struct.pack("!BBHHH", 8, 0, my_checksum, packet_id, seq)
                packet = header + data
                start_time = time.time()
                sock.sendto(packet, (dest_addr, 0))
                raw_packet, curr_addr_tuple = sock.recvfrom(65535)
                end_time = time.time()
                curr_addr = curr_addr_tuple[0]
        else: # udp
            udp = socket.getprotobyname('udp')
            port = 33434
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as recv_socket, \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp) as send_socket:
                recv_socket.settimeout(timeout)
                send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                if sys.platform == "win32":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.connect((dest_addr, port))
                        local_ip = s.getsockname()[0]
                    recv_socket.bind((local_ip, 0))
                    recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                else:
                    recv_socket.bind(("", port))
                
                start_time = time.time()
                send_socket.sendto(b'', (dest_addr, port))
                _, curr_addr_tuple = recv_socket.recvfrom(65535)
                end_time = time.time()
                curr_addr = curr_addr_tuple[0]
                if sys.platform == "win32":
                    recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        hop_data["ip"] = curr_addr
        hop_data["rtt"] = (end_time - start_time) * 1000
        try:
            hop_data["name"] = socket.gethostbyaddr(curr_addr)[0]
        except socket.herror:
            hop_data["name"] = curr_addr
        
        country, asn = await get_geoip_info(curr_addr)
        hop_data["country"] = country
        hop_data["asn"] = asn

    except (socket.timeout, IOError):
        pass # Keep hop_data as is (ip='*')
    except Exception as e:
        # In parallel mode, we don't want one error to stop everything.
        # Log it or store it in hop_data if needed.
        print(f"Error probing TTL {ttl}: {e}", file=sys.stderr)

    return hop_data

async def _run_traceroute_sequential(dest_addr, max_hops, timeout, proto):
    """按顺序执行路由追踪"""
    for ttl in range(1, max_hops + 1):
        hop_data = await _probe_hop(dest_addr, ttl, timeout, proto)
        yield hop_data
        if hop_data["ip"] == dest_addr:
            break

async def _run_traceroute_parallel(dest_addr, max_hops, timeout, proto):
    """并行执行路由追踪"""
    tasks = [_probe_hop(dest_addr, ttl, timeout, proto) for ttl in range(1, max_hops + 1)]
    results = await asyncio.gather(*tasks)
    
    # Sort by TTL just in case gather doesn't preserve order
    results.sort(key=lambda h: h['ttl'])
    
    for hop_data in results:
        yield hop_data
        if hop_data["ip"] == dest_addr:
            # In parallel mode, we've already done all the work,
            # but we can stop yielding if we've hit the destination.
            break

async def run_traceroute(host, max_hops, timeout, proto, parallel):
    """
    执行路由追踪。这是一个异步生成器，会为每一跳产出一个结果字典。
    如果权限不足或设置失败，会引发异常。
    """
    if parallel and proto == 'udp' and sys.platform == 'win32':
        print("Warning: Parallel UDP traceroute is not supported on Windows due to OS limitations. Falling back to sequential mode.", file=sys.stderr)
        parallel = False
        
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

    if parallel:
        async for hop in _run_traceroute_parallel(dest_addr, max_hops, timeout, proto):
            yield hop
    else:
        async for hop in _run_traceroute_sequential(dest_addr, max_hops, timeout, proto):
            yield hop


async def server_handler(websocket, args):
    """处理单个客户端连接。"""
    print(f"Client connected from {websocket.remote_address}")
    
    # --- Default values ---
    mode = "upload" # Default mode for legacy clients
    simulation_options = {}

    # --- Nested Coroutines ---

    async def sender(duration, sim_opts):
        """
        服务端发送器，用于反向和双向模式。
        实现了发送缓冲区和Nagle算法模拟。
        """
        # 从客户端配置中获取模拟选项
        sim_mtu = sim_opts.get('sim_mtu')
        sim_latency = sim_opts.get('sim_latency')
        sim_jitter = sim_opts.get('sim_jitter')
        sim_sndbuf = sim_opts.get('sim_sndbuf')
        sim_tcp_nodelay = sim_opts.get('sim_tcp_nodelay', False)
        sim_loss = sim_opts.get('sim_loss')

        chunk_size = sim_mtu if sim_mtu else 65536
        chunk = b'\0' * chunk_size
        seq_num = 0

        # 根据 --sim-sndbuf 设置队列大小，模拟发送缓冲区
        # 如果未设置，提供一个合理的默认值 (128) 以防止无限缓冲。
        queue_maxsize = (sim_sndbuf // chunk_size) if sim_sndbuf else 128
        data_queue = asyncio.Queue(maxsize=queue_maxsize)

        # --- 数据发送协程 (消费者) ---
        async def sending_coroutine():
            nonlocal seq_num
            # Nagle 算法模拟 (如果 sim_tcp_nodelay 为 False)
            if not sim_tcp_nodelay:
                buffer = bytearray()
                nagle_timeout = 0.2  # 200ms
                while True:
                    try:
                        data = await asyncio.wait_for(data_queue.get(), timeout=nagle_timeout)
                        if data is None:  # 收到结束信号
                            if buffer:
                                await websocket.send(buffer)
                            break
                        
                        buffer.extend(data)
                        if len(buffer) >= chunk_size:
                            await websocket.send(buffer)
                            buffer.clear()
                    
                    except asyncio.TimeoutError:
                        if buffer:
                            await websocket.send(buffer)
                            buffer.clear()
                    except websockets.exceptions.ConnectionClosed:
                        break
            # TCP_NODELAY 模拟 (立即发送)
            else:
                while True:
                    try:
                        data = await data_queue.get()
                        if data is None:
                            break
                        
                        # 模拟丢包
                        if sim_loss and random.random() * 100 < sim_loss:
                            # 丢包，但序列号仍然增加
                            pass
                        else:
                            await websocket.send(data)

                    except websockets.exceptions.ConnectionClosed:
                        break
            
            while not data_queue.empty():
                data_queue.get_nowait()

        # --- 数据生成循环 (生产者) ---
        async def producing_coroutine():
            nonlocal seq_num
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    # 模拟延迟和抖动
                    if sim_latency is not None:
                        delay_ms = sim_latency
                        if sim_jitter is not None:
                            delay_ms += random.uniform(-sim_jitter, sim_jitter)
                        
                        # 确保延迟不为负
                        if delay_ms > 0:
                            await asyncio.sleep(delay_ms / 1000.0)
                    
                    # 包装数据和序列号
                    data_to_send = struct.pack('>Q', seq_num) + chunk
                    seq_num += 1
                    await data_queue.put(data_to_send)
                except websockets.exceptions.ConnectionClosed:
                    break
            await data_queue.put(None)

        # 启动生产者和消费者
        sender_task = asyncio.create_task(sending_coroutine())
        producer_task = asyncio.create_task(producing_coroutine())
        await asyncio.gather(sender_task, producer_task)
        
        try:
            await websocket.send("EOT_S") # End of Transmission from Server
        except websockets.exceptions.ConnectionClosed:
            pass

    async def receiver(sim_opts):
        """
        服务端接收器，用于上传和双向模式。
        实现了接收缓冲区和丢包检测模拟。
        """
        sim_rcvbuf = sim_opts.get('sim_rcvbuf')
        sim_loss = sim_opts.get('sim_loss')
        expected_seq_num = 0
        
        async def process_message(message):
            nonlocal expected_seq_num
            if message == "EOT_C":
                return False

            if sim_loss is not None:
                try:
                    seq_num = struct.unpack('>Q', message[:8])[0]
                    # data = message[8:] # 在服务端，我们不关心数据内容
                    if seq_num > expected_seq_num:
                        # 服务端不记录丢包，只调整期望的序列号
                        expected_seq_num = seq_num
                    expected_seq_num += 1
                except struct.error:
                    print("Warning: Received a malformed packet on server.", file=sys.stderr)
            return True

        if not sim_rcvbuf:
            # 无模拟：直接从websocket读取
            async for message in websocket:
                if not await process_message(message):
                    break
        else:
            # 接收缓冲区模拟
            chunk_size = 65536 # 假设与客户端块大小一致
            queue_maxsize = (sim_rcvbuf // chunk_size) if sim_rcvbuf else 0
            data_queue = asyncio.Queue(maxsize=queue_maxsize)
            
            # 从websocket读取并放入队列的协程
            async def socket_reader():
                try:
                    async for message in websocket:
                        await data_queue.put(message)
                        if message == "EOT_C":
                            break
                except websockets.exceptions.ConnectionClosed:
                    # 确保消费者可以退出
                    await data_queue.put("EOT_C")
            
            reader_task = asyncio.create_task(socket_reader())
            
            # 从队列中获取数据进行处理
            while True:
                message = await data_queue.get()
                if not await process_message(message):
                    break
            
            await reader_task # 等待reader任务结束

    try:
        # Authentication
        if args.token:
            client_token = await websocket.recv()
            if client_token != args.token:
                print(f"Authentication failed for {websocket.remote_address}. Closing connection.")
                await websocket.close(code=1008, reason="Invalid token")
                return

        initial_message = await websocket.recv()

        # 首先尝试解析为JSON
        try:
            command_data = json.loads(initial_message)
            
            # --- 新版客户端测试配置 ---
            if isinstance(command_data, dict) and 'mode' in command_data:
                mode = command_data.get('mode')
                simulation_options = command_data.get('simulation_options', {})
                print(f"Received test setup from {websocket.remote_address}: mode={mode}, sim_options={simulation_options}")
            
            # --- 其他JSON命令 (如路由追踪, ping) ---
            elif isinstance(command_data, dict) and command_data.get('command') == 'reverse_traceroute':
                client_ip = websocket.remote_address[0]
                print(f"Starting reverse traceroute for {client_ip}")
                try:
                    async for hop in run_traceroute(client_ip, args.tr_max_hops, args.tr_timeout, args.tr_proto, args.tr_parallel):
                        await websocket.send(json.dumps({"type": "hop", "data": hop}))
                except (PermissionError, ValueError, IOError) as e:
                    await websocket.send(json.dumps({"type": "error", "message": str(e)}))
                except Exception as e:
                    await websocket.send(json.dumps({"type": "error", "message": f"An unexpected error occurred: {e}"}))
                finally:
                    await websocket.send(json.dumps({"type": "end"}))
                return
            elif isinstance(command_data, dict) and command_data.get('command') == 'ping':
                print(f"Starting latency test for {websocket.remote_address}")
                try:
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            if data.get('type') == 'ping':
                                await websocket.send(json.dumps({"type": "pong", "seq": data.get('seq')}))
                        except json.JSONDecodeError:
                            pass
                except websockets.exceptions.ConnectionClosed:
                    pass
                finally:
                    print(f"Latency test finished for {websocket.remote_address}")
                return
            
        except (json.JSONDecodeError, TypeError):
            # --- 旧版客户端兼容逻辑 ---
            mode = initial_message
            print(f"Received legacy command from {websocket.remote_address}: {mode}")

        # --- 根据模式执行测试 ---
        duration = args.time or 10
        
        if mode == "bidir" or mode == "BIDIR":
            print(f"Starting bidirectional test for {websocket.remote_address}")
            sender_task = asyncio.create_task(sender(duration, simulation_options))
            receiver_task = asyncio.create_task(receiver(simulation_options))
            await asyncio.gather(sender_task, receiver_task)
            print(f"Bidirectional test finished for {websocket.remote_address}")

        elif mode == "reverse" or mode == "REVERSE":
            print(f"Starting reverse test for {websocket.remote_address}")
            await sender(duration, simulation_options)
            print(f"Reverse test finished for {websocket.remote_address}")

        elif mode == "upload" or mode == "UPLOAD":
            print(f"Starting upload test for {websocket.remote_address}")
            await receiver(simulation_options)
            print(f"Upload test finished for {websocket.remote_address}")
        
        elif mode == "UDP": # UDP模式保持独立，因为它不使用这里的sender/receiver
            print(f"Starting UDP test for {websocket.remote_address}")
            jitter = 0
            last_transit_time = -1
            last_seq = -1
            lost_packets = 0
            total_packets = 0
            start_time = time.time()
            while time.time() - start_time < duration + 2:
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
            report = {"jitter_ms": jitter_ms, "lost_packets": lost_packets, "total_packets": total_packets, "loss_percent": loss_percent}
            await websocket.send(json.dumps(report))
            print(f"UDP test finished for {websocket.remote_address}: Jitter={jitter_ms:.3f}ms, Lost={lost_packets}/{last_seq + 1} ({loss_percent:.2f}%)")
        
        else: # 默认处理未知命令，视为上传
            print(f"Unknown command '{mode}', defaulting to upload test for {websocket.remote_address}")
            await receiver(simulation_options)
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

        # 显示模拟参数
        sim_params = []
        if args.sim_mtu:
            sim_params.append(f"  MTU: {args.sim_mtu} bytes")
        if args.sim_latency is not None:
            sim_params.append(f"  Latency: {args.sim_latency} ms")
        if args.sim_jitter is not None:
            sim_params.append(f"  Jitter: {args.sim_jitter} ms")
        
        if sim_params:
            print("\nSimulation Parameters:")
            for param in sim_params:
                print(param)
            print("-" * 40)
        
        # 显示丢包模拟结果
        if args.sim_loss is not None:
            total_sent = sum(stats['total_sent_packets'])
            total_lost = sum(stats['lost_packets'])
            actual_loss_rate = (total_lost / total_sent) * 100 if total_sent > 0 else 0
            print("\nPacket Loss Simulation:")
            print(f"  Configured Loss Rate: {args.sim_loss:.2f}%")
            print(f"  Total Packets Sent: {total_sent}")
            print(f"  Total Packets Lost: {total_lost}")
            print(f"  Actual Loss Rate: {actual_loss_rate:.2f}%")
            print("-" * 40)


async def client_worker(worker_id, uri, args, stats):
    """单个客户端工作流，负责一个连接"""
    
    async def sender(websocket):
        # 模拟MTU
        chunk_size = args.sim_mtu if args.sim_mtu else 65536
        chunk = b'\0' * chunk_size
        seq_num = 0
        
        # 根据 --sim-sndbuf 设置队列大小，模拟发送缓冲区
        # 如果未设置，队列大小为0（无限），不产生背压
        # 设置一个默认值 (128) 以防止在接收端限速时，发送队列无限增长导致假死。
        queue_maxsize = (args.sim_sndbuf // chunk_size) if args.sim_sndbuf else 128
        data_queue = asyncio.Queue(maxsize=queue_maxsize)

        # --- 数据发送协程 (消费者) ---
        async def sending_coroutine():
            # Nagle 算法模拟 (如果 --sim-tcp-nodelay 未设置)
            if not args.sim_tcp_nodelay:
                buffer = bytearray()
                nagle_timeout = 0.2  # 200ms
                while True:
                    try:
                        # 等待数据，但有超时
                        data = await asyncio.wait_for(data_queue.get(), timeout=nagle_timeout)
                        if data is None:  # 收到结束信号
                            if buffer:
                                await websocket.send(buffer)
                            break
                        
                        buffer.extend(data)
                        if len(buffer) >= chunk_size:
                            await websocket.send(buffer)
                            buffer.clear()
                    
                    except asyncio.TimeoutError:
                        # 超时，发送缓冲区中的任何数据
                        if buffer:
                            await websocket.send(buffer)
                            buffer.clear()
                    except websockets.exceptions.ConnectionClosed:
                        break
            # TCP_NODELAY 模拟 (立即发送)
            else:
                while True:
                    try:
                        data = await data_queue.get()
                        if data is None:
                            break
                        await websocket.send(data)
                    except websockets.exceptions.ConnectionClosed:
                        break
            
            # 确保队列被完全清空，以防生产者仍在等待
            while not data_queue.empty():
                data_queue.get_nowait()

        # --- 数据生成循环 (生产者) ---
        async def producing_coroutine():
            nonlocal seq_num
            start_time = time.time()
            bytes_to_send = args.bytes / args.parallel if args.bytes else None
            
            while True:
                if bytes_to_send and stats['bytes_uploaded'][worker_id] >= bytes_to_send:
                    break
                if not bytes_to_send and args.time and time.time() - start_time >= args.time:
                    break
                
                try:
                    # 模拟延迟和抖动
                    if args.sim_latency is not None:
                        delay_ms = args.sim_latency
                        if args.sim_jitter is not None:
                            delay_ms += random.uniform(-args.sim_jitter, args.sim_jitter)
                        
                        # 确保延迟不为负
                        if delay_ms > 0:
                            await asyncio.sleep(delay_ms / 1000.0)

                    # 包装数据和序列号
                    data_with_seq = struct.pack('>Q', seq_num) + chunk
                    stats['total_sent_packets'][worker_id] += 1
                    seq_num += 1

                    # 模拟丢包
                    if args.sim_loss and random.random() * 100 < args.sim_loss:
                        # 丢包，不发送，但计数器已增加
                        stats['bytes_uploaded'][worker_id] += len(chunk) # 仍然计算为已上传
                        continue

                    await data_queue.put(data_with_seq)
                    stats['bytes_uploaded'][worker_id] += len(chunk)
                except websockets.exceptions.ConnectionClosed:
                    break
            
            # 发送结束信号
            await data_queue.put(None)

        # 启动生产者和消费者
        sender_task = asyncio.create_task(sending_coroutine())
        producer_task = asyncio.create_task(producing_coroutine())
        await asyncio.gather(sender_task, producer_task)
        
        # 在所有数据发送后发送 EOT
        try:
            await websocket.send("EOT_C")
        except websockets.exceptions.ConnectionClosed:
            pass


    async def receiver(websocket):
        bytes_to_receive = args.bytes / args.parallel if args.bytes else None
        start_time = time.time()
        expected_seq_num = 0

        while bytes_to_receive is None or stats['bytes_downloaded'][worker_id] < bytes_to_receive:
            try:
                message = await websocket.recv()
                if message == "EOT_S":
                    break
                
                # 如果启用了丢包模拟，则解析序列号
                if args.sim_loss is not None:
                    try:
                        seq_num = struct.unpack('>Q', message[:8])[0]
                        data = message[8:]
                        
                        if seq_num > expected_seq_num:
                            stats['lost_packets'][worker_id] += seq_num - expected_seq_num
                        
                        expected_seq_num = seq_num + 1
                        stats['bytes_downloaded'][worker_id] += len(data)

                    except struct.error:
                        # 收到格式不正确的数据包，可能来自不支持序列号的旧版服务器
                        stats['bytes_downloaded'][worker_id] += len(message)
                else:
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

            # 构造并发送包含测试模式和模拟选项的JSON对象
            test_config = {
                "simulation_options": {
                    "sim_tcp_nodelay": args.sim_tcp_nodelay,
                    "sim_sndbuf": args.sim_sndbuf,
                    "sim_rcvbuf": args.sim_rcvbuf,
                    "sim_mtu": args.sim_mtu,
                    "sim_latency": args.sim_latency,
                    "sim_jitter": args.sim_jitter,
                    "sim_loss": args.sim_loss,
                }
            }

            if args.bidir:
                test_config["mode"] = "bidir"
                await websocket.send(json.dumps(test_config))
                sender_task = asyncio.create_task(sender(websocket))
                receiver_task = asyncio.create_task(receiver(websocket))
                await asyncio.gather(sender_task, receiver_task)

            elif args.udp:
                # UDP模式保持原有逻辑，不发送JSON配置
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
                test_config["mode"] = "reverse"
                await websocket.send(json.dumps(test_config))
                await receiver(websocket)
            else: # TCP Upload
                test_config["mode"] = "upload"
                await websocket.send(json.dumps(test_config))
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


async def run_ping_client(uri, args):
    """客户端执行延迟测试 (ping) 的逻辑"""
    print(f"Pinging {args.client} with {args.ping_count} packets.")
    rtts = []
    lost_packets = 0
    
    try:
        async with websockets.connect(uri) as websocket:
            if args.token:
                await websocket.send(args.token)
            
            await websocket.send(json.dumps({"command": "ping"}))
            
            for seq in range(args.ping_count):
                send_time_ns = time.time_ns()
                try:
                    await websocket.send(json.dumps({"type": "ping", "seq": seq}))
                    # Wait for pong with a timeout
                    response_str = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    recv_time_ns = time.time_ns()
                    
                    response = json.loads(response_str)
                    if response.get('type') == 'pong' and response.get('seq') == seq:
                        rtt_ms = (recv_time_ns - send_time_ns) / 1_000_000
                        rtts.append(rtt_ms)
                        print(f"Pong from {args.client}: seq={seq} time={rtt_ms:.3f} ms")
                    else:
                        lost_packets += 1
                        print(f"Unexpected response for seq={seq}: {response}")

                except asyncio.TimeoutError:
                    lost_packets += 1
                    print(f"Request timed out for seq={seq}")
                except (websockets.exceptions.ConnectionClosed, json.JSONDecodeError) as e:
                    print(f"Connection error during ping: {e}")
                    lost_packets += (args.ping_count - seq)
                    break
                
                if seq < args.ping_count - 1:
                    await asyncio.sleep(1) # Wait 1 second between pings

            # Print summary
            print("\n--- ping statistics ---")
            print(f"{args.ping_count} packets transmitted, {args.ping_count - lost_packets} received, {lost_packets / args.ping_count * 100:.1f}% packet loss")
            if rtts:
                min_rtt = min(rtts)
                avg_rtt = sum(rtts) / len(rtts)
                max_rtt = max(rtts)
                print(f"rtt min/avg/max = {min_rtt:.3f}/{avg_rtt:.3f}/{max_rtt:.3f} ms")

    except Exception as e:
        print(f"Connection error: {e}")


async def start_client(uri, args):
    """启动wperf客户端并协调所有工作流"""
    if args.reverse_traceroute:
        await run_reverse_traceroute_client(uri, args)
        return

    if args.ping:
        await run_ping_client(uri, args)
        return

    if not args.json:
        print(f"Connecting to wperf server at {uri}, running {args.parallel} parallel streams")
    
    start_time = time.time()
    # Shared state for all workers and the reporter
    stats = {
        'bytes_uploaded': [0] * args.parallel,
        'bytes_downloaded': [0] * args.parallel,
        'lost_packets': [0] * args.parallel,
        'total_sent_packets': [0] * args.parallel,
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
  
  # Run a latency (ping) test
  {prog_name} -c <server_ip> --ping
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
    client_group.add_argument("--ping", action="store_true", help="Run a latency test (ping). Incompatible with other test types.")
    client_group.add_argument("--ping-count", type=int, default=10, metavar='<n>', help="Number of pings to send. Default: 10.")
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
    traceroute_group.add_argument("--tr-proto", type=str, default='udp', choices=['udp', 'icmp'], help="Protocol to use for traceroute probes. Default: udp.")
    traceroute_group.add_argument("--tr-parallel", action="store_true", help="Run traceroute probes in parallel to speed up the process.")

    # Simulation options
    sim_group = parser.add_argument_group('Simulation Options', 'Parameters for simulating network kernel options at the application layer')
    sim_group.add_argument("--sim-tcp-nodelay", action="store_true", help="Simulate disabling Nagle's algorithm (TCP_NODELAY=1).")
    sim_group.add_argument("--sim-sndbuf", type=str, metavar='<size>', help="Simulate the size of the TCP send buffer (SO_SNDBUF).")
    sim_group.add_argument("--sim-rcvbuf", type=str, metavar='<size>', help="Simulate the size of the TCP receive buffer (SO_RCVBUF).")
    sim_group.add_argument("--sim-mtu", type=str, metavar='<size>', help="Simulate Maximum Transmission Unit (MTU). Sets the max data size per send call.")
    sim_group.add_argument("--sim-latency", type=int, metavar='<ms>', help="Simulate a fixed network latency in milliseconds.")
    sim_group.add_argument("--sim-jitter", type=int, metavar='<ms>', help="Simulate network jitter in milliseconds. Actual latency will fluctuate around the base latency.")
    sim_group.add_argument("--sim-loss", type=float, metavar='<rate>', help="Simulate packet loss rate (0.0 to 100.0).")

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

    def size_to_bytes(size_str):
        """Helper to parse size strings like '10K', '1M'."""
        if not size_str:
            return None
        size_str = str(size_str).upper()
        try:
            if size_str.endswith('K'):
                return int(size_str[:-1]) * 1024
            elif size_str.endswith('M'):
                return int(size_str[:-1]) * 1024 * 1024
            elif size_str.endswith('G'):
                return int(size_str[:-1]) * 1024 * 1024 * 1024
            else:
                return int(size_str)
        except (ValueError, TypeError):
            return None

    if args.bytes:
        args.time = None # -n overrides -t
        parsed_size = size_to_bytes(args.bytes)
        if parsed_size is None:
            print("Error: Invalid format for --bytes. Use a number with an optional K, M, or G suffix.", file=sys.stderr)
            sys.exit(1)
        args.bytes = parsed_size

    if args.sim_sndbuf:
        parsed_size = size_to_bytes(args.sim_sndbuf)
        if parsed_size is None:
            print("Error: Invalid format for --sim-sndbuf. Use a number with an optional K, M, or G suffix.", file=sys.stderr)
            sys.exit(1)
        args.sim_sndbuf = parsed_size

    if args.sim_rcvbuf:
        parsed_size = size_to_bytes(args.sim_rcvbuf)
        if parsed_size is None:
            print("Error: Invalid format for --sim-rcvbuf. Use a number with an optional K, M, or G suffix.", file=sys.stderr)
            sys.exit(1)
        args.sim_rcvbuf = parsed_size
    
    if args.sim_mtu:
        parsed_size = size_to_bytes(args.sim_mtu)
        if parsed_size is None:
            print("Error: Invalid format for --sim-mtu. Use a number with an optional K, M, or G suffix.", file=sys.stderr)
            sys.exit(1)
        args.sim_mtu = parsed_size

    if args.sim_loss is not None:
        if not 0.0 <= args.sim_loss <= 100.0:
            print("Error: --sim-loss rate must be between 0.0 and 100.0.", file=sys.stderr)
            sys.exit(1)
    
    if args.ping:
        if args.reverse or args.bidir or args.udp or args.bytes or args.time:
             print("Error: --ping cannot be used with other test types (-R, --bidir, --udp, -n, -t).", file=sys.stderr)
             sys.exit(1)

    # Set default test duration if not specified for client tests
    if args.client and not args.reverse_traceroute and not args.ping:
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
                async for hop in run_traceroute(args.traceroute, args.tr_max_hops, args.tr_timeout, args.tr_proto, args.tr_parallel):
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