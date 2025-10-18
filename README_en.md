# wperf - WebSocket Network Performance Testing Tool
<img width="512" height="256" alt="wperf_card" src="https://github.com/user-attachments/assets/4108034c-9ff4-4a35-9169-4c30a3e10fea" />

[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

wperf is a WebSocket-based network performance testing tool with the core advantage of easily traversing NAT and firewall environments. It is similar to iperf3 and is used to measure network bandwidth, latency, jitter, and packet loss.

## Features

- 🌐 **NAT Traversal** - Based on WebSocket, it can easily traverse complex network environments and firewalls.
- 🚀 **TCP Bandwidth Testing** - Measure upload and download bandwidth
- 🔄 **Bidirectional Testing** - Perform upload and download tests simultaneously
- ⏱️ **End-to-end Latency Test (Ping)** - Measure WebSocket-based round-trip time (RTT)
- 📊 **UDP Simulation** - Measure jitter and packet loss
- 📍 **Traceroute** - Support for local, reverse, ICMP/UDP probes, and parallel probing
- 🌍 **GeoIP Information** - Display ASN and country/region information for each hop in traceroute
- 🔒 **Authentication** - Support token authentication
- 📈 **Real-time Reporting** - Periodically output test progress
- 🔢 **Parallel Connections** - Support multiple parallel connections to improve test accuracy
- 📄 **JSON Output** - Support machine-readable JSON format output
- ⚡ **High Performance Asynchronous** - Based on asyncio and websockets library
- 🔬 **Network Behavior Simulation** - Simulate network characteristics like MTU, latency, jitter, packet loss, buffers, and Nagle's algorithm at the application layer.

#### TODO List

- [ ] Simultaneous testing against multiple servers with a unified comparison report.
- [ ] More realistic simulation of packet loss and CWND (Congestion Window) behavior.
- [ ] Performance simulation for different types of data traffic (e.g., video streaming, small interactive packets).
- [ ] More and more...


## Installation

### Requirements

- Python 3.7 or higher
- websockets library

### Installation Steps

1. Clone or download this project:
```bash
git clone <repository-url>
cd wperf
```

2. Install dependencies:
```bash
pip install websockets
```

Or use requirements.txt:
```bash
pip install -r requirements.txt
```

## Quick Start

### Start Server

Run on the server:

```bash
wperf -s
```

By default, it listens on port 8765. You can specify another port using the `-p` parameter:

```bash
wperf -s -p 9000
```

### Run Client Test

Run a basic upload test on the client:

```bash
wperf -c <server-ip> -t 10
```

## Usage

### Command Line Arguments

#### General Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-s, --server` | Run in server mode | - |
| `-c, --client <host>` | Run in client mode, connect to the specified server | - |
| `-p, --port <port>` | Port number to listen on or connect to | 8765 |
| `--token <token>` | Authentication token | None |
| `-i, --interval <sec>` | Interval time for reporting bandwidth (seconds) | 1 |
| `-t, --time <sec>` | Test duration (seconds) | 10 |
| `-n, --bytes <size>` | Number of bytes to transfer (e.g.: 10M, 1G) | - |

#### Client-only Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-R, --reverse` | Reverse mode (server sends, client receives) | false |
| `--bidir` | Bidirectional test (send and receive simultaneously) | false |
| `-P, --parallel <n>` | Number of parallel client streams | 1 |
| `-J, --json` | Output results in JSON format | false |
| `--udp` | Simulate UDP traffic and measure jitter/packet loss | false |
| `-b, --bandwidth <mbps>` | Target bandwidth (Mbps, for UDP mode) | 1 |
| `--ping` | **Client only**. Run an end-to-end latency test (ping). | false |
| `--ping-count <n>` | Number of packets to send for the ping test. | 5 |

#### Traceroute Parameters

> **Note**: The traceroute function requires administrator or root privileges to run.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--traceroute <host>` | Run in standalone traceroute mode, trace to the specified host | - |
| `--reverse-traceroute` | **Client only**. Request the server to perform a reverse traceroute to the current client. Must be used with `-c`. | false |
| `--tr-max-hops <n>` | Maximum number of hops for traceroute | 30 |
| `--tr-timeout <sec>` | Timeout for each hop (seconds) | 1 |
| `--tr-proto <proto>` | Protocol to use for traceroute probes (`udp` or `icmp`). | `udp` |
| `--tr-parallel` | Run traceroute probes in parallel to speed up the process. | false |

#### Network Behavior Simulation Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--sim-mtu <size>` | Simulate Maximum Transmission Unit (MTU). | Not set |
| `--sim-latency <ms>` | Simulate a fixed network latency. | 0 |
| `--sim-jitter <ms>` | Simulate network jitter (latency variation). | 0 |
| `--sim-loss <rate>` | Simulate packet loss rate (0-100). | 0 |
| `--sim-tcp-nodelay` | Simulates disabling the Nagle algorithm (TCP_NODELAY=1), sending small packets immediately. | false |
| `--sim-sndbuf <size>` | Simulates the size of the TCP send buffer (SO_SNDBUF). E.g., `128K`, `1M`. | System Default |
| `--sim-rcvbuf <size>` | Simulates the size of the TCP receive buffer (SO_RCVBUF). | System Default |

### Usage Examples

> **Note**: The following examples uniformly use `wperf` as the command name. If you run the Python script directly, replace it with `wperf`. If you are using a compiled executable, use the appropriate executable name (e.g., `wperf` or `wperf.exe`).

#### 1. TCP Upload Test (Client to Server)

Test upload speed for 10 seconds:

```bash
# Server
wperf -s

# Client
wperf -c 192.168.1.100 -t 10
```

#### 2. TCP Download Test (Server to Client)

Use the `-R` parameter for reverse testing:

```bash
# Client
wperf -c 192.168.1.100 -t 10 -R
```

#### 3. Bidirectional Test

Test upload and download simultaneously:

```bash
# Client
wperf -c 192.168.1.100 -t 10 --bidir
```

#### 4. UDP Simulation Test

Measure jitter and packet loss:

```bash
# Client
wperf -c 192.168.1.100 -t 10 --udp -b 10
```

This command will send simulated UDP packets at a target bandwidth of 10 Mbps.

#### 5. Parallel Connection Test

Test using 4 parallel connections:

```bash
# Client
wperf -c 192.168.1.100 -t 10 -P 4
```

#### 6. Transfer Specified Number of Bytes

Transfer 100MB of data:

```bash
# Client
wperf -c 192.168.1.100 -n 100M
```

Supported units: K (kilobytes), M (megabytes), G (gigabytes)

#### 7. JSON Format Output

Output results in JSON format for easier script processing:

```bash
# Client
wperf -c 192.168.1.100 -t 10 -J
```

#### 8. Using Authentication

Both server and client need to configure the same token:

```bash
# Server
wperf -s --token mySecretToken

# Client
wperf -c 192.168.1.100 -t 10 --token mySecretToken
```

#### 9. Custom Port

Use a non-default port:

```bash
# Server
wperf -s -p 9000

# Client
wperf -c 192.168.1.100 -p 9000 -t 10
```

#### 10. Local Traceroute

Trace the network path to `google.com`. This mode runs independently and does not require connecting to a `wperf` server.

```bash
# Requires administrator/root privileges
sudo wperf --traceroute google.com --tr-proto icmp --tr-parallel
```

Example output:
```
traceroute to google.com (142.250.199.14), 30 hops max
1  [US, AS15169 GOOGLE]    192.168.1.1 (192.168.1.1) 1.234 ms
2  * * *
3  [US, AS7922 COMCAST]   some.router.com (96.120.88.193) 9.876 ms
...
12 [US, AS15169 GOOGLE]   142.250.199.14 (142.250.199.14) 15.432 ms
```

#### 11. End-to-end Latency Test (Ping)

Measure the round-trip latency between the client and server.

```bash
# Client
wperf -c 192.168.1.100 --ping --ping-count 10
```
Example output:
```
Pinging 192.168.1.100:8765...
seq=0, rtt=12.34 ms
seq=1, rtt=11.98 ms
...
--- statistics ---
10 packets transmitted, 10 received, 0% packet loss
rtt min/avg/max = 11.98/12.15/12.45 ms
```

#### 12. Reverse Traceroute (Server to Client)

Diagnose the network path from server to client. The client connects to the server and initiates the request.

```bash
# Client (requires administrator/root privileges)
sudo wperf -c 192.168.1.100 --reverse-traceroute
```
The server will execute traceroute to the client's public IP and stream the results back to the client in real-time for display.

#### 13. Using Network Behavior Simulation

```bash
# Test with a small simulated send buffer and disabled Nagle algorithm
wperf -c <server-ip> -t 10 --sim-sndbuf 128K --sim-tcp-nodelay
```

#### 14. Comprehensive Network Simulation Example

Simulate a link with high latency, jitter, some packet loss, and a restricted MTU.

```bash
# Simulate a link with high latency, jitter, and slight packet loss, while limiting MTU
wperf -c <server-ip> -t 10 --sim-latency 200 --sim-jitter 30 --sim-loss 1.5 --sim-mtu 1400
```

## Output Explanation

### TCP Test Output

Example text mode output:

```
------------------------------------------------------------
Interval        Transfer        Bandwidth
[SUM]   [sec]           [MBytes]        [Mbits/sec]
------------------------------------------------------------
[SUM]   0.0-1.0         11.23           94.56
[SUM]   1.0-2.0         12.05           101.23
[SUM]   2.0-3.0         11.89           99.87
...
------------------------------------------------------------
[SUM]   0.0-10.0        115.67          97.25
------------------------------------------------------------
```

### UDP Test Output

UDP mode output example:

```
----------------------------------------
Jitter: 2.345 ms
Lost/Total: 15/10000 (0.15%)
----------------------------------------
```

### Sample Report Output (with Network Simulation)

When network simulation is enabled, the final report will include a dedicated section to display the parameters and resulting statistics, such as packet loss.

```
... (Original report content) ...

Simulation Parameters:
  MTU: 1400 bytes
  Latency: 200 ms
  Jitter: 30 ms

Packet Loss Simulation:
  Configured Loss Rate: 1.50%
  Total Packets Sent: 15231
  Total Packets Lost: 228
  Actual Loss Rate: 1.50%
```

### JSON Output Format

JSON output contains detailed test information:

```json
{
    "start": {
        "timestamp": {
            "time": "2024-01-01 12:00:00 UTC",
            "timesecs": 1704110400.0
        },
        "connecting_to": {
            "host": "192.168.1.100",
            "port": 8765
        },
        "test_parameters": {
            "time": 10,
            "bytes": null,
            "parallel": 1,
            "reverse": false,
            "bidir": false,
            "interval": 1
        }
    },
    "intervals": [],
    "end": {
        "sum_sent": {
            "bytes": 121234567,
            "bits_per_second": 97000000
        },
        "sum_received": {
            "bytes": 0,
            "bits_per_second": 0
        }
    }
}
```

## How It Works

### Architecture Design

wperf uses the WebSocket protocol for bidirectional communication, based on the following design:

1. **Server Mode**: Listen on a specified port, waiting for client connections
2. **Client Mode**: Connect to the server and execute tests
3. **Test Types**:
   - **UPLOAD**: Client sends data to server
   - **REVERSE**: Server sends data to client
   - **BIDIR**: Bidirectional simultaneous transmission
   - **UDP**: Simulate UDP packet transmission
   - **REVERSE_TRACEROUTE**: Client requests, server performs reverse traceroute

### TCP Test Process

1. Client connects to server
2. If authentication is enabled, perform token verification
3. Client sends test mode (UPLOAD/REVERSE/BIDIR)
4. Start transmitting 64KB data blocks
5. Periodically report transmission progress
6. Send EOT (End of Transmission) signal
7. Calculate and display final statistics

### UDP Simulation Process

1. Client sends "UDP" mode identifier
2. Send packets with sequence numbers and timestamps at the specified target bandwidth
3. Server receives packets and calculates:
   - **Jitter**: Calculated using RFC 1889 algorithm
   - **Packet Loss**: Detected based on sequence numbers
4. After the test ends, the server returns a statistical report

### Traceroute Process

wperf supports two traceroute modes:

1.  **Local Traceroute (`--traceroute`)**
    -   This is a standalone mode, similar to the system's `traceroute` or `tracert` command.
    -   It uses raw sockets to send probe packets with incrementing TTL (Time-To-Live).
    -   Supports both **UDP** and **ICMP** probe protocols (set via `--tr-proto`).
    -   Supports **parallel probing** (`--tr-parallel`) to send all probes simultaneously, speeding up the trace.
    -   Each hop router returns an ICMP "Time Exceeded" message when the TTL decrements to zero.
    -   wperf captures these ICMP messages, records the router's IP address and response time.
    -   This process requires administrator or root privileges to create raw sockets.

2.  **Reverse Traceroute (`--reverse-traceroute`)**
    -   This is a client-server collaborative function for diagnosing the network path from server to client.
    -   The client sends a `reverse_traceroute` command to the server through WebSocket connection.
    -   After receiving the command, the server obtains the client's public IP address from the WebSocket connection.
    -   The server then executes the same probing process as local traceroute with that client IP as the target.
    -   The server streams each hop's results (IP, latency, GeoIP, etc.) back to the client via WebSocket in real-time.
    -   The client receives and formats these results, providing a network path view of "seeing yourself from a remote location".

### Parallel Connections

When using the `-P` parameter to specify multiple parallel connections:

1. Create multiple independent WebSocket connections
2. Each connection transmits data independently
3. Summarize statistics from all connections
4. Provide overall bandwidth measurement

### NAT Traversal Capability

Traditional network testing tools (such as iperf3) establish direct TCP or UDP connections between client and server, which usually fails in environments with NAT (Network Address Translation) or strict firewalls, as complex port forwarding configurations are required.

wperf cleverly solves this problem by utilizing the WebSocket protocol:
1.  **Based on HTTP/HTTPS**: WebSocket connections begin with a standard HTTP/HTTPS request, which means it can use ports 80 and 443 that are almost always open in the network.
2.  **No Port Forwarding Required**: As long as the server is accessible from the public network (e.g., deployed on a cloud server), any client behind NAT can actively initiate a connection without any port forwarding settings on the client side.

This makes wperf an ideal tool for performance testing in home networks, enterprise internal networks, or any complex network topology.

### Network Behavior Simulation

The network behavior simulation features work at the **application layer** to mimic real-world network conditions without altering OS-level kernel parameters.

- **MTU Simulation (`--sim-mtu`)**: At the sender side, `wperf` actively slices data into chunks that do not exceed the specified MTU size before sending them.
- **Latency and Jitter Simulation (`--sim-latency`, `--sim-jitter`)**: At the sender side, before sending each packet, `wperf` introduces a delay using `asyncio.sleep()`. This delay is dynamically calculated from the fixed `latency` value plus a random value within the range of `[-jitter, +jitter]`.
- **Packet Loss Simulation (`--sim-loss`)**:
    - **Sequence Numbers**: To accurately track packets, `wperf` introduces a sequence number into its data protocol for each packet.
    - **Sender-side Drop**: The sender generates a random number for each packet. If this number falls within the configured loss probability (e.g., `1.5%`), the packet (along with its sequence number) is simply not sent.
    - **Receiver-side Detection**: The receiver inspects the sequence numbers of incoming packets. If it detects a gap (e.g., receiving packet 103 immediately after 101), it registers packet 102 as lost. The actual loss rate is then calculated based on the total count of lost packets.
- **Buffer Simulation (`--sim-sndbuf`, `--sim-rcvbuf`)**: `wperf` uses a fixed-size internal buffer to simulate the constraints of TCP send/receive buffers.
- **Nagle Algorithm Simulation (`--sim-tcp-nodelay`)**: `wperf` immediately sends small data chunks as they arrive, mimicking the effect of disabling the Nagle algorithm.

**Important Note**: This is an application-level simulation designed to provide a reproducible, cross-platform performance reference. The results are not identical to true kernel parameter tuning but are highly valuable for understanding the performance impact of these network characteristics.

## Technical Details

### Dependencies

- **asyncio**: Python's asynchronous I/O framework
- **websockets**: WebSocket client and server implementation
- **struct**: Used for packing and unpacking binary data (UDP mode)
- **json**: JSON data serialization

### Data Block Size

- TCP mode: 65536 bytes (64KB)
- UDP mode: 1400 bytes (simulating standard UDP packet size)

### Jitter Calculation

Using the algorithm defined in RFC 1889 Section 6.3.1:

```
D(i,j) = (Rj - Sj) - (Ri - Si) = (Rj - Ri) - (Sj - Si)
J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
```

Where:
- S: Send timestamp
- R: Receive timestamp
- D: Transmission time difference
- J: Smoothed jitter value

## Limitations and Known Issues

1. **WebSocket Overhead**: WebSocket has additional protocol overhead compared to raw TCP/UDP
2. **UDP Simulation**: Actually uses TCP connection to simulate UDP behavior, not real UDP
3. **Firewall**: Some network environments may block WebSocket connections
4. **Accuracy**: Measurement results may not be precise enough in high latency or high packet loss networks

## Troubleshooting

### Connection Failure

- Check if the server IP address and port are correct
- Ensure the firewall allows connections on the specified port
- Verify that the server is running

### Authentication Failure

- Ensure the client and server use the same token
- Check if the token string is correct (case-sensitive)

### Low Bandwidth Results

- Try increasing the number of parallel connections (`-P` parameter)
- Check network conditions and server load
- Ensure no other applications are consuming bandwidth

## Comparison with iperf3

| Feature | wperf | iperf3 |
|---------|-------|--------|
| Protocol | WebSocket | TCP/UDP |
| Installation | Single Python script | Requires compilation and installation |
| Cross-platform | Any platform where Python is available | Requires platform-specific compilation |
| NAT/Firewall Traversal | **Very Easy** (Based on WebSocket, typically uses ports 80/443) | **Difficult** (Requires port forwarding or specific firewall rules) |
| Performance Overhead | Higher (WebSocket protocol) | Lower (Raw sockets) |
| UDP Support | Simulation | Real UDP |

## Contributing

Issues and pull requests are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[dongkid](https://github.com/dongkid)

## Acknowledgements

This project is inspired by [iperf3](https://github.com/esnet/iperf).

---

**Note**: wperf is an educational and testing tool. For production network performance testing, it is recommended to use well-tested tools such as iperf3.
