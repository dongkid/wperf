# wperf - WebSocket 网络性能测试工具

<img width="512" height="256" alt="wperf_card" src="https://github.com/user-attachments/assets/4108034c-9ff4-4a35-9169-4c30a3e10fea" />

[English Version](README_en.md) | [![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

wperf 是一个基于 WebSocket 的网络性能测试工具，其核心优势是能够轻松穿透 NAT 和防火墙环境。它类似于 iperf3，用于测量网络带宽、延迟、抖动和丢包率。

## 特性

- 🌐 **NAT 穿透** - 基于 WebSocket，可轻松穿透复杂的网络环境和防火墙。
- 🚀 **TCP 带宽测试** - 测量上传和下载带宽
- 🔄 **双向测试** - 同时进行上传和下载测试
- ⏱️ **端到端延迟测试 (Ping)** - 测量基于 WebSocket 的往返时间 (RTT)
- 📊 **UDP 模拟** - 测量抖动和丢包率
- 📍 **路由追踪** - 支持本地、反向、ICMP/UDP 探针及并行探测
- 🌍 **GeoIP 信息** - 在路由追踪中显示每一跳的ASN和国家/地区信息
- 🔒 **身份验证** - 支持 token 认证
- 📈 **实时报告** - 定期输出测试进度
- 🔢 **多连接并行** - 支持多个并行连接以提高测试准确性
- 📄 **JSON 输出** - 支持机器可读的 JSON 格式输出
- ⚡ **异步高性能** - 基于 asyncio 和 websockets 库
- 🔬 **网络行为模拟** - 在应用层模拟 MTU、延迟、抖动、丢包、缓冲区和 Nagle 算法等网络特性。

#### TODO List

- [ ] 多服务器同时测试并生成统一的对比报告
- [ ] 更真实地模拟丢包与 CWND (拥塞窗口) 行为
- [ ] 模拟不同类型数据（如视频流、小数据包）的传输性能
- [ ] More and more...


## 安装

### 依赖要求

- Python 3.7 或更高版本
- websockets 库

### 安装步骤

1. 克隆或下载此项目：
```bash
git clone <repository-url>
cd wperf
```

2. 安装依赖：
```bash
pip install websockets
```

或使用 requirements.txt：
```bash
pip install -r requirements.txt
```

## 快速开始

### 启动服务端

在服务器上运行：

```bash
wperf -s
```

默认监听端口 8765，可以使用 `-p` 参数指定其他端口：

```bash
wperf -s -p 9000
```

### 运行客户端测试

在客户端上运行基本的上传测试：

```bash
wperf -c <server-ip> -t 10
```

## 使用说明

### 命令行参数

#### 通用参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-s, --server` | 以服务端模式运行 | - |
| `-c, --client <host>` | 以客户端模式运行，连接到指定服务器 | - |
| `-p, --port <port>` | 监听或连接的端口号 | 8765 |
| `--token <token>` | 身份验证令牌 | 无 |
| `-i, --interval <sec>` | 报告带宽的间隔时间（秒） | 1 |
| `-t, --time <sec>` | 测试持续时间（秒） | 10 |
| `-n, --bytes <size>` | 传输的字节数（如：10M, 1G） | - |

#### 客户端专用参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-R, --reverse` | 反向模式（服务器发送，客户端接收） | false |
| `--bidir` | 双向测试（同时发送和接收） | false |
| `-P, --parallel <n>` | 并行客户端流的数量 | 1 |
| `-J, --json` | 以 JSON 格式输出结果 | false |
| `--udp` | 模拟 UDP 流量并测量抖动/丢包 | false |
| `-b, --bandwidth <mbps>` | 目标带宽（Mbps，用于 UDP 模式） | 1 |
| `--ping` | **客户端专用**。运行一个端到端的延迟测试 (ping)。 | false |
| `--ping-count <n>` | Ping 测试发送的数据包数量。 | 5 |


### 网络行为模拟参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--sim-mtu <size>` | 模拟最大传输单元 (MTU)。 | 未启用 |
| `--sim-latency <ms>` | 模拟固定的网络延迟。 | 0 |
| `--sim-jitter <ms>` | 模拟网络抖动（延迟变化）。 | 0 |
| `--sim-loss <rate>` | 模拟丢包率 (0-100)。 | 0 |
| `--sim-tcp-nodelay` | 模拟禁用 Nagle 算法，让小数据包立即发送。 | 未启用 |
| `--sim-sndbuf <size>` | 模拟 TCP 发送缓冲区的大小，并提供单位示例（如 `128K`, `1M`）。 | 未启用 |
| `--sim-rcvbuf <size>` | 模拟 TCP 接收缓冲区的大小。 | 未启用 |
#### 路由追踪参数

> **注意**: 路由追踪功能需要管理员或 root 权限才能运行。

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--traceroute <host>` | 以独立的路由追踪模式运行，追踪到指定主机 | - |
| `--reverse-traceroute` | **客户端专用**。请求服务器对当前客户端进行反向路由追踪。必须与 `-c` 一起使用。 | false |
| `--tr-max-hops <n>` | 路由追踪的最大跳数 | 30 |
| `--tr-timeout <sec>` | 每一跳的超时时间（秒） | 1 |
| `--tr-proto <proto>` | 路由追踪使用的探针协议 (`udp` 或 `icmp`)。 | `udp` |
| `--tr-parallel` | 并行执行路由追踪探测以加快速度。 | false |

### 使用示例

> **注意**：以下示例统一使用 `wperf` 作为命令名。如果您直接运行 Python 脚本，请将其替换为 `wperf`。如果您使用的是编译后的可执行文件，请使用相应的可执行文件名（例如 `wperf` 或 `wperf.exe`）。


#### 1. TCP 上传测试（客户端到服务器）

测试 10 秒的上传速度：

```bash
# 服务端
wperf -s

# 客户端
wperf -c 192.168.1.100 -t 10
```

#### 2. TCP 下载测试（服务器到客户端）

使用 `-R` 参数进行反向测试：

```bash
# 客户端
wperf -c 192.168.1.100 -t 10 -R
```

#### 3. 双向测试

同时测试上传和下载：

```bash
# 客户端
wperf -c 192.168.1.100 -t 10 --bidir
```

#### 4. UDP 模拟测试

测量抖动和丢包率：

```bash
# 客户端
wperf -c 192.168.1.100 -t 10 --udp -b 10
```

此命令将以 10 Mbps 的目标带宽发送模拟 UDP 数据包。

#### 5. 并行连接测试

使用 4 个并行连接进行测试：

```bash
# 客户端
wperf -c 192.168.1.100 -t 10 -P 4
```

#### 6. 传输指定字节数

传输 100MB 数据：

```bash
# 客户端
wperf -c 192.168.1.100 -n 100M
```

支持的单位：K（千字节）、M（兆字节）、G（千兆字节）

#### 7. JSON 格式输出

以 JSON 格式输出结果，便于脚本处理：

```bash
# 客户端
wperf -c 192.168.1.100 -t 10 -J
```

#### 8. 使用身份验证

服务端和客户端都需要配置相同的 token：

```bash
# 服务端
wperf -s --token mySecretToken

# 客户端
wperf -c 192.168.1.100 -t 10 --token mySecretToken
```

#### 9. 自定义端口

使用非默认端口：

```bash
# 服务端
wperf -s -p 9000

# 客户端
wperf -c 192.168.1.100 -p 9000 -t 10
```

#### 10. 本地路由追踪

追踪到 `google.com` 的网络路径。此模式独立运行，不需要连接到 `wperf` 服务器。

```bash
# 需要管理员/root权限
sudo wperf --traceroute google.com --tr-proto icmp --tr-parallel
```
输出示例：
```
traceroute to google.com (142.250.199.14), 30 hops max
1  [US, AS15169 GOOGLE]    192.168.1.1 (192.168.1.1) 1.234 ms
2  * * *
3  [US, AS7922 COMCAST]   some.router.com (96.120.88.193) 9.876 ms
...
12 [US, AS15169 GOOGLE]   142.250.199.14 (142.250.199.14) 15.432 ms
```

#### 11. 端到端延迟测试 (Ping)

测量客户端和服务器之间的往返延迟。

```bash
# 客户端
wperf -c 192.168.1.100 --ping --ping-count 10
```
输出示例：
```
Pinging 192.168.1.100:8765...
seq=0, rtt=12.34 ms
seq=1, rtt=11.98 ms
...
--- statistics ---
10 packets transmitted, 10 received, 0% packet loss
rtt min/avg/max = 11.98/12.15/12.45 ms
```

#### 12. 反向路由追踪（服务器到客户端）

诊断从服务器到客户端的网络路径。客户端连接到服务器并发起请求。

```bash
# 客户端 (需要管理员/root权限)
sudo wperf -c 192.168.1.100 --reverse-traceroute
```
服务器将执行 traceroute 到该客户端的公网 IP，并将结果实时流式传输回客户端显示。

## 输出说明

#### 13. 使用网络行为模拟

```bash
# 模拟小发送缓冲区和禁用的Nagle算法进行测试
wperf -c <server-ip> -t 10 --sim-sndbuf 128K --sim-tcp-nodelay
```

#### 14. 综合网络模拟示例

模拟一个高延迟、有抖动和轻微丢包的一般质量链路，并限制MTU。

```bash
# 模拟一个高延迟、有抖动和轻微丢包的一般质量链路，并限制MTU
wperf -c <server-ip> -t 10 --sim-latency 200 --sim-jitter 30 --sim-loss 1.5 --sim-mtu 1400
```

### TCP 测试输出

文本模式输出示例：

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

### UDP 测试输出

UDP 模式输出示例：

```
----------------------------------------
Jitter: 2.345 ms
Lost/Total: 15/10000 (0.15%)
----------------------------------------
```

### 测试报告样例（含网络模拟）

当启用网络模拟参数时，最终的报告会包含一个专门的部分来展示这些参数和相关的统计数据，例如丢包情况。

```
... (原有报告内容) ...

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

### JSON 输出格式

JSON 输出包含详细的测试信息：

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

## 工作原理

### 架构设计

wperf 使用 WebSocket 协议进行双向通信，基于以下设计：

1. **服务端模式**：监听指定端口，等待客户端连接
2. **客户端模式**：连接到服务器并执行测试
3. **测试类型**：
   - **UPLOAD**：客户端发送数据到服务器
   - **REVERSE**：服务器发送数据到客户端
   - **BIDIR**：双向同时传输
   - **UDP**：模拟 UDP 数据包传输
   - **REVERSE_TRACEROUTE**：客户端请求，服务器执行反向路由追踪

### TCP 测试流程

1. 客户端连接到服务器
2. 如果启用了身份验证，进行 token 验证
3. 客户端发送测试模式（UPLOAD/REVERSE/BIDIR）
4. 开始传输 64KB 的数据块
5. 定期报告传输进度
6. 发送 EOT（传输结束）信号
7. 计算并显示最终统计信息

### UDP 模拟流程

1. 客户端发送 "UDP" 模式标识
2. 以指定的目标带宽发送带有序列号和时间戳的数据包
3. 服务器接收数据包并计算：
   - **抖动（Jitter）**：使用 RFC 1889 的算法计算
   - **丢包率**：基于序列号检测丢失的数据包
4. 测试结束后，服务器返回统计报告

### 路由追踪流程

wperf 支持两种路由追踪模式：

1.  **本地路由追踪 (`--traceroute`)**
    -   这是一个独立的模式，类似于系统的 `traceroute` 或 `tracert` 命令。
    -   它使用原始套接字（Raw Sockets）发送具有递增 TTL（Time-To-Live）的探测包。
    -   支持 **UDP** 和 **ICMP** 两种探针协议（通过 `--tr-proto` 设置）。
    -   支持 **并行探测** (`--tr-parallel`)，可同时发送所有探测包以加快追踪速度。
    -   每一跳的路由器在 TTL 减为零时会返回一个 ICMP "Time Exceeded" 消息。
    -   wperf 捕获这些 ICMP 消息，记录下路由器的 IP 地址和响应时间。
    -   此过程需要管理员或 root 权限才能创建原始套接字。

2.  **反向路由追踪 (`--reverse-traceroute`)**
    -   这是一个客户端-服务器协作的功能，用于诊断从服务器到客户端的网络路径。
    -   客户端通过 WebSocket 连接向服务器发送一个 `reverse_traceroute` 命令。
    -   服务器收到命令后，从 WebSocket 连接中获取客户端的公网 IP 地址。
    -   服务器随后以该客户端 IP 为目标，执行与本地路由追踪相同的探测流程。
    -   服务器将每一跳的结果（IP、延迟、GeoIP等）通过 WebSocket 实时流式传输回客户端。
    -   客户端接收并格式化显示这些结果，提供一种“从远端看自己”的网络路径视图。

### 并行连接

当使用 `-P` 参数指定多个并行连接时：

1. 创建多个独立的 WebSocket 连接
2. 每个连接独立传输数据
3. 汇总所有连接的统计信息
4. 提供总体带宽测量

### NAT 穿透能力

传统网络测试工具（如 iperf3）在客户端和服务器之间建立直接的 TCP 或 UDP 连接，这在经过 NAT（网络地址转换）或严格防火墙的环境中通常会失败，因为需要复杂的端口转发配置。

wperf 通过利用 WebSocket 协议巧妙地解决了这个问题：
1.  **基于 HTTP/HTTPS**：WebSocket 连接始于一个标准的 HTTP/HTTPS 请求，这意味着它可以使用网络中几乎总是开放的 80 和 443 端口。
2.  **无需端口转发**：只要服务端可以从公网访问（例如，部署在云服务器上），任何位于 NAT 后面的客户端都可以主动发起连接，无需在客户端一侧进行任何端口转发设置。

这使得 wperf 成为在家庭网络、企业内部网络或任何复杂网络拓扑中进行性能测试的理想工具。

## 技术细节

### 依赖库

- **asyncio**：Python 的异步 I/O 框架
- **websockets**：WebSocket 客户端和服务器实现

### 网络行为模拟原理

此功能并非直接修改操作系统的 TCP 内核参数，而是在 **应用层** 通过内部的流量控制和缓冲策略来 **模拟** 这些行为。

- **MTU 模拟 (`--sim-mtu`)**：在发送端，`wperf` 会将数据主动切片成不超过指定 MTU 大小的数据块再发送。
- **延迟和抖动模拟 (`--sim-latency`, `--sim-jitter`)**：在发送端，`wperf` 在发送每个数据包之前，会通过 `asyncio.sleep()` 插入一个动态计算的延迟。该延迟由固定的 `latency` 和一个在 `[-jitter, +jitter]` 范围内的随机值组成。
- **丢包模拟 (`--sim-loss`)**：
    - **引入序列号**：为了准确追踪丢包，`wperf` 为每个（模拟的）数据包协议引入了序列号。
    - **发送方丢弃**：在发送端，程序会根据配置的丢包率（如 `1.5%`）产生一个随机数。如果随机数落在丢包概率范围内，该数据包（连同其序列号）将不会被发送。
    - **接收方检测**：在接收端，程序会检查收到的序列号是否连续。当检测到序列号不连续时（例如，收到 101 后直接收到了 103），就将 102 标记为丢失数据包。最终根据丢失的包总数计算出实际的丢包率。
- **缓冲区模拟 (`--sim-sndbuf`, `--sim-rcvbuf`)**：`wperf` 内部维护一个固定大小的缓冲区来模拟 TCP 收发缓冲区的限制。
- **Nagle 算法模拟 (`--sim-tcp-nodelay`)**：`wperf` 会在收到小数据块时立即发送，模拟禁用 Nagle 算法的效果。

**重要提示**：这是一个应用层模拟，其目的是提供一个可复现的、跨平台的性能参考。其结果不完全等同于真实的内核参数调优，但具有很高的参考价值。
- **struct**：用于打包和解包二进制数据（序列号、时间戳等）
- **json**：JSON 数据序列化

### 数据块大小

- TCP 模式：65536 字节（64KB）
- UDP 模式：1400 字节（模拟标准 UDP 数据包大小）

### 抖动计算

使用 RFC 1889 第 6.3.1 节定义的算法：

```
D(i,j) = (Rj - Sj) - (Ri - Si) = (Rj - Ri) - (Sj - Si)
J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
```

其中：
- S：发送时间戳
- R：接收时间戳
- D：传输时间差异
- J：平滑抖动值

## 限制和已知问题

1. **WebSocket 开销**：相比原始 TCP/UDP，WebSocket 有额外的协议开销
2. **UDP 模拟**：实际使用 TCP 连接模拟 UDP 行为，不是真正的 UDP
3. **防火墙**：某些网络环境可能阻止 WebSocket 连接
4. **准确性**：在高延迟或高丢包网络中，测量结果可能不够精确

## 故障排除

### 连接失败

- 检查服务器 IP 地址和端口是否正确
- 确保防火墙允许指定端口的连接
- 验证服务端是否正在运行

### 身份验证失败

- 确保客户端和服务端使用相同的 token
- 检查 token 字符串是否正确（区分大小写）

### 低带宽结果

- 尝试增加并行连接数（`-P` 参数）
- 检查网络条件和服务器负载
- 确保没有其他应用占用带宽

## 与 iperf3 的比较

| 特性 | wperf | iperf3 |
|------|-------|--------|
| 协议 | WebSocket | TCP/UDP |
| 安装 | 单个 Python 脚本 | 需要编译安装 |
| 跨平台 | Python 可用的任何平台 | 需要针对平台编译 |
| NAT/防火墙穿透 | **非常容易**（基于 WebSocket，通常使用 80/443 端口） | **困难**（需要端口转发或特定防火墙规则） |
| 性能开销 | 较高（WebSocket 协议） | 较低（原始套接字） |
| UDP 支持 | 模拟 | 真实 UDP |

## 贡献

欢迎提交问题报告和拉取请求！

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 作者

[dongkid](https://github.com/dongkid)

## 致谢

本项目受 [iperf3](https://github.com/esnet/iperf) 的启发。

---

**注意**：wperf 是一个教育和测试工具。对于生产环境的网络性能测试，建议使用经过充分测试的工具如 iperf3。
