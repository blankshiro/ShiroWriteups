# CTF Name – Understand Space Politics

-   **Category:** Forensics

## Challenge

> A file has been leaked out from the higher-ups, and it is rumored to contain chairman mao's little red book, which is the space politics bible that we will ever need.

## Solution

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# ls
hello_there.7z
                                                                             
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# file hello_there.7z    
hello_there.7z: 7-zip archive data, version 0.4                                                                         
```

It looks like a `7-zip` archive, so let’s unzip it with `7za`!

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# 7za e hello_there.7z

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 7 3700X 8-Core Processor              (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 414 bytes (1 KiB)

Extracting archive: hello_there.7z
--
Path = hello_there.7z
Type = 7z
Physical Size = 414
Headers Size = 146
Method = LZMA2:12
Solid = -
Blocks = 1

Everything is Ok

Size:       292
Compressed: 414

┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# ls
hello_there.7z  hello_there.tar.gz

┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# file hello_there.tar.gz 
hello_there.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 10240
```

Hmm.. It’s another compressed file but this time it’s `gzip`?

Let’s unzip it using `gzip`!

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# gzip -d hello_there.tar.gz   

┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# ls
hello_there.7z  hello_there.tar                                                                             
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# file hello_there.tar   
hello_there.tar: POSIX tar archive (GNU)
```

Wow.. it’s another compressed file.

Let’s unzip it using `tar`!

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# tar xvf hello_there.tar
hello_there.zip
    
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# ls
hello_there.7z  hello_there.tar  hello_there.zip                                                                             
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# file hello_there.zip 
hello_there.zip: Zip archive data, at least v2.0 to extract, compression method=store
```

Guess what? It’s another zip file. :(

Let’s try to unzip it using `unzip`!

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# unzip hello_there.zip 
Archive:  hello_there.zip
[hello_there.zip] hello_there.txt password: 
password incorrect--reenter: 
password incorrect--reenter: 
   skipping: hello_there.txt         incorrect password
```

Oh? We might be near the flag!

How do we break the password? Perhaps a password cracker?

Luckily for us, there’s a ZIP Password BruteForcer on [GitHub](https://github.com/The404Hacking/ZIP-Password-BruteForcer)! 

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# git clone https://github.com/The404Hacking/ZIP-Password-BruteForcer
Cloning into 'ZIP-Password-BruteForcer'...
remote: Enumerating objects: 18, done.
remote: Total 18 (delta 0), reused 0 (delta 0), pack-reused 18
Receiving objects: 100% (18/18), 38.75 KiB | 12.92 MiB/s, done.
Resolving deltas: 100% (3/3), done.
    
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# cd ZIP-Password-BruteForcer 
```

Before we move on, we need to have a wordlist ready. In this challenge, I used the famous `rockyou.txt`!

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics/ZIP-Password-BruteForcer]
└─# locate rockyou
...
/usr/share/wordlists/rockyou.txt
```

Let’s crack the password!

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics/ZIP-Password-BruteForcer]
└─# python ZIP-Password-BruteForcer.py

 ###################################
 # ZIP Password BruteForcer        #
 ###################################
 # Coded By Sir.4m1R               #
 # The404Hacking                   #
 # Digital Security ReSearch Group #
 # T.me/The404Hacking              #
 ###################################
 GitHub:
 https://github.com/The404Hacking/ZIP-Password-BruteForcer

 [1] Zip Password Cracker
 [0] Exit

 [?] Enter Number : 1
 
 
 #########################################
 # Zip Password Brute Forcer (Top Speed) #
 #########################################
 # The404Hacking                         #
 # Digital Security ReSearch Group       #
 # T.me/The404Hacking                    #
 #########################################
 
 [+] ZIP File Address: /home/kali/cyber_league/understand_space_politics/hello_there.zip

 [+] Password List Address: /usr/share/wordlists/rockyou.txt

 [*] Password Found :)
 [*] Password: 2hot4u

 [***] Took 2.063865 seconds to Srack the Password. That is, 837 attempts per second.
```

Yay! We found the password `2hot4u`. Let’s use it to unzip the protected file.

```bash
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# unzip hello_there.zip 
Archive:  hello_there.zip
[hello_there.zip] hello_there.txt password: 
 extracting: hello_there.txt         
                       
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# ls                          
hello_there.7z  hello_there.tar  hello_there.txt  hello_there.zip  ZIP-Password-BruteForcer                                                                                                                    
┌──(root㉿kali)-[/home/kali/cyber_league/understand_space_politics]
└─# cat hello_there.txt         
CYBERLEAGUE{Y0U_Fo|_|nD_3e!}
```



