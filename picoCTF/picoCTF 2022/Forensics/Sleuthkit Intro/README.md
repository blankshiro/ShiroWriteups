# CTF Name – Sleuthkit Intro

## Challenge

> Download the disk image and use `mmls` on it to find the size of the Linux partition. Connect to the remote checker service to check your answer and get the flag.

## Solution

```bash
┌──(shiro㉿shiro)-[~/CTFs/picoCTF/Forensics]
└─$ sudo wget https://artifacts.picoctf.net/c/114/disk.img.gz              3 ⨯
[sudo] password for shiro: 
--2022-06-09 21:11:23--  https://artifacts.picoctf.net/c/114/disk.img.gz
Resolving artifacts.picoctf.net (artifacts.picoctf.net)... 13.224.250.39, 13.224.250.29, 13.224.250.75, ...
Connecting to artifacts.picoctf.net (artifacts.picoctf.net)|13.224.250.39|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 29714372 (28M) [application/octet-stream]
Saving to: ‘disk.img.gz’

disk.img.gz         100%[==================>]  28.34M  10.1MB/s    in 2.8s    

2022-06-09 21:11:26 (10.1 MB/s) - ‘disk.img.gz’ saved [29714372/29714372]
```

Let’s unzip the file!

```bash
┌──(shiro㉿shiro)-[~/CTFs/picoCTF/Forensics]
└─$ sudo gzip -d disk.img.gz

┌──(shiro㉿shiro)-[~/CTFs/picoCTF/Forensics]
└─$ ls
disk.img
```

Let’s display the volume contents using the `mmls` command!

```bash
┌──(shiro㉿shiro)-[~/CTFs/picoCTF/Forensics]
└─$ mmls disk.img 
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000204799   0000202752   Linux (0x83)
```

Great! We have the length of the partition which is `202752`.

Let’s verify this with the given checker.

```bash
┌──(shiro㉿shiro)-[~/CTFs/picoCTF/Forensics]
└─$ nc saturn.picoctf.net 52279
What is the size of the Linux partition in the given disk image?
Length in sectors: 202752
202752
Great work!
picoCTF{mm15_f7w!}
```







