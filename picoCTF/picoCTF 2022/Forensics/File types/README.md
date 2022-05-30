# CTF Name – File types

## Challenge

> This file was found among some files marked confidential but my pdf reader cannot read it, maybe yours can.

## Solution

```bash
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls
Flag.pdf

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file Flag.pdf 
Flag.pdf: shell archive text

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# cat Flag.pdf 
#!/bin/sh
# This is a shell archive (produced by GNU sharutils 4.15.2).
# To extract the files from this archive, save it to some FILE, remove
# everything before the '#!/bin/sh' line above, then type 'sh FILE'.
...

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# sh Flag.pdf 
x - created lock directory _sh00046.
x - extracting flag (text)
Flag.pdf: 119: uudecode: not found
restore of flag failed
flag: MD5 check failed
x - removed lock directory _sh00046.
```

It seems like we need to install some packages for it to work.

```bash
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# apt install sharutils -y   
...

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# sh Flag.pdf             
x - created lock directory _sh00046.
x - extracting flag (text)
x - removed lock directory _sh00046.

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag    
flag: current ar archive

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ar xv flag
x - flag
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag
flag: cpio archive

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# cpio --file flag --extract               
cpio: flag not created: newer or same age version exists
2 blocks
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# mv flag flag_cpio         
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# cpio --file flag_cpio --extract
2 blocks
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls
flag  flag_cpio  Flag.pdf
                                                                     
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag                      
flag: bzip2 compressed data, block size = 900k

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# bunzip2 flag
bunzip2: Can't guess original name for flag -- using flag.out
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls
flag.out  Flag.pdf
                                                                      
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag.out
flag.out: gzip compressed data, was "flag", last modified: Tue Mar 15 06:50:39 2022, from Unix, original size modulo 2^32 328

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# gunzip flag.out
gzip: flag.out: unknown suffix -- ignored

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# mv flag.out flag.gz
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# gunzip flag.gz 
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls
flag  Flag.pdf

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag    
flag: lzip compressed data, version: 1

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# lzip -d flag
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls          
flag_cpio  flag.out  Flag.pdf
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag.out
flag.out: LZ4 compressed data (v1.4+)

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# lz4 -d flag.out flag
                                                                             flag.out             : decoded 266 bytes 
 
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag    
flag: LZMA compressed data, non-streamed, size 254

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# unlzma flag          
unlzma: flag: Filename has an unknown suffix, skipping
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# mv flag flag.lzma  
                                                                      
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# unlzma flag.lzma

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag
flag: lzop compressed data - version 1.040, LZO1X-1, os: Unix

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# lzop -d flag
lzop: flag: unknown suffix -- ignored
skipping flag [flag.raw]
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# mv flag flag.lzop

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# lzop -d flag.lzop
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag
flag: lzip compressed data, version: 1

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# lzip -d flag
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls          
flag.out  Flag.pdf
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag.out
flag.out: XZ compressed data, checksum CRC64

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# unxz flag.out   
unxz: flag.out: Filename has an unknown suffix, skipping
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# mv flag.out flag.xz

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# unxz flag.xz     

┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# ls
flag  Flag.pdf
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# file flag
flag: ASCII text
    
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# cat flag
7069636f4354467b66316c656e406d335f6d406e3170756c407431306e5f
6630725f3062326375723137795f37396230316332367d0a
```

Finally, we have an ASCII text.. but what is it?

It looks like a hex encoded text, so let’s decode it using `xxd`!

```bash
┌──(root㉿kali)-[/home/kali/pico/file_types]
└─# cat flag | xxd -r -p
picoCTF{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_79b01c26}
```

