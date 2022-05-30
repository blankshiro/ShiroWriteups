# CTF Name – credstuff

## Challenge

> We found a leak of a blackmarket website's login credentials. Can you find the password of the user cultiris and successfully decrypt it? The first user in usernames.txt corresponds to the first password in passwords.txt. The second user corresponds to the second password, and so on.

## Solution

```bash
┌──(root㉿kali)-[/home/kali/pico/credstuff]
└─# tar xvf leak.tar     
leak/
leak/passwords.txt
leak/usernames.txt
                                                                             
┌──(root㉿kali)-[/home/kali/pico/credstuff]
└─# cd leak 
                                                                             
┌──(root㉿kali)-[/home/kali/pico/credstuff/leak]
└─# grep -n cultiris usernames.txt
378:cultiris

┌──(root㉿kali)-[/home/kali/pico/credstuff/leak]
└─# sed -n 378p passwords.txt
cvpbPGS{P7e1S_54I35_71Z3}

┌──(root㉿kali)-[/home/kali/pico/credstuff/leak]
└─# decoder -s cvpbPGS{P7e1S_54I35_71Z3}
________                          .___            
\______ \   ____   ____  ____   __| _/___________                            
 |    |  \_/ __ \_/ ___\/  _ \ / __ |/ __ \_  __ \                           
 |    `   \  ___/\  \__(  <_> ) /_/ \  ___/|  | \/                           
/_______  /\___  >\___  >____/\____ |\___  >__|                              
        \/     \/     \/           \/    \/                                  
                                                                             
              Automate the Manual :)                                         
                                                                             
---
[#] Provided string: cvpbPGS{P7e1S_54I35_71Z3}
---

-------------------------------------------------------

[%] Common Encodings
[+] AtBash decoded: XEKYKTHKVHRA

-------------------------------------------------------

[%] Rot Encodings (13 - 47)

[+] ROT13 decoded: picoCTF{C7r1F_54V35_71M3}
[+] ROT47 decoded: 4GA3!v$L!f6`$0dcxbd0f`+bN

-------------------------------------------------------

[%] Ceaser Cipher (with shifts 0 - 9)

[&] Shift: 0 Decoded: cvpbPGS{P7e1S_54I35_71Z3}
[&] Shift: 1 Decoded: buoaOFR{O6d0R_43H24_60Y2}
[&] Shift: 2 Decoded: atnzNEQ{N5c9Q_32G13_59X1}
[&] Shift: 3 Decoded: zsmyMDP{M4b8P_21F02_48W0}
[&] Shift: 4 Decoded: yrlxLCO{L3a7O_10E91_37V9}
[&] Shift: 5 Decoded: xqkwKBN{K2z6N_09D80_26U8}
[&] Shift: 6 Decoded: wpjvJAM{J1y5M_98C79_15T7}
[&] Shift: 7 Decoded: voiuIZL{I0x4L_87B68_04S6}
[&] Shift: 8 Decoded: unhtHYK{H9w3K_76A57_93R5}
[&] Shift: 9 Decoded: tmgsGXJ{G8v2J_65Z46_82Q4}

-------------------------------------------------------
```

