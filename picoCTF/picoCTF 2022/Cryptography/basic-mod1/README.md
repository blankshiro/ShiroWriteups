# CTF Name – basic-mod1

## Challenge

> We found this weird message being passed around on the servers, we think we have a working decryption scheme. Take each number mod 37 and map it to the following character set: 0-25 is the alphabet (uppercase), 26-35 are the decimal digits, and 36 is an underscore. Wrap your decrypted message in the picoCTF flag format (i.e. picoCTF{decrypted_message})

## Solution

```bash
┌──(root㉿kali)-[/home/kali/pico/basic_mod_1]
└─# cat message.txt 
91 322 57 124 40 406 272 147 239 285 353 272 77 110 296 262 299 323 255 337 150 102                                                                              
┌──(root㉿kali)-[/home/kali/pico/basic_mod_1]
└─# cat solve.py   
import string

with open("message.txt") as f:
        contents = f.read()
        numbers = [int(val) for val in contents.split()]
        for number in numbers:
                mod = number % 37
                if mod in range(0, 26):
                        print(string.ascii_uppercase[mod], end="")
                elif mod in range(26, 36):
                        print(string.digits[mod-26], end="")
                else:
                        print("_", end="")    
                        
┌──(root㉿kali)-[/home/kali/pico/basic_mod_1]
└─# python3 solve.py    
R0UND_N_R0UND_ADD17EC2
```

