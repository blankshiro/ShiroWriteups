# CTF Name – basic-mod2

## Challenge

> Take each number mod 41 and find the modular inverse for the result. Then map to the following character set: 1-26 are the alphabet, 27-36 are the decimal digits, and 37 is an underscore. Wrap your decrypted message in the picoCTF flag format (i.e. picoCTF{decrypted_message})

## Solution

```bash
┌──(root㉿kali)-[/home/kali/pico/basic_mod2]
└─# cat message.txt
104 85 69 354 344 50 149 65 187 420 77 127 385 318 133 72 206 236 206 83 342 206 370                                                                              
┌──(root㉿kali)-[/home/kali/pico/basic_mod2]
└─# cat solve.py   
import string

with open ("message.txt") as f:
        contents = f.read()
        numbers = [int(val) for val in contents.split()]
        for number in numbers:
                mod = pow(number, -1, 41)
                if mod in range(1, 27):
                        print(string.ascii_uppercase[mod-1], end="")
                elif mod in range(27, 37):
                        print(string.digits[mod - 27], end="")
                else:
                        print("_", end="")                                                                             
┌──(root㉿kali)-[/home/kali/pico/basic_mod2]
└─# python3 solve.py
1NV3R53LY_H4RD_DADAACAA
```

