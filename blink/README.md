## Original source

https://linuxgazette.net/issue79/sebastian.html

Remove the leading space from every line, otherwise "yadda equ 42" will produce syntax errors


## Required linux packages

- gputils
- picprog
- python3-intelhex


## How to build

```
gpasm blink.s
/usr/share/python3-intelhex/hex2bin.py blink.hex blink.bin
od -t x2 -Ax -w2 -v blink.bin > blink.dump
```
