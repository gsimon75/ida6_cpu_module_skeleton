# A minimal skeleton for an IDA 6.x cpu module

The IDA Python API for cpu modules isn't too well documented, so to test my assumptions and interpretations the best
way was to actually write such a cpu module.

There are some python cpu modules shipped with IDA (`ebc.py`, `msp430.py` and `spu.py`), and there is `idaapi.py` too,
but there were three open questions:

- what is the minimal set of methods to implement
- what shall actually be done in them
- what properties of the cpu class must be set and to what values

Obviously I wanted to keep this as simple as possible, so I chose a simple cpu with a minimal instruction set: pic16f84

NOTE: IDA already has a very nice cpu module for all PICMicro chips, that knows not only the CPU but also the memory
layout, the peripheral registers, etc., so this repo serves NO PRACTICAL PURPOSE AT ALL, except for being a
proof-of-concept and perhaps a skeleton for other cpu modules.

The folder [`blink`](blink) contains a minimal pic code that blinks some leds, I found it [here](https://linuxgazette.net/issue79/sebastian.html)

The folder [`minimal_api`](minimal_api) contains the stripped-down versions of the original python cpu modules, with
all cpu-specific things removed, so that I could see which such module implements which methods.

The result is in [`pic16f84.py`](pic16f84.py), which is just a cpu module (no loader, no memory layout), so when you
use it, manually create a RAM segment (the IDE will offer it) and put its address to some high value like 0x8000

NOTE: IDA 6.x still uses python2.7, so no python3 features are available (hence the `class NamedEnum`).

By writing this I've learned what I wanted, so it makes no sense to complete it with all the missing features,
so it's intentionally left incomplete and most probably it'll stay this way.

