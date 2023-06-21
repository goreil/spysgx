#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./sqr_mlt')



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

with context.silent:
    for i in range(100):
        io = start(argv=[str(i)]) 
        out = int(io.recvline(), 0)
        assert pow(3, i, 8555135299883116411) == out, "Failed on {}".format(i)


