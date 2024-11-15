+++
title = "Hack The Box - Convoluted Boot"
description = "Convoluted was not a lie"
date = 2024-11-14
[taxonomies]
categories = ["Hack The Box", "Reversing"]
+++
## Introduction

I really enjoyed this challenge for a few reasons! First, it took me far out of my comfort zone and forced me to learn a lot. Second, it's not a challenge where you can just load the binary in Ghidra and then just grind through the various functions labelling them along with filling out any data structures you encounter as you go. Third, there's actually very little code to dig through, and I foolishly thought that this might actually be simpler than it turned out to be, so I really enjoyed the twist where this turned into rabbit hole after rabbit hole to dive down!

The only file in the archive downloaded from Hack The Box is a modest 2kb file `convolutedboot.bin`. The description of the challenge gives a hint that it is used in a network boot setup and that it likely contains a bootkit.

Running `file` on the file gives no hint of its content, just returning `data`. Running `strings` on the file gives quite a lot of useful information, however.

Notably, it contains a string giving a hint at how to run the challenge software in QEMU, as well some strings that look like they might be commands to a bootloader of some sort.

## The Boot ROM

We can use `objdump` to disassemble the boot image code, specifying that address and data size should be 16 bits and the architecture is `i386`. It's also useful to set the loading address so that any absolute addressing will line up with the contents of the binary:
```
objdump --adjust-vma=0x7c00 -b binary -m i386 -Maddr16,data16 -D -s convolutedboot.bin > init.s
```

After some initialization code, to set up the segment registers and the stack pointer, and a call to print out "Looking for PXE...", we see the first really functional bit of code:

```asm
mov    $0x5650,%ax
int    $0x1a
```

Searching for what interrupt `0x1a` is meant to do on the i386 isn't particularly helpful in this case. The sources I found listed a fair few entries for what the interrupt does based on the value of `%ax`, but none listed `0x5650` as an entry. 
Thankfully, there is an open source project [iPXE](https://ipxe.org/), which can shed some light what these two lines are doing. Reading the source code the x86-specific implementation, it appears that this call retrieves a pointer to a PXENV+ structure[^pxenv].

From here, the code starts to make a bit more sense. It calls interrupt `0x1a`, checks that the returned value in `%ax` matches the expectation, and then stores the PXENV+ struct pointer for later retrieval. There is a switch on the PXENV+ version, which I ignored to some extent, because QEMU embeds iPXE, and iPXE hardcodes the version to `0x201`. The only really interesting thing that the code does with the PXENV+ structure, after determining the version, is to pull out the function pointers for calling `pxe_entry`, which allows calling the PXE API.

There is another key PXE interaction through a function at address `0x7e24`, which is to call the API through the `pxe_entry` function pointer saved earlier.

The first call is to `PXENV_GET_CACHED_INFO` (opcode `0x71`), some of the result of which is saved to memory, but it doesn't appear to affect too much.

The next calls are to `PXENV_FILE_EXEC` (opcode `0xe5`). These calls are what set up the boot environment by issuing the commands to the PXE environment (as seen in the output of `strings`:
```
kernel http://distro.ibiblio.org/tinycorelinux/12.x/x86/release/distribution_files/vmlinuz
initrd http://distro.ibiblio.org/tinycorelinux/12.x/x86/release/distribution_files/core.gz
imgfree convolutedboot.bin
boot
```

At this point is seems sensible to download these files, as we may want to have them later for further analysis!

However, between `PXENV_GET_CACHED_INFO` and the first `PXENV_FILE_EXEC` command, there is some interesting code that copies data from within the boot ROM to another address:
```asm
subw   $0x6,%ds:0x413
mov    %ds:0x413,%ax
shl    $0x6,%ax
mov    %ax,%es
mov    $0x342,%cx
xor    %di,%di
mov    $0x7f81,%si
repnz movsw %ds:(%si),%es:(%di)
```

Then, between `PXENV_FILE_EXEC(imgfree convolutedboot.bin)` and `PXENV_FILE_EXEC(boot)`, the boot code pushes the long return address of the start of the call to `PXENV_FILE_EXEC(boot)` and then the address of the copied code, and triggers the copied code with a long return.
```asm
mov    %ds:0x413,%ax
shl    $0x6,%ax
mov    %ax,%es
xor    %ax,%ax
push   %cs
push   $0x7d2d
push   %es
push   %ax
lret
```

This code is where things start to get interesting.

### Debugging the Boot ROM

I usually like to avoid invoking the debugger or even running the code as long as I possibly can, but I couldn't figure out a particular bit of magic code when I was working through this challenge originally. The code to copy data from the boot image to some address in memory.

The code is clearly copying `0x342` words from `%ds:(%si)` to `%es:(%di)`, but what I couldn't understand is what the first three instructions are doing. I have since looked again an I think I may have a slightly better understanding now[^rmaddr].

Luckily it's possible (if unpleasant) to debug the bootloader in QEMU using GDB. One can take the `qemu-system-i386` command line suggested by the string entry in the binary itself, and append `-s` to start a GDB server on TCP port `1234` and `-S` to pause execution until GDB connects and the execution is continued.

On the client side, the following command was useful to set up a basic GDB session, with a breakpoint at `0x7c00` to debug from the start of the boot code execution:

```
gdb -ex 'lay asm' -ex 'lay regs' -ex 'target remote :1234' -ex 'set architecture i386' -ex 'b *0x7c00' -ex 'continue'
```

One thing worth noting is that GDB doesn't support real mode addressing very well, so you need to construct the flat address yourself if you want to inspect memory as follows `segment register << 4 + register (or immediate value)`. E.g.: `x/b $es * 16 + $di` in GDB.

My debugging experience in GDB was pretty unpleasant, mostly due to not finding a way to get it to interpret the instructions correctly, so I tended to use breakpoints based on addresses from the `objdump` output and `nexti` to step through instructions, again referencing the `objdump` output and not trusting the instructions displayed in GDB.

## Patching the Kernel

Having used the debugger to determine that the data copied is copied to `0x9ac00` (at least on my setup), this helps with understanding the next step in the bootkit injection: patching the kernel.

Since we know how much data was copied, and from where, we can use `dd` and `objdump` to disassemble this as code:

```
dd if=convolutedboot.bin bs=1 skip=(math 0x381) count=(math '0x342 * 0x2') > strangeness.bin
objdump -b binary -m i386 -Maddr16,data16 -D -s strangeness.bin > strangeness.s
```

We know that on calling this function, `%es` is the segment address of the function and `%eax` is zero.

The first thing the code does is to add the address of the function into a number of locations (these will turn out to be addresses used in code executed later in the process, making this code position independent).

The next thing this code does it search for a string in memory starting at the very beginning of memory. It takes the dword value at `function+0x119` and Xor's it with `0x37373737` (yielding `8b 84 24 e0` in byte order, not a little-endian number), then if that matches it tests the next 4 bytes against the value at `function+0x11d` (yielding `00 00 00 81` after xor), then 4 bytes from `function+0x121` (yielding `c4 bc 00 00` after xor), the 4 bytes from `function+0x125` (yielding `00 5b 5e 5f` after), and finally 2 bytes from `function+0x129` (yielding `5d c3` after xor).

If the data matches, then the function patches it with the data from `function+0x12b` with length `0x12`.

I ended up writing a little python program to find the full byte string and apply the patch. It turns out the patched data exists in the `vmlinuz` file used in the `kernel` PXE command.

I'm not exactly sure what the patched code is doing, but it's easy enough to compare the original code with the patched. It appears to have replaced the cleanup and return of a function to a call to another function in the copied memory:

Original:
```asm
    3178:	8b 84 24 e0 00 00 00 	mov    0xe0(%esp),%eax
    317f:	81 c4 bc 00 00 00    	add    $0xbc,%esp
    3185:	5b                   	pop    %ebx
    3186:	5e                   	pop    %esi
    3187:	5f                   	pop    %edi
    3188:	5d                   	pop    %ebp
    3189:	c3                   	ret
```

Patched:
```asm
    3178:	bb 34 ad 09 00       	mov    $0x9ad34,%ebx
    317d:	ff d3                	call   *%ebx
    317f:	eb fe                	jmp    0x317f
    3181:	5e                   	pop    %esi
    3182:	be e0 a1 70 00       	mov    $0x70a1e0,%esi
    3187:	b8 9e ad 89 95       	mov    $0x9589ad9e,%eax
```

The function called, the one at `0x9ad34` in my setup, can be disassembled, but first we should go back to the code that was adding the base address of the first function called from the bootloader to various offsets. It turns out these offsets are needed to fully understand what is going on in this function.

I wrote a small python program to patch all the offsets gathered from the assembly in `strangeness.s`, created earlier:

```python
#!/usr/bin/env python3

from struct import pack, unpack

offsets = [
    0x12c,
    0x13b,
    0x14b,
    0x15f,
    0x170,
    0x184,
    0x214,
    0x21a,
    0x2a3,
    0x27b,
    0x2c3,
    0x2c8,
    0x256,
    0x23b,
    0x263,
    0x410,
    0x322,
    0x327,
]

with open('strangeness.bin', 'rb') as inf:
    data = inf.read()
    patched_data = [b for b in data]

    for offset in offsets:
        to_patch = unpack('<I', data[offset:offset+4])[0]
        print(f'to_patch: 0x{to_patch:08x}')

        patched = to_patch + 0x9ac00

        print(f'patched: 0x{patched:08x}')

        patched_data[offset:offset+4] = list(pack('<I', patched))

    with open('callback.bin', 'wb') as outf:
        outf.write(bytes(patched_data[0x134:]))
```

This creates a new file `callback.bin`, which we can disassemble as follows:
```
objdump --adjust-vma 0x9ad34 -b binary -m i386 -D -s callback.bin > callback.s
```

The code for the function that is triggered directly from the patched kernel code looks as follows:
```asm
   9ad34:	5e                   	pop    %esi
   9ad35:	be e0 a1 70 00       	mov    $0x70a1e0,%esi
   9ad3a:	b8 9e ad 09 00       	mov    $0x9ad9e,%eax
   9ad3f:	56                   	push   %esi
   9ad40:	81 c6 9c 04 00 00    	add    $0x49c,%esi
   9ad46:	8b 1e                	mov    (%esi),%ebx
   9ad48:	89 18                	mov    %ebx,(%eax)
   9ad4a:	bf b2 ad 09 c0       	mov    $0xc009adb2,%edi
   9ad4f:	89 3e                	mov    %edi,(%esi)
   9ad51:	5e                   	pop    %esi
   9ad52:	56                   	push   %esi
   9ad53:	81 c6 00 03 00 00    	add    $0x300,%esi
   9ad59:	8b 1e                	mov    (%esi),%ebx
   9ad5b:	89 58 04             	mov    %ebx,0x4(%eax)
   9ad5e:	bf 72 ae 09 c0       	mov    $0xc009ae72,%edi
   9ad63:	89 3e                	mov    %edi,(%esi)
   9ad65:	5e                   	pop    %esi
   9ad66:	56                   	push   %esi
   9ad67:	83 c6 18             	add    $0x18,%esi
   9ad6a:	8b 1e                	mov    (%esi),%ebx
   9ad6c:	89 58 08             	mov    %ebx,0x8(%eax)
   9ad6f:	bf 32 ae 09 c0       	mov    $0xc009ae32,%edi
   9ad74:	89 3e                	mov    %edi,(%esi)
   9ad76:	5e                   	pop    %esi
   9ad77:	56                   	push   %esi
   9ad78:	81 c6 78 03 00 00    	add    $0x378,%esi
   9ad7e:	8b 1e                	mov    (%esi),%ebx
   9ad80:	89 58 0c             	mov    %ebx,0xc(%eax)
   9ad83:	bf fc ae 09 c0       	mov    $0xc009aefc,%edi
   9ad88:	89 3e                	mov    %edi,(%esi)
   9ad8a:	5e                   	pop    %esi
   9ad8b:	8b 84 24 e0 00 00 00 	mov    0xe0(%esp),%eax
   9ad92:	90                   	nop
   9ad93:	81 c4 bc 00 00 00    	add    $0xbc,%esp
   9ad99:	5b                   	pop    %ebx
   9ad9a:	5e                   	pop    %esi
   9ad9b:	5f                   	pop    %edi
   9ad9c:	5d                   	pop    %ebp
   9ad9d:	c3                   	ret
```

What this appears to be doing is saving the values of 4 function pointers, and then replacing those function pointers with the addresses of some functions in the copied data. Again, another detail I don't understand is why the addresses have `0xc0000000` added, but the other content of the values seems to immediately leap out as being the addresses of functions in the copied data. Confirming this, if a breakpoint is set at say `0xc009adb2`, it will be triggered during the system boot.

This code is also careful to replicate the epilogue of the patched function, adjusting the stack pointer and popping the expected register values before returning to the return address from the calling function, i.e. this function does not return control to its caller, but to the caller's caller.

## Understanding the Patches

To recap, it looks like the boot image patches the kernel to make a callback to a function which then replaces a number of function pointers with pointers to its own code.

After some more investigation, it appears that the callback function modifies the system call table with pointers to its own code.

It makes the following patches relative to the base address `0x70a1e0`:
- Offset `0x49c`, which divided by 4 is `0x127`, or `openat`[^openat]
- Offset `0x300`, which divided by 4 is `0xc0`, or `mmap2`[^mmap2]
- Offset `0x18`, which divided by 4 is `0x06`, or `close`[^close]
- Offset `0x378`, which divided by 4 is `0xde`, which doesn't appear to map to any system call on i386[^x86syscalls]

With this in mind, we can understand what the functions assigned to those offsets are doing a little better.

### `openat`

The patched `openat` tests the second argument for string equality with `/lib/libc.so.6`, calls the original function pointer for the system call, and saves the returned file descriptor to the address `0xc009adae`. The arguments to the system call are held in a `struct pt_regs` pointer, so the reference to `0x4(%eax)` maps to the value of `%ecx` in `struct pt_regs`, which would be the second argument to `openat`.

### `mmap2`

The patched `mmap2` call tests that we have a non-zero saved file descriptor at `0xc009adae`, compares the file descriptor argument to `mmap2` (fifth argument to the syscall, at `0x10(%eax)`) with the saved file descriptor, and if equal modifies the protection argument (`0x8(%eax)`) by doing a logical or to set the `PROT_WRITE` bit. Then, after calling the saved original function for the system call, it compares the result to ensure the call was successful, if so it tests the first word for equality with `0x4b3ff`, and if that matches it copies data from the boot image to offset `0xc6952` from the base address of the mapped segment.

Looking at the output of `readelf -lS libc.so.6` on the file extracted from the `initrd` (initial ramdisk) referenced in the boot image, it can be seen that the `.plt`, `.plt.got`, `.text`, and `__libc_freeres_fn` get mapped into the same segment in that order. Examining the `.plt` section with `objdump -j .plt -s lib.so.6`, it can be seen that the first word of the executable segment in the library is indeed equal to `0x0004b3ff` (reversing the byte order from the dumped data due to little-endian encoding).

With all this in mind, it looks like the modified `mmap2` call patches the function `key_decryptsession` in `/lib/libc.so.6` to contain completely different code, which is contained within `callback.bin`/`callback.s` with offset `0x9b01b` up to offset `0x9b072`.

We can perform this patch on the version of `libc` from the `initrd` image (assuming we already have a copy of it under `patched/libc.so.6`:
```
dd if=callback.bin bs=1 skip=(math 0x9b01b-0x9ad34) count=(math 0x9b072-0x9b01b) |
    dd conv=notrunc bs=1 seek=(math 0x19000+0xc6952) of=patched/libc.so.6
```

Where `0x19000` is the segment offset and `0xc6952` is the patch address from above, and the skip and count addresses are calculated from the start and end addresses for the copy specified in the patched `mmap2` function, taking into account the `--adjust-vma` argument used to generate the disassembly using `objdump`.

We can then use `objdump` to yield the new function definition, with all relative addresses coherent with the rest of `libc`:
```
❱ objdump -j .text --disassemble=key_decryptsession patched/libc.so.6

patched/libc.so.6:     file format elf32-i386


Disassembly of section .text:

000df952 <key_decryptsession@GLIBC_2.1>:
   df952:	05 fa b5 14 00       	add    $0x14b5fa,%eax
   df957:	60                   	pusha
   df958:	e8 00 00 00 00       	call   df95d <key_decryptsession@GLIBC_2.1+0xb>
   df95d:	5b                   	pop    %ebx
   df95e:	81 eb 5d f9 0d 00    	sub    $0xdf95d,%ebx
   df964:	81 c3 ac 4e 16 00    	add    $0x164eac,%ebx
   df96a:	8b 1b                	mov    (%ebx),%ebx
   df96c:	8b 1b                	mov    (%ebx),%ebx
   df96e:	8b 1b                	mov    (%ebx),%ebx
   df970:	81 fb 63 61 74 00    	cmp    $0x746163,%ebx
   df976:	75 2f                	jne    df9a7 <key_decryptsession@GLIBC_2.1+0x55>
   df978:	6a 07                	push   $0x7
   df97a:	68 e0 38 06 00       	push   $0x638e0
   df97f:	68 00 c0 04 08       	push   $0x804c000
   df984:	e8 00 00 00 00       	call   df989 <key_decryptsession@GLIBC_2.1+0x37>
   df989:	5b                   	pop    %ebx
   df98a:	81 eb 89 f9 0d 00    	sub    $0xdf989,%ebx
   df990:	81 c3 80 80 0b 00    	add    $0xb8080,%ebx
   df996:	ff d3                	call   *%ebx
   df998:	83 c4 0c             	add    $0xc,%esp
   df99b:	bb ad b7 ad 0d       	mov    $0xdadb7ad,%ebx
   df9a0:	b8 de 00 00 00       	mov    $0xde,%eax
   df9a5:	cd 80                	int    $0x80
   df9a7:	61                   	popa
   df9a8:	c3                   	ret
   df9a9:	10 89 c2 83 c8 ff    	adc    %cl,-0x377c3e(%ecx)
   df9af:	85 d2                	test   %edx,%edx
   df9b1:	74 16                	je     df9c9 <key_decryptsession@GLIBC_2.1+0x77>
   df9b3:	83 7c 24 10 00       	cmpl   $0x0,0x10(%esp)
   df9b8:	75 0f                	jne    df9c9 <key_decryptsession@GLIBC_2.1+0x77>
   df9ba:	8b 44 24 14          	mov    0x14(%esp),%eax
   df9be:	8b 54 24 18          	mov    0x18(%esp),%edx
   df9c2:	89 03                	mov    %eax,(%ebx)
   df9c4:	31 c0                	xor    %eax,%eax
   df9c6:	89 53 04             	mov    %edx,0x4(%ebx)
   df9c9:	8b 54 24 1c          	mov    0x1c(%esp),%edx
   df9cd:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
   df9d4:	74 05                	je     df9db <key_decryptsession@GLIBC_2.1+0x89>
   df9d6:	e8 51 75 fe ff       	call   c6f2c <__stack_chk_fail@@GLIBC_2.4>
   df9db:	83 c4 24             	add    $0x24,%esp
   df9de:	5b                   	pop    %ebx
   df9df:	5e                   	pop    %esi
   df9e0:	c3                   	ret
```

### `close`

The patched `close` just tests the equality of the closed file descriptor with the saved one, and if it matches it clears the saved file descriptor. This would prevent patching any other memory mapped file during execution, where its file descriptor happened to match due to file descriptor reuse after close.

### Novel System Call `0xde`

The newly defined system call is intrinsically tied to the patched `key_decryptsession` function. It probably makes most sense to look at the new system call in combination with the patched `key_decryptsession`.

## What is the Flag?

So far, we've been through quite a few steps to get to where we are. We can see that there a few kernel patches in place, and they coordinate to patch `libc` at the time when it is mapped into memory by the runtime linker.

It's still completely unclear what the flag could be at this point, though we have finally reached the step where we might get an answer for that.

### `key_decryptsession`

Looking at the patched `key_decryptsession`, it appears to use `call`/`pop` to perform position-independent addressing relative to `%eip`.

First it loads a pointer at offset `0x164eac` relative to the `libc` base address and dereferences it three times before performing a comparison with the loaded dword value and `cat\0`. This offset lies in the global offset table in section `.got`, and using `readelf -r` to read the relocations in `libc.so.6`, we can see that `0x164eac` is the address of a relocation named `__progname@@GLIBC_2.0`. This looks promising as an indication that the flag involves some action with the `cat` command. The multiple dereferences start from the address of the of the entry in the global offset table and yield the first four bytes of the `__progname` string for comparison.

If that comparison is equal, it pushes some arguments onto the stack and calls the function at offset `0xb8080` from the `libc` base address. `0xb8080` is the offset of the `mprotect` function, which accepts its arguments on the stack. This call, with the parameters `(0x804c000, 0x638e0, 0x7)`, which match the address and size of the executable segment in the `busybox` (non-position-independent) executable in the `initrd`, makes that segment writable in addition to its regular protection flags.

After that call is completed, it calls the new system call `0xde` with one argument: `0xdadb7ad`.

### System Call `0xde`

The newly installed system call does two distinct things: it patches the `busybox` executable if it is not already patched, otherwise it performs some operations to validate flag data.

To determine if the patch is applied, it examines address `0x80a4479`, comparing it with `0x53565755`. This address appears to correspond to the start of a function, with `0x53565755` being equivalent to `push %ebp; push %edi; push %esi; push %ebx`.

The patch is applied by xor'ing the function with the data between `0xc009b073` and `0xc009b177`, and then setting the next five bytes to values `e8 e5 61 ff ff`.

This yields the following function at address `0x80a4479`:
```asm
080a4479 <.data>:
 80a4479:	83 f8 00             	cmp    $0x0,%eax
 80a447c:	0f 84 f2 00 00 00    	je     0x80a4574
 80a4482:	80 38 73             	cmpb   $0x73,(%eax)
 80a4485:	0f 85 e9 00 00 00    	jne    0x80a4574
 80a448b:	80 78 01 65          	cmpb   $0x65,0x1(%eax)
 80a448f:	0f 85 df 00 00 00    	jne    0x80a4574
 80a4495:	80 78 02 63          	cmpb   $0x63,0x2(%eax)
 80a4499:	0f 85 d5 00 00 00    	jne    0x80a4574
 80a449f:	80 78 03 72          	cmpb   $0x72,0x3(%eax)
 80a44a3:	0f 85 cb 00 00 00    	jne    0x80a4574
 80a44a9:	80 78 04 65          	cmpb   $0x65,0x4(%eax)
 80a44ad:	0f 85 c1 00 00 00    	jne    0x80a4574
 80a44b3:	80 78 05 74          	cmpb   $0x74,0x5(%eax)
 80a44b7:	0f 85 b7 00 00 00    	jne    0x80a4574
 80a44bd:	80 78 06 00          	cmpb   $0x0,0x6(%eax)
 80a44c1:	0f 85 ad 00 00 00    	jne    0x80a4574
 80a44c7:	51                   	push   %ecx
 80a44c8:	52                   	push   %edx
 80a44c9:	50                   	push   %eax
 80a44ca:	b8 20 c1 04 08       	mov    $0x804c120,%eax
 80a44cf:	ff d0                	call   *%eax
 80a44d1:	83 c4 0c             	add    $0xc,%esp
 80a44d4:	85 c0                	test   %eax,%eax
 80a44d6:	0f 88 9f 00 00 00    	js     0x80a457b
 80a44dc:	6a 00                	push   $0x0
 80a44de:	89 e7                	mov    %esp,%edi
 80a44e0:	6a 04                	push   $0x4
 80a44e2:	57                   	push   %edi
 80a44e3:	50                   	push   %eax
 80a44e4:	bb 60 c1 04 08       	mov    $0x804c160,%ebx
 80a44e9:	ff d3                	call   *%ebx
 80a44eb:	89 c1                	mov    %eax,%ecx
 80a44ed:	58                   	pop    %eax
 80a44ee:	83 c4 08             	add    $0x8,%esp
 80a44f1:	5b                   	pop    %ebx
 80a44f2:	83 f9 04             	cmp    $0x4,%ecx
 80a44f5:	75 55                	jne    0x80a454c
 80a44f7:	69 db 0b df 96 e2    	imul   $0xe296df0b,%ebx,%ebx
 80a44fd:	81 c3 41 08 80 14    	add    $0x14800841,%ebx
 80a4503:	ba 92 a6 4a 54       	mov    $0x544aa692,%edx
 80a4508:	50                   	push   %eax
 80a4509:	b8 de 00 00 00       	mov    $0xde,%eax
 80a450e:	cd 80                	int    $0x80
 80a4510:	89 c1                	mov    %eax,%ecx
 80a4512:	58                   	pop    %eax
 80a4513:	39 d1                	cmp    %edx,%ecx
 80a4515:	75 35                	jne    0x80a454c
 80a4517:	b9 00 00 00 00       	mov    $0x0,%ecx
 80a451c:	83 f9 07             	cmp    $0x7,%ecx
 80a451f:	75 bb                	jne    0x80a44dc
 80a4521:	bf 90 d5 04 08       	mov    $0x804d590,%edi
 80a4526:	6a 43                	push   $0x43
 80a4528:	ff d7                	call   *%edi
 80a452a:	6a 6f                	push   $0x6f
 80a452c:	ff d7                	call   *%edi
 80a452e:	6a 72                	push   $0x72
 80a4530:	ff d7                	call   *%edi
 80a4532:	6a 72                	push   $0x72
 80a4534:	ff d7                	call   *%edi
 80a4536:	6a 65                	push   $0x65
 80a4538:	ff d7                	call   *%edi
 80a453a:	6a 63                	push   $0x63
 80a453c:	ff d7                	call   *%edi
 80a453e:	6a 74                	push   $0x74
 80a4540:	ff d7                	call   *%edi
 80a4542:	6a 21                	push   $0x21
 80a4544:	ff d7                	call   *%edi
 80a4546:	6a 0a                	push   $0xa
 80a4548:	ff d7                	call   *%edi
 80a454a:	eb 21                	jmp    0x80a456d
 80a454c:	bf 90 d5 04 08       	mov    $0x804d590,%edi
 80a4551:	6a 57                	push   $0x57
 80a4553:	ff d7                	call   *%edi
 80a4555:	6a 72                	push   $0x72
 80a4557:	ff d7                	call   *%edi
 80a4559:	6a 6f                	push   $0x6f
 80a455b:	ff d7                	call   *%edi
 80a455d:	6a 6e                	push   $0x6e
 80a455f:	ff d7                	call   *%edi
 80a4561:	6a 67                	push   $0x67
 80a4563:	ff d7                	call   *%edi
 80a4565:	6a 21                	push   $0x21
 80a4567:	ff d7                	call   *%edi
 80a4569:	6a 0a                	push   $0xa
 80a456b:	ff d7                	call   *%edi
 80a456d:	b8 d0 c9 04 08       	mov    $0x804c9d0,%eax
 80a4572:	ff e0                	jmp    *%eax
 80a4574:	b8 20 c1 04 08       	mov    $0x804c120,%eax
 80a4579:	ff e0                	jmp    *%eax
 80a457b:	c3                   	ret
 80a457c:	c3                   	ret
 80a457d:	e8 e5 61 ff ff       	call   0x809a767
```

Busybox makes frequent use of the `regparm`[^regparm] function attribute to have its internal functions pass parameters through `%eax`, `%edx` and `%ecx` in that order, as opposed to passing arguments on the stack as is the standard calling convention for i386.

The functions called from this function using function pointers relate to the following relocations from `libc`:
- `0x804c120` holds the address `0x80c8048`, which is marked as the relocation address for `open64@GLIBC_2.1`
- `0x804c160` holds the address `0x80c8058`, which is marked as the relocation address for `read@GLIBC_2.0`
- `0x804d590` holds the address `0x80c8564`, which is marked as the relocation address for `putchar_unlocked@GLIBC_2.0`
- `0x804c9d0` holds the address `0x80c8274`, which is marked as the relocation address for `exit@GLIBC_2.0`

With these details in mind, it appears that this function takes a filename as its first argument. If that filename is not equal to `secret`, it jumps to `open64` so that the return from `open64` will return to the caller of the patched function.

If the filename is equal to `secret`, it will call `open64` with the same parameters passed to this function.

It then calls `read` to read 4 bytes from the opened file into the dword at the top of the stack. It tests the return value to ensure exactly 4 bytes were read, and if not it jumps to a section of code that prints out "Wrong!" and exits.

So far it looks like the flag will be the contents of a file called `secret` that must have a multiple of 4 bytes of content.

Now, onto the other role of the newly installed system call `0xde`.

#### Flag validation

The code in user space proceeds as follows:

- Take the 4 bytes read from the file as `%ebx`
- Multiply the value by `0xe296df0b` (or patched value, see below)
- Add `0x14800841`
- Store `0x544aa692` (or patched value, see below) in `%edx`
- Call the system call `0xde` via `int 0x80`

In kernel space two main things are happening:
- Flag calculation:
    - The parameter in `%ebx` is multiplied by `0x45f90000` and then by itself
    - The parameter in `%ebx` is multiplied by `0xfd20dcb3`
    - These two values are then added together with `0xa0f27f57`
    - This forms a quadratic equation of the form `0x45f90000 * %ebx * %ebx + 0xfd20dcb3 * %ebx + 0xa0f27f57`
    - This value is stored on the stack (above the registers stored with `pusha`)
- Interactions with and modifications to the user space code:
    - The dword at `0x80a4518` (offset `0x9f` from the function start) is loaded and compared with 0, 1, 2, 3, 4, and 5 in sequence
        - This coincides with the immediate value used in `mov $0x0,%ecx` in the function above
    - When it matches, the offsets `0x80` and `0x8b` into the function are patched by xor'ing the existing values with inline values
        - These offsets coincide with the immediate values for the instructions `imul $0xe296df0b,%ebx,%ebx` and `mov $0x544aa692,%edx` respectively in the function above
    - After patching (or no match being found for the counter variable), the counter at `0x80a4518` is incremented

Returning to user space, the following happens:
- Compare the return value from the system call with `0x544aa692` (or patched value after the initial pass)
- If the comparison fails, jump to the code that prints "Wrong!" and exits
- If the comparison succeeds and the patched counter value is equal to 7, print "Correct!"

So, it looks like we just need to create a file called `secret`, which contains a sequence of 28 bytes that satisfies the constraints applied after the transformation split across user and kernel space.

## Finding the Flag

We can extract the relevant values from the code:
- The initial values of multiplier and target value, `0xe296df0b` and `0x544aa692` respectively
- The static values and the general form of the applied transformation
    - Multiply `%ebx` by `multiplier`
    - Add `0x14800841` to `%ebx`
    - Calculate `0x45f90000 * %ebx * %ebx + 0xfd20dcb3 * %ebx + 0xa0f27f57`
    - Compare the result with `target`
- The values which are xor'd with `multiplier` on each pass
    - `0xb0796ab2`
    - `0xccddf7bc`
    - `0x16d7ead8`
    - `0x7289e68`
    - `0xf6804ff8`
    - `0x6ea0855c`
- The values which are xor'd with `target` on each pass
    - `0x3b3211d`
    - `0x7d2691d5`
    - `0x98ad6bfb`
    - `0x4a0a9a7a`
    - `0x617e30ed`
    - `0xc28d160b`

When I first came to solve this, I was pretty tired after the amount of work to get this far, so I just wrote a brute force implementation in rust.

The brute force implementation just looks something like this (assuming you have the values for target and multiplier to pass in):
```rust
fn brute_force(target: u32, multiplier: u32) -> Option<u32> {
    for a in 0x20..0x7f {
        for b in 0x20..0x7f {
            for c in 0x20..0x7f {
                for d in 0x20..0x7f {
                    let start: u32 = (a << 24) + (b << 16) + (c << 8) + d;

                    let first = start.wrapping_mul(multiplier).wrapping_add(0x14800841);
                    let ebx = first.wrapping_mul(0x45f90000).wrapping_mul(first);
                    let ecx = first.wrapping_mul(0xfd20dcb3);

                    let result = ebx.wrapping_add(ecx).wrapping_add(0xa0f27f57);

                    if result == target {
                        return Some(start);
                    }
                }
            }
        }
    }

    None
}
```

It's not pretty but it got me the answer and took less than 3 seconds to run.

### A More Efficient Solution

I wasn't satisfied by this brute force search solution, and so investigated a more efficient solution. This took a bit of research to understand the properties of modulo arithmetic. As I saw it, adding and subtracting with integer overflow are simple to reverse, but overflowing multiplication, and particularly find the inverse of the sum of two overflowing multiplications, would be challenging.

It turns out there is a simple algorithm (the Extended Euclidean Algorithm[^exteuclid]) which can be used to find the multiplicative inverse of a number modulo N. This would be helpful in reversing the initial multiplication.

As noted earlier, part of the process is a quadratic equation. It turns out that it is possible to find the solution to a quadratic equation modulo N based on the solutions to the equation modulo the primes that comprise the prime factorization of N. In this case, we have quite a simple case, because we are only interested in solving modulo 2<sup>32</sup>.

The technique used is Hensel lifting[^hensel]. Essentially, you need to find a solution to the equation modulo the prime, and then lift the solution to each higher power until the desired power is reached (i.e. in our case, solve modulo 2, then lift the solution to modulo 4, modulo 8, all the way to modulo 2<sup>32</sup>). Solving modulo 2 is simple enough, given an exhaustive search for a solution only has to cover two possible values.

The equation we need to solve is the following:

```
0x45f90000 * x * x + 0xfd20dcb3 * x + 0xa0f27f57 - target = 0
```

With the value of `x` from the above equation, we can then subtract `0x14800841` and multiply that by the multiplicative inverse of the `multiplier` value (assuming there is one).

The following rust program implements the Extended Euclidean Algorithm for finding the multiplicative inverse modulo N, as well as solving quadratic equations modulo 2<sup>32</sup> (which also depends on the former algorithm). It runs in a matter of hundreds of microseconds, as opposed to taking seconds. Arguably the brute force method was more efficient here, since it yielded an answer much faster, taking into account time spent researching and developing the more efficient solution, but the whole point of these exercises for me is to learn something!

```rust
use std::u8;

fn main() {
    let (targets, multipliers) = initialize_targets_and_multipliers();

    let mut flag = vec![];

    for i in 0..7 {
        let answer = direct(targets[i], multipliers[i]).unwrap();

        flag.push(u8::try_from(answer & 0xff).unwrap());
        flag.push(u8::try_from((answer >> 8) & 0xff).unwrap());
        flag.push(u8::try_from((answer >> 16) & 0xff).unwrap());
        flag.push(u8::try_from((answer >> 24) & 0xff).unwrap());
    }

    println!("{}", std::str::from_utf8(flag.as_slice()).unwrap());
}

// The binary has initial values for target and multiplier, and the previous value is xor'd with a
// different value on each pass to yield a new target and multiplier.
// This function initializes the targets and multipliers as required for finding the flag.
fn initialize_targets_and_multipliers() -> (Vec<u32>, Vec<u32>) {
    let target_masks = vec![
        0x3b3211du32,
        0x7d2691d5,
        0x98ad6bfb,
        0x4a0a9a7a,
        0x617e30ed,
        0xc28d160b,
    ];
    let multiplier_masks = vec![
        0xb0796ab2u32,
        0xccddf7bc,
        0x16d7ead8,
        0x7289e68,
        0xf6804ff8,
        0x6ea0855c,
    ];

    let mut targets = vec![0u32; 7];
    let mut multipliers = vec![0u32; 7];

    targets[0] = 0x544aa692;
    multipliers[0] = 0xe296df0b;

    for (i, t) in target_masks.iter().enumerate() {
        targets[i + 1] = targets[i] ^ t
    }

    for (i, m) in multiplier_masks.iter().enumerate() {
        multipliers[i + 1] = multipliers[i] ^ m
    }

    (targets, multipliers)
}

// Calculates the solution more directly by finding multiplicative inverses and solving the
// quadratic equation in the binary
fn direct(target: u32, multiplier: u32) -> Option<u32> {
    // Quadratic parameters
    let a = 0x45f90000u32;
    let b = 0xfd20dcb3u32;
    let c = 0xa0f27f57u32.wrapping_sub(target);

    let solution = solve_quadratic(a, b, c)?;

    let inverse = multiplicative_inverse(multiplier.into(), 1 << 32)?;

    let answer = solution.wrapping_sub(0x14800841).wrapping_mul(inverse);

    Some(answer)
}

// Solve a quadratic equation of the form a*x^2 + b*x + c = 0 (mod 2^32)
fn solve_quadratic(a: u32, b: u32, c: u32) -> Option<u32> {
    let mut solutions = vec![];

    let (a, b, c) = (a as u64, b as u64, c as u64);

    if c % 2 == 0 {
        solutions.push(0);
    } else if ((a % 2) + (b % 2) + (c % 2)) % 2 == 0 {
        solutions.push(1);
    } else {
        return None;
    }

    for power in 1..32 {
        let m = 1 << power;

        for s in solutions.iter_mut() {
            let x = *s;

            // Value of the quadratic at x
            let fx = a
                .wrapping_mul(x)
                .wrapping_mul(x)
                .wrapping_add(b.wrapping_mul(x))
                .wrapping_add(c);

            // If the previous solution is also valid with this modulus, we can exit early
            if fx & ((m << 1) - 1) == 0 {
                continue;
            }

            // Value of derivative of the quadratic at x
            let dfx = a.wrapping_mul(2).wrapping_mul(x).wrapping_add(b);

            // If fx == 0 or dfx == 0 then there is no solution. m should always divide fx, so this
            // is added as a sanity check.
            if fx == 0 || dfx == 0 || fx % m != 0 {
                return None;
            }

            // Least residue of -(fx / m) (mod m)
            let target = m - ((fx >> power) & (m - 1));

            // Perform Hensel lifting to raise the previous solution to the new modulus
            // We need to find n s.t (fx / m) + dfx.n = 0 (mod m)
            let n = target.wrapping_mul(multiplicative_inverse(dfx, m)? as u64) & (m - 1);

            // Lift solution (mod 2^p) to (mod 2^(p+1))
            *s = m.wrapping_mul(n).wrapping_add(x) & ((m << 1) - 1);
        }
    }

    // We expect only only one solution to our quadratic. If there are more than one, return None
    // to flag the mismatched expectation so the logic can be re-evaluated.
    if solutions.len() == 1 {
        Some(solutions[0] as u32)
    } else {
        None
    }
}

// Attempt to find the inverse of x (mod m) such that x * x = 1 (mod m) using the extended Euclidean
// algorithm, return None if no inverse can be found.
fn multiplicative_inverse(x: u64, m: u64) -> Option<u32> {
    let m = m as i64;

    let mut r = (x as i64, m as i64);
    let mut s = (1, 0);

    loop {
        let q = r.0 / r.1;

        r = (r.1, r.0 - q * r.1);
        s = (s.1, s.0 - q * s.1);

        if r.1 == 0 {
            return if r.0 == 1 {
                Some((s.0 % m) as u32)
            } else {
                None
            };
        }
    }
}
```

[^pxenv]: [https://github.com/ipxe/ipxe/blob/8fc11d8a4ad41f15af3d081250865f971312d871/src/arch/x86/interface/pxe/pxe_entry.S#L179-L222](https://github.com/ipxe/ipxe/blob/8fc11d8a4ad41f15af3d081250865f971312d871/src/arch/x86/interface/pxe/pxe_entry.S#L179-L222)

[^rmaddr]: Having dug a bit deeper, it appears that the address `0x413` holds the number of kilobytes before the extended BIOS data area (EBDA) or unusable memory, as a segment address. The code appears to reserve some memory at the end of the "conventional memory" area, and then utilize that memory to store its own code, so as to preserve it beyond boot. [http://wiki.osdev.org/Memory_Map_(x86)](http://wiki.osdev.org/Memory_Map_(x86))

[^openat]: [https://www.man7.org/linux/man-pages/man2/openat.2.html](https://www.man7.org/linux/man-pages/man2/openat.2.html)

[^mmap2]: [https://www.man7.org/linux/man-pages/man2/mmap2.2.html](https://www.man7.org/linux/man-pages/man2/mmap2.2.html)

[^close]: [https://www.man7.org/linux/man-pages/man2/close.2.html](https://www.man7.org/linux/man-pages/man2/close.2.html)

[^x86syscalls]: [https://x86.syscall.sh/](https://x86.syscall.sh/)

[^regparm]: [https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html#index-regparm-function-attribute_002c-x86](https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html#index-regparm-function-attribute_002c-x86)

[^exteuclid]: [https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)

[^hensel]: [https://en.wikipedia.org/wiki/Hensel's_lemma](https://en.wikipedia.org/wiki/Hensel's_lemma)
