+++
title = "Hack The Box - PTRACE_NOPEEKING"
description = "A write-up for the Hack The Box reverse engineering challenge \"PTRACE_NOPEEKING\""
date = "2024-09-15"
[taxonomies]
categories=["Hack The Box", "Reversing"]
+++
I'm going to try my first write up for a Hack The Box challenge, because I thought this one was cool!

## Introduction

This genre of challenge involves reverse engineering an executable to find a flag. The flag is typically user input that triggers some success condition. This input could be provided to a remote connection or, in the case of this exercise, no remote connection is required, meaning that the flag must be encoded in the executable itself somehow.

I tend to start with an open mind, more considering what the program does than what might constitute its flag.

The zip archive downloaded from Hack The Box for this challenge contains a single file: a Linux x86_64 executable named `nopeeking`. The executable is stripped, so no hints from symbol names.

On startup, the program calls `mmap` to set up some shared memory for interprocess communication, and then calls `fork` to create a child process.

The child process sets up bidirectional `ptrace` attachment by triggering the parent process to
trace it, and then attaching to the parent process, writing its own pid to the parent process (to
indicate it has attached) and continuing the parent process.

This circular `ptrace` setup is where things get interesting. This means we can't attach a debugger to the process for easy dynamic analysis. If we try to attach to either running process, we get "operation not permitted" because the process is already being traced. If we try to start the process under the debugger, it breaks the process to the point where the flag prompt is never shown.

## Process Setup

After forking, the parent process enters a wait loop, essentially waiting for the child to complete its ptrace attachments. It waits for a value to be populated in a static variable I labelled `global_tracee_pid`. The pid itself isn't too important at this point, given the `fork` call returns the child pid, but it is significant as a synchronization step.

The child process makes a number of `ptrace` calls to set up the circular tracing. Essentially, the following:
```c
ptrace(PTRACE_TRACEME, parent_pid, 0, 0);
ptrace(PTRACE_ATTACH, parent_pid, 0, 0);
ptrace(PTRACE_POKETEXT, parent_pid, &global_tracee_pid, pid);
ptrace(PTRACE_CONT, parent_pid, 0, 0);
```

This attaches the parent to trace the child, attaches the child to trace the parent, writes the child pid to the address of the static variable the parent is waiting on, and then resumes execution of the parent.

The initial process setup looks something like the following:

![Process setup diagram](/images/htb-ptrace-nopeeking/setup.mermaid.svg)

## Continued Execution

After the initial tracing setup has completed, there are two main routines that run in both child and parent processes:
- one that waits for the tracee process to stop, and then examines the place where the process stopped and potentially performs some interaction with the tracee process dependent on where it stopped
- one that validates the flag input, and contains `ud2` instructions at various points to trigger the process to stop and the tracer process to interact with its tracee

The two processes run concurrently. There is a mutex to prevent both
processes entering their flag validation routine at the same time, so only one process will ever stop at any given time due to executing the `ud2` instruction.

### Global Variables and Shared Data

In terms of the shared memory set up with `mmap`, these fall into two categories:
- A sort of mutex implementation to prevent both processes entering code that might cause them to stop at the same time
    - Let's call these `mmap_child_active`, `mmap_parent_active` and `mmap_parent_child`
- The flag input character buffer and index
    - Let's call these `mmap_flag_input` and `mmap_flag_index`

There are also a few process-local global variables that are important:
- Some kind of global state at `0x202118`. The value at the address referenced by this pointer determines the code path taken in the flag validation functions.
    - Let's call this `global_state_ptr`, and the value at the address `global_state`
- The tracee pid at `0x202140`
    - Let's call this `global_tracee_pid`
- The value of the current character being processed (after some processing) at `0x202144`
    - Let's call this `global_current_char`
- A boolean flag at `0x202180`
    - Let's call this `global_flag_valid`
- An index at `0x202184`
    - Let's call this `global_flag_data_index`

There are also some static data arrays, which are used to validate the flag:
- There is a boolean array (stored as 32 bit values) starting at `0x202020`
    - Let's call this `global_bit_flags`
- There is are two arrays of bytes (stored as 32 bit vlaues) starting at `0x2020A0` and `0x2020E0`
    - Let's call these `global_flag_data_part2` and `global_flag_data_part1` respectively

### Wait and Interact Routine

This is where I started reading and understanding the program. I think it's the better place to start the description too, because it gives a lot of context to the structure of the flag validation routines.

This routine is called by both parent and child processes, and takes two arguments: a pid and a boolean flag. Essentially, there is one meaningful argument, given every call passes a value of `1` for the boolean flag.

The boolean flag determines whether `wait` is called or `waitpid` is called to wait for the specified pid, and the latter path is always taken.

The entry to this function essentially looks like the following in pseudo C:
```c,linenos
int waitstatus;
int stopsig;
int tag;
struct user_regs_struct pt_regs;

if (0 == waitpid(pid, &waitstatus, WNOHANG)) {
    return;
}
if (WTERMSIG(waitstatus) == 0) {
    return;
}
if (!WIFSTOPPED(waitstatus)) {
    return;
}
stopsig = WSTOPSIG(waitstatus);

ptrace(PTRACE_GETREGS, pid, 0, &pt_regs);

tag = ptrace(PTRACE_PEEKTEXT, pid, pt_regs.rip, 0) >> 16;

if (SIGILL != stopsig) {
    return;
}

if (tag == <value>) {
    // do something
} 
```

This code does the following:
- test that the tracee process stopped (line 6), if not return
- test that the terminating signal for the tracee != 0 (line 9), if not return
  - I'm not sure about this, and may be wrong! It doesn't really make sense to me, but this macro is the only one I could see with a definition consistent with the assembly.
  - This test seems redundant, given it boils down to `(waitstatus && 0x7f) != 0` when the next test is `(waitstatus && 0xff) == 0x7f`
- test if the tracee stopped due to a signal (line 12), if not return
- find the signal that caused the tracee to stop (line 15)
- fetch the registers from the tracee (line 17)
- fetch the <acronym title="Double word, i.e. 4 bytes">dword</acronym> at the address referenced by the instruction pointer in the tracee (line 19)
    - shift the fetched value right by 16 to retain only the upper two bytes of the original dword
- test that the signal that caused the tracee was the expected `SIGILL` (illegal instruction), if not return
- branch to different code paths based on the value of `tag`

After executing the `ud2` instruction, and triggering the illegal instruction exception, the instruction pointer `rip` still points to the `ud2` instruction[^ud2].

Since the `ud2` instruction is two bytes in length, the `PTRACE_PEEKTEXT` call loads the `ud2` instruction and the next two bytes. Since x86_64 is a little-endian architecture, the `ud2` bytes `0f0b` occupy the lower bytes of the dword read (as `0x0b0f`). Shifting right by 16 bits retain only the upper two bytes and obtains what I'll call the "tag" which is used by the tracer to determine what action it should take next.

There is a long chain of comparisons between this "tag" and various constant values to determine the next code path in the tracer. These code paths interact with registers in the tracee, static variables local to the tracer and tracee, or shared memory setup earlier with `mmap`.

After executing the specific branch, the tracer code uses more ptrace calls to advance the instruction pointer `rip` in the tracee by 4 bytes and continue the process. This causes the instruction pointer to advance just past the `ud2` instruction and the "tag".

In pseudo-C, continuing from the above block:
```c
pt_regs.rip += 4;
ptrace(PTRACE_SETREGS, pid, 0, &pt_regs);
ptrace(PTRACE_CONT, pid, 0, 0);
```

At this point, I think it makes sense to talk more about what is happening in the tracee.

### Flag Validation Routine

In the tracee, the flag validation routine is executed in steps that end with a `ud2` instruction. This instruction generates an illegal instruction exception in the tracee, and passes control to the tracer.

The general structure of the flag validation procedure, is as follows:

```
<procedure instructions>
ud2
<two byte tag>
<procedure instructions>
ud2
<two byte tag>
...
```

The `<two byte tag>` is the tag referenced in the previous section.

This structure makes these procedures more challenging to disassemble, given the disassembler (quite reasonably) assumes that the data immediately following the `ud2` instruction will be more instructions, but it is actually some arbitrary data.

The disassembly in the free version of IDA[^ida] looks sensible from the entry point until the first `ud2` instruction is encountered. At best, the IDA output yields isolated blocks where it's hard to see where the execution will resume after the tracer makes the `ptrace` call to continue the tracee. At worst, since the tag is being interpreted as part of the instructions, it can be interpreted as part of an instruction  whose length isn't 2 bytes, leading to the disassembly of subsequent instructions being incorrect!

For example, consider the instructions following the `ud2` instruction at address `0x1296` in the following disassembly from `objdump`:
```
1296: 0f 0b                        	ud2
1298: 55                           	push	rbp
1299: 4f c7 45 dc 00 00 00 00      	mov	qword ptr [r13 - 36], 0
12a1: 48 8b 05 70 0e 20 00         	mov	rax, qword ptr [rip + 2100848] # 0x202118
...
```

After the bytes `0f 0b` at address `0x1298` (the `ud2` instruction), the next instruction is `push rbp` (opcode `0x55`) and after that we have `mov qword ptr [r13 - 36], 0`, whose first byte is `0x4f`. Note that after a `ud2` instruction we expect a two byte "tag" to inform the tracer's code path when the tracee stops, and `0x4f55` is one value explicitly tested for by the function that interacts with the tracee.

What we actually want for the disassembly at these addresses looks more like the following:
```
1296: 0f 0b                         ud2
1998: 55 4f                         [TAG, do not disassemble]     
129A: c7 45 dc 00 00 00 00          mov dword ptr [rbp-24h], 0
12A1: 48 8b 05 70 0e 20 00          mov rax, qword ptr [rip + 2100848] # 0x202118
...
```

In order to disassemble the code in these functions, I wrote a python script using the [iced-x86](https://github.com/icedland/iced) python bindings. The script served two purposes for me, both disassembling the code as it is executed, but also making it clear which "tag" is seen by the tracer process after each `ud2` instruction, to be able to more easily reconstruct the entire code executed as a sequence of instructions.

To do this, I first followed the flow in both flag flag validation functions (parent and child) to find the first `ud2` instruction executed in the initial state. With these addresses, I could write a python script to replicate the implementation seen in the tracer process. That is:
- Disassemble until encountering a `ud2` instruction
- Fetch and print the tag
- Advance the instruction pointer by 4 bytes
- Continue disassembling from the new location
- Terminate on encountering a `ret` instruction

```python
from iced_x86 import Decoder, Formatter, FormatterSyntax

data = b''

with open('nopeeking', 'rb') as f:
    data = f.read()

formatter = Formatter(FormatterSyntax.MASM)
formatter.branch_leading_zeros = False
formatter.space_after_operand_separator = True

// These addresses are the entry points to the `ud2`-heavy flows
for rip in (0x1047, 0x127A):
    cont = True

    while cont:
        decoder = Decoder(64, data[rip:], ip=rip)

        for instr in decoder:
            finstr = formatter.format(instr)
            print(f'{instr.ip:04X}h {finstr}')

            if finstr == 'ud2':
                tag = data[instr.next_ip] + (data[instr.next_ip+1] << 8)
                rip = instr.ip + 4

                print('---')
                print(f'TAG: 0x{tag:02X}')
                print('---')
                break

            if finstr == 'ret':
                cont = False
                break

    print('='*80)
```

This outputs something like the following:
```
❱ python3 ud2.py
1047h mov dword ptr [202184h], 0
1051h mov dword ptr [202180h], 1
105Bh mov eax, 0
1060h mov r8d, eax
1063h ud2
---
TAG: 0x4F55
---
1067h ud2
---
TAG: 0x5253
---
106Bh mov dword ptr [rbp-20h], 0
1072h mov rax, [202118h]
1079h mov word ptr [rax], 0D4h
107Eh cmp dword ptr [rbp-20h], 0
1082h jne near ptr 11D9h
1088h mov eax, 0
108Dh jmp near ptr 121Fh
1092h mov rax, [202158h]
1099h mov eax, [rax]
109Bh cdqe
109Dh lea rdx, [rax*4]
10A5h lea rax, [202020h]
10ACh mov eax, [rdx+rax]
10AFh test eax, eax
10B1h jne short 10C4h
10B3h ud2
---
TAG: 0x4743
---
... (long output truncated)
```

This both reconstructs the tracee function as a linear set of instructions and outputs the tag so the behaviour triggered in the tracer can easily be determined.

For example, the tag `0x5253` is only present in the code executed by the child process, and triggers the parent to read the flag from standard input.

## Understanding How The Flag Is Actually Validated

I started out by trying to understand the validation function in the child process, because its validation function contains a call to `puts("The first half of the flag looks correct")`. This turned out to be a red herring, because the flag is not verified as halves in a straightforward manner - the halves are interleaved with each other.

The child and parent processes only handle half of the flag input each. Which process handles which byte is determined by the `global_bit_flags` data. If the value is `0` for the corresponding index then the child processes the byte, if it is `1` then the parent processes the byte.

I have chosen to say that the child/parent processes the byte, based on the flag validation function passing that initial test. The actual validation of the data is done in the other process from the one that initially consumes the byte (as opposed to generating a random number). This is the detail that it took me longest to figure out.

Both processes are constantly racing, and if the wrong process enters its validation function for a given index, then it generates a random byte that will eventually be ignored. If the correct process enters its validation function for a given index, then then the value is marked with a bit flag `0x200` to indicate it should affect the validation outcome.

There is a transform applied to the flag input provided to the user, which converts the user input into a form that can be directly compared to the data in `global_flag_data_part1` and `global_flag_data_part2`.

The input transform that is applied (both to actual input characters and random bytes) is as follows:
```asm
mov     rax, [rbp+pt_regs.r8]
movzx   edx, al
mov     rax, cs:mmap_flag_index
mov     eax, [rax]
sub     edx, eax
mov     eax, edx
lea     edx, [rax+1Ah]
mov     rax, cs:mmap_flag_index
mov     eax, [rax]
sub     eax, 1
imul    eax, 2Ch ; ','
xor     eax, edx
mov     eax, eax
movzx   eax, al
mov     [rbp+pt_regs.rax], rax
```

As C code:
```c
output = (((value & 0xff) - mmap_flag_index + 0x1a) ^ (0x2c * (mmap_flag_index - 1))) & 0xff
```

This transform is dependent on the character position, so we need to know in which order the data in `global_flag_data_part1` and `global_flag_data_part2` are compared to its output. This code section is also a good example of the tracer process taking input from register `r8` from the tracee, applying its own processing to it, and then passing it back to the tracee through register `rax`.

The next crucial step after this is for the _tracer_ to store the transformed value in `global_current_char` in the _tracee_. The next step after this in the tracer is for it to load the value of `global_current_char` in its own process memory into the tracee's `rax` register.

It is at this point that the tracee checks the appropriate bit flags are set (and that this should affect the validation outcome), before optionally passing it to the validation function, which just does an equality check, setting `global_flag_valid` to `0` if any character is invalid.

The tricky part here is that the process that started processing the current character isn't the one to actually validate that character. So, while the child process takes the first character (given `global_bit_flags[0] == 0`), it passes that value to the parent process to actually perform the test, and so it tests it against `global_flag_data_part2[global_flag_data_index]`. It is only while the parnt process is the tracee that it performs this test.

I was puzzled for quite a while, having thought I understood how the flag input was being transformed, how it could possibly reach the values in what I labelled `global_flag_data_part1`. I think part of my flawed thinking came from being influenced by the success message mentioned earlier with the `puts("The first half of the flag looks correct")` call in the function only called in the child process.

In any case, with all this in mind, it was quite simple to write a python script to generate the correct flag input, by applying the inverse of the transform listed above to the appropriate value from `global_flag_data_part1` or `global_flag_data_part2`.

```python
#!/usr/bin/env python3

import operator
import struct


def unpack_dwords(data):
    count = len(data) >> 2

    result = []

    for index in range(count):
        result.append(struct.unpack('<l', data[index*4:index*4+4])[0])

    return result


data = b''

with open('nopeeking', 'rb') as f:
    data = f.read()

# File offset of global_bit_flags
bits = unpack_dwords(data[0x2020:0x208c])

# File offset of global_flag_data_part1
data_1 = unpack_dwords(data[0x20e0:0x2118])
# File offset of global_flag_data_part2
data_2 = unpack_dwords(data[0x20a0:0x20d4])

result = ''

index_1 = 0
index_2 = 0

for (i, b) in enumerate(bits):
    v = 0
    if b == 0:
        v = data_2[index_1]
        index_1 += 1
    else:
        v = data_1[index_2]
        index_2 += 1

    mask = operator.and_(0xff, 0x2c * i)

    res = operator.xor(mask, v) - 0x1a + i + 1

    result += chr(res)

print(result)
```

This script loads the data directly from the `nopeeking` executable, then applies the inverse of the transform function described above, and finally prints out the flag.

[^ud2]: [https://www.felixcloutier.com/x86/ud](https://www.felixcloutier.com/x86/ud)

[^ida]: [https://hex-rays.com/ida-free/](https://hex-rays.com/ida-free/)
