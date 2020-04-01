A toy C-compiler for the RW2a instruction set
=============================================

A C compiler building executables only using five primitive instructions, which
can be run using the virtual machine from https://github.com/rolfwr/rwisa-vm

The RW instuction set can be summarized as:

| Opcode           | Description    | C-like implementation              |
| ---------------- | -------------- | ---------------------------------- |
| 00               | Halt           | exit(0)                            |
| 01 srcptr        | Output Byte    | putchar(mem[srcptr])               |
| 02 jmpptr srcptr | Branch If Plus | if (mem[srcptr] < 128) pc = jmpptr |
| 03 dstptr srcptr | Subtract       | mem[dstptr] -= mem[srcptr]         |
| 04 dstptr        | Input Byte     | mem[dstptr] = getchar()            |

The trailing bytes following an opcode byte indicated by srcptr, dstptr and
jmpptr represent little endian encoded unsigned integer values that refer
to memory locations. For ISA identifiers suffixed by "2" such as RWa2 and RWb2,
the these are four byte little endian unsigned integers. I.e. this format uses
32-bit pointers.

The RWa2 executable image is headerless, meaning that the first byte of an
executable image contains the first opcode to be executed.