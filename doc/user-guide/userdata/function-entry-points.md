### Function Entry Points

**Description**

For most binaries the disassembler is able to determine all function entry points
automatically. In some cases, however, some function entry points may be missed,
and may be manually pointed out in the userdata.

**Format**

A list of addresses that are the starting address of a function.

**Example**
```
{
    "userdata": {
        ...
        "function-entry-points": [
            "0xa0100044",
            "0xa010011c",
            "0xa0100292",
            "0xa010029c",
            "0xa0100710",
            "0xa010072a",
            ...
         ]
     }
}
```

**Finding Function Entry Points**

Low function coverage may be an indicator of function entry points missed.
Function coverage is defined as the ratio of the number of instructions that
are part of some function and the total number of instructions in the code
sections (minus confirmed embedded data regions). Function coverage is
displayed in the printed output when running the disassembler (without
analysis):

```
> chkx analyze -d <binary>
...
Disassembly        : 0.16
Construct functions: 0.86
Disassembly information: 
   Instructions         : 32699
   Unknown instructions : 0
   Functions            : 429 (coverage: 96.68%)
   Function overlap     : 993 (counting multiples: 993)
   Jumptables           : 16
   Data blocks          : 20
...
```

To aid the identificaton of function entry points, the disassembler prints
out a (text) file that contains a listing of all instructions not contained
in functions. E.g.,
```
> chkx analyze -d <binary>
...
> more <binary>.cch/a/<binary>_orphan.log
...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Data block (size: 12 bytes)

  0x9870      Code:<0x295d4>
  0x9874      FAddr:<0x9914>
  0x9878      Code:<0x9300>
================================================================================

    0x987c  08 40 2d e9       PUSH         {R3,LR}
    0x9880  2c 30 9f e5       LDR          R3, 0x98b4
    0x9884  00 30 d3 e5       LDRB         R3, [R3]
    0x9888  00 00 53 e3       CMP          R3, #0
    0x988c  08 80 bd 18       POPNE        {R3,PC}
  B 0x9890  20 30 9f e5       LDR          R3, 0x98b8
    0x9894  00 00 53 e3       CMP          R3, #0
    0x9898  01 00 00 0a       BEQ          0x98a4
  B 0x989c  18 00 9f e5       LDR          R0, 0x98bc
    0x98a0  23 ff ff eb       BL           0x9534
  B 0x98a4  08 30 9f e5       LDR          R3, 0x98b4
    0x98a8  01 20 a0 e3       MOV          R2, #1
    0x98ac  00 20 c3 e5       STRB         R2, [R3]
    0x98b0  08 80 bd e8       POP          {R3,PC}
  B 0x98b4  38 64 03 00       ANDEQ        R6, R3, R8,LSR R4
    0x98b8  00 00 00 00       ANDEQ        R0, R0, R0
    0x98bc  cc dd 02 00       ANDEQ        SP, R2, R12,ASR#27
    0x98c0  08 40 2d e9       PUSH         {R3,LR}
    0x98c4  34 30 9f e5       LDR          R3, 0x9900
    0x98c8  00 00 53 e3       CMP          R3, #0
    0x98cc  02 00 00 0a       BEQ          0x98dc
  B 0x98d0  2c 00 9f e5       LDR          R0, 0x9904
    0x98d4  2c 10 9f e5       LDR          R1, 0x9908
    0x98d8  cc ff ff eb       BL           0x9810
  B 0x98dc  28 00 9f e5       LDR          R0, 0x990c
    0x98e0  00 30 90 e5       LDR          R3, [R0]
    0x98e4  00 00 53 e3       CMP          R3, #0
    0x98e8  08 80 bd 08       POPEQ        {R3,PC}
  B 0x98ec  1c 30 9f e5       LDR          R3, 0x9910
    0x98f0  00 00 53 e3       CMP          R3, #0
    0x98f4  08 80 bd 08       POPEQ        {R3,PC}
  B 0x98f8  33 ff 2f e1       BLX          R3
    0x98fc  08 80 bd e8       POP          {R3,PC}
...
```
Missing function entry points are easy to spot at 0x987c and 0x98c0.