### Arm-Thumb switch points

**Description**

ARM binaries may mix the ARM and Thumb-2 representation for code. The analyzer
supports both representations. In many binaries these switch points are indicated
in the binary itself by the compiler (this is always the case for binaries
compiled with debug, and often in other binaries as well). However, if the
swich points are not explicitly present in the binary, the current version of
the disassembler cannot automatically
determine them. For these binaries the user has the option to manually indicate
the switch points in the userdata.

**Format**

A list of addresses followed by a colon and the letter 'T' or 'A'
that indicate starting addresses of Thumb-2 and ARM code representation regions.


**Example**

```
{
   "userdata": {
       ....
       "arm-thumb": [
           "0x18638:A",
           "0x18908:T",
           "0x18950:A",
           "0x18974:T",
           "0x21210:A"
        ]
    }
}
```
