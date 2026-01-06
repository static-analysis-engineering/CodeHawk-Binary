### Function Annotations

Function annotations can be used to improve the quality of a decompilation of
a function to C code. A function annotation ranges from names and types for
register and stack
variables to corrections to reaching definitions and typing inference rules.

**Format**

The top-level format of function annotations is a list of individual function
annotations:
```
{
    "userdata": {
        ...
        {
            "function-annotations": [
                {
                    "faddr": <function-address in hex>,
                    "register-variable-introductions": [
                        ...
                    ],
                    "stack-variable-introductions: [
                        ...
                    ],
                    "typing-rules": [
                        ...
                    ],
                    "remove-reaching-definitions": [
                        ...
                    ]
                },
                ...
           }
       }
}
```
where all properties are optional except for the function address.

**Format: register-variable-introductions**:

The format for **register-variable introductions** is a list of individual
register annotations
```
     [
         {
             "iaddr": <instruction-address in hex>,
             "name": <chosen name>,
             "typename": <name of a data type>,
             "mods": [<modifications of the type>]
         },
         {
             ...
         
     ]
```
The instruction address is the address of the instruction where the
register to be renamed gets assigned, that is, the register is the
left-hand side in an instruction (assignment or call). If a register
gets assigned in multiple paths in parallel, the instruction address
should be the lowest address. These introductions can be considered
as ssa (static single assignment) locations. 

The chosen name is the name to be given to the register. The name will
be used in the lifting as long as the register has the current definition.
It is the user's responsibility to ensure that there are no name clashes
with other variables. 

The type name is the name of the type of the register for that particular
assignment (a register can have many types during its lifetime within a
function). The type name is either a primitive C type (like int or
unsigned short, etc.) or the name of a type for which a typedef is given
in the header file. The reason for restricting the type name to simple
names is that full-featured C parsing needs to be applied when reading
in these files. For convenience, some modifications can be added to the
mods property to modify the typename: 
- <code>ptrto</code>: indicating that the register type is a pointer to
  the type indicated by the type name
- <code>cast</code>: indicating that the type given should override the
  type that may have been inferred by type inference. Adding <code>cast</code>
  furthermore ensures that the assigning instruction will be exposed in
  the lifting.

*Note:* The name of the register itself does not have to be included in
the record, as it is automatically inferred from the instruction address.
At present the annotation is limited to instructions with a single LHS
register. That is, instructions that assign to multiple registers such
as the ARM instructions <code>LDM</code> or ARM call instructions that
assign to both <code>R0</code> and <code>R1</code> are currently not
handled.

*Note:* The typename is optional. The analyzer performs its own type inference
based on function signatures and other type information. Unless types are
introduced that are not present in any function signatures or other type
information it is often better to omit the typename initially and only add
a typename if a typename is not inferred automatically.

**Example: register-variable-introductions:**

```
                "register-variable-introductions": [
                    {
                        "iaddr": "0xe2b34",
                        "name": "t",
                        "typename": "EVP_PKEY_ASN1_METHOD",
                        "mods": ["ptrto", "cast"]
                    },
                    {
                        "iaddr": "0xe2b40",
                        "name": "flags",
                        "typename": "unsigned long"
                    },
                    {
                        "iaddr": "0xe2b88",
                        "name": "obj"
                    },
                    ...
```

**Format: stack-variable-introductions:**

The format for **stack-variable-introductions** is a list of individual
(local) stack variable annotations:
```
    [
        {
            "offset": <offset in bytes (positive)>,
            "name": <chosen name>
            "typename": <name of a data type>,
            "mods": [<modifications of the type>]
        },
        {
            ...
     ]
```
The offset is the offset *in bytes* where the stack variable is located, defined
as 
```
<address of stack-pointer at function entry> - <start address of stack variable>
```
Note that this number must be positive as the stack grows down, and thus any
local stack variable is located at an address that is less in value than the
address of the stack-pointer at function entry.

The name, typename, and mods are the same as for register-variable introductions
with the exception that stack variables can have an additional type of modification
expressed in the mods property:
- <code>array:\<n\></code>: indicating that the stack variable type is an array
  of <code>n</code> elements of the type given.

It is the user's responsibility to ensure that stack variables do not overlap and
that names do not clash with each other or with register variables.


**Example: stack-variable-introductions:**

```
                "stack-variable-introductions": [
                    {
                        "offset": 32,
                        "name": "md",
                        "typename": "unsigned char",
                        "mods": ["array:16"]
                    },
                    {
                        "offset": 56,
                        "name": "md_ctx",
                        "typename": "EVP_MD_CTX"
                    }
                ]
```

**Format: remove-reaching-definitions:**

The format for **remove-reaching-definitions** is a list of register variables
associated with the reaching definitions to be removed:
```
    [
        {
            "var": <name-of-register>,
            "uselocs": [ hex-addresses ],
            "rdeflocs": [ hex-addresses ]
        },
        {
            ...
    ]
```
The <code>var</code> property holds the name of the register for which the
addresses given in the <code>rdeflocs</code> property are to be removed 
from the instructions with addresses given in the <code>uselocs</code> property.
