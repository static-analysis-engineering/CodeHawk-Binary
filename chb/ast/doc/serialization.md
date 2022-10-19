# Patching Intermediate Representation (PIR)

## Serialization Format

Serialization of the AST representation is in json format.

The json file contains the following items at the top level:

- **global-symbol-table**: symbol table with type definitions and global variable
  definitions, including function prototypes.

- **functions**: a list of records, one for each function.

For each function, the json structure contains a record with the following items:

- **name**: name of the function (can be the same as the address).
- **va**: virtual address of the function
- **prototype**: type-index of the function prototype
- **ast**: a record containing a list of nodes representing the high-level and
  low-level AST, and starting indices for both
- **spans**: a list of span records that map location ids and expressions ids
  to addresses in the binary (see [below](#spans))
- **provenance**: a mapping from the high-level ast representation to the low-level
  ast representation, including reaching definitions and definitions used
  (described [here](./api.md#provenance)).
- **available-expressions**: a mapping from instruction addresses to expressions
  available in any lvalue visible at that address (see [below](#available-expressions)).
- **storage**: a mapping from lvalues to locations in the binary (see [below](#storage))


### Spans

Spans provide a connection between entities in the AST and (virtual) addresses
in the assembly code. There are currently two kinds of spans:
- **instruction spans**: an instruction span record contains the location id
  of an ASTInstruction, together with a list of spans consisting of a base address
  and a size that indicates the number of bytes that are related, which should
  cover an integral number of assembly instructions. A list is provided to allow
  for multiple non-contigous ranges.
  ```
        {
          "locationid": 6,
          "spans": [
            {
              "base_va": "0xcc6",
              "size": 2
            }
          ]
        },
  ```
- **expression spans**: an expression span record contains the expression id
  of an ASTExpr, together with a list of of spans as before. Expression spans
  are intended to provide a connection from AST to assembly code for those
  assembly instructions that do not have corresponding AST instructions, in
  particular, return statements and branches. At present these are provided
  only for return statements that return a value, and for conditional branches,
  where the return expression and the condition, respectively, are linked, via
  their id, to the return instruction(s) and conditional branch instruction.
  An expression span is represented in the json ast file as follows:
  ```
        {
          "exprid": 346,
          "spans": [
            {
              "base_va": "0xd26",
              "size": 2
            }
          ]
        },
  ```


### Available Expressions

Available expressions provide information at each instruction address which
expressions are available in registers and possibly stack variables. It is
currently represented as a mapping from address to the name of the variable
to the expression represented as a string:
```
instruction address (as hex-string)
    -> variable name
          -> (id of variable lval node,
	          id of expression node,
	          expression (as string))
```

Note that the id of the variable is not the lvalid, but the id of the node,
and similarly the id of the expression is not the exprid, but the id of the
expression node. The reason to use the id rather than the lvalid/exprid is
that these lvals and expressions do not directly correspond to lvals or
expressions in the assembly code, since most of the lvals are not accessed
at most of the locations. Furthermore, making these lvals and expressions
anonymous, allows for sharing these lvals and expressions across different
locations.


### Storage

Storage provides a mapping from lvals to physical storage locations with
optionally a size (in bytes):
```
lval-id -> physical location * (optional size)
```

where
physical storage locations may include:
- *registers* (architecture specific);
- *stack locations*, specified by a byte offset from the stack-pointer at function
  entry;
- *heap locations*, specified by a base pointer and a byte offset;
- *global locations*, specified by their virtual address

The mapping need not be total, since the physical location of an lvalue may not
be known or may not be constant (e.g., an array element, represented by the
lvalue a[i], may have many different physical locations).