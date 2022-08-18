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
- **spans**: a list of span records that map location ids to addresses in the binary;
- **provenance**: a mapping from the high-level ast representation to the low-level
  ast representation, including reaching definitions and definitions used
  (described [here](./api.md#provenance)).
- **available-expressions**: a mapping from instruction addresses to expressions
  available in any lvalue visible at that address (pending).
- **storage**: a mapping from lvalues to locations in the binary (see [below](#storage))


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