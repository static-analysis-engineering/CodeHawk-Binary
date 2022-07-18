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
  ast representation (see [below](#provenance))
- **available-expressions**: a mapping from instruction addresses to expressions
  available in any lvalue visible at that address (see [below](#available-expressions))
- **definitions-used**: a mapping from definitions to their uses
  (see [below](#definitions-used))
- **storage**: a mapping from lvalues to locations in the binary (see [below](#storage))


### Provenance

Provenance relates the high-level AST representation to the low-level representation.
It consists of two parts:
1. **Instruction Mapping**: A mapping from high-level instructions
   to low-level instructions:
   ```
   high-level instr-id -> low-level instr-id list
   ```
2. **Reaching Definitions**: A mapping from expressions in either low level
   or high level instructions to the instructions that <ins>may</ins> define them.
   ```
   expr-id -> instr-id list
   ```
3. **Expression Mapping**: A mapping from expressions (either high-level or
   low-level) to lists of expressions (at the same or a lower level).
   ```
   expr-id -> expr-id list
   ```

### Available Expressions<a name="available-expressions"></a>

Available expressions (similar to Use-Def in static analysis parlance)
provide information at each instruction which
expressions are available in which variables. It is a mapping from instruction
addresses to a list of records with the following data.

- *variable name*: the variable name can either be a low-level variable name
  like a register (e.g., R3) or a high-level variable name (e.g., a stack
  variable, with its given name);
- *instr-id*: the instr-id of the instruction that <ins>must</ins> have
  assigned the variable, this
  can either be a high-level instruction or a low-level instruction;
- *expr*: a string representation of the expression. This item is for
  information only, since it is implied by the instr-id;
- *(optional) type of the expression*

This information relies on the availability of data-flow analysis results.
Incorrect information can affect the correctness of the patch. Too little
information may lead to larger-than-necessary patches.

### Definitions Used<a name="definitions-used"></a>

Used definitions (similar to Def-Use in static analysis parlance) provide
information for each definition which other instructions <ins>may</ins>
make use of this definition. This is useful to determine if a change in
this definition impacts other instructions than the one targeted for patching.

It is a mapping from instruction addresses to records with the following data:
- *low-level instr-id*: the instruction that performs the definition
- *list of low-level instr-ids*: the instructions that <ins>may</ins>
  use the definition

The reason to include the instr-id of the instruction that performs the
definition is that for each instruction address there may be multiple
instructions.

Similar to Available Expressions, Definitions Used relies on the availability
of data-flow analysis results. Incorrect information (e.g., a particular use
of a definition is omitted) may lead to incorrect patches.


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