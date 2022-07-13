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
- **ast**: a list of nodes representing the high-level and low-level AST,
  with starting indices for both
- **spans**: a list of span records that map location ids to addresses in the binary;
- **provenance**: a mapping from the high-level ast representation to the low-level
  ast representation (see [below](#provenance))
- **available-expressions**: a mapping from instruction addresses to expressions
  available in any lvalue visible at that address (see [below](#available-expressions))
- **used-definitions**: a mapping from definitions to their uses
  (see [below](#used-definitions))
- **storage**: a mapping from lvalues to locations in the binary (see [below](#storage))


### Provenance

Provenance relates the high-level AST representation to the low-level representation.
It consists of two parts:
1. A mapping from high-level instructions to low-level instructions:
   ```
   high-level instr-id -> low-level instr-id list
   ```
2. Within the low level, for every instruction, a mapping from lval-expressions
   in that instruction to instructions that may have defined that lval
   ```
   low-level instr-id -> lval-expr-id -> low-level instr-id list
   ```

The low-level lval-expr relationships include both right-hand side and left-hand
sides of assignments and calls, as, for example, in the store instruction:
```
*(R7 + 4) = R2 + R5
```
the lval-expressions are R7, R2, and R5, and thus for each of these a link is
provided to the instruction that may define them, allowing the tracing of address
computations.

For a load instruction, such as
```
R5 = *(R7 + 4)
```
the lval-expressions are R7 and <code>(\*(R7 + 4))</code>. Providing provenance for
<code>\*(R7 + 4)</code> requires knowing which memory location is referenced,
which is not always possible. If the memory location is not known, the lval-expr
should not be included in the provenance.

We may want to include a third type of provenance, that maps low-level lval-expressions
(or equivalently, lvals) to high-level lval-expressions (or lvals), for example, for
the load instruction above we could have:
```
*(R7 + 4) maps to stackvar_24
```
that is, the lval-expression references the variable stackvar_24 (which has a
known location, the stack location at 24 bytes offset from
the function top-of-the-stack).

Of course this mapping may be different for each instruction, so we would have

3. A mapping from low-level to high-level lval-expressions (or lvals) for each instruction:
   ```
   low-level instr-id -> low-level lval-expr-id -> high-level lval-expr-id
   ```

There may be some debate about what is considered a *known location*, e.g., is
an lval expressed as
```
bumper->brake_state
```
where bumper is an argument to the function, a known location?


### Available Expressions<a name="available-expressions"></a>

Available expressions (similar to Use-Def in static analysis parlance)
provide information at each (low-level) instruction which
expressions are available in which registers. It is a mapping from instruction
addresses to records with the following data:
- *register name*: e.g., R3, R7, etc.
- *low-level instr-id*: the instr-id of the instruction that assigned the value
  in the register that still is in the register at this address;
- *low-level expr*: for information only, since it is implied by the instr-id
- *(optional) type of the expression*

We may want to extend this to other lvals beyond registers, but those would
probably not be directly usable by the patcher (since they require setting up
the address first).

Note that the mapping is necessarily partial and considered best-effort;
it may be left empty entirely if this information is not available.

### Used Definitions<a name="used-definitions"></a>

Used definitions (similar to Def-Use in static analysis parlance) provide
information for each definition which other instructions make use of this
definition. This is useful to determine if a change in this definition impacts
other instructions than the one targeted for patching.

It is a mapping from instruction addresses to records with the following data:
- *low-level instr-id*: the instruction that performs the definition
- *list of low-level instr-ids*: the instructions that use the definition

The reason to include the instr-id of the instruction that performs the
definition is that for each instruction address there may be multiple
instructions.

If a mapping for a particular instruction address is included the list of
low-level instr-ids should be exact or an over-approximation to avoid
unintended effects of patches. This mapping also is best-effort and
may be left empty entirely if this information is not available.


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
  entry);
- *heap locations*, specified by a base pointer and a byte offset;
- *global locations*, specified by their virtual address

Again, this mapping is best effort, since a physical location may not be known
for every lvalue.