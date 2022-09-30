# Patching Intermediate Representation (PIR)

## Abstract Syntax Tree Construction API

- [Statements](#statements)
- [Statement labels](#labels)
- [Instructions](#instructions)
- [Variables](#variables)
- [Storage](#storage)
- [Offsets](#offsets)
- [Other lvals and expressions](#otherlvals)
- [Unary and binary operators](#operators)
- [Types](#types)
- [Provenance](#provenance)


### Statements

Statements provide the control flow structure of a program. The most
elementary statement is the instruction sequence that contains a
list of instructions. This statement typically serves to represent
a basic block in a binary. Statements can be composed hierarchically
to form a tree, for example a branch statement has two child
statements: the if branch and the else branch; a loop statement has
one child statement: the loop body. A sequence of statements can
be combined into a statement block.

Statements are also used to represent so-called unstructured control
flow, with GoTos. At its most basic level any control flow graph,
which usually is readily available for a function in an executable,
can be converted into a tree of statements using goTos, branches,
and switches. To produce more readable code, a more sophisticated
control-flow-graph destructuring is usually preferable. To provide
provenance relationships we may have a low-level CFG-based abstract
syntax tree that includes all assembly instructions and a high-level
structured abstract syntax tree for readable output representation.

Statements have a stmtid that uniquely identifies the statement, and
that is used as destination identification for unstructured control
flow constructs such as goTos. Statements also have a locationid
that can be used to relate the statement to a location in the binary,
usually expressed by a span that can represent one or more ranges
of addresses in the binary.

Statements may also have one or more labels that can be used in
identifying the statement in C, or that serve as the case selectors
in a switch statement.

All of the statement construction methods below have an optional
argument for the stmtid and the locationid. If either or both are
not present a new value is generated automatically.


#### Construction methods provided

- **mk_block**: creates a collection of statements that are executed
  sequentially. An initially empty node may be created first, with
  statements being added to them later, in case of a top-down
  construction. Each time a statement is added a new object is returned,
  as ASTNode objects are immutable.
  ```
  def mk_block(self,
    stmts: List[ASTStmt],
    stmtid: Optional[int],
    locationid: Optional[int],
    labels: List[ASTLabel] = []) -> ASTBlock
  ```

- **mk_loop**: repeats the given statement (which will often be a block)
  by wrapping it with an infinite loop construct (e.g. `while (1)`).
  ```
  def mk_loop(
    self,
    body: AST.ASTStmt,
    stmtid: Optional[int] = None,
    locationid: Optional[int] = None) -> AST.ASTLoop
  ```

- **mk_return_stmt**: creates a return statement with an optional
  return expression.
  ```
  def mk_return_stmt(self,
    expr: Optional[ASTExpr],
    stmtid: Optional[int],
    locationid: Optional[int],
    labels: List[ASTLabel] = []) -> ASTReturn
  ```

- **mk_break_stmt**: creates a break statement.
  ```
  def mk_break_stmt(self,
    stmtid: Optional[int],
    locationid: Optional[int]) -> ASTBreak
  ```

- **mk_continue_stmt**: creates a continue statement.
  ```
  def mk_continue_stmt(self,
    stmtid: Optional[int],
    locationid: Optional[int]) -> ASTContinue
  ```

- **mk_branch**: creates a if-then-else statement with a condition
  expression and if and else branches as child statements. The target
  address is the address in hex of the target of the conditional
  jump.
  ```
  def mk_branch(self,
    condition: ASTExpr,
    ifbranch: ASTStmt,
    elsebranch: ASTStmt,
    targetaddr: str,
    stmtid: Optional[int],
    locationid: Optional[int],
    labels: List[ASTLabel] = []) -> ASTBranch
  ```

- **mk_instr_sequence**: creates a statement for a basic block with
  a sequence of assignments and calls.
  ```
  def mk_instr_sequence(self,
    instrs: List[ASTInstruction],
    stmtid: Optional[int],
    locationid: Optional[int],
    labels: List[ASTLabel] = []) -> ASTInstrSequence
  ```

- **mk_goto_stmt**: creates a goTo statement with a label name as destination;
  the destination address is the target address of the jump instruction, in hex.
  ```
  def mk_goto_stmt(self,
    destinationlabel: str,
    destinationaddress: str,
    stmtid: Optional[int],
    locationid: Optional[int],
    labels: List[ASTLabel] = []) -> ASTGoto
  ```

- **mk_switch_stmt**: creates a switch statement with a switch expression and
  cases as child statements. It is the callers responsibility to make sure that
  the child statements have the appropriate case labels.
  ```
  def mk_switch_stmt(self,
    switchexpr: ASTExpr,
    cases: List[ASTStmt],
    stmtid: Optional[int],
    locationid: Optional[int],
    labels: List[ASTLabel] = []) -> ASTSwitch
  ```

### Statement Labels<a name="labels"></a>

Labels serve two purposes: to provide a named statement as target
for a goto in a C program, and to provide the case labels in a switch
statement.

#### Construction methods

**mk_label**: creates a label that sets a marker in the control flow,
  to be used as a target for a goto statement.
  ```
  def mk_label(self,
    name: str,
    locationid: Optional[int]) -> ASTLabel
  ```

**mk_case_label**: creates a case label for a switch statement with
  a single expression.
  ```
  def mk_case_label(self,
    expr: ASTExpr,
    locationid: Optional[int]) -> ASTCaseLabel
  ```

**mk_case_range_label**: creates a case label for a switch statement
   for a range of values, expressed by its minimum value and maximum
   value (syntax is a gcc extension, it is not in the C standard).
   ```
   def mk_case_range_label(self,
     lowexpr: ASTExpr,
     highexpr: ASTExpr,
     locationid: Optional[int]) -> ASTCaseRangeLabel
   ```

**mk_default_label**: creates a default case label for a switch statement.
  ```
  def mk_default_label(self, locationid: Optional[int]) -> ASTDefaultLabel
  ```


### Instructions

Instructions represent actions that do not involve control flow (at
least within the function) and that are always executed sequentially.
The sole exception is a call to a non-returning function that also
acts as a return statement. Instructions are always grouped as a
sequence within an instruction sequence statement.

There are two types of instructions: an assignment and a call. An
assignment consists of a left-hand-side (lval) and a right-hand-side
(expression). A call consists
of an optional left-hand-side (lval) to which the return value from the call is
assigned, an expression that is the target of the call (an lval expression
of a variable of type function in case of a direct call, or any other
expression in case of an indirect call), and a list of expressions that
represent the arguments to the call (preferably in conformance with the
arity of the function type, but this is not checked).

Instructions have an instrid that uniquely identifies the instruction
and that is used in expressing provenance relationships.
Instructions, like statements, have a locationid that can be used to
relate the statement to a location in the binary.

Instructions in the high-level representations can be linked to instructions
at the low-level. The construction methods have an optional argument
low_level_instrids to record this relationship. A link can also be made
directly with the method <code>addto_instruction_mapping</code>.


#### Construction methods provided

- **mk_assign**: creates an assignment from a lhs (lval) and rhs (expression)
  ```
  def mk_assign(self,
    lval: ASTLval,
    rhs: ASTExpr,
    instrid: Optional[int] = None,
    locationid: Optional[int] = None,
    low_level_instrids: List[int] = []) -> ASTAssign
  ```

- **mk_call**: creates a call from an optional lhs (lval), a target (expression),
  and a list of arguments (expressions)
  ```
  def mk_call(self,
    lval: Optional[ASTLval],
    tgt: ASTExpr,
    args: List[ASTExpr],
    instrid: Optional[int] = None,
    locationid: Optional[int] = None,
    low_level_instruids: List[int] = []) -> ASTCall
  ```

- **mk_var_assign**: creates an assignment from a variable name and rhs
  (expression); an lval with the given name is created (as described
  below under Variables)
  ```
  def mk_var_assign(self,
    vname: str,
    rhs: ASTExpr,
    optinstrid: Optional[int] = None,
    oplocationid: Optional[int] = None,
    low_level_instrids: List[int] = []) -> ASTAssign
  ```
  
- **mk_var_var_assign**: creates an assignment from one variable name to another
  variable name; an lval and lval-expression for the two variables is
  created (as described below under Variables)
  ```
  def mk_var_var_assign(
    self, vname: str,
    rhsname: str,
    optinstrid: Optional[int] = None,
    optlocationid: Optional[int] = None,
    low_level_instrids: List[int] = []) -> ASTAssign
  ```

- **mk_var_call**: creates a call instruction with a variable name as lhs argument
  ```
  def mk_var_call(self,
    vname: str,
    tgt: ASTExpr,
    args: List[ASTExpr],
    optinstrid: Optional[int] = None,
    optlocationid: Optional[int] = None,
    low_level_instrids: List[int] = []) -> ASTCall
  ```
- **mk_tgt_call**: creates a call instruction with a function name as tgt expression
  ```
  def mk_tgt_call(self,
    lval: Optional[ASTLval],
    tgtname: str,
    args: List[ASTExpr],
    optinstrid: Optional[int] = None,
    optlocationid: Optional[int] = None,
    low_level_instrids: List[int] = []) -> ASTCall
  ```

- **mk_default_call**: creates a call instruction with only a function name and
  arguments, and optionally a type for the function name; this method tries
  to determine if the function has a return value (i.e., does not return
  void). If so it will create a tmp variable with a description that
  indicates this variable holds a return value from the named function,
  if the function has void return type, the lval is set to None.
  ```
  def mk_default_call(self,
    tgtvname: str,
    args: List[ASTExpr],
    tgtvtype: Optional[ASTTyp],
    optinstrid: Optional[int] = None,
    optlocationid: Optional[int] = None,
    low_level_instrids: List[int] = []) -> ASTCall
  ```

- **addto_instruction_mapping**: creates an explicit link between a
  high-level instruction and one or more low-level instructions.
  ```
  def addto_instruction_mapping(self,
    high_level_instrid: int,
    low_level_instrids: List[int]) -> None
  ```

### Variables

Variables have a name. For named variables it is the user's responsibility
to ensure that distinct variables (i.e. distinct storage locations) have
distinct names (within a function) and that distinct global variables have
distinct names (across all functions). Local variables in different
functions may have the same name (functions have different name spaces).

The basic data structure for a variable is the ASTVarInfo, which holds the
name, type (optional), the parameter index (zero-based) if the variable is
a formal parameter to a function, the global address (optional) if the
address is known, and an optional description of what the variable holds.
The varinfo is stored in the local or global symbol table on first creation.

The first creation of the varinfo determines the associate data. Once a
variable exists (either in the global or local symbol table)
subsequent calls to create a variable with the same name (in the same name
space) result in retrieval of the existing varinfo rather than creating a
new one, thereby ignoring the associate data provided.

Only one instance exists of the ASTVarInfo data structure, held in the
symboltable for each name. Multiple instances of related ASTVariable,
ASTLval, and ASTLvalExpr may exist within the abstract syntax tree structure

Lvalues have unique identifiers to distinguish them in space and time.

Lvalues generally have storage, which can be specified as an optional
argument to lval creation. Three methods, <code>mk_register_variable_lval</code>,
<code>mk_flag_variable_lval</code>
and <code>mk_stack_variable_lval</code> create a storage record automatically.

Temporary variables are automatically given unique names. Temporary variables
have no storage.


#### Construction methods provided

- **mk_vinfo**: creates/returns a varinfo data structure from the symboltable
  a vinfo is considered global if (1) it has a global address, or (2) its
  type is a function type.
  A vinfo can be forced global by giving it a global address of 0, if the
  actual address is not known.
  ```
  def mk_vinfo(self,
       vname: str,
       vtype: Optional[ASTTyp] = None,
       parameter: Optional[int] = None,
       globaladdress: Optional[int] = None,
       vdescr: Optional[str] = None) -> ASTVarInfo
  ```
  
- **mk_vinfo_variable**: creates/returns a variable from a vinfo
  ```
  def mk_vinfo_variable(self, vinfo: ASTVarInfo) -> ASTVariable
  ```

- **mk_lval**: creates/returns an lval from an lhost and an offset
  ```
  def mk_lval(self,
        lhost: ASTLHost,
	offset: ASTOffset,
	storage: Optional[ASTStorage] = None) -> ASTLval
  ```

- **mk_vinfo_lval**: creates/returns an lval (lhs) (with optional offset) from
  a vinfo
  ```
  def mk_vinfo_lval(self,
        vinfo: ASTVarInfo,
	offset: ASTOffset = nooffset,
	storage: Optional[ASTStorage] = None) -> ASTLval
  ```
  
- **mk_vinfo_lval_expression**: creates/returns an lval-expression (rhs) (with
  optional offset) from a vinfo
  ```
  def mk_vinfo_lval_expression(self,
       vinfo: ASTVarInfo,
       offset: ASTOffset = nooffset,
       storage: Optional[ASTStorage] = None) -> ASTLvalExpression
  ```

- **mk_named_variable**: creates a variable with the given a name (and will
  implicitly create a varinfo, if necessary)
  ```
  def mk_named_variable(self,
       vname: str,
       vtype: Optional[ASTTyp] = None,
       parameter: Optional[int] = None,
       globaladdress: Optional[int] = None,
       vdescr: Optional[str] = None) -> ASTVariable
   ```
  
- **mk_named_lval**: creates an lval (lhs) (with optional offset) with the given
  name
  ```
  def mk_named_lval(self,
       vname: str,
       vtype: Optional[ASTTyp] = None,
       parameter: Optional[int] = None,
       globaladdress: Optional[int] = None,
       vdescr: Optional[str] = None,
       offset: ASTOffset = nooffset,
       storage: Optional[ASTStorage] = None) -> ASTLval
  ```
  
- **mk_named_lval_expression**: creates an lval expression (rhs) (with optional
  offset) with the given name
  ```
  def mk_named_lval_expression(self,
       vname: str,
       vtype: Optional[ASTTyp] = None,
       parameter: Optional[int] = None,
       globaladdress: Optional[int] = None,
       vdescr: Optional[str] = None,
       offset: ASTOffset = nooffset,
       storage: Optional[ASTStorage] = None) -> ASTLvalExpression
  ```

- **mk_register_variable_lval**: creates an lval for a register and automatically
  creates a storage record for the register, with an optional argument for the
  name of the register if the name of the register is not the same as the name of
  the variable to be created
  ```
  def mk_register_variable_lval(self,
       name: str,
       registername: Optional[str] = None,
       vtype: Optional[ASTTyp] = None,
       parameter: Optional[int] = None,
       vdescr: Optional[str] = None) -> ASTLval
  ```

- **mk_flag_variable_lval**: creates an lval for a (processor) flag and automatically
  creates a storage record for the flag, with an optional argument for the name
  of the flag if the name of the flag is not the same as the name the variable to
  be created
  ```
  def mk_flag_variable_lval(self,
      name: str,
      flagname: Optional[str] = None,
      vdescr: Optional[str] = None) -> ASTLval
  ```

- **mk_stack_variable_lval**: creates an lval for a stack variable and automatically
  creates a storage record for the stack variable. The offset is specified as an
  offset from the stack pointer at function entry, in bytes (negative for local
  variables, positive for the parent stack frame)
  ```
  def mk_stack_variable_lval(self,
       name: str,
       offset: int,
       vtype: Optional[ASTTyp] = None,
       parameter: Optional[int] = None,
       vdescr: Optional[str] = None,
       size: Optional[int] = None) -> ASTLval
  ```

- **mk_tmp_variable**: creates a new varinfo/variable with a unique name
  ```
  def mk_tmp_variable(self, vtype: Optional[ASTTyp], vdescr: Optional[str]) -> ASTVariable
  ```

- **mk_tmp_lval**: creates a new varinfo/lval (lhs) with a unique name
  ```
  def mk_tmp_variable(self, vtype: Optional[ASTTyp], vdescr: Optional[str]) -> ASTLval
  ```

- **mk_tmp_lval_expression**: creates new varinfo/lval-expression (rhs) with a
  unique name
  ```
  def mk_tmp_variable(self, vtype: Optional[ASTTyp], vdescr: Optional[str]) -> ASTLvalExpression
  ```

### Storage

Lvalues are (mostly) associated with physical locations in the architecture
such as registers, flags, stack locations, heap locations, and global locations.
From a function point-of-view five distinct types of storage are recognized:
- registers: this includes the standard CPU registers, but may also include
  the processor status word, or individual flags in the processor status
  words. Registers are identified by their name.
- flags: flags in the processor status word can also be separately identified.
  Flags are identified by their name.
- stack locations: these are memory locations identified by a fixed offset
  (specified in bytes) from the stack pointer value at function entry.
  Offsets can be positive (parent stack frame or argument slots) or negative
  (local stack frame) or zero (return address on x86, local stack frame on ARM).
- base locations: these are memory locations identified by a fixed offset
  (specified in bytes) from a base pointer, specified by an expression
  (represented by a string) that is guaranteed to be constant throughout the
  lifetime of the function, e.g., a pointer argument to the function.
- global locations: these are memory locations identified by their virtual
  address (represented as a hex string).

Storage locations may optionally have a size (specified in bits), or can be
set to be the default word size of the architecture (e.g., 32 bits for
ARM32/Thumb2 or x86).

#### Construction methods provided

- **mk_register_storage**: create a storage record for a register with a
  known (registered) register name. The size of the register is determined
  from a dictionary of register sizes.
  ```
  def mk_register_storage(self, name: str) -> ASTRegisterStorage
  ```

- **mk_flag_storage**: create a storage record for a flag with a known
  (registered) flag name.

- **mk_stack_storage**: create a storage record for a stack slot (in either
  the parent stack frame or the local stack frame) by providing the offset
  from the value of the stack pointer at function entry (in bytes) and,
  optionally, the size of the stack slot.
  ```
  def mk_stack_storage(self, offset: int, size: Optional[int]) -> ASTStackStorage
  ```

- **mk_base_storage**: create a storage record for a memory location with
  an unambiguously specified base pointer (an expression represented by a
  string), which can be a pointer passed as argument to the function, or
  a return value from a call to malloc within the function, or any other
  pointer returned by a call to some function within the function at hand.
  ```
  def mk_base_storage(self, base: str, offset: int, size: Optional[int]) -> ASTBaseStorage
  ```

- **mk_global_storage**: create a storage record for a global memory location
  specified by its address, represented as a hex string.
  ```
  def mk_global_storage(self, address: str, size: Optional[int]) -> ASTGlobalStorage
  ```


### Offsets

The default offset in lval creation is NoOffset, provided as constant
value <code>nooffset</code>.

The other two options are a field offset (to access struct fields) and
an index offset (to access array elements).

To create a field offset, create a the compinfo data structure first to
obtain the compkey value of the struct. The type of the field can then
be obtained from the compinfo data structure.

An index offset can be created either with an integer or with an expression;
note that by C semantics the index offset must be scaled by the size of
the array element.

The field offset and index offset can have sub-offsets. Default for these
sub-offsets is <code>nooffset</code>.


#### Construction methods provided:

- **mk_field_offset**: create a field offset from the name of the field and
  the key of corresponding struct (compinfo)
  ```
  def mk_field_offset(self,
       fieldname: str, compkey: int, offset: ASTOffset = nooffset) -> ASTFieldOffset
  ```

- **mk_scalar_index_offset**: create an index offset from an integer value
  ```
  def mk_scalar_index_offset(self,
       index: int, offset: ASTOffset = nooffset) -> ASTIndexOffset
  ```

- **mk_expr_index_offset**: create an index offset from an expression
  ```
  def mk_expr_index_offset(self,
       indexexpr: ASTExpr, offset: ASTOffset = nooffset) -> ASTIndexOffset
  ```


### Other lvals and expressions<a name="otherlvals"></a>

Lvals (lhs) can also be made from dereferenced pointer expressions
(memory reference, or memref expressions).

Several kinds of other expressions can be created, some with operators defined
[here](#operators).


#### Construction methods provided:

- **mk_lval_expression**: create an lval expression for a generic lhost and offset
  ```
  def mk_lval_expression(self, lval: ASTLval) -> ASTLvalExpr
  ```

- **mk_memref**: create an lhs base value (lhost) from an expression
  ```
  def mk_memref(self, memexp: ASTExpr) -> ASTMemRef
  ```

- **mk_memref_lval**: create an lval (lhs) from a memref and an offset
  ```
  def mk_memref_lval(self, memexp: ASTExpr, offset: ASTOffset = nooffset) -> ASTLval
  ```

- **mk_memref_expression**: create an val expression (rhs) from a a memref
  and an offset
  ```
  def mk_memref_expression(self, memexp: ASTExpr, offset: ASTOffset = nooffset) -> ASTExpr
  ```

- **mk_integer_constant**: create an integer constant from an integer
  ```
  def mk_integer_constant(self, cvalue: int) -> ASTIntegerConstant
  ```

- **mk_string_constant**: create a string constant from a string and the
  expression that produced the string address, and the string address
  itself (in hex) (to ensure proper identification)
  ```
  def mk_string_constant(self,
       expr: Optional[ASTExpr],
       cstr: str,
       string_address: Optional[str] = None) -> ASTStringConstant
  ```

- **mk_unary_expression**: create an expression that applies a unary operator
  to an expression (for op see [operators](#operators))
  ```
  def mk_unary_expression(self, op: str, exp: ASTExpr) -> ASTExpr
  ```
  
- **mk_binary_expression**: create an expression that applies a binary operator
  to two expressions (for op see [operators](#operators))
  ```
  def mk_binary_expression(self, op: str, exp1: ASTExpr, exp2: ASTExpr) -> ASTExpr
  ```
  
- **mk_question_expression**: create an expression that applies the question
  operator to three expressions
  ```
  def mk_question_expression(self,
       exp1: ASTExpr, exp2: ASTExpr, exp3: ASTExpr) -> ASTExpr
  ```

- **mk_address_of_expression**: create an expression that applies the address-of
  operator to an lval
  ```
  def mk_address_of_expression(self, lval: ASTLval) -> ASTExpr
  ```
  
- **mk_cast_expression**: create an expression that casts another expression to
  a given type
  ```
  def mk_cast_expression(self, tgttyp: ASTTyp, exp: ASTExpr) -> ASTExpr
  ```

- **mk_sizeof_expression**: create an expression that takes the size of a type
  ```
  def mk_sizeof_expression(self, typ: ASTTyp) -> ASTExpr
  ```

#### Some special-purpose expressions

- **mk_plus_expression**: create a sum binary expression
  ```
  def mk_plus_expression(self, exp1: ASTExpr, exp2: ASTExpr) -> ASTExpr
  ```

- **mk_minus_expression**: create a difference binary expression
  ```
  def mk_minus_expression(self, exp1: ASTExpr, exp2: ASTExpr) -> ASTExpr
  ```

- **mk_multiplication_expression**: create a product binary expression
  ```
  def mk_multiplication_expression(self, exp1: ASTExpr, exp2: ASTExpr) -> ASTExpr
  ```

- **mk_negation_expression**: create a negation unary expression
  ```
  def mk_negation_expression(self, exp: ASTExpr) -> ASTExpr
  ```

- **mk_bitwise_not_expression**: create a bitwise not unary expression
  ```
  def mk_bitwise_not_expression(self, exp: ASTExpr) -> ASTExpr
  ```

- **mk_logical_not_expression**: create a logical not unary expression
  ```
  def mk_logical_no_expression(self, exp: ASTExpr) -> ASTExpr
  ```


### Unary and Binary Operators<a name="operators"></a>

The operators for the unary and binary expression nodes are expressed by their names
represented as strings. The following names are recognized:

#### Unary operators
| operator name | pretty-printed | description |
| :---:          | :---:         | :---        |
| <code>bnot</code> | <code> ~ </code> | bitwise not |
| <code>lnot</code> | <code> ! </code> | logical not |
| <code>neg</code>  | <code> -</code>  | unary minus |


#### Binary operators
| operator name | pretty-printed | description |
| :---:         | :---:          | :---        |
| <code>and</code> | <code> && </code> | logical and |
| <code>asr</code> | <code> >> </code> | arithmetic shift right |
| <code>band</code> | <code> & </code> | bitwise and |
| <code>bor</code> | <code> \| </code>  | bitwise or |
| <code>bxor</code> | <code> ^ </code> | bitwise xor |
| <code>div</code> | <code> / </code>  | integer division |
| <code>eq</code>  | <code> == </code> | equal |
| <code>ge</code>  | <code> >= </code> | greater than or equal to |
| <code>gt</code>  | <code> > </code>  | greater than |
| <code>land</code> | <code> && </code> | logical and |
| <code>le</code> | <code> <= </code> | less than or equal to |
| <code>lor</code> | <code> \|\| </code> | logical or |
| <code>lsl</code> | <code> << </code> | logical shift left |
| <code>lsr</code> | <code> >> </code> | logical shift right |
| <code>lt</code> | <code> < </code> | less than |
| <code>minus</code> | <code> - </code> | subtraction |
| <code>mod</code> | <code> % </code> | modulo |
| <code>mult</code> | <code> * </code> | multiplication |
| <code>ne</code> | <code> != </code> | not equal |
| <code>plus</code> | <code> + </code> | addition |


### Types

#### Integer and Floatint Point Types

Integer and Float types can be created directly with their [ikind](#ikind) or
[fkind](#fkind) specifiers with

- **mk_integer_ikind_type**:
  ```
  def mk_integer_ikind_type(self, ikind: str) -> ASTTypInt
  ```

- **mk_float_fkind_type**:
  ```
  def mk_float_fkind_type**(self, fkind: str) -> ASTTypFloat
  ```

They can also be obtained as properties of the AbstractSyntaxTree object:

- **char_type**
- **signed_char_type**
- **unsigned_char_type**
- **bool_type**
- **int_type**
- **unsigned_int_type**
- **short_type**
- **unsigned_short_type**
- **long_type**
- **unsigned_long_type**
- **long_long_type**
- **unsigned_long_long_type**

and for floats:

- **float_type**
- **double_type**
- **long_double_type**

#### Construction methods for other types

- **mk_pointer_type**: Specify the type of the data pointed at:
  ```
  def mk_pointer_type(self, tgttyp: ASTTyp) -> ASTTyp
  ```

- **mk_array_type**: Specify the element type and, optionally, an expression for the
  number of elements:
  ```
  def mk_array_type(self, tgttype: ASTTyp, size: Optional[ASTExpr]) -> ASTTyp
  ```

- **mk_int_sized_array_type**: Specify the element type and the declared size:
  ```
  def mk_int_sized_array_type(self, tgttype: ASTTyp, size: int) -> ASTTyp
  ```


#### Construction methods for structs

Struct types are specified by the compinfo data structure, ASTCompInfo. Compinfo
data structures are uniquely identified by an integer key (ckey) to be provided
by the user. When a new compinfo is created it is registers in the global symbol
table; subsequent attempts to create a compinfo with the same ckey value will
just return the one created earlier. It is also possible to pre-populate the
global symbol table with compinfo data structures, if they are available up front.
Struct types are thus global and shared by different functions. Field offsets also
include the ckey of the compinfo that they belong to.

- **mk_compinfo**: Specify the fields as FieldInfos:
  ```
  def mk_compinfo(
     self, cname: str, ckey: int, fieldinfos: List[ASTFieldInfo],
     is_union: bool) -> ASTCompInfo
  ```

- **mk_compinfo_with_fields**: Specify the fields as a list of (name, type) tuples:
  ```
  def mk_cominfo_with_fields(
     self, cname: str, ckey: int, fields: List[Tuple[str, ASTTyp]],
     is_union: bool) -> ASTCompInfo
   ```

- **mk_fieldinfo**: Specify the name and type for a single field, with they key
  of the compinfo to which it belongs; optionally the byte offset at which the
  field is located within the struct can be specified as well:
  ```
  def mk_fieldinfo(
     self, fname: str, ftype: ASTTyp, ckey: int, byteoffset: Optional[int]) -> ASTFieldInfo
  ```

- **mk_comp_type**: Specify a compinfo to get a struct type. The compinfo will be added
  to the symbol table, so that subsequent declarations may specify only the key and the
  name:
  ```
  def mk_comp_type(self, cinfo: ASTCompInfo) -> AST.ASTTypComp
  ```

- **mk_comp_type_by_key**: Specify a compinfo ckey value and struct name to get a struct
  type; the corresponding compinfo must have been added earlier to use this method.
  ```
  def mk_comp_type_by_key(self, ckey: int, cname: str) -> ASTTypComp
  ```

#### Construction methods for enums

Enum types are specified by the enuminfo data structure, ASTEnumInfo. Enuminfo data
structures are uniquely identified by their name (enumname) to be provided by the
user. Each enum type has an enumkind, specified by a string (same as ikind for integers)
that specifies the particular kind of integer used for this enum. The individual enum
values are specified the enumitem data structure, ASTEnumItem, that specifies the
name (itemname) and the value as an expression (ASTExpr).

- **mk_enum_info**: Specify the enum items as EnumItems:
  ```
  def mk_enum_info(
     self, enumname: str, enumkind: str, enumitems: List[ASTEnumItem]) -> ASTEnumInfo
  ```

- **mk_enuminfo_with_constants**: Specify the enum items as of a list of (name, integer
  value) tuples:
  ```
  def mk_enuminfo_with_constants(
     self, enumname: str, enumkind: str, enumitems: List[Tuple[str, int]]) -> ASTEnumInfo
  ```

- **mk_enum_item**: Specify the name and expression for a single enumeration value:
  ```
  def mk_enum_item(self, itemname: str, itemexpr: AST.ASTExpr) -> ASTEnumItem
  ```

- **mk_enumitem_by_value**: Specify the name and integer value for a single enumeration
  value:
  ```
  def mk_enumitem_by_value(self, itemname: str, itemvalue: int) -> ASTEnumItem
  ```

- **mk_enum_type**: Specify an enuminfo to get an enum type. If the enuminfo is new
  it will be registered, so that future enum types for the same enum can be created
  by specifying the name only.
  ```
  def _mk_enum_type(self, einfo: ASTEnumInfo) -> ASTTypEnum
  ```

- **mk_enum_type_by_name**: Specify the name of an enuminfo to get an enum type; the
  enuminfo with that name must have been registered earlier.
  ```
  def mk_enum_type_by_name(self, enumname: str) -> ASTTypEnum
  ```


#### Integer Type Specifiers<a name="ikind"></a>

| ikind | pretty-printed |
| :---  | :--- |
| <code>ibool</code> | <code>bool</code> |
| <code>ichar</code> | <code>char</code> |
| <code>ischar</code> | <code>signed char</code> |
| <code>iuchar</code> | <code>unsigned char</code> |
| <code>iint</code> | <code>int</code> |
| <code>iuint</code> | <code>unsigned int</code> |
| <code>ishort</code> | <code>short</code> |
| <code>iushort</code> | <code>unsigned short</code> |
| <code>ilong</code> | <code>long</code> |
| <code>iulong</code> | <code>unsigned long</code> |
| <code>ilonglong</code> | <code>long long</code> |
| <code>iulonglong</code> | <code>unsigned long long</code> |


#### Float Type Specifiers<a name="fkind"></a>

| fkind | pretty-printed |
| :---  | :--- |
| <code>float</code> | <code>float</code> |
| <code>fdouble</code> | <code>double</code> |
| <code>flongdouble</code> | <code>long double</code> |


### Provenance

Provenance provides a connection between the high-level AST representation
that is presented to the reader (in the form of C code) and a low-level AST
representation that can be more directly related to the assembly code. We
currently support the following relationships:

1. **Instruction Mapping**: a mapping from high-level instructions to low-level
   instructions.
   ```
   high-level instr-id -> low-level instr-id list
   ```

2. **Expression Mapping**: a mapping from high-level expressions to low-level
   expressions.
   ```
   high-level expr-id -> low-level expr-id
   ```

3. **Lval Mapping**: a mapping from high-level lvals to low-level lvals.
   ```
   high-level lval-id -> low-level lval-id
   ```

4. **Reaching Definitions**: a mapping from expressions (mostly lval-exprs) to the
   instructions that <ins>may</ins> define them.
   ```
   expr-id -> instr-id list
   ```
   This information can be used by the patcher to identify the instruction(s) that
   may have to be changed to achieve a given modification in an expression.

5. **Flag reaching definitions**: a mapping from expressions involving flags to
   the instructions that <ins>may</ins> set these flags.
   ```
   expr-id -> instr-id list
   ```
   This mapping is kept separate from the regular reaching definitions, because
   different tools may handle processor status word flags differently. Some
   different possibilities for creating this relationship include:
   - identify all flags explicitly (e.g., C, N, V, Z for ARM) as flag variables,
     use the full flag expression as the low-level branch condition (e.g.,
     Z = 1 for EQ in ARM), and include a link from the expr-id for the lval-expr
     for Z to the associated instruction that sets Z (e.g., a CMP instruction);
     the CMP instruction can be defined as an assignment to each flag variable
     individually, or to some ignored left-hand side, because the only relevant
     information about this instruction is its right-hand side, the test
     expression.
   - use a generic flagvariable, say flag, and use the rvalue of this variable
     as the low-level branch condition, and include a link from the flag
     lval-expr to the CMP instruction (which can be an assignment of the test
     expression to the flag variable).

5. **Definitions Used**: a mapping from lvalues to the instructions that
   <ins>may</ins> use the values assigned to these lvalues (lvalue id's uniquely
   identify the instruction that performs the definition).
   ```
   lval-id -> instr-id list
   ```
   This information can be used by the patcher to determine if other parts of the
   function would be affected if the definition performed by this instruction would
   be changed.


#### Provenance Implementation

The Abstract Syntax Tree has a **provenance** property that returns a ASTProvenance
object with the following methods to enter the relationships described above:
```
add_instruction_mapping(hl_instrid: int, ll_instrid: int) -> None

add_expression_mapping(hl_exprid: int, ll_exprid: int) -> None

add_lval_mapping(hl_lvalid: int, ll_lvalid: int) -> None

add_reaching_definitions(exprid: int, instrids: List[int]) -> None

add_flag_reaching_definitions(exprid: int, instrids: List[int]) -> None

add_definitions_used(lvalid: int, instrids: List[int]) -> None
```

The serialization is automatically included in the function serialization
by the ASTApplicationInterface.