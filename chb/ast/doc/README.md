# Patching Intermediate Represention (PIR)

## Introduction

The Patching Intermediate Representation aims to provide an intermediate representation
that combines a high-level C-like representation with assembly-level data to allow
relating edits in the high-level representation
to assembly instructions that affect the constructs involved.

The basic representation is an abstract syntax tree (AST) with nodes representing
control flow structures, instructions, expressions, and types. The nodes are modeled
after the CIL (C Intermediate Language, <https://people.eecs.berkeley.edu/~necula/cil/>) data structures. Instruction and expression
nodes have explicit links to assembly instructions and assembly-level memory locations
and registers.

The AST library, implemented in python, provides an API to construct the abstract
syntax tree, to serialize it to a json file, and to deserialize it again from the
json representation. The library provides various ways to extend the functionality
of the basic representation via Visitor classes.

### Quick Links:

- [Structure](#Structure)
- [Abstract Syntax Tree API](api.md)
- [Visitor Classes](visitors.md)

## Structure

The basic data structure is the **ASTNode**, the building block of the abstract
syntax tree. They are organized in a hierarchy as follows:

- **ASTStmt**: abstract control flow statement
  - *ASTReturn*: return statement
  - *ASTBlock*: sequence of control flow statements
  - *ASTInstrSequence*: sequence of instructions (basic block)
  - *ASTBranch*: if-then-else branch statement
- **ASTInstruction**: abstract instruction (sequential control flow)
  - *ASTAssign*: assignment instruction, left-hand-side := right-hand-side
  - *ASTCall*: call instruction, (left-hand-side :=) call(..arguments..)
- **ASTLval**: left-hand-side location consisting of a base location and offset
- **ASTLHost**: abstract left-hand-side base location
  - *ASTVariable*: location denoted by a variable
  - *ASTMemRef*: location denoted by a dereferenced pointer expression
- **ASTOffset**: abstract representation of location offset
  - *ASTNoOffset*: no offset
  - *ASTFieldOffset*: offset within a struct given by a field name
  - *ASTIndexOffset*: offset within an array given by an index expression
- **ASTExpr**: abstract expression
  - *ASTConstant*: abstract constant expression
    - *ASTIntegerConstant*: integer constant
      - *ASTGlobalAddressConstant*: integer constant that represents the address of
        a global variable
    - *ASTStringConstant*: string constant
  - *ASTLvalExpr*: value in a left-hand-side location
    - *ASTSubstitutedExpr*: expression equivalent to value in left-hand-side location
  - *ASTSizeOfExpr*: size of a type
  - *ASTCastExpr*: cast of an expression to a given type
  - *ASTUnaryOp*: unary expression
  - *ASTBinaryOp*: binary expression
  - *ASTQuestion*: question mark expression (c ? x : y in C)
  - *ASTAddressOf*: address of a location (& operator in C)
- **ASTTyp**: abstract variable type
  - *ASTTypVoid*: void type
  - *ASTTypInt*: integer type
  - *ASTTypFloat*: float type
  - *ASTTypPtr*: pointer type
  - *ASTTypArray*: array type
  - *ASTTypFun*: function type
  - *ASTTypNamed*: typedef type
  - *ASTTypComp*: structured type (struct or union)

with auxiliary nodes:

- **ASTVarInfo**: definition of local or global variable
- **ASTCompInfo**: definition of struct
- **ASTFieldInfo**: definition of field of a struct
- **ASTFunArgs**: definition of function parameter list
- **ASTFunArg**: definition of function parameter
