# PIR Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


### Version 0.1.0-2022-09-20

- Added mk_sizeof_expression to AbstractSyntaxTree and Deserializer.

---

### Version 0.1.0-2022-08-19

- Removed instruction_mapping, expression_mapping, and reaching_definitions.
  from AbstractSyntaxTree (as they are now provided in ASTProvenance object).
- Changed Changelog to be in reverse chronological order.

---

### Version 0.1.0-2022-08-18

- Added available expressions to Abstract Syntax Tree.

---

### Version 0.1.0-2022-08-17

- Removed call-back feature from ASTFunction and simplified ASTApplicationInterface.
- Changed signature for add_function_ast in ASTApplicationInterface to
  provide a list of ASTStmt, rather than a separately identified high-level ast
  and low-level ast.
- Minor corrections to ASTNode.
- Added question item to Deserializer.
- Added ASTProvenance class.

---

### Version 0.1.0-2022-08-15

- Changed ASTFunction interface to ASTApplicationInterface.
- Changed serialization to have a list of start nodes instead of just two.

---

### Version 0.1.0-2022-08-14

- Added Identity Transformer.

---

### Version 0.1.0-2022-08-11

- Added flag variable, with constructor functions and storage.
- Added alternative way to add functions to the application interface.

---

### Version 0.1.0-2022-08-10

- Added line position to ASTCPrettyPrinter.

---

### Version 0.1.0-2022-08-08

- Added versioning (based on [semantic-versioning](https://semver.org/)).
- Added CHANGELOG.md.
- Changed printed version of asr from <code>s>></code> to <code>>></code>.

---
