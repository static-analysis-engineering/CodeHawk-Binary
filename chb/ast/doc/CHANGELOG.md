## PIR Changelog

### Version 0.1.0-20220808

- Added versioning (based on [semantic-versioning](https://semver.org/))
- Added CHANGELOG.md
- Changed printed version of asr from <code>s>></code> to <code>>></code>

---

### Version 0.1.0-20220810

- Added line position to ASTCPrettyPrinter

---

### Version 0.1.0-20220811

- Added flag variable, with constructor functions and storage
- Added alternative way to add functions to the application interface

---

### Version 0.1.0-20220814

- Added Identity Transformer

---

### Version 0.1.0-20220815

- Changed ASTFunction interface to ASTApplicationInterface
- Changed serialization to have a list of start nodes instead of just two

---

### Version 0.1.0-20220817

- Removed call-back feature from ASTFunction and simplified ASTApplicationInterface
- Changed signature for add_function_ast in ASTApplicationInterface to provide a list of ASTStmt, rather than a separately identified high-level ast and low-level ast.
- Minor corrections to ASTNode
- Added question item to Deserializer
