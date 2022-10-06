## Visitor Classes

Four visitor classes are provided to operate on or manipulate an abstract syntax tree.
They differ in the return types of their methods.

### ASTVisitor

The ASTVisitor class is the standard visitor with an abstract callback method for each node
type without a return value. Example:
```
@abstractmethod
def visit_return_stmt(self, stmt: ASTReturn) -> None:
    ...
```


The following subclasses are provided:

- **ASTNOPVisitor**: a concrete subclass with with empty methods. This class is useful
  for use cases where only a few of the nodes need callback methods.
  
- **ASTCPrettyPrinter**: a C pretty printer for an abstract syntax tree

- **ASTVariablesReferenced**: a class that allows the collection of variables referenced
  within an abstract syntax tree, used by the pretty printer to determine which variables
  to include in the local variable declarations.

- **ASTLiveCode**: a class that allows the collection of instructions and statements
  that are live, that is, the variables assigned in assignment instructions are used
  elsewhere.

- **ASTStorageChecker**: a class that allows checking whether all lvalues have been
  associated with a storage location.


### ASTIndexer

The ASTIndexer class is a visitor with an abstract callback method for each node that
returns an integer. Example:
```
@abstractmethod
def index_return_stmt(self, stmt: ASTReturn) -> int:
    ...
```

The following subclasses are provided:

- **ASTSerializer**: a class that provides the serialization of the abstract syntax
  tree to a dictionary format that can be saved in json. Each node is assigned an
  index in bottom-up fashion to enable structure sharing.

- **ASTByteSizeCalculator**: a class that can be used to calculate the size in bytes
  of expressions and types, traversing the tree in a bottom-up fashion.


### ASTTransformer

The ASTTransformer class is a visitor that transforms nodes into nodes of the same
structural kind, that is, statements can be transformed into other statements,
expressions can be transformed into other expressions, etc. Examples:
```
@abstractmethod
def visit_return_stmt(self, stmt: ASTReturn) -> ASTStmt
    ...

@abstractmethod
def visit_lval_expressions(self, expr: ASTLvalExpr) -> ASTExpr
    ...
```

Use cases for this visitor class is to transform the abstract syntax tree to produce
equivalent, but more readable code, by rewriting expressions, or to rearrange control
flow to reflect empty statements.

The following subclass is currently provided:

- **ASTExprPropagator**: a class that propagates and substitutes lval-expressions by
  the corresponding expressions assigned to those lvals, to eliminate explicit
  references to register variables in the higher-level representation


### ASTCTyper

The ASTCTyper class is a visitor that assigns to relevant nodes an associated type.
Example:
```
@abstractmethod
def ctype_lval_expression(self, expr: ASTLvalExpr) -> Optional[ASTTyp]:
    ...
```
By default the callback methods on the ASTTyp nodes return the node itself. Example:
```
def ctype_array_typ(self, typ: ASTTypArray) -> Optional[ASTTyp]:
    return typ
```