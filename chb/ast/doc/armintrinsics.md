## ARM Intrinsic Functions

Some ARM instructions can be directly represented in C code by means of
*arm intrinsics*, as described in the
[ARM C Language Extensions](https://developer.arm.com/documentation/101028/0013/?lang=en)
manual.

For convenience some of these functions are provided in the ARMIntrinsics class, as
documented below.

### Example of Use

Given a <code>REV16 R5, R5</code> assembly instruction, a corresponding call to the
intrinsic function can be constructed as follows, assuming an instance of
<code>AbstractSyntaxTree</code>, <code>astree</code>:
```
rev16vinfo = ARMInstructions().rev16
rev16tgt = astree.mk_vinfo_lval_expression(rev16vinfo)
lhs = astree.mk_register_variable_lval("R5",vtype=astree.unsigned_int)
rhs = astree.mk_register_variable_lval_expression("R5",vtype=astree.unsigned_int)
callinstr = astree.mk_call(lhs, rev16tgt, [rhs])
```

### Instruction Intrinsics Provided


| mnemonic | method | function signature |
| :---- | :---- | :--- |
| CLZ   | clz   | <code>unsigned int __clz(uint32_t x)</code> |
| CLS   | cls   | <code>unsigned int __cls(uint32_t x)</code> |
| RBIT  | rbit  | <code>uint32_t __rbit(uint32_t x)</code> |
| REV   | rev   | <code>unsigned int __rev(uint32_t x)</code> |
| REV16 | rev16 | <code>uint32_t __rev16(uint32_t x)</code> |