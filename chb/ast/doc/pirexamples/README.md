# PIR ILLUSTRATED

## A few small functions

- [crypto/asn1/ameth_lib.c: EVP_PKEY_get0_asn1](6f891f20_e277c.md):
  A small function that returns the value of a field.
  
- [crypto/asn1/ameth_lib.c: ameth_cmp](6f891f20_e26e4.md):
  Another small function that returns a slightly more complex expression.

- [crypto/asn1/ameth_lib.c: EVP_PKEY_asn1_set_private](6f891f20_e2860.md):
  A small void-returning function with three updates.


## Predicated Instructions

ARM allows conditional execution of instructions using condition codes
that are part of almost all instruction types. Predicated instructions
are handled in a few different ways in the lifting to C, depending on
their context and purpose.

The first option is to create full control flow in the control flow
graph. This approach is followed, for example, when a return instruction
(usually POP) is predicated. The following function provides an example:

- [crypto/asn1/ameth_lib.c: EVP_PKEY_asn1_free](6f891f20_e28a8.md):

The second option is to create light-weight control flow, which is not
present in the cfg, but is introduced in the process of lifting by
breaking up a basic block into fragments and inserting if statements
accordingly. This approach is illustrated in the following function:

- [crypto/asn1/a_enum.c: ASN1_ENUMERATED_get](6f891f20_d4b98.md):