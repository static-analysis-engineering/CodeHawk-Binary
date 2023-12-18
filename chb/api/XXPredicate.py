# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------


from typing import List, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import (
    InterfaceDictionaryRecord, apiregistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.BTerm import BTerm
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.bctypes.BCTyp import BCTyp


class XXPredicate(InterfaceDictionaryRecord):
    """External predicate used in preconditions, postconditions, and sideeffects.
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def is_xp_allocation_base(self) -> bool:
        return False

    @property
    def is_xp_block_write(self) -> bool:
        return False

    @property
    def is_xp_buffer(self) -> bool:
        return False

    @property
    def is_xp_enum(self) -> bool:
        return False

    @property
    def is_xp_constant_false(self) -> bool:
        return False

    @property
    def is_xp_freed(self) -> bool:
        return False

    @property
    def is_xp_functional(self) -> bool:
        return False

    @property
    def is_xp_function_pointer(self) -> bool:
        return False

    @property
    def is_xp_initialized(self) -> bool:
        return False

    @property
    def is_xp_initialized_range(self) -> bool:
        return False

    @property
    def is_xp_input_formatstring(self) -> bool:
        return False

    @property
    def is_xp_invalidated(self) -> bool:
        return False

    @property
    def is_xp_modified(self) -> bool:
        return False

    @property
    def is_xp_new_memory(self) -> bool:
        return False

    @property
    def is_xp_stack_address(self) -> bool:
        return False

    @property
    def is_xp_heap_address(self) -> bool:
        return False

    @property
    def is_xp_global_address(self) -> bool:
        return False

    @property
    def is_xp_no_overlap(self) -> bool:
        return False

    @property
    def is_xp_not_null(self) -> bool:
        return False

    @property
    def is_xp_null(self) -> bool:
        return False

    @property
    def is_xp_not_zero(self) -> bool:
        return False

    @property
    def is_xp_non_negative(self) -> bool:
        return False

    @property
    def is_xp_null_terminated(self) -> bool:
        return False

    @property
    def is_xp_output_formatstring(self) -> bool:
        return False

    @property
    def is_xp_positive(self) -> bool:
        return False

    @property
    def is_xp_relational_expr(self) -> bool:
        return False

    @property
    def is_xp_sets_errno(self) -> bool:
        return False

    @property
    def is_xp_starts_thread(self) -> bool:
        return False

    @property
    def is_xp_tainted(self) -> bool:
        return False

    @property
    def is_xp_validmem(self) -> bool:
        return False

    @property
    def is_xp_disjunction(self) -> bool:
        return False


@apiregistry.register_tag("ab", XXPredicate)
class XXPAllocationBase(XXPredicate):
    """Term is start of dynamically allocated memory region.

    args[0]: index of base pointer in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_allocation_base(self) -> bool:
        return True

    @property
    def base_pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "allocation-base(" + str(self.base_pointer) + ")"


@apiregistry.register_tag("bw", XXPredicate)
class XXPBlockWrite(XXPredicate):
    """Bytes are written to the indicated memory region.

    args[0]: index of base type in bcdictionary
    args[1]: index of base pointer in interfacedictionary
    args[2]: index of size term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_block_write(self) -> bool:
        return True

    @property
    def base_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def base_pointer(self) -> "BTerm":
        return self.id.bterm(self.args[1])

    @property
    def size(self) -> "BTerm":
        return self.id.bterm(self.args[2])

    def __str__(self) -> str:
        return (
            "block-write("
            + str(self.base_type)
            + ", "
            + str(self.base_pointer)
            + ", "
            + str(self.size)
            + ")")


@apiregistry.register_tag("b", XXPredicate)
class XXPBuffer(XXPredicate):
    """Buffer for the indicated memory region must exist.

    args[0]: index of base type in bcdictionary
    args[1]: index of base pointer in interfacedictionary
    args[2]: index of size term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_buffer(self) -> bool:
        return True

    @property
    def base_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def base_pointer(self) -> "BTerm":
        return self.id.bterm(self.args[1])

    @property
    def size(self) -> "BTerm":
        return self.id.bterm(self.args[2])

    def __str__(self) -> str:
        return (
            "buffer("
            + str(self.base_type)
            + ", "
            + str(self.base_pointer)
            + ", "
            + str(self.size)
            + ")")


@apiregistry.register_tag("e", XXPredicate)
class XXPEnum(XXPredicate):
    """Enum value must be included in given enumeration.

    args[0]: enum value term in interfacedictionary
    args[1]: index of name in bdictionary
    args[2]: 1 if this is a flag value
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_enum(self) -> bool:
        return True

    @property
    def enum_value(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    @property
    def enum_name(self) -> str:
        return self.bd.string(self.args[1])

    @property
    def is_xp_flag(self) -> bool:
        return self.args[2] == 1

    def __str__(self) -> str:
        return (
            "enum("
            + str(self.enum_value)
            + ", "
            + self.enum_name
            + ", "
            + ("flag" if self.is_xp_flag else "_")
            + ")")


@apiregistry.register_tag("f", XXPredicate)
class XXPFalse(XXPredicate):
    """Constant false predicate."""

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_constant_false(self) -> bool:
        return True

    def __str__(self) -> str:
        return "false"


@apiregistry.register_tag("fr", XXPredicate)
class XXPFreed(XXPredicate):
    """Pointer to memory region has been freed.

    args[0]: index of pointer in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_freed(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "freed(" + str(self.pointer) + ")"


@apiregistry.register_tag("fn", XXPredicate)
class XXPFunctional(XXPredicate):
    """Function has no side effects."""

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_functional(self) -> bool:
        return True

    def __str__(self) -> str:
        return "functional"


@apiregistry.register_tag("fp", XXPredicate)
class XXPFunctionPointer(XXPredicate):
    """Term is address of a function.

    args[0]: index of pointer in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_function_pointer(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "function-pointer(" + str(self.pointer) + ")"


# missing "inc" for includes struct constant


@apiregistry.register_tag("i", XXPredicate)
class XXPInitialized(XXPredicate):
    """Term is initialized.

    args[0]: index of term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_initialized(self) -> bool:
        return True

    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "initialized(" + str(self.term) + ")"


@apiregistry.register_tag("ir", XXPredicate)
class XXPInitializedRange(XXPredicate):
    """Memory region is initialized for the given range.

    args[0]: index of base type in bcdictionary
    args[1]: index of base pointer in interfacedictionary
    args[2]: index of size term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_initialized_range(self) -> bool:
        return True

    @property
    def base_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def base_pointer(self) -> "BTerm":
        return self.id.bterm(self.args[1])

    @property
    def size(self) -> "BTerm":
        return self.id.bterm(self.args[2])

    def __str__(self) -> str:
        return (
            "initialized-range("
            + str(self.base_type)
            + ", "
            + str(self.base_pointer)
            + ", "
            + str(self.size)
            + ")")


@apiregistry.register_tag("ifs", XXPredicate)
class XXPInputFormatString(XXPredicate):
    """Term points to a format string for input (scanf)

    args[0]: index of pointer in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_input_formatstring(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "input-formatstring(" + str(self.pointer) + ")"


@apiregistry.register_tag("inv", XXPredicate)
class XXPInvalidated(XXPredicate):
    """Term points at invalidated object.

    args[0]: index of pointer in interfacedicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_invalidated(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "invalidated(" + str(self.pointer) + ")"


@apiregistry.register_tag("m", XXPredicate)
class XXPModified(XXPredicate):
    """Term points to object that is modified.

    args[0]: index of pointer in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_modified(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "modified(" + str(self.pointer) + ")"


@apiregistry.register_tag("nm", XXPredicate)
class XXPNewMemory(XXPredicate):
    """Term points at the base of memory allocated in this function.

    args[0]: index of base pointer in interfacedictionary
    args[1]: index of size term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_new_memory(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    @property
    def size(self) -> "BTerm":
        return self.id.bterm(self.args[1])

    def __str__(self) -> str:
        return "new-memory(" + str(self.pointer) + ", " + str(self.size) + ")"


@apiregistry.register_tag("sa", XXPredicate)
class XXPStackAddress(XXPredicate):
    """Term is a stack address.

    args[0]: index of term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_stack_address(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "stack-address(" + str(self.term) + ")"


@apiregistry.register_tag("ha", XXPredicate)
class XXPHeapAddress(XXPredicate):
    """Term is a heap address.

    args[0]: index of term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_heap_address(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "heap-address(" + str(self.term) + ")"


@apiregistry.register_tag("ga", XXPredicate)
class XXPGlobalAddress(XXPredicate):
    """Term is a global address.

    args[0]: index of term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_global_address(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "global-address(" + str(self.term) + ")"


@apiregistry.register_tag("no", XXPredicate)
class XXPNoOverlap(XXPredicate):
    """There is no overlap between the two memory regions indicated.

    args[0]: index of pointer to first memory region in interfacedictionary
    args[1]: index of pointer to second memory region in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_no_overlap(self) -> bool:
        return True

    @property
    def pointer1(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    @property
    def pointer2(self) -> "BTerm":
        return self.id.bterm(self.args[1])

    def __str__(self) -> str:
        return (
            "no-overlap(" + str(self.pointer1) + ", " + str(self.pointer2) + ")")


@apiregistry.register_tag("nn", XXPredicate)
class XXPNotNull(XXPredicate):
    """Pointer term is not NULL.

    args[0]: index of pointer in interface dicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_not_null(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "not-null(" + str(self.pointer) + ")"


@apiregistry.register_tag("nu", XXPredicate)
class XXPNull(XXPredicate):
    """Pointer term is NULL.

    args[0]: index of pointer in interface dicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_null(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "null(" + str(self.pointer) + ")"


@apiregistry.register_tag("nz", XXPredicate)
class XXPNotZero(XXPredicate):
    """Term is not zero.

    args[0]: index of term in interface dicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_not_zero(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "not-zero(" + str(self.term) + ")"


@apiregistry.register_tag("nng", XXPredicate)
class XXPNonNegative(XXPredicate):
    """Term is non-negative.

    args[0]: index of term in interface dicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_non_negative(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "non-negative(" + str(self.term) + ")"


@apiregistry.register_tag("nt", XXPredicate)
class XXPNullTerminated(XXPredicate):
    """Pointer term is null-terminated

    args[0]: index of pointer in interface dicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_null_terminated(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "null-terminated(" + str(self.pointer) + ")"


@apiregistry.register_tag("ofs", XXPredicate)
class XXPOutFormatString(XXPredicate):
    """Term points to a format string for output (printf)

    args[0]: index of pointer in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_output_formatstring(self) -> bool:
        return True

    @property
    def pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "output-formatstring(" + str(self.pointer) + ")"


@apiregistry.register_tag("pos", XXPredicate)
class XXPPositive(XXPredicate):
    """Term is positive.

    args[0]: index of term in interface dictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_positive(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "positive(" + str(self.term) + ")"


@apiregistry.register_tag("x", XXPredicate)
class XXPRelationalExpr(XXPredicate):
    """Given relational expression holds between two terms.

    tags[1]: relational operator
    args[0]: index of first term in interfacedictionary
    args[1]: index of second term in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_relational_expr(self) -> bool:
        return True

    @property
    def relational_operator(self) -> str:
        return self.tags[1]

    @property
    def term1(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    @property
    def term2(self) -> "BTerm":
        return self.id.bterm(self.args[1])

    def __str__(self) -> str:
        return (
            str(self.term1)
            + " "
            + self.relational_operator
            + " "
            + str(self.term2))


@apiregistry.register_tag("errno", XXPredicate)
class XXPSetsErrno(XXPredicate):
    """Function sets errno."""

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_sets_errno(self) -> bool:
        return True

    def __str__(self) -> str:
        return "sets-errno"


@apiregistry.register_tag("st", XXPredicate)
class XXPStartsThread(XXPredicate):
    """Starts thread indicated by pointer with given arguments.

    args[0]: index of function pointer in interface dictionary
    args[1..]: indices of arguments passed to function pointer
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_starts_thread(self) -> bool:
        return True

    @property
    def function_pointer(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    @property
    def function_arguments(self) -> List["BTerm"]:
        return [self.id.bterm(a) for a in self.args[1:]]

    def __str__(self) -> str:
        return (
            "starts-thread("
            + str(self.function_pointer)
            + ", "
            + ", ".join(str(t) for t in self.function_arguments))


@apiregistry.register_tag("t", XXPredicate)
class XXPTainted(XXPredicate):
    """Term is tainted.

    args[0]: index of term in interfacedicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_tainted(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "tainted(" + str(self.term) + ")"


@apiregistry.register_tag("v", XXPredicate)
class XXPValidMem(XXPredicate):
    """Term points to valid memory

    args[0]: index of term in interfacedicationary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_validmem(self) -> bool:
        return True

    @property
    def term(self) -> "BTerm":
        return self.id.bterm(self.args[0])

    def __str__(self) -> str:
        return "validmem(" + str(self.term) + ")"


@apiregistry.register_tag("dis", XXPredicate)
class XXPDisjunction(XXPredicate):
    """Disjunction of xpredicates.

    args[0]: index of xpredicate list in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_disjunction(self) -> bool:
        return True

    @property
    def xpredicates(self) -> List["XXPredicate"]:
        return self.id.xpredicate_list(self.args[0])

    def __str__(self) -> str:
        return " || ".join(str(x) for x in self.xpredicates)



@apiregistry.register_tag("con", XXPredicate)
class XXPConditional(XXPredicate):
    """Conditional xpredicate.

    args[0]: index of antecedent xpredicate in interfacedictionary
    args[1]: index of consequent xpredicate in interfacedictionary
    """

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        XXPredicate.__init__(self, ixd, ixval)

    @property
    def is_xp_conditional(self) -> bool:
        return True

    @property
    def antecedent_xp(self) -> "XXPredicate":
        return self.id.xpredicate(self.args[0])

    @property
    def consequent_xp(self) -> "XXPredicate":
        return self.id.xpredicate(self.args[1])

    def __str__(self) -> str:
        return str(self.antecedent_xp) + " implies " + str(self.consequent_xp)
