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
"""Predicate over expressions in a function context."""

from typing import List, TYPE_CHECKING

from chb.app.FnXPODictionaryRecord import (
    FnXPODictionaryRecord, xporegistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.BTerm import BTerm
    from chb.app.FnXPODictionary import FnXPODictionary
    from chb.bctypes.BCTyp import BCTyp
    from chb.invariants.XXpr import XXpr


class XPOPredicate(FnXPODictionaryRecord):

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        FnXPODictionaryRecord.__init__(self, xpod, ixval)

    @property
    def is_xpo_allocation_base(self) -> bool:
        return False

    @property
    def is_xpo_block_write(self) -> bool:
        return False

    @property
    def is_xpo_buffer(self) -> bool:
        return False

    @property
    def is_xpo_enum(self) -> bool:
        return False

    @property
    def is_xpo_constant_false(self) -> bool:
        return False

    @property
    def is_xpo_freed(self) -> bool:
        return False

    @property
    def is_xpo_functional(self) -> bool:
        return False

    @property
    def is_xpo_function_pointer(self) -> bool:
        return False

    @property
    def is_xpo_initialized(self) -> bool:
        return False

    @property
    def is_xpo_initialized_range(self) -> bool:
        return False

    @property
    def is_xpo_input_formatstring(self) -> bool:
        return False

    @property
    def is_xpo_invalidated(self) -> bool:
        return False

    @property
    def is_xpo_modified(self) -> bool:
        return False

    @property
    def is_xpo_new_memory(self) -> bool:
        return False

    @property
    def is_xpo_stack_address(self) -> bool:
        return False

    @property
    def is_xpo_heap_address(self) -> bool:
        return False

    @property
    def is_xpo_global_address(self) -> bool:
        return False

    @property
    def is_xpo_no_overlap(self) -> bool:
        return False

    @property
    def is_xpo_not_null(self) -> bool:
        return False

    @property
    def is_xpo_null(self) -> bool:
        return False

    @property
    def is_xpo_not_zero(self) -> bool:
        return False

    @property
    def is_xpo_non_negative(self) -> bool:
        return False

    @property
    def is_xpo_null_terminated(self) -> bool:
        return False

    @property
    def is_xpo_output_formatstring(self) -> bool:
        return False

    @property
    def is_xpo_positive(self) -> bool:
        return False

    @property
    def is_xpo_relational_expr(self) -> bool:
        return False

    @property
    def is_xpo_sets_errno(self) -> bool:
        return False

    @property
    def is_xpo_starts_thread(self) -> bool:
        return False

    @property
    def is_xpo_tainted(self) -> bool:
        return False

    @property
    def is_xpo_validmem(self) -> bool:
        return False

    @property
    def is_xpo_disjunction(self) -> bool:
        return False
        

@xporegistry.register_tag("ab", XPOPredicate)
class XPOAllocationBase(XPOPredicate):
    """Expression is start of dynamically allocated memory region.

    args[0]: index of base pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_allocation_base(self) -> bool:
        return True

    @property
    def base_pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "allocation-base(" + str(self.base_pointer) + ")"


@xporegistry.register_tag("bw", XPOPredicate)
class XPOBlockWrite(XPOPredicate):
    """Bytes are written to the indicated memory region.

    args[0]: index of base type in bcdictionary
    args[1]: index of base pointer in xprdicationary
    args[2]: index of size term in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_block_write(self) -> bool:
        return True

    @property
    def base_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def base_pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[1])

    @property
    def size(self) -> "XXpr":
        return self.xd.xpr(self.args[2])

    def __str__(self) -> str:
        return (
            "block-write("
            + str(self.base_type)
            + ", "
            + str(self.base_pointer)
            + ", "
            + str(self.size)
            + ")")


@xporegistry.register_tag("b", XPOPredicate)
class XPOBuffer(XPOPredicate):
    """Buffer for the indicated memory region must exist.

    args[0]: index of base type in bcdictionary
    args[1]: index of base pointer in xprdicationary
    args[2]: index of size term in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_buffer(self) -> bool:
        return True

    @property
    def base_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def base_pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[1])

    @property
    def size(self) -> "XXpr":
        return self.xd.xpr(self.args[2])

    def __str__(self) -> str:
        return (
            "buffer("
            + str(self.base_type)
            + ", "
            + str(self.base_pointer)
            + ", "
            + str(self.size)
            + ")")


@xporegistry.register_tag("e", XPOPredicate)
class XPOEnum(XPOPredicate):
    """Enum value must be included in given enumeration.

    args[0]: enum value expression in xprdictionary
    args[1]: index of name in bdictionary
    args[2]: 1 if this is a flag value
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_enum(self) -> bool:
        return True

    @property
    def enum_value(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def enum_name(self) -> str:
        return self.bd.string(self.args[1])

    @property
    def is_xpo_flag(self) -> bool:
        return self.args[2] == 1

    def __str__(self) -> str:
        return (
            "enum("
            + str(self.enum_value)
            + ", "
            + self.enum_name
            + ", "
            + ("flag" if self.is_xpo_flag else "_")
            + ")")


@xporegistry.register_tag("f", XPOPredicate)
class XPOPFalse(XPOPredicate):
    """Constant false predicate."""

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_constant_false(self) -> bool:
        return True

    def __str__(self) -> str:
        return "false"


@xporegistry.register_tag("fr", XPOPredicate)
class XPOFreed(XPOPredicate):
    """Pointer to memory region has been freed.

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_freed(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "freed(" + str(self.pointer) + ")"


@xporegistry.register_tag("fn", XPOPredicate)
class XPOFunctional(XPOPredicate):

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_functional(self) -> bool:
        return True

    def __str__(self) -> str:
        return "functional"


@xporegistry.register_tag("fp", XPOPredicate)
class XPOFunctionPointer(XPOPredicate):
    """Expression is address of a function.

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)
    
    @property
    def is_xpo_function_pointer(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "function-pointer(" + str(self.pointer) + ")"


# missing "inc" for includes struct constant


@xporegistry.register_tag("i", XPOPredicate)
class XPOInitialized(XPOPredicate):
    """Expression is initialized.

    args[0]. index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_initialized(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "initialized(" + str(self.expr) + ")"


@xporegistry.register_tag("ir", XPOPredicate)
class XPOInitializedRange(XPOPredicate):
    """Memory region is initialized for the given range.

    args[0]: index of base type in bcdictionary
    args[1]: index of base pointer in xprdictionary
    args[2]: index of size in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_initialized_range(self) -> bool:
        return True

    @property
    def base_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    @property
    def base_pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[1])

    @property
    def size(self) -> "XXpr":
        return self.xd.xpr(self.args[2])

    def __str__(self) -> str:
        return (
            "initialized-range("
            + str(self.base_type)
            + ", "
            + str(self.base_pointer)
            + ", "
            + str(self.size)
            + ")")

    
@xporegistry.register_tag("ifs", XPOPredicate)
class XPOInputFormatString(XPOPredicate):
    """Expression points to a format string for input (scanf).

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_input_formatstring(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "input-formatstring(" + str(self.pointer) + ")"


@xporegistry.register_tag("inv", XPOPredicate)
class XPOInvalidated(XPOPredicate):
    """Expression points at invalidated object.

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_invalidated(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "invalidated(" + str(self.pointer) + ")"


@xporegistry.register_tag("nm", XPOPredicate)
class XPONewMemory(XPOPredicate):
    """Expression points at the base of memory allocated in this function.

    args[0]: index of base pointer in xprdictionary
    args[1]: index of size in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_new_memory(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def size(self) -> "XXpr":
        return self.xd.xpr(self.args[1])

    def __str__(self) -> str:
        return "new-memory(" + str(self.pointer) + ", " + str(self.size) + ")"
    
    
@xporegistry.register_tag("sa", XPOPredicate)
class XPOStackAddress(XPOPredicate):
    """Expression is a stack address.

    args[1]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)    

    @property
    def is_xpo_stack_address(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "stack-address(" + str(self.expr) + ")"


@xporegistry.register_tag("ha", XPOPredicate)
class XPOHeapAddress(XPOPredicate):
    """Expression is a stack address.

    args[1]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)    

    @property
    def is_xpo_heap_address(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "heap-address(" + str(self.expr) + ")"
    

@xporegistry.register_tag("ga", XPOPredicate)
class XPOGlobalAddress(XPOPredicate):
    """Expression is a global address.

    args[1]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)    

    @property
    def is_xpo_global_address(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "global-address(" + str(self.expr) + ")"
    

@xporegistry.register_tag("no", XPOPredicate)
class XPONoOverlap(XPOPredicate):
    """There is no overlap between the two memory regions indicated.

    args[0]: index of pointer to first memory region in xprdictionary
    args[1]: index of pointer to second memory region in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_no_overlap(self) -> bool:
        return True

    @property
    def pointer1(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def pointer2(self) -> "XXpr":
        return self.xd.xpr(self.args[1])

    def __str__(self) -> str:
        return (
            "no-overlap(" + str(self.pointer1) + ", " + str(self.pointer2) + ")")
    

@xporegistry.register_tag("nn", XPOPredicate)
class XPONotNull(XPOPredicate):
    """Pointer expression is not NULL.

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_not_null(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "not-null(" + str(self.pointer) + ")"
    

@xporegistry.register_tag("nu", XPOPredicate)
class XPONull(XPOPredicate):
    """Pointer expression is NULL.

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_null(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "null(" + str(self.pointer) + ")"
    

@xporegistry.register_tag("nz", XPOPredicate)
class XPONotZero(XPOPredicate):
    """Expression is not zero.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_not_zero(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "not-zero(" + str(self.expr) + ")"
    

@xporegistry.register_tag("nng", XPOPredicate)
class XPONonNegative(XPOPredicate):
    """Expression is non-negative.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_non_negative(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "non-negative(" + str(self.expr) + ")"
    
    
@xporegistry.register_tag("nt", XPOPredicate)
class XPONullTerminated(XPOPredicate):
    """Pointer points to null-terminated string.

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_null_terminated(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "null-terminated(" + str(self.pointer) + ")"


@xporegistry.register_tag("ofs", XPOPredicate)
class XPOOutputFormatString(XPOPredicate):
    """Pointer points to a format string for output (printf)

    args[0]: index of pointer in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_output_format_string(self) -> bool:
        return True

    @property
    def pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "output-format-string(" + str(self.pointer) + ")"
    

@xporegistry.register_tag("pos", XPOPredicate)
class XPOPositive(XPOPredicate):
    """Expression is positive.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_positive(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "positive(" + str(self.expr) + ")"


@xporegistry.register_tag("x", XPOPredicate)
class XPORelationalExpr(XPOPredicate):
    """Given relation holds between two expressions.

    tags[1]: relational operator
    args[0]: index of first expression in xprdictionary
    args[1]: index of second expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_relational_expr(self) -> bool:
        return True

    @property
    def relational_operator(self) -> str:
        return self.tags[1]

    @property
    def expr1(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def expr2(self) -> "XXpr":
        return self.xd.xpr(self.args[1])

    def __str__(self) -> str:
        return (
            str(self.expr1)
            + " "
            + self.relational_operator
            + " "
            + str(self.expr2))


@xporegistry.register_tag("errno", XPOPredicate)
class XPOSetsErrno(XPOPredicate):
    """Function sets errno."""

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_sets_errno(self) -> bool:
        return True

    def __str__(self) -> str:
        return "sets-errno"


@xporegistry.register_tag("st", XPOPredicate)
class XPOStartsThread(XPOPredicate):
    """Starts thread indicated by pointer with given arguments.

    args[0]: index of function in xprdictionary
    args[1...]: indices of arguments passed to function pointer
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_starts_thread(self) -> bool:
        return True

    @property
    def function_pointer(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def function_arguments(self) -> List["XXpr"]:
        return [self.xd.xpr(a) for a in self.args[1:]]

    def __str__(self) -> str:
        return (
            "starts-thread("
            + str(self.function_pointer)
            + ", "
            + ", ".join(str(t) for t in self.function_arguments))


@xporegistry.register_tag("t", XPOPredicate)
class XPOTainted(XPOPredicate):
    """Expression is tainted.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_tainted(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "tainted(" + str(self.expr) + ")"


@xporegistry.register_tag("v", XPOPredicate)
class XPOValidMem(XPOPredicate):
    """Expression points to valid memory.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self, xpod: "FnXPODictionary", ixval: IndexedTableValue) -> None:
        XPOPredicate.__init__(self, xpod, ixval)

    @property
    def is_xpo_validmem(self) -> bool:
        return True

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    def __str__(self) -> str:
        return "validmem(" + str(self.expr) + ")"

    
