# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs LLC
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
"""All types involved in creating type constraints.

Based on type_base_variable_t in bchlib/bCHLibTypes:

type type_base_variable_t =                       tags [0]   tags    args
 | FunctionType of string                           "f"        2      0
 | DataAddressType of string                        "d"        2      0
 | GlobalVariableType of string                     "g"        2      0

type type_cap_label_t =
 | FRegParameter of register                        "fr"       1      1
 | FStackParameter of int                           "fs"       1      1
 | FLocStackAddress of int                          "sa"       1      1
 | FReturn                                          "fx"       1      0
 | Load                                              "l"       1      0
 | Store                                             "s"       1      0
 | LeastSignificantByte                            "lsb"       1      0
 | LeastSignificantHalfword                        "lsh"       1      0
 | OffsetAccess of int * int                         "a"       1      2
 | OffsetAccessA of int * int                       "aa"       1      2

type type_constant_t =
 | TyAsciiDigit                                     "ad"       1      0
 | TyAsciiCapsLetter                                "ac"       1      0
 | TyAsciiSmallLetter                               "as"       1      0
 | TyAsciiControl                                   "ac"       1      0
 | TyAsciiPrintable                                 "ap"       1      0
 | TyAscii                                           "a"       1      0
 | TyExtendedAscii                                  "ac"       1      0
 | TyZero                                            "z"       1      0
 | TyTInt of ikind_t                                "ti"       2      0
 | TyTFloat of fkind_t                              "tf"       2      0
 | TyTUnknown                                        "u"       1      0

type type_term_t
 | TyVariable of type_variable_t                     "v"       1      1
 | TyConstant of type_constant_t                     "c"       1      1

type type_constraint_t
 | TyVar of type_term_t                              "v"       1      1
 | TySub of type_term_t * type_term_t                "s"       1      2
 | TyZeroCheck of type_term_t                        "z"       1      1
"""

from typing import cast, List, TYPE_CHECKING

from chb.bctypes.TypeConstraintDictionaryRecord import (
    TypeConstraintDictionaryRecord, tcdregistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.Register import Register
    from chb.bctypes.TypeConstraintDictionary import TypeConstraintDictionary


class TypeBaseVariable(TypeConstraintDictionaryRecord):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraintDictionaryRecord.__init__(self, tcd, ixval)

    @property
    def is_function(self) -> bool:
        return False

    @property
    def is_data_address(self) -> bool:
        return False

    @property
    def is_global_variable(self) -> bool:
        return False

    @property
    def addr(self) -> str:
        raise UF.CHBError("Not implemented")

    def __str__(self) -> str:
        return "type-base-variable:" + str(self.tags[0])


@tcdregistry.register_tag("f", TypeBaseVariable)
class TypeBaseFunctionType(TypeBaseVariable):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeBaseVariable.__init__(self, tcd, ixval)

    @property
    def addr(self) -> str:
        return self.tags[1]

    @property
    def is_function(self) -> bool:
        return True

    def __str__(self) -> str:
        return "sub_" + self.addr


@tcdregistry.register_tag("d", TypeBaseVariable)
class TypeBaseDataAddressType(TypeBaseVariable):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeBaseVariable.__init__(self, tcd, ixval)

    @property
    def addr(self) -> str:
        return self.tags[1]

    @property
    def is_data_address(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.addr


@tcdregistry.register_tag("g", TypeBaseVariable)
class TypeBaseGlobalVariabletype(TypeBaseVariable):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeBaseVariable.__init__(self, tcd, ixval)

    @property
    def addr(self) -> str:
        return self.tags[1]

    @property
    def is_global_varibale(self) -> bool:
        return True

    def __str__(self) -> str:
        return "gv_" + self.addr


class TypeCapLabel(TypeConstraintDictionaryRecord):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraintDictionaryRecord.__init__(self, tcd, ixval)

    @property
    def is_reg_param(self) -> bool:
        return False

    @property
    def is_stack_param(self) -> bool:
        return False

    @property
    def is_freturn(self) -> bool:
        return False

    @property
    def is_load(self) -> bool:
        return False

    @property
    def is_store(self) -> bool:
        return False

    @property
    def is_offset_access(self) -> bool:
        return False


@tcdregistry.register_tag("fr", TypeCapLabel)
class TypeCapLabelFRegParameter(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def register(self) -> "Register":
        return self.bd.register(self.args[0])

    @property
    def is_reg_param(self) -> bool:
        return True

    def __str__(self) -> str:
        return "param_" + str(self.register)


@tcdregistry.register_tag("fs", TypeCapLabel)
class TypeCapLabelFStackParameter(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def offset(self) -> int:
        return self.args[0]

    @property
    def is_stack_param(self) -> bool:
        return True

    def __str__(self) -> str:
        return "stack_" + str(self.offset)


@tcdregistry.register_tag("fx", TypeCapLabel)
class TypeCapLabelFReturn(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def is_freturn(self) -> bool:
        return True

    def __str__(self) -> str:
        return "rtn"


@tcdregistry.register_tag("l", TypeCapLabel)
class TypeCapLabelLoad(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def is_load(self) -> bool:
        return True

    def __str__(self) -> str:
        return "load"


@tcdregistry.register_tag("s", TypeCapLabel)
class TypeCapLabelStore(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def is_store(self) -> bool:
        return True

    def __str__(self) -> str:
        return "store"


@tcdregistry.register_tag("a", TypeCapLabel)
class TypeCapLabelOffsetAccess(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def size(self) -> int:
        return self.args[0]

    @property
    def offset(self) -> int:
        return self.args[1]

    @property
    def is_offset_access(self) -> bool:
        return True

    def __str__(self) -> str:
        size = "" if self.size == 4 else "s_" + str(self.size) + "_"
        off = "acc_" + str(self.offset)
        return size + off


@tcdregistry.register_tag("aa", TypeCapLabel)
class TypeCapLabelOffsetAccessArray(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def size(self) -> int:
        return self.args[0]

    @property
    def offset(self) -> int:
        return self.args[1]

    @property
    def is_offset_access(self) -> bool:
        return True

    def __str__(self) -> str:
        return "se_" + str(self.size) + "_acci_" + str(self.offset)


@tcdregistry.register_tag("sa", TypeCapLabel)
class TypeCapLabelStackAddress(TypeCapLabel):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeCapLabel.__init__(self, tcd, ixval)

    @property
    def offset(self) -> int:
        return self.args[0]

    @property
    def is_ptr_stackaddress(self) -> bool:
        return True

    def __str__(self) -> str:
        return "stackaddr_" + str(self.offset)



class TypeVariable(TypeConstraintDictionaryRecord):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraintDictionaryRecord.__init__(self, tcd, ixval)

    @property
    def basevar(self) -> "TypeBaseVariable":
        return self.tcd.type_basevar(self.args[0])

    @property
    def is_function(self) -> bool:
        return self.basevar.is_function

    @property
    def is_data_address(self) -> bool:
        return self.basevar.is_data_address

    @property
    def is_global_variable(self) -> bool:
        return self.basevar.is_global_variable

    @property
    def base_addr(self) -> str:
        return self.basevar.addr

    @property
    def capabilities(self) -> List["TypeCapLabel"]:
        return self.tcd.type_cap_label_list(self.args[1:])

    def __str__(self) -> str:
        if len(self.capabilities) > 0:
            return (
                str(self.basevar)
                + "."
                + ".".join(str(c) for c in self.capabilities))
        else:
            return str(self.basevar)


class TypeConstant(TypeConstraintDictionaryRecord):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraintDictionaryRecord.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "type-constant:" + self.tags[0]


@tcdregistry.register_tag("ad", TypeConstant)
class TypeConstantAsciiDigit(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_digit"


@tcdregistry.register_tag("asl", TypeConstant)
class TypeConstantAsciiSmallLetter(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_letter"


@tcdregistry.register_tag("acl", TypeConstant)
class TypeConstantAsciiCapsLetter(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_caps"


@tcdregistry.register_tag("ac", TypeConstant)
class TypeConstantAsciiControl(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_ctrl"


@tcdregistry.register_tag("ap", TypeConstant)
class TypeConstantAsciiPrintable(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_ascii_p"


@tcdregistry.register_tag("a", TypeConstant)
class TypeConstantAscii(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_ascii"


@tcdregistry.register_tag("ax", TypeConstant)
class TypeConstantExtendedAscii(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_ascii_x"



@tcdregistry.register_tag("z", TypeConstant)
class TypeConstantZero(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "t_zero"


@tcdregistry.register_tag("ti", TypeConstant)
class TypeConstantTInt(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    @property
    def ikind(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return "int (" + str(self.ikind) + ")"


@tcdregistry.register_tag("tf", TypeConstant)
class TypeConstantTFloat(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    @property
    def fkind(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return "float (" + str(self.fkind) + ")"


@tcdregistry.register_tag("u", TypeConstant)
class TypeConstantUnknown(TypeConstant):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstant.__init__(self, tcd, ixval)

    def __str__(self) -> str:
        return "ty_top"


class TypeTerm(TypeConstraintDictionaryRecord):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraintDictionaryRecord.__init__(self, tcd, ixval)

    @property
    def is_typevar(self) -> bool:
        return False

    @property
    def is_typeconstant(self) -> bool:
        return False

    def __str__(self) -> str:
        return "type-term:" + self.tags[0]


@tcdregistry.register_tag("v", TypeTerm)
class TypeTermVariable(TypeTerm):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeTerm.__init__(self, tcd, ixval)

    @property
    def typevar(self) -> TypeVariable:
        return self.tcd.type_variable(self.args[0])

    @property
    def is_typevar(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.typevar)


@tcdregistry.register_tag("c", TypeTerm)
class TypeTermConstant(TypeTerm):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeTerm.__init__(self, tcd, ixval)

    @property
    def typeconstant(self) -> TypeConstant:
        return self.tcd.type_constant(self.args[0])

    @property
    def is_typeconstant(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.typeconstant)


class TypeConstraint(TypeConstraintDictionaryRecord):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraintDictionaryRecord.__init__(self, tcd, ixval)

    @property
    def is_var_constraint(self) -> bool:
        return False

    @property
    def is_subtype_constraint(self) -> bool:
        return False

    @property
    def is_zerocheck_constraint(self) -> bool:
        return False

    def __str__(self) -> str:
        return "type-constraint:" + self.tags[0]


@tcdregistry.register_tag("v", TypeConstraint)
class TypeVariableConstraint(TypeConstraint):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraint.__init__(self, tcd, ixval)

    @property
    def typeterm(self) -> TypeTerm:
        return self.tcd.type_term(self.args[0])

    @property
    def typevar(self) -> TypeVariable:
        return cast(TypeTermVariable, self.typeterm).typevar

    @property
    def is_var_constraint(self) -> bool:
        return True

    def __str__(self) -> str:
        return "VAR " + str(self.typeterm)


@tcdregistry.register_tag("s", TypeConstraint)
class SubTypeConstraint(TypeConstraint):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraint.__init__(self, tcd, ixval)

    @property
    def term1(self) -> TypeTerm:
        return self.tcd.type_term(self.args[0])

    @property
    def term2(self) -> TypeTerm:
        return self.tcd.type_term(self.args[1])

    @property
    def is_subtype_constraint(self) -> bool:
        return True

    @property
    def typevars(self) -> List[TypeVariable]:
        result: List[TypeVariable] = []
        if self.term1.is_typevar:
            result.append(cast(TypeTermVariable, self.term1).typevar)
        if self.term2.is_typevar:
            result.append(cast(TypeTermVariable, self.term2).typevar)
        return result

    @property
    def basevars(self) -> List[TypeBaseVariable]:
        return [t.basevar for t in self.typevars]

    def __str__(self) -> str:
        return str(self.term1) + " <: " + str(self.term2)


@tcdregistry.register_tag("z", TypeConstraint)
class ZeroCheckTypeConstraint(TypeConstraint):

    def __init__(
            self,
            tcd: "TypeConstraintDictionary",
            ixval: IndexedTableValue) -> None:
        TypeConstraint.__init__(self, tcd, ixval)

    @property
    def typeterm(self) -> TypeTerm:
        return self.tcd.type_term(self.args[0])

    @property
    def is_zerocheck_constraint(self) -> bool:
        return True

    @property
    def typevar(self) -> TypeVariable:
        return cast(TypeTermVariable, self.typeterm).typevar

    def __str__(self) -> str:
        return "zero-check(" + str(self.typeterm) + ")"
