# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2026  Aarno Labs LLC
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

from datetime import datetime
from typing import cast, Dict, List, Tuple, TYPE_CHECKING

from chb.bctypes.BCVisitor import BCVisitor

if TYPE_CHECKING:
    from chb.app.Instruction import Instruction
    from chb.bctypes.BCAttribute import BCAttribute, BCAttributes
    import chb.bctypes.BCAttrParam as AP
    from chb.bctypes.BCCompInfo import BCCompInfo
    import chb.bctypes.BCConstant as BCC
    from chb.bctypes.BCEnumInfo import BCEnumInfo
    from chb.bctypes.BCEnumItem import BCEnumItem
    import chb.bctypes.BCExp as BCE
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArgs, BCFunArg
    from chb.bctypes.BCLHost import BCHostVar, BCHostMem
    from chb.bctypes.BCLval import BCLval
    from chb.bctypes.BCOffset import BCNoOffset, BCFieldOffset, BCIndexOffset
    import chb.bctypes.BCTyp as BCT
    from chb.bctypes.BCTypeInfo import BCTypeInfo
    from chb.bctypes.BCVarInfo import BCVarInfo


def get_varinfo_functions(
        varinfos: List["BCVarInfo"]
) -> Tuple[List["BCVarInfo"], List["BCVarInfo"]]:

    fns: List["BCVarInfo"] = []
    newfns: List["BCVarInfo"] = []
    for vinfo in varinfos:
        if vinfo.vtype.is_function:
            if vinfo.vid >= 10000:
                ftype = cast("BCT.BCTypFun", vinfo.vtype)
                if ftype.has_arguments():
                    newfns.append(vinfo)
                else:
                    pass
            else:
                fns.append(vinfo)
    return (fns, newfns)


class BCHeaderCode:

    def __init__(self) -> None:
        self._outputlines: List[str] = []
        self._pos: int = 0    # position in the line

    @property
    def outputlines(self) -> List[str]:
        return self._outputlines

    @property
    def pos(self) -> int:
        return self._pos

    def newline(self, indent: int = 0) -> None:
        self._outputlines.append(" " * indent)
        self._pos = indent

    def write(self, s: str) -> None:
        self._outputlines[-1] += s
        self._pos += len(s)

    def __str__(self) -> str:
        return "\n".join(self.outputlines)


class BCHeaderPrettyPrinter(BCVisitor):

    def __init__(
            self,
            varinfos: List["BCVarInfo"],
            typeinfos: List["BCTypeInfo"],
            compinfos: List["BCCompInfo"],
            indentation: int = 2) -> None:
        self._varinfos = varinfos
        self._typeinfos = typeinfos
        self._compinfos = compinfos
        self._indentation = indentation
        self._indent = 0
        self._ccode = BCHeaderCode()
        self._newfunctionsmode: bool = False
        self._returntype_replacements = 0
        self._parameter_type_replacements = 0

    @property
    def indentation(self) -> int:
        return self._indentation

    @property
    def indent(self) -> int:
        return self._indent

    def increase_indent(self) -> None:
        self._indent += self.indentation

    def decrease_indent(self) -> None:
        self._indent -= self.indentation

    @property
    def ccode(self) -> BCHeaderCode:
        return self._ccode

    @property
    def varinfos(self) -> List["BCVarInfo"]:
        return self._varinfos

    @property
    def typeinfos(self) -> List["BCTypeInfo"]:
        return self._typeinfos

    @property
    def compinfos(self) -> List["BCCompInfo"]:
        return self._compinfos

    @property
    def returntype_replacements(self) -> int:
        return self._returntype_replacements

    @property
    def parameter_type_replacements(self) -> int:
        return self._parameter_type_replacements

    def set_newfunctions_mode(self) -> None:
        self._newfunctionsmode = True

    def increment_returntype_replacements(self) -> None:
        self._returntype_replacements += 1

    def increment_parameter_type_replacements(self) -> None:
        self._parameter_type_replacements += 1

    @property
    def is_newfunctionsmode(self) -> bool:
        return self._newfunctionsmode

    def to_header_file(self, callers: Dict[str, List["Instruction"]] = {}) -> str:
        self.ccode.newline()
        self.ccode.write("// Header file from generated signatures")
        self.ccode.newline()
        self.ccode.write("//   Date: " + datetime.today().strftime("%Y-%m-%d"))
        self.ccode.newline()
        self.ccode.newline()
        if len(self.typeinfos) > 0:
            self.ccode.newline()
            self.ccode.write("// Type definitions")
            self.ccode.newline()
            for typeinfo in self.typeinfos:
                self.ccode.newline()
                typeinfo.accept(self)
            self.ccode.newline()
            self.ccode.newline()
        for cinfo in self.compinfos:
            self.ccode.write(
                "// compinfo " + cinfo.cname + " (" + str(cinfo.ckey) + ")")
            self.ccode.newline()
            cinfo.accept(self)
            self.ccode.newline()
        self.ccode.newline()
        self.ccode.newline()
        (fns, newfns) = get_varinfo_functions(self.varinfos)
        for vinfo in fns:
            if vinfo.vname in callers:
                self.write_callers(callers[vinfo.vname])
            vinfo.accept(self)
            self.ccode.newline()
            self.ccode.newline()
        self.ccode.newline()
        self.ccode.newline()
        self.set_newfunctions_mode()
        self.ccode.write("// Newly generated function signatures (")
        self.ccode.write(str(len(newfns)) + ")")
        self.ccode.newline()
        self.ccode.newline()
        for vinfo in newfns:
            if self.check_vinfo_for_inclusion(vinfo):
                vinfo.accept(self)
                self.ccode.newline()
                self.ccode.newline()
        self.ccode.newline()
        self.ccode.newline()
        if self.returntype_replacements > 0:
            self.ccode.write("// " + str(self.returntype_replacements)
                             + " return types were replaced by int")
            self.ccode.newline()
        if self.parameter_type_replacements > 0:
            self.ccode.write("// " + str(self.parameter_type_replacements)
                             + " parameter types were replaced by void*")
        return str(self.ccode)

    def write_callers(self, instrs: List["Instruction"]) -> None:
        for instr in instrs:
            self.ccode.newline()
            self.ccode.write("// ")
            self.ccode.write(instr.annotation)
        self.ccode.newline()

    def check_vinfo_for_inclusion(self, vinfo: "BCVarInfo") -> bool:
        ftype = cast("BCT.BCTypFun", vinfo.vtype)
        argtypes = ftype.argtypes
        if argtypes is None:
            return False

        funargs = argtypes.funargs
        if len(funargs) == 0:
            return False

        if ftype.returntype.is_unknown:
            self.increment_returntype_replacements()
            self.ccode.write("// Replacing unknown returntype by int")
            self.ccode.newline()
        for (i, arg) in enumerate(funargs):
            if arg.typ.is_unknown:
                self.increment_parameter_type_replacements()
                self.ccode.write("// Replacing unknown type of argument ")
                self.ccode.write(str(i + 1))
                self.ccode.write(" with void *")
                self.ccode.newline()
        return True

    def visit_lval(self, lval: "BCLval") -> None:
        pass

    def visit_varinfo(self, vinfo: "BCVarInfo") -> None:
        if vinfo.vtype.is_function:
            ftype = cast("BCT.BCTypFun", vinfo.vtype)
            if ftype.returntype.is_unknown:
                self.ccode.write("int")
            else:
                ftype.returntype.accept(self)
            self.ccode.write(" ")
            self.ccode.write(vinfo.vname)
            self.ccode.write("(")
            if ftype.argtypes is not None:
                ftype.argtypes.accept(self)
            if ftype.is_vararg:
                self.ccode.write(", ...")
            self.ccode.write(")")
            if vinfo.attributes is None or vinfo.attributes.is_empty:
                self.ccode.write(";")
            else:
                self.ccode.newline()
                vinfo.attributes.accept(self)
                self.ccode.write(";")
        else:
            pass

    def visit_variable(self, var: "BCHostVar") -> None:
        pass

    def visit_memref(self, memref: "BCHostMem") -> None:
        pass

    def visit_no_offset(self, offset: "BCNoOffset") -> None:
        pass

    def visit_field_offset(self, offset: "BCFieldOffset") -> None:
        pass

    def visit_index_offset(self, offset: "BCIndexOffset") -> None:
        pass

    def visit_integer_constant(self, c: "BCC.BCCInt64") -> None:
        pass

    def visit_string_constant(self, c: "BCC.BCStr") -> None:
        pass

    def visit_lval_expression(self, expr: "BCE.BCExpLval") -> None:
        pass

    def visit_cast_expression(self, expr: "BCE.BCExpCastE") -> None:
        pass

    def visit_unary_expression(self, expr: "BCE.BCExpUnOp") -> None:
        pass

    def visit_binary_expression(self, expr: "BCE.BCExpBinOp") -> None:
        pass

    def visit_question_expression(self, expr: "BCE.BCExpQuestion") -> None:
        pass

    def visit_address_of_expression(self, expr: "BCE.BCExpAddressOf") -> None:
        pass

    def visit_void_typ(self, typ: "BCT.BCTypVoid") -> None:
        self.ccode.write("void")

    def visit_integer_typ(self, typ: "BCT.BCTypInt") -> None:
        self.ccode.write(str(typ))

    def visit_float_typ(self, typ: "BCT.BCTypFloat") -> None:
        self.ccode.write(str(typ))

    def visit_pointer_typ(self, typ: "BCT.BCTypPtr") -> None:
        typ.tgttyp.accept(self)
        self.ccode.write(" *")

    def visit_array_typ(self, typ: "BCT.BCTypArray") -> None:
        pass

    def visit_fun_typ(self, typ: "BCT.BCTypFun") -> None:
        typ.returntype.accept(self)
        self.ccode.write(" (")
        if typ.argtypes is not None:
            typ.argtypes.accept(self)
        self.ccode.write(")")

    def visit_funargs(self, funargs: "BCFunArgs") -> None:
        args = funargs.funargs
        if len(args) == 0:
            self.ccode.write("void")
        else:
            for arg in args[:-1]:
                arg.accept(self)
                self.ccode.write(", ")
            args[-1].accept(self)

    def visit_funarg(self, funarg: "BCFunArg") -> None:
        if funarg.typ.is_unknown:
            self.ccode.write("void *")
        else:
            funarg.typ.accept(self)
        self.ccode.write(" ")
        self.ccode.write(funarg.name)

    def visit_named_typ(self, typ: "BCT.BCTypNamed") -> None:
        self.ccode.write(typ.tname)

    def visit_comp_typ(self, typ: "BCT.BCTypComp") -> None:
        self.ccode.write("struct " + typ.compname)

    def visit_compinfo(self, cinfo: "BCCompInfo") -> None:
        self.ccode.write("struct " + cinfo.cname + " {")
        if len(cinfo.fieldinfos) > 0:
            self.increase_indent()
            self.ccode.newline(indent=self.indent)
            for (i, finfo) in enumerate(cinfo.fieldinfos):
                finfo.fieldtype.accept(self)
                self.ccode.write(" ")
                self.ccode.write(finfo.fieldname)
                self.ccode.write(";")
                if i < len(cinfo.fieldinfos) - 1:
                    self.ccode.newline(indent=self.indent)
            self.decrease_indent()
            self.ccode.newline()
            self.ccode.write("};")
            self.ccode.newline()
        else:
            self.ccode.write(" };")
            self.ccode.newline()

    def visit_fieldinfo(self, finfo: "BCFieldInfo") -> None:
        pass

    def visit_enum_typ(self, typ: "BCT.BCTypEnum") -> None:
        self.ccode.write("enum " + typ.ename)

    def visit_enuminfo(self, einfo: "BCEnumInfo") -> None:
        self.ccode.write("enuminfo: Not yet implemented")

    def visit_enumitem(self, eitem: "BCEnumItem") -> None:
        pass

    def visit_typeinfo(self, tinfo: "BCTypeInfo") -> None:
        self.ccode.write("typedef ")
        tinfo.ttype.accept(self)
        self.ccode.write(" ")
        self.ccode.write(tinfo.tname)
        self.ccode.write(";")

    def visit_attributes(self, attrs: "BCAttributes") -> None:
        if len(attrs.attrs) == 0:
            return

        self.ccode.write("  __attribute__((")
        attrs.attrs[0].accept(self)
        if len(attrs.attrs) == 1:
            self.ccode.write("))")
            return

        for attr in attrs.attrs[1:]:
            self.ccode.write(",")
            self.ccode.newline(indent=17)
            attr.accept(self)
        self.ccode.newline()
        self.ccode.write("               ))")

    def visit_attribute(self, attr: "BCAttribute") -> None:
        self.ccode.write(attr.name)
        self.ccode.write("(")
        if len(attr.params) == 0:
            pass
        else:
            for param in attr.params[:-1]:
                param.accept(self)
                self.ccode.write(", ")
            attr.params[-1].accept(self)
        self.ccode.write(")")

    def visit_attr_param_int(self, param: "AP.BCAttrParamInt") -> None:
        self.ccode.write(str(param.intvalue))

    def visit_attr_param_str(self, param: "AP.BCAttrParamStr") -> None:
        self.ccode.write('"' + param.strvalue + '"')

    def visit_attr_param_cons(self, param: "AP.BCAttrParamCons") -> None:
        self.ccode.write(param.name)
        if len(param.params) > 0:
            self.ccode.write("(")
            for p in param.params[:-1]:
                p.accept(self)
                self.ccode.write(", ")
            param.params[-1].accept(self)
            self.ccode.write(")")
        else:
            self.ccode.write("()")
