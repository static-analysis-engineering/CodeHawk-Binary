# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023      Aarno Labs LLC
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

from typing import cast, List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary

@x86registry.register_tag("bsf", X86Opcode)
@x86registry.register_tag("bswap", X86Opcode)
@x86registry.register_tag("btc", X86Opcode)
@x86registry.register_tag("btr", X86Opcode)
@x86registry.register_tag("clflush", X86Opcode)
@x86registry.register_tag("cli", X86Opcode)    
@x86registry.register_tag("cmova", X86Opcode)
@x86registry.register_tag("cmovbe", X86Opcode)
@x86registry.register_tag("cmovc", X86Opcode)
@x86registry.register_tag("cmovg", X86Opcode)
@x86registry.register_tag("cmovge", X86Opcode)    
@x86registry.register_tag("cmovl", X86Opcode)
@x86registry.register_tag("cmovle", X86Opcode)
@x86registry.register_tag("cmovnc", X86Opcode)
@x86registry.register_tag("cmovns", X86Opcode)
@x86registry.register_tag("cmovnz", X86Opcode)
@x86registry.register_tag("cmovs", X86Opcode)    
@x86registry.register_tag("cmovz", X86Opcode)
@x86registry.register_tag("cmpxch", X86Opcode)
@x86registry.register_tag("cmpxchg8b", X86Opcode)
@x86registry.register_tag("cwb", X86Opcode)
@x86registry.register_tag("cwde", X86Opcode)
@x86registry.register_tag("emms", X86Opcode)
@x86registry.register_tag("fadd", X86Opcode)
@x86registry.register_tag("fild", X86Opcode)
@x86registry.register_tag("fistp", X86Opcode)
@x86registry.register_tag("fld", X86Opcode)
@x86registry.register_tag("fmul", X86Opcode)
@x86registry.register_tag("fnclex", X86Opcode)
@x86registry.register_tag("fnsave", X86Opcode)
@x86registry.register_tag("frstor", X86Opcode)
@x86registry.register_tag("fxrstor", X86Opcode)
@x86registry.register_tag("fxsave", X86Opcode)
@x86registry.register_tag("fsubrp", X86Opcode)
@x86registry.register_tag("int", X86Opcode)
@x86registry.register_tag("invlpg", X86Opcode)
@x86registry.register_tag("invpcid", X86Opcode)
@x86registry.register_tag("iretd", X86Opcode)
@x86registry.register_tag("jecxz", X86Opcode)
@x86registry.register_tag("ldmxcsr", X86Opcode)
@x86registry.register_tag("lidt", X86Opcode)
@x86registry.register_tag("lldt", X86Opcode)
@x86registry.register_tag("lock", X86Opcode)
@x86registry.register_tag("lodsb", X86Opcode)
@x86registry.register_tag("ltr", X86Opcode)
@x86registry.register_tag("mfence", X86Opcode)
@x86registry.register_tag("movntdqa", X86Opcode)
@x86registry.register_tag("movs", X86Opcode)
@x86registry.register_tag("movups", X86Opcode)
@x86registry.register_tag("rdmsr", X86Opcode)
@x86registry.register_tag("rdpmc", X86Opcode)
@x86registry.register_tag("rdseed", X86Opcode)
@x86registry.register_tag("rep ins", X86Opcode)
@x86registry.register_tag("rep outs", X86Opcode)
@x86registry.register_tag("repne scas", X86Opcode)
@x86registry.register_tag("scasb", X86Opcode)
@x86registry.register_tag("serialize", X86Opcode)
@x86registry.register_tag("sgdt", X86Opcode)
@x86registry.register_tag("sidt", X86Opcode)
@x86registry.register_tag("sldt", X86Opcode)
@x86registry.register_tag("sti", X86Opcode)
@x86registry.register_tag("stos", X86Opcode)
@x86registry.register_tag("str", X86Opcode)
@x86registry.register_tag("sysexit", X86Opcode)
@x86registry.register_tag("tpause", X86Opcode)
@x86registry.register_tag("ud2", X86Opcode)
@x86registry.register_tag("unknown", X86Opcode)
@x86registry.register_tag("wait", X86Opcode)
@x86registry.register_tag("wbinvd", X86Opcode)
@x86registry.register_tag("xgetbv", X86Opcode)
@x86registry.register_tag("xrstor", X86Opcode)
@x86registry.register_tag("xrstors", X86Opcode)
@x86registry.register_tag("xsave", X86Opcode)
@x86registry.register_tag("xsaves", X86Opcode)
class X86Unknown(X86Opcode):
    """Temporary placeholder for instructions not yet handled."""

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    def annotation(self, xdata: InstrXData) -> str:
        return "unknown:pending"
