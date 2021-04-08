# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""MIPS function basic block."""

import xml.etree.ElementTree as ET

from typing import List, Sequence, TYPE_CHECKING

import chb.app.DictionaryRecord as D
import chb.app.Instruction as I
import chb.app.StackPointerOffset as S
import chb.util.IndexedTable as IT
import chb.simulate.SimUtil as SU
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.mips.MIPSBlock
    import chb.mips.MIPSDictionary
    import chb.mips.MIPSOperand

'''
class SpOffset(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.mipsfunction = d.mipsfunction
        self.vd = self.mipsfunction.vardictionary
        self.xd = self.vd.xd

    def get_level(self): return int(self.args[0])

    def get_offset(self): return self.xd.get_interval(int(self.args[1]))

    def is_closed(self): return self.get_offset().is_closed()

    def __str__(self):
        level = self.get_level() + 1
        return ('[' * level) + ' ' + str(self.get_offset()).rjust(4) + ' ' + (']' * level)


class MIPSInstrXData(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.mipsfunction = d.mipsfunction
        self.vd = self.mipsfunction.vardictionary
        self.xd = self.vd.xd
        self.app = self.mipsfunction.app
        self.bd = self.app.bdictionary

    def is_function_argument(self):
        return len(self.tags) > 1 and self.tags[1] == 'arg'

    def get_function_argument_callsite(self):
        return self.bd.get_address(self.args[2])

    def get_xprdata(self):
        if len(self.tags) == 0:
            return([],self.args,[])
        key = self.tags[0]
        if key.startswith('a:'):
            xprs = []
            key = key[2:]
            for (i,c) in enumerate(key):
                arg = int(self.args[i])
                xd = self.xd
                if c == 'v': xprs.append(xd.get_variable(arg))
                elif c == 'x': xprs.append(xd.get_xpr(arg))
                elif c == 'a': xprs.append(xd.get_xpr(arg))
                elif c == 's': xprs.append(self.bd.get_string(arg))
                elif c == 'i': xprs.append(self.xd.get_interval(arg))
                elif c == 'l': xprs.append(arg)
            return (self.tags[1:],self.args,xprs)
        return (self.tags,self.args,[])

'''

class MIPSInstruction(I.Instruction):

    def __init__(
            self,
            b: "chb.mips.MIPSBlock.MIPSBlock",
            xnode: ET.Element) -> None:
        I.Instruction.__init__(self, b, xnode)

    @property
    def mnemonic(self) -> str:
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).mnemonic

    @property
    def mipsdictionary(self) -> "chb.mips.MIPSDictionary.MIPSDictionary":
        return self.app.mipsdictionary

    @property
    def opcodetext(self) -> str:
        try:
            mnemonic = self.mnemonic
            operands = self.operands
            return mnemonic.ljust(8) + ','.join([ str(op) for op in operands ])
        except IT.IndexedTableError as e:
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            raise UF.CHBError('Error for MIPS opcode ' + str(opcode) + ': '
                              + str(e))

    @property
    def operands(self) -> Sequence["chb.mips.MIPSOperand.MIPSOperand"]:
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_operands()

    @property
    def bytestring(self) -> str:
        return self.mipsdictionary.read_xml_mips_bytestring(self.xnode)

    @property
    def stackpointer_offset(self) -> S.StackPointerOffset:
        return self.function.fndictionary.read_xml_sp_offset(self.xnode)

    @property
    def annotation(self) -> str:
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_global_variables(xdata)

    def get_operand_values(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return self.mipsdictionary.read_xml_mips_opcode(self.xnode).get_operand_values(xdata)

    def get_load_address(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return self.mipsdictionary.read_xml_mips_opcode(self.xnode).get_load_address()

    # returns a pair of (lhs,rhs) global references
    def get_global_refs(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        lhs = opcode.get_lhs(xdata)
        rhs = opcode.get_rhs(xdata)
        return ([ x for x in lhs if x.is_structured_var() or x.is_global_value() ],
                    [ x for x in rhs if x.is_structured_expr() ])

    # returns a list of strings
    def get_strings(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_strings(xdata)

    # returns a dictionary gvar -> count
    def get_global_variables(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_global_variables(xdata)

    def get_registers(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_registers()

    def refers_to_register(self,registers):
        return any( [ reg for reg in registers if reg in self.get_registers() ])

    def get_annotation(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode).get_annotation(xdata)
        return str(opcode).ljust(40)

    def is_return_instruction(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_return()

    def is_restore_register_instruction(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_restore_register()

    def is_call_instruction(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_call_instruction(xdata)

    def is_load_word_instruction(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_load_word()

    def is_store_word_instruction(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_store_word()

    def is_call_to_app_function(self,tgtaddr):
        if self.is_call_instruction():
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            ctgtaddr = opcode.get_target(xdata)
            return  (not ctgtaddr is None) and str(ctgtaddr) == tgtaddr
        return False

    def get_call_facts(self):
        if not self.is_call_instruction():
            raise UF.CHBError("Not a call instruction: " + str(self))
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        result = {}
        callargs = self.get_annotated_call_arguments()
        if callargs:
            result['args'] = callargs
        tgt = self.get_call_target()
        if tgt == 'call-target:u':
            result['t'] = '?'
        else:
            result['t'] = str(tgt)
        return result

    def get_annotated_call_arguments(self):
        if self.is_call_instruction():
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            return opcode.get_annotated_call_arguments(xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    def get_call_target(self):
        if self.is_call_instruction():
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            opcode =  self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            return opcode.get_call_target(xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    def get_call_arguments(self):
        if self.is_call_instruction():
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            return opcode.get_arguments(xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    def has_string_arguments(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return opcode.is_call_instruction(xdata) and opcode.has_string_arguments(xdata)

    def has_stack_arguments(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return opcode.is_call_instruction(xdata) and opcode.has_stack_arguments(xdata)

    def is_branch_instruction(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.is_branch_instruction()

    def has_branch_condition(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.has_branch_condition()

    def get_branch_condition(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_branch_condition(xdata)

    def is_memory_assign(self):
        if self.get_mnemonic() == 'sw':
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            if len(xprs) >= 3:
                lhs = xprs[0]
                return (lhs.has_denotation ()
                            and lhs.get_denotation().is_memory_variable())
        return False

    def get_memory_assign(self):
        if self.is_memory_assign():
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            lhs = xprs[0].get_denotation()
            rhs = xprs[2]
            return (lhs,rhs)
        else:
            raise CHBError('Instruction is not a memory assign')

    def get_return_expr(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_return_expr(xdata)

    def get_rhs_expr(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_rhs(xdata)

    def get_lhs(self):
        xdata = self.fndictionary.read_xml_instrx(self.xnode)
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_lhs(xdata)

    # false, true condition
    def get_ft_conditions(self):
        if self.is_branch_instruction():
            xdata = self.fndictionary.read_xml_instrx(self.xnode)
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            return opcode.get_ft_conditions(xdata)
        return []

    def simulate(self,simstate):
        try:
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            opcode.simulate(self.iaddr,simstate)
        except SU.CHBSimError as e:
            e.instrtxt = self.to_string(align=False)
            raise e

    def to_string(self,sp=False,opcodetxt=True,align=True,opcodewidth=40):
        pesp = str(self.stackpointer_offset) + '  ' if sp else ''
        if align:
            popcode = self.opcodetext.ljust(opcodewidth) if opcodetxt else ''
            return pesp + popcode + self.get_annotation()
        else:
            popcode = self.get_opcode_text()
            return popcode + '  [[' + self.get_annotation() + ']]'

    def __str__(self): return self.to_string()
