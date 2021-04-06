# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs, LLC
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
"""X86 Assembly Instruction Data."""

import chb.util.fileutil as UF

import chb.asm.FnX86DictionaryRecord as D
import chb.simulate.SimulationState as S
import chb.simulate.SimUtil as SU

class EspOffset(D.FnX86DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.FnX86DictionaryRecord.__init__(self,d,index,tags,args)
        self.asmfunction = d.asmfunction
        self.vd = self.asmfunction.vardictionary
        self.xd = self.vd.xd

    def get_level(self): return int(self.args[0])

    def get_offset(self): return self.xd.get_interval(int(self.args[1]))

    def __str__(self):
        level = self.get_level() + 1
        return ('[' * level) + ' ' + str(self.get_offset()).rjust(4) + ' ' + (']' * level)
        

class AsmInstrXData(D.FnX86DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.FnX86DictionaryRecord.__init__(self,d,index,tags,args)
        self.asmfunction = d.asmfunction
        self.vd = self.asmfunction.vardictionary
        self.xd = self.vd.xd
        self.app = self.asmfunction.app
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
                elif c == 's': xprs.append(self.bd.get_string(arg))
                elif c == 'i': xprs.append(self.xd.get_interval(arg))
                elif c == 'l': xprs.append(arg)
            return (self.tags[1:],self.args,xprs)
        return (self.tags,self.args,[])

    

class AsmInstruction(object):

    def __init__(self,asmb,xnode):
        self.asmblock = asmb                               # AsmBlock
        self.asmfunction = self.asmblock.asmfunction       # AsmFunction
        self.xnode = xnode
        self.iaddr = self.xnode.get('ia')
        self.x86dictionary = self.asmfunction.app.x86dictionary
        self.idictionary = self.asmfunction.dictionary

    def get_mnemonic(self):
        return (self.x86dictionary.read_xml_opcode(self.xnode)).get_mnemonic()

    def get_opcode_text(self):
        return self.x86dictionary.read_xml_opcode_text(self.xnode)

    def get_operands(self):
        return (self.x86dictionary.read_xml_opcode(self.xnode)).get_operands()

    def get_byte_string(self):
        return self.x86dictionary.read_xml_bytestring(self.xnode)

    def get_esp_offset(self):
        return self.idictionary.read_xml_esp_offset(self.xnode)

    def is_return_instruction(self):
        return (self.x86dictionary.read_xml_opcode(self.xnode)).is_return()

    def is_conditional_branch_instruction(self):
        return (self.x86dictionary.read_xml_opcode(self.xnode)).is_conditional_branch()

    def is_branch_instruction(self):
        return self.is_conditional_branch_instruction()

    def has_branch_predicate(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        if opcode.is_conditional_branch():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.has_predicate(xdata)
        return False

    def get_branch_predicate(self):
        if self.has_branch_predicate():
            opcode = self.x86dictionary.read_xml_opcode(self.xnode)
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.get_predicate(xdata)

    def get_ft_conditions(self):
        if self.has_branch_condition():
            opcode = self.x86dictionary.read_xml_opcode(self.xnode)
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.get_ft_conditions(xdata)        

    def is_indirect_jump(self):
        return (self.x86dictionary.read_xml_opcode(self.xnode)).is_indirect_jump()

    def get_jumptable_targets(self):
        if self.is_indirect_jump():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return (self.x86dictionary.read_xml_opcode(self.xnode)).get_targets(xdata)

    def get_selector_expr(self):
        if self.is_indirect_jump():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return (self.x86dictionary.read_xml_opcode(self.xnode)).get_selector_expr(xdata)

    def has_branch_condition(self):
        if self.is_conditional_branch_instruction():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            return len(xprs) > 0
        return False

    def get_branch_condition(self):
        if self.has_branch_condition():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            return xprs[0]
        raise UF.CHBError('Instruction does not have a branch condition: '
                          + str(self))

    def has_return_expr(self):
        return (self.x86dictionary.read_xml_opcode(self.xnode)).has_return_expr()

    def get_return_expr(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return (self.x86dictionary.read_xml_opcode(self.xnode)).get_return_expr(xdata)

    def get_annotation(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        opcode = self.x86dictionary.read_xml_opcode(self.xnode).get_annotation(xdata)
        return str(opcode).ljust(40)

    def get_opcode_operations(self):
        return self.x86dictionary.read_xml_opcode(self.xnode).get_opcode_operations()

    def get_operand_values(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return self.x86dictionary.read_xml_opcode(self.xnode).get_operand_values(xdata)

    def is_function_argument(self):
        xdata = (self.idictionary.read_xml_instrx(self.xnode))
        return xdata.is_function_argument()

    def get_function_argument_callsite(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return xdata.get_function_argument_callsite()

    def is_call_instruction(self):
        return self.x86dictionary.read_xml_opcode(self.xnode).is_call()

    def get_call_target(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        if opcode.is_call():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.get_call_target(xdata)

    def get_call_arguments(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        if opcode.is_call():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.get_arguments(xdata)

    # returns a list of (rolename,parameter name, argument value)
    def get_ioc_arguments(self):
        results = []
        if self.is_dll_call():
            models = self.asmfunction.app.models
            tgt = self.get_call_target().get_stub()
            args = self.get_call_arguments()
            dll = tgt.get_dll()
            fname = tgt.get_name()
            if models.has_dll_summary(dll,fname):
                summary = models.get_dll_summary(dll,fname)
                params = summary.get_stack_parameters()
                if not params is None:
                    if len(args) == len(params):
                        for (param,arg) in zip(params,args):
                            iocroles = [ role for role in param.get_roles() if role.is_ioc() ]
                            for iocrole in iocroles:
                                ioc = iocrole.get_ioc_name()
                                rolename = iocrole.name
                                results.append((rolename,param.name,arg))
        return results

    def get_annotated_call_arguments(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        if opcode.is_call():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.get_annotated_arguments(xdata)

    def is_call_to_app_function(self,tgtaddr):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        if opcode.is_call():
            ctgtaddr = opcode.get_target_address()
            return (not ctgtaddr is None) and str(ctgtaddr) == tgtaddr

    def is_dll_call(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.is_dll_call(xdata)

    def is_so_call(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.is_so_call(xdata)

    def is_app_call(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.is_app_call(xdata)

    def is_unresolved_call(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.is_unresolved_call(xdata)

    def has_global_value_unresolved_call_target(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.has_global_value_unresolved_call_target(xdata) 

    def get_unresolved_call_target(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        if opcode.is_unresolved_call(xdata):
            return opcode.get_unresolved_call_target(xdata)

    def get_structured_lhs(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        lhs = opcode.get_lhs(xdata)
        return [ x for x in lhs if x.is_structured_var() ]

    def has_structured_lhs(self):
        return len(self.get_structured_lhs()) > 0

    def get_rhs(self):
        opcode = self.x86dictionary.read_xml_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.get_rhs(xdata)

    def get_structured_rhs(self):
        rhs = self.get_rhs()
        return [ x for x in rhs if x.is_structured_expr() ]

    def is_memory_assign(self):
        if self.get_mnemonic() == 'mov':
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            if len(xprs) == 3:
                lhs = xprs[0]
                return (lhs.has_denotation ()
                            and lhs.get_denotation().is_memory_variable())
        return False

    def get_memory_assign(self):
        if self.is_memory_assign():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            lhs = xprs[0].get_denotation()
            rhs = xprs[2]
            return (lhs,rhs)
        else:
            raise UF.CHBError('Instruction is not a memory assign')

    def simulate(self,simstate):
        try:
            opcode = self.x86dictionary.read_xml_opcode(self.xnode)
            opcode.simulate(self.iaddr,simstate)
        except SU.CHBSimError as e:
            e.instrtxt = self.to_string(align=False)
            raise e

    def to_opcode_operations_string(self,opcodewidth=25):
        popcode = self.get_opcode_text().ljust(opcodewidth)
        opcodeops = '; '.join(self.get_opcode_operations())
        return popcode + opcodeops

    def to_string(self,bytestring=False,bytes=False,esp=False,opcodetxt=True,align=True,opcodewidth=25):
        pesp = str(self.get_esp_offset()) + '  ' if esp else ''
        pbytes = self.get_byte_string().ljust(20)  if bytes else ''
        if align:
            popcode = self.get_opcode_text().ljust(opcodewidth) if opcodetxt else ''
            return pesp + pbytes + popcode + self.get_annotation()
        else:
            popcode = self.get_opcode_text()
            return popcode + '  [[' + self.get_annotation() + ']]'


    def __str__(self): return self.to_string()
