# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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


import chb.app.DictionaryRecord as D

class SpOffset(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.mipsfunction = d.mipsfunction
        self.vd = self.mipsfunction.vardictionary
        self.xd = self.vd.xd

    def get_level(self): return int(self.args[0])

    def get_offset(self): return self.xd.get_interval(int(self.args[1]))

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

class MIPSInstruction(object):

    def __init__(self,asmb,xnode):
        self.mipsblock = asmb                               # MIPSBlock
        self.mipsfunction = self.mipsblock.mipsfunction     # MIPSFunction
        self.xnode = xnode
        self.iaddr = self.xnode.get('ia')
        self.mipsdictionary = self.mipsfunction.app.mipsdictionary
        self.idictionary = self.mipsfunction.dictionary

    def get_mnemonic(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_mnemonic()

    def get_opcode_text(self):
        return self.mipsdictionary.read_xml_mips_opcode_text(self.xnode)

    def get_operands(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_operands()

    def get_byte_string(self):
        return self.mipsdictionary.read_xml_mips_bytestring(self.xnode)

    def get_sp_offset(self):
        return self.idictionary.read_xml_sp_offset(self.xnode)

    def get_operand_values(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return self.mipsdictionary.read_xml_mips_opcode(self.xnode).get_operand_values(xdata)

    # returns a pair of (lhs,rhs) global references
    def get_global_refs(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        lhs = opcode.get_lhs(xdata)
        rhs = opcode.get_rhs(xdata)
        return ([ x for x in lhs if x.is_structured_var() or x.is_global_value() ],
                    [ x for x in rhs if x.is_structured_expr() ])

    # returns a list of strings
    def get_strings(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_strings(xdata)

    # returns a dictionary gvar -> count
    def get_global_variables(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_global_variables(xdata)

    def get_registers(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_registers()

    def refers_to_register(self,registers):
        return any( [ reg for reg in registers if reg in self.get_registers() ])

    def get_annotation(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode).get_annotation(xdata)
        return str(opcode).ljust(40)

    def is_return_instruction(self):
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_return()

    def is_call_instruction(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).is_call_instruction(xdata)

    def is_call_to_app_function(self,tgtaddr):
        if self.is_call_instruction():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            ctgtaddr = opcode.get_target(xdata)
            return  (not ctgtaddr is None) and str(ctgtaddr) == tgtaddr
        return False

    def get_call_target(self):
        if self.is_call_instruction():
            xdata = self.idictionary.read_xml_instrx(self.xnode)            
            opcode =  self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            return opcode.get_target(xdata)

    def get_call_arguments(self):
        if self.is_call_instruction():
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            return opcode.get_arguments(xdata)
        print('**Not a call instruction**')
        print(str(self))
        exit(1)

    def has_string_arguments(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return opcode.is_call_instruction(xdata) and opcode.has_string_arguments(xdata)

    def is_branch_instruction(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.is_branch_instruction()

    def has_branch_condition(self):
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.has_branch_condition()

    def get_branch_condition(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
        return opcode.get_branch_condition(xdata)

    def is_memory_assign(self):
        if self.get_mnemonic() == 'sw':
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            (xtags,xargs,xprs) = xdata.get_xprdata()
            if len(xprs) >= 3:
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
            raise CHBError('Instruction is not a memory assign')

    def get_return_expr(self):
        xdata = self.idictionary.read_xml_instrx(self.xnode)
        return (self.mipsdictionary.read_xml_mips_opcode(self.xnode)).get_return_expr(xdata)

    # false, true condition
    def get_ft_conditions(self):
        if self.is_branch_instruction():
            xdata = self.idictionary.read_xml_instrx(self.xnode)
            opcode = self.mipsdictionary.read_xml_mips_opcode(self.xnode)
            return opcode.get_ft_conditions(xdata)
        return []

    def to_string(self,sp=False,opcodetxt=True,align=True,opcodewidth=40):
        pesp = str(self.get_sp_offset()) + '  ' if sp else ''
        if align:
            popcode = self.get_opcode_text().ljust(opcodewidth) if opcodetxt else ''
            return pesp + popcode + self.get_annotation()
        else:
            popcode = self.get_opcode_text()
            return popcode + '  [[' + self.get_annotation() + ']]'

    def __str__(self): return self.to_string()
