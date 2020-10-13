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

import chb.simulate.SimUtil as SU

def simplify_result(id1,id2,x1,x2):
    if id1 == id2:
        return str(x1)
    else:
        return str(x1) + ' (= ' + str(x2) + ')'

branch_opcodes = [ 'beq', 'beql', 'bne',  'blez', 'bltz', 'bgez' ]
call_opcodes = [ 'jal', 'jalr', 'bal', 'jr' ]

class MIPSOpcodeBase(object):

    def __init__(self,mipsd,index,tags,args):
        self.mipsd = mipsd
        self.app = self.mipsd.app
        self.bd = self.app.bdictionary
        self.ixd = self.mipsd.app.interfacedictionary
        self.index = index
        self.tags = tags
        self.args = args

    def get_key(self):
        return (','.join(self.tags),','.join([str(x) for x in self.args]))

    def get_mnemonic(self): return self.tags[0]

    # returns the lhs variables of an assignment if this is an assignment, else []
    def get_lhs(self,xdata): return []

    # returns the rhs expressions of an assignment if this is an assignment, else []
    def get_rhs(self,xdata): return []

    # returns a list of the operands of the opcode
    def get_operands(self):
        try:
            return [ self.mipsd.get_mips_operand(i) for i in self.args ]
        except:
            print('Instruction ' + str(self))
            return []


    # returns rhs-values of operands
    def get_operand_values(self,xdata): return []

    # returns a list of strings
    def get_strings(self,xdata): return []

    # returns a dictionary gv -> count
    def get_global_variables(self,xdata): return {}

    # returns a dictionary of name -> MIPSRegister
    def get_registers(self):
        result = {}
        operands = self.get_operands()
        for op in self.get_operands():
            if op.is_mips_register():
                r = op.get_mips_register()
                result.setdefault(str(r),r)
            elif op.is_mips_indirect_register():
                r = op.get_mips_indirect_register()
                result.setdefault(str(r),r)
        return result

    def get_branch_condition(self,xdata): return None

    """
    Combines general original opcode operands from (tags,args) with generated
    (inferred) operand data from xdata to create a description of the
    instruction. xdata.get_xprdata() converts expression/variable indices to
    expressions and variables, which are made available in xprs.
    """
    def get_annotation(self,xdata): return self.__str__()

    def get_ft_conditions(self,xdata): return []

    def is_return(self):
        return self.tags[0] == 'jr' and str(self.get_operands()[0]) == 'ra'

    def is_branch_instruction(self):
        return self.tags[0] in branch_opcodes

    def is_call_instruction(self,xdata): return False

    def is_restore_register(self): return False

    def has_branch_condition(self): return False

    def is_return_instruction(self): return False

    def simulate(self,iaddr,simstate):
        raise SU.CHBSimError(simstate,iaddr,
                             'Simulation not yet supported for ' + str(self)
                             + ' at address ' + str(iaddr))

    def __str__(self):
        return self.tags[0] + ':pending'

