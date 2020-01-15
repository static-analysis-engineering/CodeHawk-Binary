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

class X86OpcodeBase(object):

    def __init__(self,x86d,index,tags,args):
        self.x86d = x86d
        self.app = self.x86d.app
        self.bd = self.app.bdictionary
        self.ixd = self.x86d.app.interfacedictionary
        self.index = index
        self.tags = tags
        self.args = args

    def is_return(self): return False
    def is_conditional_branch(self): return False
    def is_indirect_jump(self): return False
    def is_call(self): return False
    def is_dll_call(self,xdata): return False
    def is_so_call(self,xdata): return False
    def is_app_call(self,xdata): return False
    def is_unresolved_call(self,xdata): return False

    def get_key(self):
        return (','.join(self.tags),','.join([str(x) for x in self.args]))

    # returns the syntactic operands
    def get_operands(self): return [ '?' ]

    # returns the lhs variables of an assignment if this is an assignment else []
    def get_lhs(self,xdata): return []

    # returns the rhs exprs of an assignment if this is an assignment else None
    def get_rhs(self,xdata): return []

    """
    Combines general original opcode operands from (tags,args) with generated
    (inferred) operand data from xdata to create a description of the
    instruction. xdata.get_xprdata() converts expression/variable indices to
    expressions and variables, which are made available in xprs.
    """
    def get_annotation(self,xdata): return self.__str__()

    def get_opcode_operations(self): return []

    # return rhs-values of operands
    def get_operand_values(self,xdata): return []

    def get_mnemonic(self): return self.tags[0]

    def get_ft_conditions(self,xdata): return []

    def simulate(self,iaddr,simstate):
        raise SU.CHBSimError(simstate,iaddr,
                                 ('Simulation not yet supported for ' + str(self)
                                    + ' at address ' + str(iaddr)))

    def __str__(self):
        return self.tags[0] + ':pending'

