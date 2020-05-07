# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
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

class MIPSCfgPath(object):

    def __init__(self,mipscfg,path):
        self.mipscfg = mipscfg    # MIPSCfg
        self.path = path          # [ block address ]

    def is_feasible(self):
        return not (any( [ not c is None and c.is_false() for c in self.get_conditions() ]))

    def has_loop_node(self):
        return any([ self.mipscfg.has_loop_level(b) for b in self.path ])

    def get_conditions(self):
        """Returns conditions per block, condition may be None."""
        result = []
        for i in range(len(self.path) - 1):
            c = self.mipscfg.get_condition(self.path[i],self.path[i+1])
            result.append(c)
        return result

    def get_call_instructions(self):
        """Returns calls per block."""
        result = []
        for i in range(len(self.path)):
            calls = self.mipscfg.mipsfunction.get_block(self.path[i]).get_call_instructions()
            result.append(calls)
        return result

    def get_block_call_instruction_strings(self):
        """Returns a list of (blockaddress, callinstr-string)."""
        result = []
        callinstrs = self.get_call_instructions()
        for i in range(len(self.path)):
            for c in callinstrs[i]:
                result.append((self.path[i],c.iaddr,c.get_annotation()))
        return result                              

    def get_constraints(self):
        """Returns constraints per block (constraint may be None."""
        result = []
        conditions = self.get_conditions()
        for c in conditions:
            k = None if c is None else c.to_input_constraint()
            result.append(k)
        return result

    def get_block_condition_strings(self):
        """Returns a list of (blockaddress, condition-string), with None excluded"""
        result = []
        conditions = self.get_conditions()
        for i in range(len(self.path) - 1):
            c = conditions[i]
            if c is None: continue
            result.append((self.path[i],str(c)))
        return result
            
