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

class FnInvariants(object):

    def __init__(self,invd,xnode):
        self.invd = invd
        self.asmfunction = self.invd.asmfunction
        self.invariants = {}           # instruction address -> BInvariantFact list
        self.initialize(xnode)

    def get_invariants(self,ia):
        if ia in self.invariants:
            return self.invariants[ia]
        else:
            return []

    def initialize(self,xnode):
        if not xnode is None:
            self._read_xml(xnode)
        else:
            print('No invariants node found')

    def __str__(self):
        lines = []
        for loc in sorted(self.invariants):
            lines.append(str(loc) + ': ')
            locinv = self.invariants[loc]
            for i in locinv:
                lines.append('  ' + str(i))
        return '\n'.join(lines)

    def _read_xml(self,xnode):
        for xloc in xnode.findall('loc'):
            ia = xloc.get('a')
            self.invariants[ia] = []
            ifacts = xloc.get('ifacts')
            if not ifacts is None:
                for findex in [ int(x) for x in ifacts.split(',') ]:
                    self.invariants[ia].append(self.invd.get_invariant_fact(findex))
