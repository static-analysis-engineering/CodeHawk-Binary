# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020 Henny Sipma
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
"""Directives representing external inputs to a symbolic simulation.

Format of directives file:

"environment": {
    "varname1" : "varvalue",
    ...
    "varnamen" : "varvaulen"
    },
"branches": {
    "iaddr1": <branchinfo>,
    ...
    "iaddrn": <branchinfo>
    },
"stubs": {
    "name1": <stubinfo>,
    ...
    "namen": <stubinfo>
    }

"""


import chb.mipsimulate.MIPSimStubs as Stubs

class MIPSimBranchDirective(object):
    """Possibly stateful directive on which conditional branch to take."""

    def __init__(self,iaddr,info):
        self.iaddr = iaddr
        self.info = info
        self.count = 0

    def get_direction(self): return self.info['branch']

        

class MIPSimDirectives(object):
    """Aggregate directives for environment, functions, and branches."""

    def __init__(self,d):
        self.stubdirectives = {}    # function name -> MIPSimStubDirective
        self.branchdirectives = {}  # iaddr -> MIPSimBranchDirective
        self._initialize(d)

    # --- branches ---

    def has_branch_directive(self,iaddr):
        return iaddr in self.brachdirectives
    
    def get_branch_directive(self,iaddr):
        if self.has_branch_directive(iaddr):
            return self.branchdirectives[iaddr]
        else:
            raise UF.CHBError('Branch directive for ' + iaddr + ' not found')

    # --- stubs ---

    def has_stub_directive(self,name):
        return name in self.stubdirectives

    def get_stub_directive(self,name):
        if self.has_stub_directive(iaddr):
            return self.stubdirectives[name]
        else:
            raise UF.CHBError('Stub directive for ' + name + ' not found')

    def set_stub_directive(self,name,d):
        self.stubdirectives[name] = Stubs.mk_stub_directive(name,d[name])

    # --- initialization ---

    def initialize_environment(self,d):
        for name in d:
            self.environment[name] = d[name]

    def initialize_branches(self,d):
        for iaddr in branches:
            self.branchdirectives[iaddr] = MIPSimBranchDirective(iaddr,d[iaddr])

    def initialize_stubs(self,d):
        for name in stubs:
            self.stubdirectives[name] = Stubs.mk_stub_directive(name,d[name])

    def _initialize(self,d):
        if 'branches' in d:
            self.initialize_branches(d['branches'])
        if 'stubs' in d:
            self.initialize_stubs(d['stubs'])
                                  
