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

import chb.util.fileutil as UF

class PEImportDirectoryNameEntry():
    '''Represents a single entry in an import table'''

    def __init__(self,peimporttable,xnode):
        self.peimporttable = peimporttable
        self.xnode = xnode
        self.address = self.xnode.get('bound-address')
        self.hint = self.xnode.get('hint')
        self.name = self.xnode.get('name')
        self.rva = self.xnode.get('rva')

    def has_summary(self):
        return self.peimporttable.has_summary(self.name)

    def as_dictionary(self):
        result = {
            "name": self.name,
            "hint": self.hint,
            "address": self.address,
            "rva": self.rva,
            "summary": "Y" if self.has_summary() else "N"
            }
        return result

    def __str__(self):
        summary = ' '
        if self.has_summary(): summary = 'Y'
        hint = self.hint
        if hint is None: hint = ' '
        return ((' ' * 3) + hint.rjust(4) + '  ' + self.address +
                '  ' + summary + '  ' + self.name)
