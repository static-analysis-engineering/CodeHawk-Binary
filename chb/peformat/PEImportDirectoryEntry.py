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

from chb.peformat.PEImportDirectoryNameEntry import PEImportDirectoryNameEntry

class PEImportDirectoryEntry(object):
    """Represents an import table."""

    def __init__(self,peheader,xnode):
        self.peheader = peheader
        self.xnode = xnode
        self.dllname = self.xnode.get('dll-name')
        self.forwarderchain = self.xnode.get('forwarder-chain')
        self.importaddresstablerva = self.xnode.get('import-address-table-rva')
        self.importlookuptablerva = self.xnode.get('import-lookup-table-rva')
        self.namerva = self.xnode.get('name-rva')
        self.timestamp = self.xnode.get('timestamp-dw')

    def get_name_entries(self):
        result = []
        for n in self.xnode.find('hint-name-table').findall('hint-name-entry'):
            result.append(PEImportDirectoryNameEntry(self,n))
        return sorted(result,key=lambda n:n.name)

    def has_summary(self,name):
        return self.peheader.app.models.has_dll_summary(self.dllname,name)

    def as_dictionary(self):
        result = {}
        result['name'] = self.dllname
        result['entries'] = {}
        for n in self.get_name_entries():
            result['entries'][n.name] = n.as_dictionary()
        return result
    
    def __str__(self):
        lines = []
        def addline(tag,value):
            lines.add(tag.ljust(32) + ': ' + value)
        lines.append('-' * 60)
        lines.append('Import table for ' + self.dllname)
        lines.append('-' * 60)
        for n in self.get_name_entries():
            lines.append(str(n))
        return '\n'.join(lines)
    
