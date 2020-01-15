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

from chb.models.ParameterRepresentation import ParameterRepresentation
from chb.models.PEDataType import PEDataType
from chb.models.PEDataType import PEDataBType
from chb.models.ParameterRole import ParameterRole

class DllFunctionParameter(object):

    def __init__(self,fapi,xnode):
        self.fapi = fapi              # DllFunctionAPI
        self.xnode = xnode
        self.name = self.xnode.get('name')
        self.size = int(self.xnode.get('size','4'))
        self.location = self.xnode.get('loc')
        self.mode = self.xnode.get('io','rw')

    def get_summary(self): return self.fapi.summary

    def has_representation(self): return not (self.xnode.find('rep') is None)

    def get_representation(self):
        if self.has_representation():
            return ParameterRepresentation(self,self.xnode.find('rep'))

    def represent_value(self,v):
        if self.has_representation():
            return self.get_representation().represent(v)
        else:
            return str(v)

    def get_type(self):
        xtype = self.xnode.find('type')
        if not xtype is None:
            return PEDataType(self.xnode.find('type'))
        xtype = self.xnode.find('btype')
        if not xtype is None:
            return PEDataBType(self.xnode.find('btype'))
        else:
            raise UF.CHBError('Summary for ' + self.fapi.summary.name + ' in dll '
                                 + self.fapi.summary.dll
                                 + ' does not have a type for parameter '
                                 + self.name)

    def is_stack_parameter(self): return 'nr' in self.xnode.attrib

    def get_stack_nr(self):
        if self.is_stack_parameter():
            return int(self.xnode.get('nr'))
        raise UF.CHBError('Not a stack parameter: ' + str(self))

    def get_register_name(self):
        if self.is_register_par():
            return self.xnode.get('reg')
        raise UF.CHBError('Not a register parameter: ' + str(self))

    def get_roles(self):
        if 'roles' in self.xnode.attrib:
            if self.xnode.get('roles') == 'none': return []
        roles = self.xnode.find('roles')
        if roles is None: return []
        return [ ParameterRole(self,r) for r in roles.findall('role') ]
