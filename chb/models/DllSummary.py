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

from chb.models.APIDoc import APIDoc
from chb.models.DllFunctionAPI import DllFunctionAPI
from chb.models.DllFunctionSemantics import DllFunctionSemantics


class DllSummary(object):

    def __init__(self,models,xnode):
        self.models = models
        self.xnode = xnode
        self.name = self.xnode.get('name')
        self.dll =  self.xnode.get('lib')

    def is_reference(self): return False

    def get_desc(self):
        return self.xnode.find('documentation').find('desc').text

    def get_api_doc(self):
        return APIDoc(self,self.xnode.find('documentation').find('apidoc'))

    def get_api(self):
        return DllFunctionAPI(self,self.xnode.find('api'))

    def get_semantics(self):
        return DllFunctionSemantics(self,self.xnode.find('semantics'))

    def get_categories(self):
        return self.get_semantics().get_categories()

    def get_io_descriptions(self):
        return self.get_semantics().get_descriptions()

    def get_parameter_roles(self):
        return self.get_api().get_parameter_roles()

    def get_norole_parameters(self):
        return self.get_api().get_norole_parameters()

    def get_ioc_roles(self):
        return self.get_api.get_ioc_roles()

    def get_stack_parameters(self):
        return self.get_api().get_stack_parameters()

    def get_stack_parameter_names(self):
        return self.get_api().get_stack_parameter_names()


    
