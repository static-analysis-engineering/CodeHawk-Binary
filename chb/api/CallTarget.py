# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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
import chb.app.DictionaryRecord as D

# ==============================================================================
#                                                                FunctionStub ==
# ==============================================================================

class FunctionStubBase(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.bd = self.d.bdictionary
        self.app = self.bd.app
        self.models = self.app.models

    def is_dll_stub(self): return False
    def is_so_stub(self): return False
    def is_syscall_stub(self): return False

    def __str__(self): return 'function-stub:' + self.tags[0]

class SOFunction(FunctionStubBase):

    def __init__(self,d,index,tags,args):
        FunctionStubBase.__init__(self,d,index,tags,args)

    def is_so_stub(self): return True

    def get_name(self): return self.bd.get_string(self.args[0])

    def __str__(self): return self.get_name()

class SyscallFunction(FunctionStubBase):

    def __init__(self,d,index,tags,args):
        FunctionStubBase.__init__(self,d,index,tags,args)

    def is_syscall_stub(self): return True

    def get_index(self): return self.args[0]

    def __str__(self): return 'syscall-' + self.get_index()

class DllFunction(FunctionStubBase):

    def __init__(self,d,index,tags,args):
        FunctionStubBase.__init__(self,d,index,tags,args)

    def is_dll_stub(self): return True

    def get_dll(self): return self.bd.get_string(self.args[0])

    def get_name(self): return self.bd.get_string(self.args[1])

    def has_summary(self):
        return self.models.has_dll_summary(self.get_dll(),self.get_name())

    def get_summary(self):
        if self.has_summary():
            return self.models.get_dll_summary(self.get_dll(),self.get_name())
        else:
            print('No summary for ' + str(self.get_dll()) + ':' + str(self.get_name()))
            return None

    def __str__(self): return self.get_name()

class JniFunction(FunctionStubBase):

    def __init__(self,d,index,tags,args):
        FunctionStubBase.__init__(self,d,index,tags,args)

    def get_jni_index(self): return self.args[0]

    def __str__(self): return 'Jni:' + str(self.get_jni_index())

class PckFunction(FunctionStubBase):

    def __init__(self,d,index,tags,args):
        FunctionStubBase.__init__(self,d,index,tags,args)

    def get_lib(self): return self.bd.get_string(self.args[0])

    def get_name(self): return self.bd.get_string(self.args[1])

    def get_packages(self):
        return [ self.bd.get_string(i) for i in self.args[2:] ]

    def __str__(self):
        return (self.get_lib() + ':' + '::'.join(self.get_packages())
                    + self.get_name())


# ==============================================================================
#                                                                  CallTarget ==
# ==============================================================================
   
class CallTargetBase(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.bd = self.d.bdictionary

    def is_dll_target(self): return False
    def is_so_target(self): return False
    def is_app_target(self): return False
    def is_unknown(self): return False

    def __str__(self): return 'call-target:' + self.tags[0]

class StubTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

    def is_dll_target(self): return self.get_stub().is_dll_stub()

    def get_dll(self):
        if self.is_dll_target():
            return  self.get_stub().get_dll()
        raise UF.CHBError('Stub target is not a dll target: ' + str(self))

    def get_name(self): return self.get_stub().get_name()

    def is_so_target(self): return self.get_stub().is_so_stub()

    def get_stub(self): return self.d.get_function_stub(self.args[0])

    def __str__(self): return str(self.get_stub())

class StaticStubTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

    def get_address(self): return self.bd.get_address(self.args[0])

    def is_so_target(self): return self.get_stub().is_so_stub()

    def get_stub(self): return self.d.get_function_stub(self.args[1])

    def __str__(self):
        return str(self.get_stub()) + '@' + str(self.get_address())

class AppTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

    def is_app_target(self): return True

    def get_address(self): return self.bd.get_address(self.args[0])

    def __str__(self):
        addr = str(self.get_address())
        if self.d.app.userdata.functionnames.has_function_name(addr):
            return 'App:' + self.d.app.userdata.functionnames.get_function_name(addr)
        elif self.d.app.has_function_name(addr):
            return 'App:' + self.d.app.get_function_name(addr)
        else:
            return 'App:' + str(self.get_address())

class InlinedAppTarget(CallTargetBase):

    # tags: [ 'inl' ]
    # args: [ address of application function, string ]
    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

    def get_address(self): return self.bd.get_address(self.args[0])

    def get_name(self): return self.bd.get_string(self.args[1])

    def __str__(self): return 'Inl:' + self.get_name()

class WrappedTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

class VirtualTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

class IndirectTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

class UnknownTarget(CallTargetBase):

    def __init__(self,d,index,tags,args):
        CallTargetBase.__init__(self,d,index,tags,args)

    def is_unknown(self): return True
