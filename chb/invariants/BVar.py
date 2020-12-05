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

class VDictionaryRecord(object):

    def __init__(self,vd,index,tags,args):
        self.vd = vd
        self.xd = vd.xd
        self.id = vd.app.interfacedictionary
        self.faddr = self.vd.asmfunction.faddr
        self.app = vd.app
        self.bd = self.app.bdictionary
        self.index = index
        self.tags = tags
        self.args =  args

    def get_function_info(self):
        return self.app.get_function_info(self.faddr)

    def get_key(self):
        return (','.join(self.tags), ','.join([str(x) for x in self.args]))

# ------------------------------------------------------------------------------
# Memory Base
# ------------------------------------------------------------------------------
class MemoryBase(VDictionaryRecord):

    def __init__(self,vd,index,tags,args):
        VDictionaryRecord.__init__(self,vd,index,tags,args)

    def is_local_stack_frame(self): return False
    def is_realigned_stack_frame(self): return False
    def is_basevar(self): return False

    def is_global(self): return False

class MemoryBaseLocalStackFrame(MemoryBase):

    def __init__(self,vd,index,tags,args):
        MemoryBase.__init__(self,vd,index,tags,args)

    def is_local_stack_frame(self): return True


class MemoryBaseRealignedStackFrame(MemoryBase):

    def __init__(self,vd,index,tags,args):
        MemoryBase.__init__(self,vd,index,tags,args)

    def is_realigned_stack_frame(self): return True

class MemoryBaseBaseVar(MemoryBase):

    def __init__(self,vd,index,tags,args):
        MemoryBase.__init__(self,vd,index,tags,args)

    def is_basevar(self): return True

    def get_basevar(self):
        return self.vd.xd.get_variable(int(self.args[0]))

    def __str__(self):
        return str(self.get_basevar())


class MemoryBaseGlobal(MemoryBase):

    def __init__(self,vd,index,tags,args):
        MemoryBase.__init__(self,vd,index,tags,args)

    def is_global(self): return True

    def __str__(self):
        return 'base:global'

class MemoryBaseUnknown(MemoryBase):

    def __init__(self,vd,index,tags,args):
        MemoryBase.__init__(self,vd,index,tags,args)

    def __str__(self): return "unknownbase:"
        
# ------------------------------------------------------------------------------
# Memory Offset
# ------------------------------------------------------------------------------

class MemoryOffsetBase(VDictionaryRecord):

    def __init__(self,vd,index,tags,args):
        VDictionaryRecord.__init__(self,vd,index,tags,args)

    def is_constant_offset(self): return False
    def is_no_offset(self): return False


class MemoryOffsetNoOffset(MemoryOffsetBase):

    def __init__(self,vd,index,tags,args):
        MemoryOffsetBase.__init__(self,vd,index,tags,args)

    def is_no_offset(self): return True

    def __str__(self): return ''

class MemoryOffsetConstantOffset(MemoryOffsetBase):

    def __init__(self,vd,index,tags,args):
        MemoryOffsetBase.__init__(self,vd,index,tags,args)

    def is_constant_offset(self): return True

    def get_offset(self): return int(self.tags[1])

    def __str__(self): return str(self.get_offset())


# ------------------------------------------------------------------------------
# Assembly variable denotation
# ------------------------------------------------------------------------------

class AssemblyVariableBase(VDictionaryRecord):

    def __init__(self,vd,index,tags,args):
        VDictionaryRecord.__init__(self,vd,index,tags,args)

    def is_memory_variable(self): return False
    def is_basevar_variable(self): return False
    def is_register_variable(self): return False
    def is_cpu_flag_variable(self): return False
    def is_auxiliary_variable(self): return False

    def is_stack_base_address(self):
        return (self.is_auxiliary_variable()
                    and self.get_auxiliary_variable().is_stack_base_address())

    def is_function_return_value(self):
        return (self.is_auxiliary_variable()
                    and self.get_auxiliary_variable().is_function_return_value())

    def is_initial_memory_value(self):
        return (self.is_auxiliary_variable()
                    and self.get_auxiliary_variable().is_initial_memory_value())

    def is_bridge_variable(self):
        return (self.is_auxiliary_variable()
                    and self.get_auxiliary_variable().is_bridge_variable())

    # returns true is this variable is a memory dereference
    def is_structured_var(self):
        return (self.is_basevar_variable()
                    or (self.is_auxiliary_variable()
                            and self.get_auxiliary_variable().is_structured_value()))

    def __str__(self): return 'assembly-variable:' + self.tags[0]

class MemoryVariable(AssemblyVariableBase):

    def __init__(self,vd,index,tags,args):
        AssemblyVariableBase.__init__(self,vd,index,tags,args)

    def is_memory_variable(self): return True

    def is_global_variable(self): return self.get_memory_base().is_global()

    def has_global_base(self): 
        if self.is_global_variable():
            return True
        if self.is_basevar_variable():
            b = self.get_basevar().get_denotation().get_auxiliary_variable()
            if b.is_initial_memory_value():
                return b.get_original_variable().get_denotation().has_global_base()
        return False

    def get_global_base(self):
        if self.is_global_variable():
            return self
        else:
            b = self.get_basevar().get_denotation().get_auxiliary_variable()
            return b.get_original_variable().get_denotation().get_global_base()

    def is_basevar_variable(self):
        return self.get_memory_base().is_basevar()

    def get_basevar(self):
        return self.get_memory_base().get_basevar()

    def is_stack_argument(self):
        return (self.get_memory_base().is_local_stack_frame()
                    and self.get_memory_offset().is_constant_offset()
                    and self.get_memory_offset().get_offset() > 0)

    def get_argument_index(self):
        if self.is_stack_argument():
            return self.get_memory_offset().get_offset() / 4

    def is_local_stack_variable(self):
        return (self.get_memory_base().is_local_stack_frame()
                    and self.get_memory_offset().is_constant_offset()
                    and self.get_memory_offset().get_offset() < 0)

    def is_return_address(self):
        return (self.get_memory_base().is_local_stack_frame()
                    and self.get_memory_offset().is_constant_offset()
                    and self.get_memory_offset().get_offset() == 0)

    def is_realigned_stack_variable(self):
        return (self.get_memory_base().is_realigned_stack_frame()
                    and self.get_memory_offset().is_constant_offset()
                    and self.get_memory_offset().get_offset() <= 0)

    def get_memory_base(self): return self.vd.get_memory_base(self.args[0])

    def get_memory_offset(self): return self.vd.get_memory_offset(self.args[1])

    def __str__(self):
        if self.is_global_variable():
            addr = str(hex(self.get_memory_offset().get_offset()))
            if self.vd.app.userdata.has_symbolic_address(addr):
                return self.vd.app.userdata.symbolicaddresses.get_symbolic_address_name(addr)
            else:
                return 'gv_' + str(hex(self.get_memory_offset().get_offset()))
        elif self.is_stack_argument():
            offset = self.get_memory_offset().get_offset()
            return 'arg.' + '{0:04d}'.format(offset)
        elif self.is_local_stack_variable():
            offset = self.get_memory_offset().get_offset()
            return 'var.' + '{0:04d}'.format(-offset)
        elif self.is_return_address():
            return 'var.0000'
        elif self.is_realigned_stack_variable():
            offset = self.get_memory_offset().get_offset()
            return 'varr.' + '{0:04d}'.format(offset)
        return str(str(self.get_memory_base())) + '[' + str(self.get_memory_offset()) + ']'

class RegisterVariable(AssemblyVariableBase):

    def __init__(self,vd,index,tags,args):
        AssemblyVariableBase.__init__(self,vd,index,tags,args)

    def is_register_variable(self): return True

    def get_register(self): return self.bd.get_register(self.args[0])

    def __str__(self): return str(self.get_register())

class CPUFlagVariable(AssemblyVariableBase):

    def __init__(self,vd,index,tags,args):
        AssemblyVariableBase.__init__(self,vd,index,tags,args)

    def is_cpu_flag_variable(self): return True

class AuxiliaryVariable(AssemblyVariableBase):

    # tags: [ 'a' ]
    # args: [ constant-value-variable: i-cvv ]
    def __init__(self,vd,index,tags,args):
        AssemblyVariableBase.__init__(self,vd,index,tags,args)

    def is_auxiliary_variable(self): return True

    def get_auxiliary_variable(self):
        return self.vd.get_constant_value_variable(self.args[0])

    def __str__(self):
        return str(self.get_auxiliary_variable())


# ------------------------------------------------------------------------------
# Constant value variable
# ------------------------------------------------------------------------------

class ConstantValueVariableBase(VDictionaryRecord):

    def __init__(self,vd,index,tags,args):
        VDictionaryRecord.__init__(self,vd,index,tags,args)

    def is_initial_register_value(self): return False
    def is_initial_memory_value(self): return False
    def is_frozen_test_value(self): return False
    def is_bridge_variable(self): return False
    def is_global_value(self): return False
    def is_function_return_value(self): return False
    def is_side_effect_value(self): return False
    def is_special_value(self): return False
    def is_structured_value(self): return False
    def is_stack_base_address(self): return False

    def is_argument_value(self): return False

class InitialRegisterValue(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_initial_register_value(self): return True

    def is_stack_base_address(self):
        return self.get_register().is_mips_register() and self.get_register().is_mips_stack_pointer()

    def get_register(self): return self.bd.get_register(self.args[0])

    def is_argument_value(self):
        return self.get_register().is_mips_register() and self.get_register().is_mips_argument_register()

    def get_argument_index(self):
        return self.get_register().get_argument_index()

    def get_level(self): return self.args[1]

    def __str__(self):
        level = self.get_level()
        if level == 0: return str(self.get_register()) + '_in'
        else: return str(self.get_register()) + '_in_' + str(level)

class InitialMemoryValue(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_initial_memory_value(self): return True

    def is_global_value(self):
        d = self.get_original_variable().get_denotation()
        return d.is_memory_variable() and d.is_global_variable()

    def is_argument_value(self):
        d = self.get_original_variable().get_denotation()
        return d.is_memory_variable() and d.is_stack_argument()

    def is_argument_deref_value(self):
        d = self.get_original_variable().get_denotation()
        if d.is_memory_variable() and d.is_basevar_variable():
            basevar = d.get_basevar()
            offset = d.get_memory_offset()
            return basevar.is_argument_value() and offset.is_constant_offset()
        return False

    def get_argument_deref_arg_offset(self,inbytes=False):
        if self.is_argument_deref_value():
            d = self.get_original_variable().get_denotation()
            basevar = d.get_basevar()
            offset = d.get_memory_offset()
            if inbytes:
                return (basevar.get_argument_index(),offset.get_offset())
            else:
                return (basevar.get_argument_index(),offset.get_offset() / 4)
        else:
            raise UF.CHBError('BVar:Error in get_argument_deref_arg_offset')

    def get_argument_index(self):
        if self.is_argument_value():
            return self.get_original_variable().get_argument_index()

    def get_original_variable(self):
        return self.xd.get_variable(self.args[0])

    def is_structured_value(self):
        return self.get_original_variable().is_structured_var()

    def __str__(self):
        if self.is_global_value():
            return str(self.get_original_variable().get_denotation()) + '_in'
        else:
            return str(self.get_original_variable().get_denotation()) + '_in'


class FrozenTestValue(ConstantValueVariableBase):

    # tags: [ testaddr, jumpaddr ]
    # args: [ var-index ]
    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_frozen_test_value(self): return True

    def get_variable(self): return self.xd.get_variable(self.args[0])

    def get_test_address(self): return self.tags[1]

    def get_jump_address(self): return self.tags[2]

    def __str__(self):
        return (str(self.get_variable())
                    + '_@val_' + str(self.get_test_address())
                    + '_@_' +  str(self.get_jump_address()))

class BridgeVariable(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_bridge_variable(self): return True

class FunctionReturnValue(ConstantValueVariableBase):

    # tags: [ callsite ]
    # args: [ ]
    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_function_return_value(self): return True

    def get_call_site(self): return str(self.tags[1])

    def get_call_instruction(self):
        return self.vd.asmfunction.get_instruction(self.get_call_site())

    def get_call_arguments(self):
        return self.get_call_instruction().get_call_arguments()

    def has_call_target(self):
        return self.get_function_info().has_call_target(self.get_call_site())

    def get_call_target(self):
        return self.get_function_info().get_call_target(self.get_call_site())

    def __str__(self):
        if self.has_call_target():
            args = self.get_call_arguments()
            if args is None:
                pargs = '(?)'
            else:
                pargs = '(' + ','.join([ str(a) for a in self.get_call_arguments() ]) + ')'
            # return 'rtn_' + str(self.get_call_target()) + pargs + '@' + str(self.get_call_site())
            return 'rtn_' + str(self.get_call_target()) + pargs + ')'
        else:
            return 'rtn_' + str(self.get_call_site())

class CallTargetValue(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def get_call_target(self): return self.id.get_call_target(self.args[0])

    def __str__(self):
        return 'call_target:' + str(self.get_call_target())


class SideEffectValue(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_side_effect_value(self): return True

    def get_call_site(self): return self.tags[1]

    def get_arg_name(self): return str(self.bd.get_string(self.args[0]))

    def has_call_target(self):
        return self.get_function_info().has_call_target(self.get_call_site())

    def get_call_target(self):
        return self.get_function_info().get_call_target(self.get_call_site())

    def __str__(self):
        if self.has_call_target():
            return 'se_' + str(self.get_call_target()) + '_' + self.get_arg_name()
        else:
            return 'se_' + str(self.get_call_site()) + '_' + self.get_arg_name()

class SymbolicValue(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_symbolic_value(self): return True

    def get_expr(self): return self.xd.get_xpr(self.args[0])

    def __str__(self): return str(self.get_expr())


class RuntimeConstant(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)


class SpecialValue(ConstantValueVariableBase):

    def __init__(self,vd,index,tags,args):
        ConstantValueVariableBase.__init__(self,vd,index,tags,args)

    def is_special_value(self): return True
