# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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
"""Simulation code for library functions."""

import chb.mipsimulate.MIPSimMemory as MM
import chb.simulate.SimSymbolicValue as SSV
import chb.simulate.SimValue as SV
import chb.simulate.SimUtil as SU

import chb.util.fileutil as UF

stubbed_libc_functions = {
    "basename": lambda app:MIPStub_basename(app),
    "calculate_checksum": lambda app:MIPStub_calculate_checksum(app),
    "close": lambda app:MIPStub_close(app),
    "closelog": lambda app:MIPStub_closelog(app),
    "fclose": lambda app:MIPStub_fclose(app),
    "fcntl64": lambda app:MIPStub_fcntl64(app),
    "feof": lambda app:MIPStub_feof(app),
    "__fgetc_unlocked": lambda app:MIPStub___fgetc_unlocked(app),
    "fgets": lambda app:MIPStub_fgets(app),
    "fileno": lambda app:MIPStub_fileno(app),
    "fopen64": lambda app:MIPStub_fopen64(app),
    "fprintf": lambda app:MIPStub_fprintf(app),    
    "free": lambda app:MIPStub_free(app),
    "fwrite": lambda app:MIPStub_fwrite(app),
    "getenv": lambda app:MIPStub_getenv(app),
    "getopt_long": lambda app:MIPStub_getopt_long(app),
    "inet_aton": lambda app:MIPStub_inet_aton(app),
    "inet_pton": lambda app:MIPStub_inet_pton(app),
    "ioctl": lambda app:MIPStub_ioctl(app),
    "longjmp": lambda app:MIPStub_longjmp(app),
    "malloc": lambda app:MIPStub_malloc(app),
    "memcpy": lambda app:MIPStub_memcpy(app),    
    "memset": lambda app:MIPStub_memset(app),
    "openlog": lambda app:MIPStub_openlog(app),
    "pclose": lambda app:MIPStub_pclose(app),
    "popen": lambda app:MIPStub_popen(app),
    "printf": lambda app:MIPStub_printf(app),
    "setenv": lambda app:MIPStub_setenv(app),
    "_setjmp": lambda app:MIPStub__setjmp(app),
    "snprintf": lambda app:MIPStub_snprintf(app),
    "socket": lambda app:MIPStub_socket(app),
    "sprintf": lambda app:MIPStub_sprintf(app),
    "strchr": lambda app:MIPStub_strchr(app),
    "strcmp": lambda app:MIPStub_strcmp(app),
    "strcpy": lambda app:MIPStub_strcpy(app),
    "strdup": lambda app:MIPStub_strdup(app),
    "strlen": lambda app:MIPStub_strlen(app),
    "strncat": lambda app:MIPStub_strncat(app),
    "strncmp": lambda app:MIPStub_strncmp(app),
    "strncpy": lambda app:MIPStub_strncpy(app),
    "strrchr": lambda app:MIPStub_strrchr(app),
    "strsep": lambda app:MIPStub_strsep(app),
    "strtok": lambda app:MIPStub_strtok(app),
    "strtok_r": lambda app:MIPStub_strtok_r(app),
    "system": lambda app:MIPStub_system(app)
    }


fcntl_cmds = {
    "0x0": "F_DUPFD",
    "0x1": "F_GETFD",
    "0x2": "F_SETFD",
    "0x3": "F_GETFL",
    "0x4": "F_SETFL"
}

class MIPSimStubDirective(object):

    def __init__(self,fname):
        self.fname = fname
        self.values = {}    # iaddr -> value
        self.comments = {}      # iaddr -> string

    def add_address(self,iaddr,value,comment=''):
        self.values[iaddr] = value
        if comment:
            self.comments[iaddr] = comment

    def has_address(self,iaddr): return iaddr in self.values

    def has_comment(self,iaddr): return iaddr in self.comments

    def get_value(self,iaddr):
        if iaddr in self.values:
            return self.values[iaddr]
        else:
            raise UF.CHBError('No directive found in ' + self.fname
                              + ' for address ' + iaddr)

    def get_comment(self,iaddr):
        if iaddr in self.comments:
            return self.comments[iaddr]
        else:
            raise UF.CHBError('No message found in ' + self.fname
                              + ' for address ' + iaddr)

    def __str__(self):
        lines = []
        lines.append('Name: ' + self.fname)
        lines.append('Directives: ')
        for iaddr in self.values:
            pcomment = '; ' + self.comments[iaddr] if iaddr in self.comments else ''
            lines.append(self.values[iaddr].ljust(10) + pcomment)
        return '\n'.join(lines)

def mk_stub_directive(fname,values):
    directive = MIPSimStubDirective(fname)
    for v in values:
        directive.add_address(v,values[v].get('value'),values[v].get('comment',''))
    return directive


class MIPSimStub(object):

    def __init__(self,app,name):
        self.app = app
        self.name = name

    def get_arg_val(self,iaddr,simstate,arg):
        """Returns a SimValue; arg must be a MIPS register."""
        return simstate.get_regval(iaddr,arg)

    def get_stack_arg_val(self,iaddr,simstate,argindex):
        """Returns a SimValue for an argument on the stack."""
        sp = simstate.get_regval(iaddr,'sp')
        stackaddr = sp.add_offset(4*argindex)
        return simstate.get_memval(iaddr,stackaddr,4)

    def get_arg_string(self,iaddr,simstate,arg):
        """Returns a string; arg must be a MIPS register."""
        saddr = self.get_arg_val(iaddr,simstate,arg)
        result = ''
        offset = 0
        if saddr.is_string_address():
            return saddr.get_string()
        elif saddr.is_symbol():
            return 'symbol:' + saddr.get_name()
        elif saddr.is_literal() and saddr.is_defined():
            if saddr.value > simstate.imagebase.get_offset_value():
                saddr = SSV.SimGlobalAddress(saddr)
            else:
                raise SU.CHBSimError(simstate,iaddr,
                                     'String argument is not a valid address: ' + str(saddr))
        while True:
            srcaddr = saddr.add_offset(offset)
            srcval = simstate.get_memval(iaddr,srcaddr,1)
            if srcval.is_literal() and srcval.is_defined():
                if srcval.value == 0:
                    break
                result += chr(srcval.value)
                offset += 1
            else:
                break
        return result

    def add_logmsg(self,iaddr,simstate,arguments,returnval=''):
        preturn = 'return value: ' + returnval if returnval else ''
        msg = 'execute ' + self.name + '(' + arguments + ') ' + preturn
        simstate.add_logmsg('stub:' + self.name,msg)
        return msg        

    def simulate(self,iaddr,simstate):
        """Dummy function."""
        raise SU.CHBSimError(simstate,iaddr,
                             'Simulation not implemented for ' + self.name)


class MIPStub_basename(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'basename')

    def simulate(self,iaddr,simstate):
        """Returns (in v0) the basename set in simstate, expressed as SimString."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SSV.mk_string_address(simstate.basename))
        return self.add_logmsg(iaddr,simstate,str(a0))
                              

class MIPStub_calculate_checksum(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'calculate_checksum')

    def simulate(self,iaddr,simstate):
        """No computation; returns -1 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(-1))
        pargs = ','.join(str(a) for a in [ a0, a1, a2])
        return self.add_logmsg(iaddr,simstate,pargs,returnval='-1')

class MIPStub_close(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'close')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0))


class MIPStub_closelog(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'closelog')

    def simulate(self,iaddr,simstate):
        """Logs i/o; no return value."""
        simstate.add_logmsg('i/o', self.name + '()')
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_fclose(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fclose')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ')')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_fcntl64(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fcntl64')

    def get_cmd_name(self,i):
        if str(i) in fcntl_cmds:
            return fcntl_cmds[str(i)]
        else:
            return str(i)

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1cmd = self.get_cmd_name(a1)
        if a1cmd == "F_SETFL":
            a2 = self.get_arg_val(iaddr,simstate,'a2')
            pargs = str(a0) + ',' + a1cmd + ',' + str(a2)
        else:
            pargs = str(a0) + ',' + a1cmd
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(0))
        return self.add_logmsg(iaddr,simstate,pargs)
        

class MIPStub_feof(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'feof')
        self.ateof = False

    def simulate(self,iaddr,simstate):
        """Alternate returning 0 and 1 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if self.ateof:
            result = 1
            self.ateof = False
        else:
            result = 0
            self.ateof = True
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(result))
        simstate.add_logmsg('i/o', self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0),returnval=str(result))

class MIPStub___fgetc_unlocked(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'__fgetc_unlocked')

    def simulate(self,iaddr,simstate):
        """Return a tainted value in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SSV.SimTaintedValue('fgetc',-1,255))
        simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0))
                              

class MIPStub_fgets(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fgets')

    def simulate(self,iaddr,simstate):
        """Inputs tainted characters."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',a0)
        if a1.is_literal() and a1.is_defined():
            for i in range(0,a1.value):
                srcval = SV.SimByteValue(ord('t'))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,a0.add_offset(a1.value),SV.SimByteValue(0))
        pargs = str(a0) + ',' + str(a1) + ',' + str(a2)
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_fileno(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fileno')

    def simulate(self,iaddr,simstate):
        """Returns a symbolic value in v0"""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if a0.is_symbolic() and a0.is_symbol():
            result = SSV.SimSymbol(a0.get_name() + '_fildes')
        else:
            result = SV.SimDoubleWordValue(-1)
        simstate.set_register(iaddr,'v0',result)
        simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ') with return value ' + str(result))
        return self.add_logmsg(iaddr,simstate,str(a0),returnval=str(result))

class MIPStub_fopen64(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fopen64')

    def simulate_success(self,iaddr,simstate,pargs,comment=''):
        returnval = SSV.mk_symbol('fopen64_rtn_' + iaddr)
        simstate.set_register(iaddr,'v0',returnval)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))

    def simulate_failure(self,iaddr,simstate,pargs,comment=''):
        returnval = SV.simZero
        simstate.set_register(iaddr,'v0',returnval)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))

    def simulate(self,iaddr,simstate):
        """Logs i/o; returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = ','.join( str(a) + ':' + str(s) for (a,s) in [ (a0,a0str), (a1,a1str) ])
        simstate.add_logmsg('i/o', self.name + '(' + pargs + ')')
        if (simstate.has_stub_directive(self.name)
            and simstate.get_stub_directive(self.name).has_address(iaddr)):
            directive = simstate.get_stub_directive(self.name)
            value = directive.get_value(iaddr)
            comment = directive.get_comment(iaddr)
            if value == 'success':
                return self.simulate_success(iaddr,simstate,pargs,comment)
            else:
                return self.simulate_failure(iaddr,simstate,pargs,comment)
        elif a0str == '/dev/console':
            return self.simulate_success(iaddr,simstate,pargs,
                                         'assume access to /dev/console is always enabled')
        else:
            return self.simulate_failure(iaddr,simstate,pargs)

class MIPStub_fwrite(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fwrite')

    def simulate(self,iaddr,simstate):
        """Logs i/o, returns 1 in v0 for now."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        simstate.set_register(iaddr,'v0',SV.simOne)
        pargs = ','.join(str(a) for a in [ a0,a1,a2,a3 ])
        simstate.add_logmsg('i/o', self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs,returnval='1')

class MIPStub_free(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'free')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_fprintf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fprintf')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        simstate.set_register(iaddr,'v0',SV.simOne)
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)                            


class MIPStub_getenv(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getenv')

    def simulate(self,iaddr,simstate):
        """Logs getenv request, returns environment variable from simstate if available."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        if simstate.has_environment_variable(a0str):
            envvalue = simstate.get_environment_variable_value(a0str)
            result = SSV.mk_string_address(envvalue)
            envmsg = 'retrieved: ' + str(result) + ' for ' + a0str
        else:
            result = SV.simZero
            envmsg = 'no environment value found for ' + a0str
        simstate.set_register(iaddr,'v0',result)
        simstate.add_logmsg('getenv', envmsg)
        pargs = str(a0) + ':' + a0str
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))
        

class MIPStub_getopt_long(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getopt_long')

    def simulate(self,iaddr,simstate):
        """Logs i/o, returns -1 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',SV.simNegOne)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs,returnval='-1')

class MIPStub_inet_aton(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'inet_aton')

    def simulate(self,iaddr,simstate):
        """Returns 0 by default."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_inet_pton(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'inet_pton')

    def simulate(self,iaddr,simstate):
        """Fails by default."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = str(a0) + ',' + str(a1) + ':' + a1str + ',' + str(a2)
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_ioctl(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'ioctl')

    def simulate(self,iaddr,simstate):
        """Returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_longjmp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'longjmp')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',a1)
        newpc = simstate.get_memval(iaddr,a0,4)
        newsp = simstate.get_memval(iaddr,a0.add_offset(4),4)
        newra = simstate.get_memval(iaddr,a0.add_offset(8),4)
        context = simstate.get_memval(iaddr,a0.add_offset(12),4).get_string()
        simstate.set_register(iaddr,'sp',newsp)
        simstate.set_register(iaddr,'ra',newra)
        simstate.restore_context(context)
        simstate.programcounter = newpc
        return self.add_logmsg(iaddr,simstate,pargs,
                               returnval=str(a1) + ' (jmpaddr:' + str(newpc)
                               + '; sp:' + str(newsp)
                               + '; ra:' + str(newra) + ')')

class MIPStub_malloc(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'malloc')

    def simulate(self,iaddr,simstate):
        """Returns a symbolic address to a heap buffer in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        base = 'malloc_' + iaddr
        address = SSV.mk_base_address(base,0,buffersize=a0)
        simstate.set_register(iaddr,'v0',address)
        simstate.add_logmsg('memory allocation',self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0))
        
                            
class MIPStub_memcpy(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'memcpy')

    def simulate(self,iaddr,simstate):
        """Copies count bytes from src to dst; returns a0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')  # dst
        a1 = self.get_arg_val(iaddr,simstate,'a1')  # src
        a2 = self.get_arg_val(iaddr,simstate,'a2')  # count
        if a0.is_stack_address() and a1.is_stack_address():
            if a2.is_defined():
                for i in range(0,a2.value):
                    srcaddr = a1.add_offset(i)
                    srcval = simstate.get_memval(iaddr,srcaddr,1)
                    tgtaddr = a0.add_offset(i)
                    simstate.set_memval(iaddr,tgtaddr,srcval)
        simstate.set_register(iaddr,'v0',a0)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_memset(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'memset')

    def simulate(self,iaddr,simstate):
        """Sets count bytes in dst to char. returns a0 in v0"""
        a0 = self.get_arg_val(iaddr,simstate,'a0')   # dst
        a1 = self.get_arg_val(iaddr,simstate,'a1')   # char
        a2 = self.get_arg_val(iaddr,simstate,'a2')   # count
        if (a0.is_address()
            and a1.is_literal() and a1.is_defined()
            and a2.is_literal() and a2.is_defined()):
            a1byte = SV.mk_simvalue(a1.value,size=1)
            for i in range(0,a2.value):
                address = a0.add_offset(i)
                simstate.set_memval(iaddr,address,a1byte)
        simstate.set_register(iaddr,'v0',a0)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_openlog(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'openlog')

    def simulate(self,iaddr,simstate):
        """Logs i/o."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pclose(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pclose')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simNegOne)
        simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0))        

class MIPStub_popen(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'popen')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1) + ':' + a1str
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_printf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'printf')

    def simulate(self,iaddr,simstate):
        """Logs i/o; returns 1 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simOne)
        pargs = str(a0) + ':' + a0str
        if '%s' in a0str:
            a1 = self.get_arg_val(iaddr,simstate,'a1')
            a1str = self.get_arg_string(iaddr,simstate,'a1')
            pargs += ',' + str(a1) + ':' + a1str
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub__setjmp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'_setjmp')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        setval = SSV.mk_global_address(int(iaddr,16) + 4)
        simstate.set_memval(iaddr,a0,setval)
        simstate.set_memval(iaddr,a0.add_offset(4),simstate.registers['sp'])
        simstate.set_memval(iaddr,a0.add_offset(8),simstate.registers['ra'])
        simstate.set_memval(iaddr,a0.add_offset(12),SSV.SimStringAddress(simstate.context.peek()))
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_snprintf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'snprintf')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a2str = self.get_arg_string(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_socket(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'socket')

    def simulate(self,iaddr,simstate):
        """Returns a symbolic value in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        returnval = SSV.mk_symbol('socket-fd',minval=0)
        simstate.set_register(iaddr,'v0',returnval)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_setenv(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'setenv')

    def simulate(self,iaddr,simstate):
        """Logs i/o; returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = (str(a0) + ':' + a0str + ',' + str(a1) + ':' + a1str
                 + ',' + str(a2))
        simstate.set_environment_variable(a0str,a1str)
        simstate.add_logmsg('i/o', self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_sprintf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sprintf')

    def simulate(self,iaddr,simstate):
        """Copies the string of the second argument to the dst argument."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        a2str = None
        a3str = None
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        if '%s' in a1str:
            a2str = self.get_arg_string(iaddr,simstate,'a2')
            printstring = a1str.replace('%s',a2str,1)
            if '%s' in printstring:
                a3str = self.get_arg_string(iaddr,simstate,'a3')
                printstring = printstring.replace('%s',a3str,1)
        elif '%02x' in a1str:
            a2 = self.get_arg_val(iaddr,simstate,'a2')
            printstring = a1str.replace('%02x',hex(a2.to_unsigned_int()),1)
            if '%02x' in printstring:
                a3 = self.get_arg_val(iaddr,simstate,'a3')
                printstring = printstring.replace('%02x',hex(a3.to_unsigned_int()),1)
            argindex = 4
            while '%02x' in printstring:
                argi = self.get_stack_arg_val(iaddr,simstate,argindex)
                printstring = printstring.replace('%02x',hex(argi.to_unsigned_int()),1)
                argindex += 1
        else:
            printstring = a1str
        if a0.is_symbol():
            simstate.add_logmsg('free sprintf',' to dst: ' + str(a0) + '; str: ' + printstring)
        else:
            for i in range(0,len(printstring)):
                srcval = SV.SimByteValue(ord(printstring[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(len(printstring)))                        
        pargs = (str(a0) + ',' + str(a1) + ':' + a1str
                 + ((',' + a2str) if a2str else '')
                 + ((',' + a3str) if a3str else ''))
        return self.add_logmsg(iaddr,simstate,pargs,
                                returnval=str(len(printstring)))

class MIPStub_strchr(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strchr')

    def simulate(self,iaddr,simstate):
        """Returns a pointer to the first character that matches the second argument."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        if a0.is_string_address() and a1.is_literal() and a1.is_defined():
            a0str = self.get_arg_string(iaddr,simstate,'a0')
            if not (chr(a1.value) in a0str):
                returnval = SV.simZero
            else:
                index = a0str.find(str(chr(a1.value)))
                returnval = SSV.mk_string_address(a0str[index:])
        elif a0.is_address():                                            
            i = 0
            while True:
                c = simstate.get_memval(iaddr,a0.add_offset(i),1)
                if c.is_literal() and c.is_defined():
                    if c.value == a1.value:
                        break
                    else:
                        i += 1
                else:
                    break
            if a0.is_string_address():
                returnval = a0
            elif a0.is_symbol():
                returnval = a0
            else:
                returnval = a0.add_offset(i)
                simstate.set_register(iaddr,'v0',returnval)
                return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))
        else:
            returnval = SV.simZero
        if a1.is_literal() and a1.is_defined():
            pa1 = "'" + chr(a1.value) + "'"
        else:
            pa1 = str(a1)
        pargs = str(a0) + ',' + pa1        
        simstate.set_register(iaddr,'v0',returnval)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))

        
class MIPStub_strcmp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strcmp')

    def simulate(self,iaddr,simstate):
        """Compares the two arguments if available, and returns the result in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')   # str1
        a1 = self.get_arg_val(iaddr,simstate,'a1')   # str2
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        if a0str == a1str:
            result = 0
        elif a0str < a1str:
            result = -1
        else:
            result = 1
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(result))
        pargs = ','.join(str(a) + ':' + str(v) for (a,v) in [ (a0,a0str), (a1,a1str) ])
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))


class MIPStub_strncmp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strncmp')

    def simulate(self,iaddr,simstate):
        """Compares the two strings up to count, if available, and returns the result in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        if a2.is_literal() and a2.is_defined():
            count = a2.value
            if a0str[:count] == a1str[:count]:
                result = 0
            elif a0str[:count] < a1str[:count]:
                result = -1
            else:
                result = 1
            result = SV.SimDoubleWordValue(result)
        else:
            result = SV.SimDoubleWordValue(0,undefined=True)
        simstate.set_register(iaddr,'v0',result)
        pargs = (str(a0) + ': "' + a0str + '", '  + str(a1) + ': "' + a1str + '", '
                 + 'count:' + str(a2))
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))
        

class MIPStub_strcpy(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strcpy')

    def get_dst_arg_index(self): return 0
    def get_src_arg_index(self): return 1

    def simulate(self,iaddr,simstate):
        """Copies characters from src to dst up to and including null terminator."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        if a1.is_string_address():
            a1str = self.get_arg_string(iaddr,simstate,'a1')
            for i in range(0,len(a1str)):
                srcval = SV.SimByteValue(ord(a1str[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,a0.add_offset(len(a1str)),SV.SimByteValue(0))
        elif a1.is_symbol():
            simstate.add_logmsg('free strcpy','src:' + str(a1) + ' to dst: ' + str(a0))
        simstate.set_register(iaddr,'v0',a0)
        pargs = str(a0) + ',' + str(a1)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strdup(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strdup')

    def simulate(self,iaddr,simstate):
        """Returns a pointer to a duplicated string in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if a0.is_string_address():
            s = a0.get_string()
            base = 'strdup_' + iaddr
            buffersize = len(s) + 1
            address = SSV.mk_base_address(base,0,buffersize=buffersize)
            simstate.basemem[base] = MM.MIPSimBaseMemory(simstate,base,buffersize=buffersize)
            for i in range(0,buffersize-1):
                simstate.set_memval(iaddr,address.add_offset(i),
                                    SV.mk_simvalue(ord(s[i]),size=1))
            simstate.set_memval(iaddr,address.add_offset(buffersize-1),SV.simZero)
            result = address
                                    
        elif a0.is_symbol():
            base = 'strdup_' + iaddr
            contents = a0.get_name() + '_duplicate'
            buffersize = len(contents) + 1
            address = SSV.mk_base_address(base,0,buffersize=buffersize)
            simstate.basemem[base] = MM.MIPSimBaseMemory(simstate,base,buffersize=buffersize)
            for i in range(0,buffersize-1):
                simstate.set_memval(iaddr,address.add_offset(i),
                                    SV.mk_simvalue(ord(contents[i]),size=1))
            result = address
        else:
            result = SSV.SimSymbol(str(a0) + '_duplicate')
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_strlen(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strlen')

    def simulate(self,iaddr,simstate):
        """Returns the length of the first argument in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        result = SV.SimDoubleWordValue(len(a0str))
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,str(a0) + ':' + a0str,returnval=str(result))

class MIPStub_strncat(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strncat')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strncpy(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strncpy')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        if (a2.is_literal() and a2.is_defined() and a0.is_address()
            and a1.is_address()):
            for i in range(0,a2.value):
                srcaddr = a1.add_offset(i)
                srcval = simstate.get_memval(iaddr,srcaddr,1)
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
        simstate.set_register(iaddr,'v0',a0)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strrchr(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strrchr')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        if a0.is_string_address() and a1.is_literal() and a1.is_defined():
            if not (chr(a1.value) in a0str):
                returnval = SV.simZero
            else:
                index = a0str.rfind(str(chr(a1.value)))
                returnval = SSV.mk_string_address(a0.get_string()[index:])
        elif a0.is_address() and a1.is_literal() and a1.is_defined():
            i = len(a0str)
            while i > 0:
                c = simstate.get_memval(iaddr,a0.add_offset(i),1)
                if c.is_literal() and c.is_defined():
                    if c.value == a1.value:
                        break
                    else:
                        i -= 1
                else:
                    break
            returnval = a0.add_offset(i)
        else:
            returnval = SV.simZero
        simstate.set_register(iaddr,'v0',returnval)
        if a1.is_literal() and a1.is_defined():
            pa1 = "'" + chr(a1.value) + "'"
        else:
            pa1 = str(a1)
        pargs = str(a0) + ':' + a0str + ',' + pa1
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))

class MIPStub_strsep(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strsep')

    def simulate(self,iaddr,simstate):
        """Default behavior for now: return *a0, set *a0 to NULL."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + a1str
        tokenptr = simstate.get_memval(iaddr,a0,4)
        simstate.set_memval(iaddr,a0,SV.simZero)
        simstate.set_register(iaddr,'v0',tokenptr)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strtok(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strtok')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')        
        if a0.is_literal() and a0.is_defined() and a0.value == 0:
            pargs = str(a0) + ',' + str(a1) + ':' + a1str
        else:
            a0str = self.get_arg_string(iaddr,simstate,'a0')        
            pargs = str(a0) + ':' + a0str + ',' + str(a1) + ':' + a1str
        result = a0 
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs)        
        

class MIPStub_strtok_r(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strtok_r')

    def simulate(self,iaddr,simstate):
        """Returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        result = SV.simZero
        simstate.set_register(iaddr,'v0',result)
        pargs = (str(a0) + ': "' + a0str + '", '
                 + str(a1) + ': "' + a1str + '", '
                 + str('state:' + str(a2)))
        return self.add_logmsg(iaddr,simstate,pargs)
               

class MIPStub_system(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'system')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')  # cmdline string
        if a0.is_literal() and a0.value == 0:
            pargs = 'NULL'
        else:
            pargs = self.get_arg_string(iaddr,simstate,'a0')
        return self.add_logmsg(iaddr,simstate,pargs)
    

