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

import datetime
import ipaddress
import time

import chb.mipsimulate.MIPSimMemory as MM
import chb.simulate.SimSymbolicValue as SSV
import chb.simulate.SimValue as SV
import chb.simulate.SimUtil as SU

import chb.util.fileutil as UF

stubbed_libc_functions = {
    "accept": lambda app:MIPStub_accept(app),
    "access": lambda app:MIPStub_access(app),
    "atoi": lambda app:MIPStub_atoi(app),
    "basename": lambda app:MIPStub_basename(app),
    "bind": lambda app:MIPStub_bind(app),
    "calculate_checksum": lambda app:MIPStub_calculate_checksum(app),
    "chdir": lambda app:MIPStub_chdir(app),
    "close": lambda app:MIPStub_close(app),
    "closelog": lambda app:MIPStub_closelog(app),
    "connect": lambda app:MIPStub_connect(app),
    "daemon": lambda app:MIPStub_daemon(app),
    "__errno_location": lambda app:MIPStub___errno_location(app),
    "exit": lambda app:MIPStub_exit(app),
    "fclose": lambda app:MIPStub_fclose(app),
    "fcntl": lambda app:MIPStub_fcntl(app),
    "fcntl64": lambda app:MIPStub_fcntl64(app),
    "feof": lambda app:MIPStub_feof(app),
    "__fgetc_unlocked": lambda app:MIPStub___fgetc_unlocked(app),
    "fgets": lambda app:MIPStub_fgets(app),
    "fileno": lambda app:MIPStub_fileno(app),
    "fopen": lambda app:MIPStub_fopen(app),
    "fopen64": lambda app:MIPStub_fopen64(app),
    "fork": lambda app:MIPStub_fork(app),
    "fprintf": lambda app:MIPStub_fprintf(app),
    "fputs": lambda app:MIPStub_fputs(app),
    "fread": lambda app:MIPStub_fread(app),
    "free": lambda app:MIPStub_free(app),
    "fscanf": lambda app:MIPStub_fscanf(app),
    "fstat": lambda app:MIPStub_fstat(app),
    "fstat64": lambda app:MIPStub_fstat64(app),
    "fwrite": lambda app:MIPStub_fwrite(app),
    "getenv": lambda app:MIPStub_getenv(app),
    "gethostname": lambda app:MIPStub_gethostname(app),
    "getline": lambda app:MIPStub_getline(app),
    "getopt": lambda app:MIPStub_getopt(app),
    "getopt_long": lambda app:MIPStub_getopt_long(app),
    "getpid": lambda app:MIPStub_getpid(app),
    "gettimeofday": lambda app:MIPStub_gettimeofday(app),
    "getuid": lambda app:MIPStub_getuid(app),
    "inet_addr": lambda app:MIPStub_inet_addr(app),
    "inet_aton": lambda app:MIPStub_inet_aton(app),
    "inet_ntoa": lambda app:MIPStub_inet_ntoa(app),
    "inet_pton": lambda app:MIPStub_inet_pton(app),
    "ioctl": lambda app:MIPStub_ioctl(app),
    "__libc_current_sigrtmax": lambda app:MIPStub___libc_current_sigrtmax(app),
    "__libc_current_sigrtmin": lambda app:MIPStub___libc_current_sigrtmin(app),
    "listen": lambda app:MIPStub_listen(app),
    "longjmp": lambda app:MIPStub_longjmp(app),
    "malloc": lambda app:MIPStub_malloc(app),
    "memcmp": lambda app:MIPStub_memcmp(app),
    "memcpy": lambda app:MIPStub_memcpy(app),
    "memmove": lambda app:MIPStub_memmove(app),
    "memset": lambda app:MIPStub_memset(app),
    "mkdir": lambda app:MIPStub_mkdir(app),
    "mktemp": lambda app:MIPStub_mktemp(app),
    "mmap": lambda app:MIPStub_mmap(app),
    "msgget": lambda app:MIPStub_msgget(app),
    "open": lambda app:MIPStub_open(app),
    "open64": lambda app:MIPStub_open64(app),
    "openlog": lambda app:MIPStub_openlog(app),
    "pclose": lambda app:MIPStub_pclose(app),
    "perror": lambda app:MIPStub_perror(app),
    "popen": lambda app:MIPStub_popen(app),
    "printf": lambda app:MIPStub_printf(app),
    "pthread_attr_init": lambda app:MIPStub_pthread_attr_init(app),
    "pthread_attr_setschedparam": lambda app:MIPStub_pthread_attr_setschedparam(app),
    "pthread_attr_setschedpolicy": lambda app:MIPStub_pthread_attr_setschedpolicy(app),
    "pthread_cond_init": lambda app:MIPStub_pthread_cond_init(app),
    "pthread_cond_signal": lambda app:MIPStub_pthread_cond_signal(app),
    "pthread_create": lambda app:MIPStub_pthread_create(app),
    "pthread_mutex_init": lambda app:MIPStub_pthread_mutex_init(app),
    "pthread_mutex_lock": lambda app:MIPStub_pthread_mutex_lock(app),
    "pthread_mutex_unlock": lambda app:MIPStub_pthread_mutex_unlock(app),
    "pthread_self": lambda app:MIPStub_pthread_self(app),
    "puts": lambda app:MIPStub_puts(app),
    "random": lambda app:MIPStub_random(app),
    "read": lambda app:MIPStub_read(app),
    "recv": lambda app:MIPStub_recv(app),
    "recvfrom": lambda app:MIPStub_recvfrom(app),
    "sched_get_priority_max": lambda app:MIPStub_sched_get_priority_max(app),
    "sched_get_priority_min": lambda app:MIPStub_sched_get_priority_max(app),
    "sched_yield": lambda app:MIPStub_sched_yield(app),
    "select": lambda app:MIPStub_select(app),
    "semget": lambda app:MIPStub_semget(app),
    "semop": lambda app:MIPStub_semop(app),
    "send": lambda app:MIPStub_send(app),
    "sendto": lambda app:MIPStub_sendto(app),
    "setenv": lambda app:MIPStub_setenv(app),
    "_setjmp": lambda app:MIPStub__setjmp(app),
    "setlogmask": lambda app:MIPStub_setlogmask(app),
    "setrlimit": lambda app:MIPStub_setrlimit(app),
    "setsockopt": lambda app:MIPStub_setsockopt(app),
    "shmat": lambda app:MIPStub_shmat(app),
    "shmget": lambda app:MIPStub_shmget(app),
    "sigaction": lambda app:MIPStub_sigaction(app),
    "sigemptyset": lambda app:MIPStub_sigemptyset(app),
    "signal": lambda app:MIPStub_signal(app),
    "sleep": lambda app:MIPStub_sleep(app),
    "snprintf": lambda app:MIPStub_snprintf(app),
    "socket": lambda app:MIPStub_socket(app),
    "sprintf": lambda app:MIPStub_sprintf(app),
    "srand": lambda app:MIPStub_srand(app),
    "sscanf": lambda app:MIPStub_sscanf(app),
    "stat": lambda app:MIPStub_stat(app),
    "strcasecmp": lambda app:MIPStub_strcasecmp(app),
    "strchr": lambda app:MIPStub_strchr(app),
    "strcmp": lambda app:MIPStub_strcmp(app),
    "strcpy": lambda app:MIPStub_strcpy(app),
    "strdup": lambda app:MIPStub_strdup(app),
    "strerror": lambda app:MIPStub_strerror(app),
    "stristr": lambda app:MIPStub_stristr(app),
    "strlen": lambda app:MIPStub_strlen(app),
    "strncat": lambda app:MIPStub_strncat(app),
    "strncmp": lambda app:MIPStub_strncmp(app),
    "strncpy": lambda app:MIPStub_strncpy(app),
    "strrchr": lambda app:MIPStub_strrchr(app),
    "strsep": lambda app:MIPStub_strsep(app),
    "strstr": lambda app:MIPStub_strstr(app),
    "strtok": lambda app:MIPStub_strtok(app),
    "strtok_r": lambda app:MIPStub_strtok_r(app),
    "strtoul": lambda app:MIPStub_strtoul(app),
    "syslog": lambda app:MIPStub_syslog(app),
    "system": lambda app:MIPStub_system(app),
    "time": lambda app:MIPStub_time(app),
    "umask": lambda app:MIPStub_umask(app),
    "usleep": lambda app:MIPStub_usleep(app),
    "vsprintf": lambda app:MIPStub_vsprintf(app),
    "waitpid": lambda app:MIPStub_waitpid(app),
    "write": lambda app:MIPStub_write(app),
    "isLanSubnet": lambda app:MIPStub_isLanSubnet(app),
    "uloop_init": lambda app:MIPStub_uloop_init(app),    # openwrt
    "msglogd": lambda app:MIPStub_msglogd(app)     # libmsglog.so
    }


fcntl_cmds = {
    "0x0": "F_DUPFD",
    "0x1": "F_GETFD",
    "0x2": "F_SETFD",
    "0x3": "F_GETFL",
    "0x4": "F_SETFL"
}


class MIPSimStub(object):

    def __init__(self,app,name):
        self.app = app
        self.name = name

    def get_arg_val(self,iaddr,simstate,arg):
        """Returns a SimValue; arg must be a MIPS register."""
        return simstate.get_regval(iaddr,arg)

    def get_arg_deref_val(self,iaddr,simstate,arg):
        """Returns a SimValue, pointed by the arg-val."""
        saddr = self.get_arg_val(iaddr,simstate,arg)
        if saddr.is_address():
            return simstate.get_memval(iaddr,saddr,4)

    def get_stack_arg_val(self,iaddr,simstate,argindex):
        """Returns a SimValue for an argument on the stack."""
        sp = simstate.get_regval(iaddr,'sp')
        stackaddr = sp.add_offset(4*argindex)
        return simstate.get_memval(iaddr,stackaddr,4)

    def get_arg_string(self,iaddr,simstate,arg):
        """Returns a string; arg must be a MIPS register."""
        saddr = self.get_arg_val(iaddr,simstate,arg)
        return self.get_string_at_address(iaddr,simstate,saddr)

    def get_string_at_address(self,iaddr,simstate,saddr):
        result = ''
        offset = 0
        if saddr.is_string_address():
            return saddr.get_string()
        elif saddr.is_symbol():
            return 'symbol:' + saddr.get_name()
        elif saddr.is_literal() and saddr.is_defined():
            if simstate.instaticlib and saddr.value > simstate.libimagebase.get_offset_value():
                saddr = SSV.SimGlobalAddress(saddr)
            elif saddr.value > simstate.imagebase.get_offset_value():
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

    def get_stack_arg_string(self,iaddr,simstate,argindex):
        sp = simstate.get_regval(iaddr,'sp')
        stackaddr = sp.add_offset(4*argindex)
        return self.get_string_at_address(iaddr,simstate,stackaddr)

    def get_arg_deref_string(self,iaddr,simstate,arg):
        """Returns a string; arg must be a MIPS register."""
        saddrptr = self.get_arg_val(iaddr,simstate,arg)
        if saddrptr.is_address():
            saddr = simstate.get_memval(iaddr,saddrptr,4)
            if saddr.is_address():
                result = ''
                offset = 0
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
            else:
                raise SU.CHBSimError(simstate,iaddr,'Pointed to value in arg_deref_string '
                                     + ' is not an address: ' + str(saddr))
        else:
            raise SU.CHBSimError(simstate.iaddr,'Argument is not an address in arg_deref_string: '
                                 + str(addrptr))

    def is_error_operation(self): return False

    def is_io_operation(self): return False

    def is_network_operation(self): return False

    def is_string_operation(self): return False

    def is_environment_operation(self): return False

    def is_thread_operation(self): return False

    def is_process_operation(self): return False

    def is_memalloc_operation(self): return False

    def is_sharedmem_operation(self): return False

    def is_system_operation(self): return False

    def is_domain_call(self): return None

    def add_logmsg(self,iaddr,simstate,arguments,returnval=''):
        preturn = 'return value: ' + returnval if returnval else ''
        msg = self.name + '(' + arguments + ') ' + preturn
        simstate.add_logmsg('stub:' + self.name,msg)
        if self.is_error_operation():
            simstate.add_logmsg('error:', msg)
        if self.is_io_operation():
            simstate.add_logmsg('i/o:', msg)
        if self.is_network_operation():
            simstate.add_logmsg('network:', msg)
        if self.is_string_operation():
            simstate.add_logmsg('string:', msg)
        if self.is_thread_operation():
            simstate.add_logmsg('thread:', msg)
        if self.is_process_operation():
            simstate.add_logmsg('process:', msg)
        if self.is_memalloc_operation():
            simstate.add_logmsg('memory allocation:',msg)
        if self.is_sharedmem_operation():
            simstate.add_logmsg('shared memory:', msg)
        if self.is_system_operation():
            simstate.add_logmsg('system', msg)
        if self.is_domain_call():
            simstate.add_logmsg('domain:' + self.is_domain_call(),msg)
        return msg        

    def simulate(self,iaddr,simstate):
        """Dummy function."""
        raise SU.CHBSimError(simstate,iaddr,
                             'Simulation not implemented for ' + self.name)

class MIPStub_accept(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'accept')

    def is_io_operation(self): return True

    def is_network_operation(self): return True

    # a new file descriptor shall be allocated for the socket
    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a2deref = self.get_arg_deref_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1 ]) + ',' + str(a2) + ':' + str(a2deref)
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(114))
        if a1.is_address() and a2deref.is_literal() and a2deref.is_defined() and a2deref.value == 16:
            simstate.set_memval(iaddr,a1,SV.mk_simvalue(0,size=2))   # sa_family = AF_UNSPEC
            simstate.set_memval(iaddr,a1.add_offset(2),SV.mk_simvalue(80,size=2)) # sa_port
            simstate.set_memval(iaddr,a1.add_offset(4),SV.mk_simvalue(444)) # internet address
            simstate.set_memval(iaddr,a1.add_offset(8),SV.mk_simvalue(0))
            simstate.set_memval(iaddr,a1.add_offset(12),SV.mk_simvalue(0))
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_access(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'access')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_atoi(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'atoi')

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        try:
            a0str = self.get_arg_string(iaddr,simstate,'a0')
        except Exception as e:
            print('atoi: ' + str(a0) + ' is not a string')
            print(str(e))
            exit(1)
        pargs = str(a0) + ':' + a0str
        try:
            result = int(a0str)
        except Exception as e:
            print('String ' + a0str + ' cannot be converted to int: ' + str(e))
            simstate.add_logmsg('error:','Conversion to int failed in atoi: ' + a0str)
            result = -1
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_basename(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'basename')

    def simulate(self,iaddr,simstate):
        """Returns (in v0) the basename set in simstate, expressed as SimString."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SSV.mk_string_address(simstate.basename))
        return self.add_logmsg(iaddr,simstate,str(a0))
                              
class MIPStub_bind(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'bind')

    def is_io_operation(self): return True

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

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

class MIPStub_chdir(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'chdir')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + str(a0str)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_close(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'close')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        return self.add_logmsg(iaddr,simstate,str(a0))


class MIPStub_closelog(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'closelog')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Logs i/o; no return value."""
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_connect(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'connect')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_daemon(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'daemon')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub___errno_location(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'__errno_location')

    def is_error_operation(self): return True

    def simulate(self,iaddr,simstate):
        result = SSV.mk_string_address('error-string')
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,str(result))

class MIPStub_exit(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'exit')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        raise SU.CHBSimExitException(simstate,iaddr,str(a0))

class MIPStub_fclose(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fclose')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if a0.is_symbol():
            if a0.is_file_descriptor():
                try:
                    a0.fd.close()
                    simstate.add_logmsg('i/o','Successfully closed ' + str(a0))
                except Exception as e:
                    simstate.add_logmsg('i/o','Error in closing ' + str(a0)
                                        + ': ' + str(e))
            elif a0.is_file_pointer():
                try:
                    a0.fp.close()
                    simstate.add_logmsg('i/o','Successfully closed ' + str(a0))
                except Exception as e:
                    simstate.add_logmsg('i/o','Error in closing ' + str(a0)
                                        + ': ' + str(e))
            else:
                simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ')')
        else:
            pass
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_fcntl(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fcntl')

    def is_io_operation(self): return True

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
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(0))
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_fcntl64(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fcntl64')

    def is_io_operation(self): return True

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
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(0))
        return self.add_logmsg(iaddr,simstate,pargs)
        

class MIPStub_feof(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'feof')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns false by default."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if a0.is_symbol() and a0.is_file_pointer():
            try:
                fp = a0.fp
                s = fp.read()
                if s == '':
                    result = 1
                else:
                    result = 0
            except:
                result = 0
        else:
            result = 0
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        simstate.add_logmsg('i/o', self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0),returnval=str(result))

class MIPStub___fgetc_unlocked(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'__fgetc_unlocked')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Return a tainted value in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SSV.SimTaintedValue('fgetc',-1,255))
        return self.add_logmsg(iaddr,simstate,str(a0))
                              

class MIPStub_fgets(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fgets')

    def is_io_operation(self): return True

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
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_fputs(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fputs')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_fileno(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fileno')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns a symbolic value in v0"""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if a0.is_symbolic() and a0.is_file_pointer():
            result = SSV.mk_filedescriptor(a0.filename,a0.fp)
        elif a0.is_symbolic() and a0.is_symbol():
            result = SSV.SimSymbol(a0.get_name() + '_fildes')
        else:
            result = SV.SimDoubleWordValue(-1)
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,str(a0),returnval=str(result))

class MIPStub_fopen(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fopen')

    def is_io_operation(self): return True

    def simulate_success(self,iaddr,simstate,pargs,filepointer,comment=''):
        returnval = SSV.mk_filepointer(filepointer)
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
        if a0str == '/dev/console':
            return self.simulate_success(iaddr,simstate,pargs,'/dev/console-filepointer',
                                         'assume access to /dev/console is always enabled')
        else:
            return self.simulate_failure(iaddr,simstate,pargs)


class MIPStub_fopen64(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fopen64')

    def is_io_operation(self): return True

    def simulate_success(self,iaddr,simstate,pargs,comment=''):
        returnval = SSV.mk_symbol('fopen64_rtn_' + iaddr)
        simstate.set_register(iaddr,'v0',returnval)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))

    def simulate_failure(self,iaddr,simstate,pargs,comment=''):
        returnval = SV.simOne
        simstate.set_register(iaddr,'v0',returnval)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(returnval))

    def simulate(self,iaddr,simstate):
        """Logs i/o; returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = ','.join( str(a) + ':' + str(s) for (a,s) in [ (a0,a0str), (a1,a1str) ])
        if a0str == '/dev/console':
            return self.simulate_success(iaddr,simstate,pargs,
                                         'assume access to /dev/console is always enabled')
        else:
            return self.simulate_failure(iaddr,simstate,pargs)

class MIPStub_fscanf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fscanf')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        result = -1
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_fstat(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fstat')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_fstat64(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fstat64')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_fwrite(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fwrite')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Logs i/o, returns 1 in v0 for now."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        simstate.set_register(iaddr,'v0',SV.simOne)
        pargs = ','.join(str(a) for a in [ a0,a1,a2,a3 ])
        return self.add_logmsg(iaddr,simstate,pargs,returnval='1')

class MIPStub_fread(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fread')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        pargs = ','.join(str(a) for a in  [ a0, a1, a2, a3 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(a2))

class MIPStub_free(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'free')

    def is_memalloc_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_fork(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fork')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(1))
        return self.add_logmsg(iaddr,simstate,'',returnval='1')

class MIPStub_fprintf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'fprintf')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        simstate.set_register(iaddr,'v0',SV.simOne)
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        return self.add_logmsg(iaddr,simstate,pargs)                            


class MIPStub_getenv(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getenv')

    def is_environment_operation(self): return True

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

class MIPStub_gethostname(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'gethostname')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = ','.join(str(a) for a in [ a0, a1])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_getline(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getline')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1deref = self.get_arg_deref_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = str(a0) + ',' + str(a1) + ':' + str(a1deref) + ',' + str(a2)
        if a2.is_file_pointer():
            line = a2.fp.readline()
            result = len(line)
            if result > 0:
                sval = SSV.mk_string_address(line)
                simstate.set_memval(iaddr,a0,sval)
                simstate.add_logmsg('i/o','Read line: ' + line + ' from ' + str(a2))
            else:
                simstate.add_logmsg('i/o','Reached eof of ' + str(a2))
                result = -1
        else:
            simstate.add_logmsg('i/o','No input read from ' + str(a2))
            result = -1
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))


class MIPStub_getopt(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getopt')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Logs i/o, returns -1 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a2str = self.get_arg_string(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(100))
        pargs = ','.join(str(a) for a in [ a0, a1 ]) + ',' + str(a2) + ':' + a2str
        return self.add_logmsg(iaddr,simstate,pargs,returnval='-1')

class MIPStub_getopt_long(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getopt_long')
        self.optarg = SV.simZero
        self.optind = 1
        self.optopt = SV.simZero

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Logs i/o, returns -1 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a2str = self.get_arg_string(iaddr,simstate,'a2')
        if a0.is_literal() and a0.is_defined() and self.optind < a0.value:
            argaddr = a1.add_offset(self.optind * 4)
            self.optopt = simstate.get_memval(iaddr,argaddr,4)
            if self.optopt.is_string_address() and self.optopt.get_string().startswith('-'):
                result = ord(self.optopt.get_string()[1])
                self.optind += 1
            else:
                result = -1
        else:
            result = -1
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        pargs = ','.join(str(a) for a in [ a0, a1 ]) + ',' + str(a0) + ':' + a2str
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_getpid(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getpid')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_gettimeofday(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'gettimeofday')

    def simulate(self,iaddr,simstate):
        t = int(time.time())
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        if a0.is_address():
            simstate.set_memval(iaddr,a0,SV.mk_simvalue(t))
            simstate.set_memval(iaddr,a0.add_offset(4),SV.simZero)
            simstate.set_memval(iaddr,a0.add_offset(8),SV.simZero)
            simstate.set_memval(iaddr,a0.add_offset(12),SV.simZero)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_getuid(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'getuid')

    def get_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_inet_addr(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'inet_addr')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        result = int(ipaddress.IPv4Address(a0str))
        result = SV.mk_simvalue(result)
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))


class MIPStub_inet_aton(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'inet_aton')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns 0 by default."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_inet_ntoa(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'inet_ntoa')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SSV.mk_string_address('0.0.0'))
        return self.add_logmsg(iaddr,simstate,str(a0))

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

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        simstate.set_register(iaddr,'v0',SV.simZero)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub___libc_current_sigrtmax(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'__libc_current_sigrtmax')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub___libc_current_sigrtmin(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'__libc_current_sigrtmin')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_listen(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'listen')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
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

    def is_memalloc_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns a symbolic address to a heap buffer in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        base = 'malloc_' + iaddr
        address = SSV.mk_base_address(base,0,buffersize=a0)
        simstate.set_register(iaddr,'v0',address)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_memcmp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'memcmp')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        if a0.is_address():
            dstaddr = a0
        elif a0.is_literal() and a0.is_defined() and a0.value > simstate.imagebase.get_offset_value():
            dstaddr = SSV.mk_global_address(a0.value)
        else:
            raise SU.CHBSimError(simstate,iaddr,'memcmp: illegal destination address: ' + str(a0))
        if a1.is_address():
            srcaddr = a1
        elif a1.is_literal() and a1.is_defined() and a1.value > simstate.imagebase.get_offset_value():
            srcaddr = SSV.mk_global_address(a1.value)
        else:
            raise SU.CHBSimError(simstate,iaddr,'memcmp: illegal source address: ' + str(a0))
        if a2.is_literal() and a2.is_defined():
            src1addr = dstaddr
            src2addr = srcaddr
            count = 0
            while count < a2.value:
                src1val = simstate.get_memval(iaddr,src1addr,1)
                src2val = simstate.get_memval(iaddr,src2addr,2)
                if not src1val.is_equal(src2val):
                    if src1val.value < src2.value:
                        result = -1
                    else:
                        result = 1
                    break
                else:
                    count += 1
                    src1addr = src1addr.add_offset(1)
                    src2addr = src2addr.add_offset(2)
            result = 0
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

                            
class MIPStub_memcpy(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'memcpy')

    def simulate(self,iaddr,simstate):
        """Copies count bytes from src to dst; returns a0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')  # dst
        a1 = self.get_arg_val(iaddr,simstate,'a1')  # src
        a2 = self.get_arg_val(iaddr,simstate,'a2')  # count
        if a0.is_address():
            dstaddr = a0
        elif a0.is_literal() and a0.is_defined() and a0.value > simstate.imagebase.get_offset_value():
            dstaddr = SSV.mk_global_address(a0.value)
        else:
            raise SU.CHBSimError(simstate,iaddr,'memcpy: illegal destination address: ' + str(a0))
        if a2.is_defined():
            if a1.is_string_address():
                srcstr = a1.get_string()
                if len(srcstr) >= a2.value:
                    for i in range(0,a2.value):
                        srcval = SV.mk_simvalue(ord(srcstr[i]),1)
                        tgtaddr = dstaddr.add_offset(i)
                        simstate.set_memval(iaddr,tgtaddr,srcval)
                    else:
                        pass
                else:
                    raise UF.CHBError('Memcpy with source string of length: '
                                      + str(len(srcstr)) + ' and length argument: '
                                      + str(a2.value))
            elif a1.is_literal() and a1.is_defined():
                if a1.value > simstate.imagebase.get_offset_value():
                    a1 = SSV.SimGlobalAddress(a1)
                    for i in range(0,a2.value):
                        srcaddr = a1.add_offset(i)
                        srcval = simstate.get_memval(iaddr,srcaddr,1)
                        tgtaddr = dstaddr.add_offset(i)
                        simstate.set_memval(iaddr,tgtaddr,srcval)
            else:
                for i in range(0,a2.value):
                    srcaddr = a1.add_offset(i)
                    srcval = simstate.get_memval(iaddr,srcaddr,1)
                    tgtaddr = dstaddr.add_offset(i)
                    simstate.set_memval(iaddr,tgtaddr,srcval)
        simstate.set_register(iaddr,'v0',dstaddr)
        pargs = ','.join(str(a) for a in [ dstaddr, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_memmove(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'memmove')

    def simulate(self,iaddr,simstate):
        """Copies count bytes from src to dst; returns a0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')  # dst
        a1 = self.get_arg_val(iaddr,simstate,'a1')  # src
        a2 = self.get_arg_val(iaddr,simstate,'a2')  # count
        if a0.is_address():
            dstaddr = a0
        elif a0.is_literal() and a0.is_defined() and a0.value > simstate.imagebase.get_offset_value():
            dstaddr = SSV.mk_global_address(a0.value)
        else:
            raise SU.CHBSimError(simstate,iaddr,'memmove: illegal destination address: ' + str(a0))
        if a2.is_defined():
            if a1.is_string_address():
                srcstr = a1.get_string()
                for i in range(0,a2.value):
                    srcval = SV.mk_simvalue(ord(srcstr[i]),1)
                    tgtaddr = dstaddr.add_offset(i)
                    simstate.set_memval(iaddr,tgtaddr,srcval)
                else:
                    pass
            elif a1.is_literal() and a1.is_defined():
                if a1.value > simstate.imagebase.get_offset_value():
                    a1 = SSV.SimGlobalAddress(a1)
                    for i in range(0,a2.value):
                        srcaddr = a1.add_offset(i)
                        srcval = simstate.get_memval(iaddr,srcaddr,1)
                        tgtaddr = dstaddr.add_offset(i)
                        simstate.set_memval(iaddr,tgtaddr,srcval)
            else:
                for i in range(0,a2.value):
                    srcaddr = a1.add_offset(i)
                    srcval = simstate.get_memval(iaddr,srcaddr,1)
                    tgtaddr = dstaddr.add_offset(i)
                    simstate.set_memval(iaddr,tgtaddr,srcval)
        simstate.set_register(iaddr,'v0',dstaddr)
        pargs = ','.join(str(a) for a in [ dstaddr, a1, a2 ])
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

class MIPStub_mkdir(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'mkdir')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_mktemp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'mktemp')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr,'v0',a0)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_msgget(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'msgget')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_mmap(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'mmap')

    def is_process_operation(self): return True

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        a4 = self.get_stack_arg_val(iaddr,simstate,4)
        a5 = self.get_stack_arg_val(iaddr,simstate,5)
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3, a4, a5 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_open(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'open')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(-1))
        simstate.add_logmsg('warning','File ' + a0str + ' was not opened')
        return self.add_logmsg(iaddr,simstate,pargs,returnval='-1')


class MIPStub_open64(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'open64')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.simZero)
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

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simNegOne)
        simstate.add_logmsg('i/o',self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr,simstate,str(a0))        

class MIPStub_perror(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'perror')

    def is_error_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + a0str
        simstate.add_logmsg('error',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_popen(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'popen')

    def is_io_operation(self): return True

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1) + ':' + a1str
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_printf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'printf')

    def is_io_operation(self): return True

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

class MIPStub_setlogmask(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'setlogmask')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_setrlimit(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'setrlimit')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_setsockopt(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'setsockopt')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        a4 = self.get_stack_arg_val(iaddr,simstate,4)
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3, a4 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_shmat(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'shmat')

    def is_sharedmem_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',SSV.mk_global_address(0x700000))
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_shmget(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'shmget')

    def is_sharedmem_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_sigaction(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sigaction')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_sigemptyset(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sigemptyset')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_signal(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'signal')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_sleep(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sleep')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
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

    def is_network_operation(self): return True

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns a symbolic value in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        # returnval = SSV.mk_symbol('socket-fd',minval=0)
        returnval = SV.mk_simvalue(113)    # notable, recognizable value
        simstate.set_register(iaddr,'v0',returnval)
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pthread_cond_init(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_cond_init')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pthread_cond_signal(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_cond_signal')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_pthread_create(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_create')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pthread_attr_init(MIPSimStub):

    def is_thread_operation(self): return True

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_attr_init')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_pthread_attr_setschedparam(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_attr_setschedparam')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pthread_attr_setschedpolicy(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_attr_setschedpolicy')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pthread_mutex_init(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_mutex_init')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        pargs = ','.join(str(a) for a in [ a0, a1 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_pthread_mutex_lock(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_mutex_lock')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_pthread_mutex_unlock(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_mutex_unlock')

    def is_thread_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_pthread_self(MIPSimStub):

    def is_thread_operation(self): return True

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'pthread_self')

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,'')


class MIPStub_puts(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'puts')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_random(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'random')

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(0x87654321))
        return self.add_logmsg(iaddr,simstate,'')


class MIPStub_read(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'read')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        if a0.is_file_descriptor():
            fp = a0.fd
            count = 0
            while (byte := fp.read(1)) and count < a2.value:
                tgtaddr = a1.add_offset(count)
                srcval = SV.SimByteValue(ord(byte))
                simstate.set_memval(iaddr,tgtaddr,srcval)
                count += 1
            result = SV.mk_simvalue(count)
        else:
            result = SV.mk_simvalue(-1)
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_recv(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'recv')
        self.buffer = None

    def is_io_operation(self): return True

    def is_network_operation(self): return True

    def get_network_input(self,iaddr,simstate,size):
        if self.buffer is None:
            if simstate.simsupport.has_network_input(iaddr):
                self.buffer = simstate.simsupport.get_network_input(iaddr,simstate,size)
        if len(self.buffer) > 0 and len(self.buffer) <= size:
            recv = self.buffer
            self.buffer = ''
            return recv
        elif len(self.buffer) > 0:
            recv = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return recv
        else:
            return ''

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3 ])
        if self.buffer and len(self.buffer) == 0:
            simstate.set_register(iaddr,'v0',SV.simOne)
            simstate.add_logmsg('i/o',self.name + '(' + pargs + '):1')
            return self.add_logmsg(iaddr,simstate,pargs,returnval='1')
        elif simstate.simsupport.has_network_input(iaddr):
            networkinput = self.get_network_input(iaddr,simstate,a2.value)
            for i in range(0,len(networkinput)):
                tgtaddr = a1.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,SV.mk_simvalue(networkinput[i],1))
            simstate.set_register(iaddr,'v0',SV.mk_simvalue(len(networkinput)))
            return self.add_logmsg(iaddr,simstate,pargs,returnval=str(len(networkinput)))
        else:
            simstate.set_register(iaddr,'v0',SV.mk_simvalue(-1))
            return self.add_logmsg(iaddr,simstate,pargs,returnval='-1')

class MIPStub_recvfrom(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'recvfrom')
        self.buffer = None

    def is_network_operation(self): return True

    def is_io_operation(self): return True

    def get_network_input(self,iaddr,simstate,size):
        if self.buffer is None:
            if simstate.simsupport.has_network_input(iaddr):
                self.buffer = simstate.simsupport.get_network_input(iaddr,simstate,size)
        if len(self.buffer) > 0 and len(self.buffer) <= size:
            recv = self.buffer
            self.buffer = ''
            return recv
        elif len(self.buffer) > 0:
            recv = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return recv
        else:
            return ''


    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        a4 = self.get_stack_arg_val(iaddr,simstate,4)
        a5 = self.get_stack_arg_val(iaddr,simstate,5)
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3, a4, a5 ])
        if self.buffer and len(self.buffer) == 0:
            simstate.set_register(iaddr,'v0',SV.simOne)
            simstate.add_logmsg('i/o',self.name + '(' + pargs + '):1')
            return self.add_logmsg(iaddr,simstate,pargs,returnval='1')
        elif simstate.simsupport.has_network_input(iaddr):
            networkinput = self.get_network_input(iaddr,simstate,a2.value)
            for i in range(0,len(networkinput)):
                tgtaddr = a1.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,SV.mk_simvalue(networkinput[i],1))
            simstate.set_register(iaddr,'v0',SV.mk_simvalue(len(networkinput)))
            return self.add_logmsg(iaddr,simstate,pargs,returnval=str(len(networkinput)))
        else:
            simstate.set_register(iaddr,'v0',SV.mk_simvalue(-1))
            return self.add_logmsg(iaddr,simstate,pargs,returnval='-1')


class MIPStub_sched_get_priority_max(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sched_get_priority_max')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_sched_get_priority_min(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sched_get_priority_min')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_sched_yield(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sched_yield')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_select(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'select')

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Returns the total number of bits set."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        a4 = self.get_stack_arg_val(iaddr,simstate,4)
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3, a4 ])
        result = SV.simZero
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_semget(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'semget')

    def is_sharedmem_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_semop(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'semop')

    def is_sharedmem_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_send(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'send')

    def is_io_operation(self): return True

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3 ])
        simstate.set_register(iaddr,'v0',a2)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(a2))


class MIPStub_sendto(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sendto')

    def is_io_operation(self): return True

    def is_network_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a3 = self.get_arg_val(iaddr,simstate,'a3')
        a4 = self.get_stack_arg_val(iaddr,simstate,4)
        a5 = self.get_stack_arg_val(iaddr,simstate,5)
        pargs = ','.join(str(a) for a in [ a0, a1, a2, a3, a4, a5 ])
        simstate.set_register(iaddr,'v0',SV.simOne)
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_setenv(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'setenv')

    def is_environment_operation(self): return True

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
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_sprintf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sprintf')

    def write_string_to_buffer(self,iaddr,simstate,s):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        if a0.is_symbol():
            simstate.addr_logmsg('free sprintf',
                                 '  to dst: ' + str(a0)
                                 + '; str: ' + str(s))
        elif a0.is_address():
            for i in range(0,len(s)):
                srcval = SV.SimByteValue(ord(s[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,a0.add_offset(len(s)),SV.SimByteValue(0))
        elif a0.is_literal() and a0.is_defined() and a0.value > simstate.imagebase.get_offset_value():
            a0 = SSV.mk_global_address(a0.value)
            for i in range(0,len(s)):
                srcval = SV.SimByteValue(ord(s[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,a0.add_offset(len(s)),SV.SimByteValue(0))
        else:
            raise SU.CHBSimError(simstate,iaddr,'Illegal destination address in sprintf: '
                                 + str(a0))

    def get_logmsg(self,iaddr,simstate,varargs,s):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str + ','  + ','.join(varargs)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(len(s)))

    def set_returnval(self,iaddr,simstate,s):
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(len(s)))

    def simulate(self,iaddr,simstate):
        """Copies the string of the second argument to the dst argument."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        if a1str == '%s':
            a2 = self.get_arg_val(iaddr,simstate,'a2')
            a2str = self.get_arg_string(iaddr,simstate,'a2')
            printstring = a2str
            varargs = [ str(a2) + ':' + a2str ]
        if a1str == '%d':
            a2 = self.get_arg_val(iaddr,simstate,'a2')
            if a2.is_literal() and a2.is_defined():
                printstring = str(a2.value)
                varargs = [ str(a2) ]
            else:
                varargs = []
                printstring = a1str
                simstate.add_logmsg('warning','  sprintf integer value not known: '
                                    + str(a2))
        else:
            varargs = []
            printstring = a1str
            simstate.add_logmsg('warning','  sprintf without substitution: ' + a1str)
        self.write_string_to_buffer(iaddr,simstate,printstring)
        self.set_returnval(iaddr,simstate,printstring)
        return self.get_logmsg(iaddr,simstate,varargs,printstring)

class MIPStub_srand(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'srand')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(0x12345678))
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_sscanf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'sscanf')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        result = -1
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_stat(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'stat')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(-1))
        return self.add_logmsg(iaddr,simstate,pargs)


class MIPStub_strcasecmp(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strcasecmp')

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        a0strlc = a0str.lower()
        a1strlc = a1str.lower()
        if a0strlc == a1strlc:
            result = 0
        elif a0strlc < a1strlc:
            result = -1
        else:
            result = 1
        result = SV.mk_simvalue(result)
        simstate.set_register(iaddr,'v0',result)
        pargs = ','.join(str(a) + ':' + str(v) for (a,v) in [(a0,a0str),(a1,a1str)])
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_strchr(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strchr')

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Copies characters from src to dst up to and including null terminator."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        if a0.is_address():
            dstaddr = a0
        elif a0.is_literal() and a0.is_defined() and a0.value > simstate.imagebase.get_offset_value():
            dstaddr = SSV.mk_global_address(a0.value)
        else:
            raise SU.CHBSimError(simstate,iaddr,'strcpy: illegal destination address: ' + str(a0))
        if a1.is_string_address():
            a1str = self.get_arg_string(iaddr,simstate,'a1')
            for i in range(0,len(a1str)):
                srcval = SV.SimByteValue(ord(a1str[i]))
                tgtaddr = dstaddr.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,dstaddr.add_offset(len(a1str)),SV.SimByteValue(0))
        elif a1.is_symbol():
            simstate.add_logmsg('free strcpy','src:' + str(a1) + ' to dst: ' + str(a0))
        else:
            a1str = self.get_arg_string(iaddr,simstate,'a1')
            for i in range(0,len(a1str)):
                srcval = SV.SimByteValue(ord(a1str[i]))
                tgtaddr = dstaddr.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,dstaddr.add_offset(len(a1str)),SV.SimByteValue(0))
        simstate.set_register(iaddr,'v0',a0)
        pargs = str(dstaddr) + ',' + str(a1) + ':' + a1str
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strdup(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strdup')

    def is_string_operation(self): return True

    def is_memalloc_operation(self): return True

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

class MIPStub_strerror(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strerror')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        rval = SSV.mk_string_address('strerror-' + str(a0))
        simstate.set_register(iaddr,'v0',rval)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_stristr(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'stristr')

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = ','.join(str(a) + ':' + s for (a,s) in [ (a0,a0str), (a1,a1str) ])
        index = a0str.lower().find(a1str.lower())
        if index >= 0:
            result = a0.add_offset(index)
        else:
            result = SV.simZero
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_strlen(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strlen')

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strncpy(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strncpy')

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

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

class MIPStub_strstr(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strstr')

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = ','.join(str(a) + ':' + s for (a,s) in [ (a0,a0str), (a1,a1str) ])
        index = a0str.find(a1str)
        if index >= 0:
            if a0.is_literal() and a0.is_defined() and a0.value > simstate.imagebase.get_offset_value():
                a0 = SSV.mk_global_address(a0.value)
                result = a0.add_offset(index)
            else:
                raise SU.CHBSimError(simstate,iaddr,'Invalid address in strstr: ' + str(a0))
        else:
            result = SV.simZero
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

class MIPStub_strtok(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strtok')

    def is_string_operation(self): return True

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

    def is_string_operation(self): return True

    def simulate_first_token(self,iaddr,simstate,srcaddr,s,sep,stateaddr):
        minpos = len(s)
        for c in sep:
            pos = s.find(c)
            if pos == -1:
                continue
            if pos < minpos:
                minpos = pos
        if minpos == len(s):
            result = srcaddr
            simstate.set_memval(iaddr,stateaddr,SV.simZero)
            pargs = str(srcaddr) + ':' + s + ',' + sep + ',' + str(stateaddr)
            simstate.set_register(iaddr,'v0',result)
            return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))
        else:
            result = srcaddr
            simstate.set_memval(iaddr,srcaddr.add_offset(minpos),SV.SimByteValue(0))
            simstate.set_memval(iaddr,stateaddr,srcaddr.add_offset(minpos+1))
            pargs = str(srcaddr) + ':' + s + ',' + sep + ',' + str(stateaddr)
            simstate.set_register(iaddr,'v0',result)
            return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

    def simulate_next_token(self,iaddr,simstate,sep,a2):
        s = self.get_arg_deref_string(iaddr,simstate,'a2')
        minpos = len(s)
        for c in sep:
            pos = s.find(c)
            if pos == -1:
                continue
            if pos < minpos:
                minpos = pos
        if minpos == len(s):
            result = self.get_arg_deref_val(iaddr,simstate,'a2')
            simstate.set_memval(iaddr,a2,SV.SimByteValue(0))
            pargs = '0, ' + sep + ',' + str(a2)
            simstate.set_register(iaddr,'v0',result)
            return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))
        else:
            result = self.get_arg_deref_val(iaddr,simstate,'a2')
            simstate.set_memval(iaddr,result.add_offset(minpos),SV.SimByteValue(0))
            simstate.set_memval(iaddr,a2,result.add_offset(minpos+1))
            pargs = '0, ' + sep + ', ' + str(a2)
            simstate.set_register(iaddr,'v0',result)
            return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))

        raise SU.CHBSimError(simstate,iaddr,'simulate_next_token not yet implemented')

    def simulate(self,iaddr,simstate):
        """Returns 0 in v0."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        if a0.is_literal() and a0.is_defined() and a0.value == 0:
            return self.simulate_next_token(iaddr,simstate,a1str,a2)
        elif a0.is_address():
            a0str = self.get_arg_string(iaddr,simstate,'a0')
            return self.simulate_first_token(iaddr,simstate,a0,a0str,a1str,a2)
        else:
            a0str = self.get_arg_string(iaddr,simstate,'a0')
            simstate.set_register(iaddr,'v0',result)
            pargs = (str(a0) + ': "' + a0str + '", '
                     + str(a1) + ': "' + a1str + '", '
                     + str('state:' + str(a2)))
            return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_strtoul(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'strtoul')

    def is_string_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a0str = self.get_arg_string(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = str(a0) + ':' + a0str + ',' + str(a1) + ',' + str(a2)
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,pargs,returnval='0')

class MIPStub_syslog(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'syslog')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        if a1str == '%s':
            a2 = self.get_arg_val(iaddr,simstate,'a2')
            a2str = self.get_arg_string(iaddr,simstate,'a2')
            pargs += ',' + str(a2) + ':' + a2str
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_system(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'system')

    def is_system_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')  # cmdline string
        if a0.is_literal() and a0.value == 0:
            pargs = 'NULL'
        else:
            pargs = self.get_arg_string(iaddr,simstate,'a0')
        return self.add_logmsg(iaddr,simstate,pargs)

class MIPStub_time(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'time')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        result = int(time.time())
        simstate.set_register(iaddr,'v0',SV.mk_simvalue(result))
        return self.add_logmsg(iaddr,simstate,str(a0),returnval=str(result))

class MIPStub_umask(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'umask')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_usleep(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'usleep')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))

class MIPStub_vsprintf(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'vsprintf')

    def simulate(self,iaddr,simstate):
        """Copies the string of the second argument to the dst argument."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a1str = self.get_arg_string(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        printstring = a1str
        if a0.is_symbol():
            simstate.add_logmsg('free vsprintf',' to dst: ' + str(a0) + '; str: ' + printstring)
        else:
            for i in range(0,len(printstring)):
                srcval = SV.SimByteValue(ord(printstring[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr,tgtaddr,srcval)
            simstate.set_memval(iaddr,a0.add_offset(len(printstring)),SV.mk_simvalue(0,size=1))
        simstate.set_register(iaddr,'v0',SV.SimDoubleWordValue(len(printstring)))
        pargs = (str(a0) + ',' + str(a1) + ':' + a1str + ',' + str(a2))
        return self.add_logmsg(iaddr,simstate,pargs,
                                returnval=str(len(printstring)))

class MIPStub_waitpid(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'waitpid')

    def is_process_operation(self): return True

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.set_register(iaddr,'v0',a0)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(a0))

class MIPStub_write(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'write')

    def is_io_operation(self): return True

    def simulate(self,iaddr,simstate):
        """Logs i/o, returns a2 in v0 for now."""
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0,a1,a2 ])
        if a0.is_literal():
            simstate.add_logmsg('i/o','Not a valid file descriptor: ' + str(a0))
            result = SV.mk_simvalue(-1)
        elif a0.is_file_descriptor() and a2.is_literal() and a2.is_defined():
            for i in range(0,a2.value):
                tgtaddr = a1.add_offset(i)
                srcval = simstate.get_memval(iaddr,tgtaddr,1)
                a0.fd.write(chr(srcval.value))
            result = a2
            simstate.add_logmsg('i/o','Successfully wrote '
                                + str(a2) + ' bytes to ' + str(a0))
        else:
            result = SV.mk_simvalue(-1)
        simstate.set_register(iaddr,'v0',result)
        return self.add_logmsg(iaddr,simstate,pargs,returnval=str(result))


class MIPStub_isLanSubnet(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'isLanSubnet')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,str(a0))


class MIPStub_uloop_init(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'uloop_init')

    def simulate(self,iaddr,simstate):
        simstate.set_register(iaddr,'v0',SV.simZero)
        return self.add_logmsg(iaddr,simstate,'')

class MIPStub_msglogd(MIPSimStub):

    def __init__(self,app):
        MIPSimStub.__init__(self,app,'msglogd')

    def simulate(self,iaddr,simstate):
        a0 = self.get_arg_val(iaddr,simstate,'a0')
        a1 = self.get_arg_val(iaddr,simstate,'a1')
        a2 = self.get_arg_val(iaddr,simstate,'a2')
        pargs = ','.join(str(a) for a in [ a0, a1, a2 ])
        simstate.add_logmsg('i/o',self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr,simstate,pargs)
