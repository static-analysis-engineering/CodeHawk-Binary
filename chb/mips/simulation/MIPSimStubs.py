# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from typing import (
    Any,
    BinaryIO,
    Callable,
    cast,
    Dict,
    IO,
    List,
    Optional,
    Tuple,
    Type,
    TYPE_CHECKING)

import datetime
import ipaddress
import os
import time


from chb.mips.simulation.MIPSimMemory import MIPSimStackMemory, MIPSimGlobalMemory

from chb.simulation.SimBaseMemory import SimBaseMemory
from chb.simulation.SimSharedMemory import SimSharedMemory
from chb.simulation.SimMappedMemory import SimMappedMemory

import chb.simulation.SimFileUtil as SFU
from chb.simulation.SimStub import SimStub
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.simulation.SimulationState import SimulationState


def stubbed_libc_functions() -> Dict[str, "MIPSimStub"]:
    return {
        "accept": MIPStub_accept(),
        "access": MIPStub_access(),
        "atoi": MIPStub_atoi(),
        "atol": MIPStub_atol(),
        "basename": MIPStub_basename(),
        "bind": MIPStub_bind(),
        "bsearch": MIPStub_bsearch(),
        "calculate_checksum": MIPStub_calculate_checksum(),
        "calloc": MIPStub_calloc(),
        "chdir": MIPStub_chdir(),
        "clock_gettime": MIPStub_clock_gettime(),
        "close": MIPStub_close(),
        "closelog": MIPStub_closelog(),
        "connect": MIPStub_connect(),
        "daemon": MIPStub_daemon(),
        "dlopen": MIPStub_dlopen(),
        "dlsym": MIPStub_dlsym(),
        "dprintf": MIPStub_dprintf(),
        "dup": MIPStub_dup(),
        "dup2": MIPStub_dup2(),
        "epoll_create": MIPStub_epoll_create(),
        "epoll_ctl": MIPStub_epoll_ctl(),
        "epoll_wait": MIPStub_epoll_wait(),
        "__errno_location": MIPStub___errno_location(),
        "execve": MIPStub_execve(),
        "exit": MIPStub_exit(),
        "_exit": MIPStub_exit(),
        "fclose": MIPStub_fclose(),
        "fcntl": MIPStub_fcntl(),
        "fcntl64": MIPStub_fcntl64(),
        "fdopen": MIPStub_fdopen(),
        "feof": MIPStub_feof(),
        "__fgetc_unlocked": MIPStub___fgetc_unlocked(),
        "fflush": MIPStub_fflush(),
        "fgets": MIPStub_fgets(),
        "fileno": MIPStub_fileno(),
        "fopen": MIPStub_fopen(),
        "fopen64": MIPStub_fopen64(),
        "fork": MIPStub_fork(),
        "fprintf": MIPStub_fprintf(),
        "fputc": MIPStub_fputc(),
        "fputs": MIPStub_fputs(),
        "fread": MIPStub_fread(),
        "free": MIPStub_free(),
        "freeaddrinfo": MIPStub_freeaddrinfo(),
        "fscanf": MIPStub_fscanf(),
        "fstat": MIPStub_fstat(),
        "fstat64": MIPStub_fstat64(),
        "fwrite": MIPStub_fwrite(),
        "getaddrinfo": MIPStub_getaddrinfo(),
        "get_current_dir_name": MIPStub_get_current_dir_name(),
        "getcwd": MIPStub_getcwd(),
        "getenv": MIPStub_getenv(),
        "gethostname": MIPStub_gethostname(),
        "getline": MIPStub_getline(),
        "getopt": MIPStub_getopt(),
        "getopt_long": MIPStub_getopt_long(),
        "getpeername": MIPStub_getpeername(),
        "getpid": MIPStub_getpid(),
        "getpwnam": MIPStub_getpwnam(),
        "getpwuid": MIPStub_getpwuid(),
        "getrlimit64": MIPStub_getrlimit64(),
        "getsockname": MIPStub_getsockname(),
        "gettimeofday": MIPStub_gettimeofday(),
        "getuid": MIPStub_getuid(),
        "gmtime": MIPStub_gmtime(),
        "index": MIPStub_index(),
        "inet_addr": MIPStub_inet_addr(),
        "inet_aton": MIPStub_inet_aton(),
        "inet_ntoa": MIPStub_inet_ntoa(),
        "inet_pton": MIPStub_inet_pton(),
        "ioctl": MIPStub_ioctl(),
        "isatty": MIPStub_isatty(),
        "__libc_current_sigrtmax": MIPStub___libc_current_sigrtmax(),
        "__libc_current_sigrtmin": MIPStub___libc_current_sigrtmin(),
        "listen": MIPStub_listen(),
        "localtime": MIPStub_localtime(),
        "lockf": MIPStub_lockf(),
        "longjmp": MIPStub_longjmp(),
        "malloc": MIPStub_malloc(),
        "mallopt": MIPStub_mallopt(),
        "memcmp": MIPStub_memcmp(),
        "memcpy": MIPStub_memcpy(),
        "memmove": MIPStub_memmove(),
        "memset": MIPStub_memset(),
        "mkdir": MIPStub_mkdir(),
        "mktemp": MIPStub_mktemp(),
        "mmap": MIPStub_mmap(),
        "msgget": MIPStub_msgget(),
        "open": MIPStub_open(),
        "open64": MIPStub_open64(),
        "openlog": MIPStub_openlog(),
        "pclose": MIPStub_pclose(),
        "perror": MIPStub_perror(),
        "popen": MIPStub_popen(),
        "printf": MIPStub_printf(),
        "pthread_attr_init": MIPStub_pthread_attr_init(),
        "pthread_attr_setschedparam": MIPStub_pthread_attr_setschedparam(),
        "pthread_attr_setschedpolicy": MIPStub_pthread_attr_setschedpolicy(),
        "pthread_cond_init": MIPStub_pthread_cond_init(),
        "pthread_cond_signal": MIPStub_pthread_cond_signal(),
        "pthread_create": MIPStub_pthread_create(),
        "pthread_mutex_init": MIPStub_pthread_mutex_init(),
        "pthread_mutex_lock": MIPStub_pthread_mutex_lock(),
        "pthread_mutex_unlock": MIPStub_pthread_mutex_unlock(),
        "pthread_self": MIPStub_pthread_self(),
        "putenv": MIPStub_putenv(),
        "puts": MIPStub_puts(),
        "rand": MIPStub_rand(),
        "random": MIPStub_random(),
        "read": MIPStub_read(),
        "realloc": MIPStub_realloc(),
        "realpath": MIPStub_realpath(),
        "reboot": MIPStub_reboot(),
        "recv": MIPStub_recv(),
        "recvfrom": MIPStub_recvfrom(),
        "remove": MIPStub_remove(),
        "rename": MIPStub_rename(),
        "rt_sigaction": MIPStub_sigaction(name="rt_sigaction"),
        "sched_get_priority_max": MIPStub_sched_get_priority_max(),
        "sched_get_priority_min": MIPStub_sched_get_priority_max(),
        "sched_yield": MIPStub_sched_yield(),
        "select": MIPStub_select(),
        "semctl": MIPStub_semctl(),
        "semget": MIPStub_semget(),
        "semop": MIPStub_semop(),
        "send": MIPStub_send(),
        "sendto": MIPStub_sendto(),
        "setenv": MIPStub_setenv(),
        "_setjmp": MIPStub__setjmp(),
        "setlogmask": MIPStub_setlogmask(),
        "setrlimit": MIPStub_setrlimit(),
        "setrlimit64": MIPStub_setrlimit(),
        "setsid": MIPStub_setsid(),
        "setsockopt": MIPStub_setsockopt(),
        "shmat": MIPStub_shmat(),
        "shmctl": MIPStub_shmctl(),
        "shmdt": MIPStub_shmdt(),
        "shmget": MIPStub_shmget(),
        "sigaction": MIPStub_sigaction(),
        "sigaddset": MIPStub_sigaddset(),
        "sigemptyset": MIPStub_sigemptyset(),
        "signal": MIPStub_signal(),
        "sigprocmask": MIPStub_sigprocmask(),
        "sleep": MIPStub_sleep(),
        "snprintf": MIPStub_snprintf(),
        "socket": MIPStub_socket(),
        "sprintf": MIPStub_sprintf(),
        "srand": MIPStub_srand(),
        "sscanf": MIPStub_sscanf(),
        "stat": MIPStub_stat(),
        "strcasecmp": MIPStub_strcasecmp(),
        "strcat": MIPStub_strcat(),
        "strchr": MIPStub_strchr(),
        "strcmp": MIPStub_strcmp(),
        "strcpy": MIPStub_strcpy(),
        "strdup": MIPStub_strdup(),
        "strerror": MIPStub_strerror(),
        "strftime": MIPStub_strftime(),
        "stristr": MIPStub_stristr(),
        "strlcpy": MIPStub_strlcpy(),
        "strlen": MIPStub_strlen(),
        "strncasecmp": MIPStub_strncasecmp(),
        "strncat": MIPStub_strncat(),
        "strncmp": MIPStub_strncmp(),
        "strncpy": MIPStub_strncpy(),
        "strrchr": MIPStub_strrchr(),
        "strsep": MIPStub_strsep(),
        "strstr": MIPStub_strstr(),
        "strtof": MIPStub_strtof(),
        "strtok": MIPStub_strtok(),
        "strtok_r": MIPStub_strtok_r(),
        "strtol": MIPStub_strtol(),
        "strtoul": MIPStub_strtoul(),
        "syslog": MIPStub_syslog(),
        "system": MIPStub_system(),
        "tcgetattr": MIPStub_tcgetattr(),
        "tcsetattr": MIPStub_tcsetattr(),
        "time": MIPStub_time(),
        "tolower": MIPStub_tolower(),
        "umask": MIPStub_umask(),
        "unlink": MIPStub_unlink(),
        "unsetenv": MIPStub_unsetenv(),
        "usleep": MIPStub_usleep(),
        "vfork": MIPStub_vfork(),
        "vsnprintf": MIPStub_vsnprintf(),
        "vsprintf": MIPStub_vsprintf(),
        "waitpid": MIPStub_waitpid(),
        "write": MIPStub_write(),
        "isLanSubnet": MIPStub_isLanSubnet(),
        "msglogd": MIPStub_msglogd(),     # libmsglog.so
        "config_commit": MIPStub_config_commit(),  # libconfig.so
        "config_get": MIPStub_config_get(),  # libconfig.so
        "config_set": MIPStub_config_set(),  # libconfig.so
        "config_match": MIPStub_config_match(),  # libconfig.so
        "config_invmatch": MIPStub_config_invmatch(),  # libconfig.so
        "config_unset": MIPStub_config_unset(),  # libconfig.so
        "init_libconfig": MIPStub_init_libconfig(),  # libconfig.so
    }


fcntl_cmds = {
    "0x0": "F_DUPFD",
    "0x1": "F_GETFD",
    "0x2": "F_SETFD",
    "0x3": "F_GETFL",
    "0x4": "F_SETFL"
}


class MIPSimStub(SimStub):

    def __init__(self, name: str) -> None:
        SimStub.__init__(self, name)

    def get_arg_val(
            self,
            iaddr: str,
            simstate: "SimulationState",
            arg: str) -> SV.SimValue:
        """Returns a SimValue; arg must be a MIPS register."""

        return simstate.regval(iaddr, arg)

    def get_arg_deref_val(
            self,
            iaddr: str,
            simstate: "SimulationState",
            arg: str) -> SV.SimValue:
        """Returns a SimValue, pointed to by the arg-val."""

        saddr = self.get_arg_val(iaddr, simstate, arg)
        if saddr.is_address:
            saddr = cast(SSV.SimAddress, saddr)
            return simstate.memval(iaddr, saddr, 4)
        else:
            return SV.simUndefinedDW

    def get_stack_arg_val(
            self,
            iaddr: str,
            simstate: "SimulationState",
            argindex: int) -> SV.SimValue:
        """Returns a SimValue for an argument on the stack."""

        sp = simstate.regval(iaddr, "sp")
        if sp.is_address:
            sp = cast(SSV.SimAddress, sp)
            if sp.is_stack_address:
                sp = cast(SSV.SimStackAddress, sp)
                stackaddr = sp.add_offset(4 * argindex)
                return simstate.memval(iaddr, stackaddr, 4)
        return SV.simUndefinedDW

    def get_nth_arg_val(
            self,
            iaddr: str,
            simstate: "SimulationState",
            argindex: int) -> SV.SimValue:
        """Returns a SimValue for either a register or stack argument."""

        if argindex < 0:
            return SV.simUndefinedDW
        elif argindex < 4:
            argname = "a" + str(argindex)
            return self.get_arg_val(iaddr, simstate, argname)
        else:
            return self.get_stack_arg_val(iaddr, simstate, argindex)

    def get_arg_string(
            self,
            iaddr: str,
            simstate: "SimulationState",
            arg: str) -> str:
        """Returns a string; arg must be a MIPS register."""

        saddr = self.get_arg_val(iaddr, simstate, arg)
        return self.get_string_at_address(iaddr, simstate, saddr)

    def get_string_at_address(
            self,
            iaddr: str,
            simstate: "SimulationState",
            saddr: SV.SimValue) -> str:
        result = ''
        offset = 0
        if saddr.is_address:
            saddr = cast(SSV.SimAddress, saddr)
            return simstate.get_string_from_memaddr(iaddr, saddr)
        elif saddr.is_symbol:
            saddr = cast(SSV.SimSymbol, saddr)
            return "symbol:" + saddr.name
        elif saddr.is_literal and not saddr.is_defined:
            return "*****address-not-defined*****"
        elif saddr.is_literal and saddr.is_defined:
            saddr = cast(SV.SimLiteralValue, saddr)
            gaddr = simstate.resolve_literal_address(iaddr, saddr.value)
            if not gaddr.is_defined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "String argument is not a valid address: " + str(saddr))
            elif gaddr.is_address:
                gaddr = cast(SSV.SimGlobalAddress, gaddr)
                return simstate.get_string_from_memaddr(iaddr, gaddr)

        raise SU.CHBSimError(
            simstate,
            iaddr,
            "String argument is not a valid address: " + str(saddr))

    def get_stack_arg_string(
            self,
            iaddr: str,
            simstate: "SimulationState",
            argindex: int) -> str:
        sp = simstate.regval(iaddr, "sp")
        if sp.is_address:
            sp = cast(SSV.SimAddress, sp)
            if sp.is_stack_address:
                sp = cast(SSV.SimStackAddress, sp)
                stackaddr = sp.add_offset(4 * argindex)
                stringaddr = simstate.memval(iaddr, stackaddr, 4)
                return self.get_string_at_address(iaddr, simstate, stringaddr)
        return "******stack-address-not-defined*******"

    def get_nth_arg_string(
            self,
            iaddr: str,
            simstate: "SimulationState",
            argindex: int) -> str:
        """Returns an associated string with a register or stack argument."""

        if argindex < 0:
            return "invalid argument index: " + str(argindex)
        elif argindex < 4:
            argname = "a" + str(argindex)
            return self.get_arg_string(iaddr, simstate, argname)
        else:
            return self.get_stack_arg_string(iaddr, simstate, argindex)

    def get_arg_deref_string(
            self,
            iaddr: str,
            simstate: "SimulationState",
            arg: str) -> str:
        """Returns a string; arg must be a MIPS register."""

        saddrptr = self.get_arg_val(iaddr, simstate, arg)
        if saddrptr.is_address:
            saddrptr = cast(SSV.SimAddress, saddrptr)
            saddr = simstate.memval(iaddr, saddrptr, 4)
            if saddr.is_address:
                saddr = cast(SSV.SimAddress, saddr)
                result = ""
                offset = 0
                while True:
                    srcaddr = saddr.add_offset(offset)
                    srcval = simstate.memval(iaddr, srcaddr, 1)
                    if srcval.is_literal and srcval.is_defined:
                        srcval = cast(SV.SimLiteralValue, srcval)
                        if srcval.value == 0:
                            break
                        result += chr(srcval.value)
                        offset += 1
                    else:
                        break
                return result
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    ("Pointed to value in arg_deref_string "
                     + " is not an address: "
                     + str(saddr)))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Argument is not an address in arg_deref_string: "
                 + str(saddrptr)))

    def substitute_formatstring(
            self,
            iaddr: str,
            simstate: "SimulationState",
            fmtstringindex: int) -> Tuple[str, List[str]]:
        """Return substituted string and arguments used (as a string)."""

        fmtstring = self.get_nth_arg_string(iaddr, simstate, fmtstringindex)

        # First check if the user supplied a custom return value
        result = simstate.simsupport.substitute_formatstring(
            self, iaddr, simstate, fmtstring)
        if result is not None:
            return result

        # Extract the format specifiers from the formatstring
        fmt_items = SU.extract_format_items(fmtstring)

        if fmt_items is None:
            simstate.add_logmsg(
                "warning",
                self.name
                + " without substitution (unable to extract format items)")
            return (fmtstring, [])

        if len(fmt_items) == 0:
            simstate.add_logmsg(
                "warning",
                self.name
                + " without substitution (no format items found)")

        # Retrieve the associated arguments and substitute them in the format string
        pos: int = 0
        printstring: str = ""
        varargs: List[str] = []
        argcounter: int = fmtstringindex + 1
        for (index, item) in fmt_items:
            printstring += fmtstring[pos:index]
            vararg: SV.SimValue = self.get_nth_arg_val(iaddr, simstate, argcounter)
            if item == "%s":
                varargstr: str = self.get_nth_arg_string(
                    iaddr, simstate, argcounter)
                printstring += varargstr
            elif item == "%d":
                if vararg.is_literal:
                    vararg = cast(SV.SimLiteralValue, vararg)
                    printstring += str(vararg.value)
                else:
                    printstring += "%d"
            else:
                printstring += item
            pos = index + len(item)
            argcounter += 1
            varargs.append(str(vararg))
        printstring += fmtstring[pos:len(fmtstring)]
        return (printstring, varargs)

    def is_error_operation(self) -> bool:
        return False

    def is_io_operation(self) -> bool:
        return False

    def is_network_operation(self) -> bool:
        return False

    def is_string_operation(self) -> bool:
        return False

    def is_environment_operation(self) -> bool:
        return False

    def is_thread_operation(self) -> bool:
        return False

    def is_process_operation(self) -> bool:
        return False

    def is_memalloc_operation(self) -> bool:
        return False

    def is_sharedmem_operation(self) -> bool:
        return False

    def is_system_operation(self) -> bool:
        return False

    def is_domain_call(self) -> Optional[str]:
        return None

    def add_logmsg(
            self,
            iaddr: str,
            simstate: "SimulationState",
            arguments: str,
            returnval: str = "") -> str:
        preturn = 'return value: ' + returnval if returnval else ''
        msg = self.name + '(' + arguments + ') ' + preturn
        simstate.add_logmsg('stub:' + self.name, msg)
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
            simstate.add_logmsg('memory allocation:', msg)
        if self.is_sharedmem_operation():
            simstate.add_logmsg('shared memory:', msg)
        if self.is_system_operation():
            simstate.add_logmsg('system', msg)
        if self.is_domain_call():
            domain = cast(str, self.is_domain_call())
            simstate.add_logmsg('domain:' + domain, msg)
        return msg

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Dummy function."""

        raise SU.CHBSimError(
            simstate,
            iaddr,
            "Simulation not implemented for " + self.name)

    def __str__(self) -> str:
        return self.name


class MIPStub_accept(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "accept")
        self.count = 0

    def is_io_operation(self) -> bool:
        return True

    def is_network_operation(self) -> bool:
        return True

    # a new file descriptor shall be allocated for the socket
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a2deref = self.get_arg_deref_val(iaddr, simstate, "a2")
        pargs = (
            ','.join(str(a) for a in [a0, a1])
            + ','
            + str(a2)
            + ':'
            + str(a2deref))
        if self.count == 0:
            simstate.set_register(iaddr, "v0", SV.mk_simvalue(4))
            rv = "4"
            self.count += 1
            if a1.is_address:
                a1 = cast(SSV.SimAddress, a1)
                if a2deref.is_literal and a2deref.is_defined:
                    a2deref = cast(SV.SimLiteralValue, a2deref)
                    if a2deref.value == 16:
                        simstate.set_memval(
                            iaddr, a1, SV.mk_simvalue(0, size=2))
                        simstate.set_memval(
                            iaddr, a1.add_offset(2), SV.mk_simvalue(80, size=2))
                        simstate.set_memval(
                            iaddr, a1.add_offset(4), SV.mk_simvalue(444))
                        simstate.set_memval(
                            iaddr, a1.add_offset(8), SV.mk_simvalue(0))
                        simstate.set_memval(
                            iaddr, a1.add_offset(12), SV.mk_simvalue(0))
        else:
            simstate.set_register(iaddr, "v0", SV.mk_simvalue(-1))
            rv = "-1"
        return self.add_logmsg(iaddr, simstate, pargs, returnval=rv)


class MIPStub_access(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "access")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(-1))
        return self.add_logmsg(iaddr, simstate, pargs, returnval="-1")


class MIPStub_atoi(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "atoi")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        try:
            a0str = self.get_arg_string(iaddr, simstate, "a0")
        except SU.CHBSimAddressError as e:
            raise e
        except Exception as e:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "atoi: " + str(a0) + " is not a string. (" + str(e) + ")")
        pargs = str(a0) + ":" + a0str
        try:
            result = int(a0str)
        except Exception as e:
            print('String ' + a0str + " cannot be converted to int: " + str(e))
            simstate.add_logmsg(
                "error:",
                "Conversion to int failed in atoi: " + a0str)
            result = 0
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_atol(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "atol")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        try:
            a0str = self.get_arg_string(iaddr, simstate, 'a0')
        except Exception as e:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "atol: " + str(a0) + " is not a string. (" + str(e) + ")")
        pargs = str(a0) + ':' + a0str
        try:
            result = int(a0str)
        except Exception as e:
            print('String ' + a0str + ' cannot be converted to long: ' + str(e))
            simstate.add_logmsg(
                'error:',
                'Conversion to long failed in atol: ' + a0str)
            result = -1
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_basename(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'basename')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns (in v0) the basename set in simstate."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")
        base = "basename_" + iaddr
        stringaddress = SSV.mk_string_address(base, simstate.modulename)
        simstate.set_register(iaddr, "v0", stringaddress)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_bind(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'bind')

    def is_io_operation(self) -> bool:
        return True

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            safamily = simstate.memval(iaddr, a1, 2)
            sapath = simstate.get_string_from_memaddr(iaddr, a1.add_offset(2))
            pargs = (
                str(a0)
                + ","
                + str(a1)
                + ":{"
                + str(safamily)
                + "," + sapath
                + "},"
                + str(a2))
        else:
            pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_bsearch(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "bsearch")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        a3 = self.get_arg_val(iaddr, simstate, "a3")
        a4 = self.get_stack_arg_val(iaddr, simstate, 4)
        pargs = ", ".join(str(a) for a in [a0, a1, a2, a3, a4])
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0")


class MIPStub_calculate_checksum(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'calculate_checksum')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """No computation; returns -1 in v0."""

        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        simstate.set_register(iaddr, 'v0', SV.SimDoubleWordValue(-1))
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        return self.add_logmsg(iaddr, simstate, pargs, returnval='-1')


class MIPStub_calloc(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "calloc")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site: str) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def is_memalloc_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Initializes the memory to 0."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        site = "calloc_" + iaddr
        base = site + ":" + str(self.sitecounter(site))
        if a0.is_literal and a0.is_defined and a1.is_literal and a1.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            a1 = cast(SV.SimLiteralValue, a1)
            buffersize = a0.value * a1.value
            address = SSV.mk_base_address(base, 0, buffersize=buffersize)
            for i in range(0, buffersize):
                tgtaddr = address.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, SV.SimByteValue(0))
            simstate.set_register(iaddr, "v0", address)
            returnval: str = str(address)
        else:
            simstate.set_register(iaddr, 'v0', SV.simZero)
            returnval = "0"
        pargs = str(a0) + ',' + str(a1)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=returnval)


class MIPStub_chdir(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'chdir')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + str(a0str)
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_clock_gettime(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'clock_gettime')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            simstate.set_memval(iaddr, a1, SV.mk_simvalue(int(time.time())))
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_close(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'close')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_closelog(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'closelog')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o; no return value."""
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_connect(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'connect')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_daemon(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'daemon')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_dlopen(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'dlopen')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        result = SSV.mk_symboltablehandle(a0str)
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_dlsym(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'dlsym')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # void *restrict handle
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const char *restrict name
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = str(a0) + ',' + str(a1) + ':' + a1str

        if a0.is_undefined or a1.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "dlsym: some argument is undefined: " + pargs)

        result: SV.SimValue

        if a0.is_symbol_table_handle:
            a0 = cast(SSV.SimSymbolTableHandle, a0)
            importsym = simstate.resolve_import_symbol(a1str)
            if importsym.is_defined:
                result = SSV.mk_dynamic_link_symbol(a0, a1str, importsym)
                a0.set_value(a1str, result)
            else:
                result = SV.simNegOne

        else:
            result = SV.simNegOne

        simstate.set_register(iaddr, "v0", result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_dprintf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'dprintf')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_dup(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'dup')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(15))
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(a0))


class MIPStub_dup2(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'dup2')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', a1)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(a1))


class MIPStub_epoll_create(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'epoll_create')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        result = SV.mk_simvalue(1)
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(result))


class MIPStub_epoll_ctl(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'epoll_ctl')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_epoll_wait(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'epoll_wait')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, pargs, returnval='1')


class MIPStub___errno_location(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "__errno_location")

    def is_error_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        base = "errno_" + iaddr
        stringaddr = SSV.mk_string_address(base, "error-string")
        simstate.set_register(iaddr, "v0", stringaddr)
        return self.add_logmsg(iaddr, simstate, str(stringaddr))


class MIPStub_execve(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "execve")

    def is_process_operation(self) -> bool:
        return True

    def retrieve_strings(
            self,
            iaddr: str,
            simstate: "SimulationState",
            addr: SSV.SimAddress) -> List[str]:
        result: List[str] = []
        saddr = simstate.memval(iaddr, addr, 4)
        if saddr.is_literal and saddr.is_defined:
            saddr = cast(SV.SimLiteralValue, saddr)
            while saddr.value > 0:
                s = self.get_string_at_address(iaddr, simstate, saddr)
                result.append(s)
                addr = addr.add_offset(4)
                saddrp = simstate.memval(iaddr, addr, 4)
                if saddrp.is_literal and saddrp.is_defined:
                    saddr = cast(SV.SimLiteralValue, saddrp)
                else:
                    break
            else:
                pass
        else:
            pass
        return result

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            a1strings = self.retrieve_strings(iaddr, simstate, a1)
            a1p = str(a1) + ":[" + ", ".join(str(s) for s in a1strings) + "]"
        else:
            a1p = str(a1)
        if a2.is_address:
            a2 = cast(SSV.SimAddress, a2)
            a2strings = self.retrieve_strings(iaddr, simstate, a2)
            a2p = str(a2) + ":[" + ", ".join(str(s) for s in a2strings) + "]"
        else:
            a2p = str(a2)
        pargs = str(a0) + ":" + a0str + ", " + str(a1p) + ", " + str(a2p)
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(-1))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_exit(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'exit')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        raise SU.CHBSimExitException(simstate, iaddr, str(a0))


class MIPStub_fclose(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fclose')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        if a0.is_symbol:
            a0 = cast(SSV.SimSymbol, a0)
            if a0.is_file_descriptor:
                try:
                    a0 = cast(SSV.SimSymbolicFileDescriptor, a0)
                    a0.filedescriptor.close()
                    simstate.add_logmsg('i/o', 'Successfully closed ' + str(a0))
                except Exception as e:
                    simstate.add_logmsg(
                        'i/o', 'Error in closing ' + str(a0) + ': ' + str(e))
            elif a0.is_file_pointer:
                try:
                    a0 = cast(SSV.SimSymbolicFilePointer, a0)
                    SFU.sim_close_file_pointer(a0)
                    simstate.add_logmsg('i/o', 'Successfully closed ' + str(a0))
                except Exception as e:
                    simstate.add_logmsg(
                        'i/o', 'Error in closing ' + str(a0) + ': ' + str(e))
            else:
                simstate.add_logmsg('i/o', self.name + '(' + str(a0) + ')')
        else:
            pass
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_fcntl(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fcntl')

    def is_io_operation(self) -> bool:
        return True

    def get_cmd_name(self, i: SV.SimLiteralValue) -> str:
        if str(i) in fcntl_cmds:
            return fcntl_cmds[str(i)]
        else:
            return str(i)

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        if a1.is_literal:
            a1 = cast(SV.SimLiteralValue, a1)
            a1cmd = self.get_cmd_name(a1)
            if a1cmd == "F_SETFL":
                a2 = self.get_arg_val(iaddr, simstate, 'a2')
                pargs = str(a0) + ',' + a1cmd + ',' + str(a2)
            else:
                pargs = str(a0) + ',' + a1cmd
        else:
            pargs = str(a0) + "," + str(a1)
        simstate.set_register(iaddr, 'v0', SV.SimDoubleWordValue(0))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_fcntl64(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fcntl64')

    def is_io_operation(self) -> bool:
        return True

    def get_cmd_name(self, i: SV.SimLiteralValue) -> str:
        if str(i) in fcntl_cmds:
            return fcntl_cmds[str(i)]
        else:
            return str(i)

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        if a1.is_literal:
            a1 = cast(SV.SimLiteralValue, a1)
            a1cmd = self.get_cmd_name(a1)
            if a1cmd == "F_SETFL":
                a2 = self.get_arg_val(iaddr, simstate, 'a2')
                pargs = str(a0) + ',' + a1cmd + ',' + str(a2)
            else:
                pargs = str(a0) + ',' + a1cmd
        else:
            pargs = str(a0) + str(a1)
        simstate.set_register(iaddr, 'v0', SV.SimDoubleWordValue(0))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_fdopen(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fdopen')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval='0')


class MIPStub_feof(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'feof')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns false by default."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        if a0.is_symbol:
            a0 = cast(SSV.SimSymbol, a0)
            if a0.is_file_pointer:
                a0 = cast(SSV.SimSymbolicFilePointer, a0)
                try:
                    fp = a0.fp
                    s = fp.read()
                    if s == '':
                        result = 1
                    else:
                        result = 0
                except Exception:
                    result = 0
            else:
                result = 0
        else:
            result = 0
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        simstate.add_logmsg('i/o', self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(result))


class MIPStub___fgetc_unlocked(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, '__fgetc_unlocked')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Return a tainted value in v0."""

        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SSV.SimTaintedValue('fgetc', -1, 255))
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_fflush(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fflush')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_fgets(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fgets')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Inputs tainted characters."""
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")

        pargs = str(a0) + "," + str(a1) + "," + str(a2)
        simstate.set_register(iaddr, "v0", a0)
        if not a0.is_address:
            return self.add_logmsg(iaddr, simstate, pargs)
        a0 = cast(SSV.SimAddress, a0)

        if a1.is_literal and a1.is_defined:
            a1 = cast(SV.SimLiteralValue, a1)
        else:
            return self.add_logmsg(iaddr, simstate, pargs)

        bytes = simstate.simsupport.read_filepointer_input(iaddr, a2, a1.value)
        if len(bytes) > 0:
            for i in range(0, len(bytes)):
                srcval = SV.SimByteValue(bytes[i])
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
            simstate.set_memval(
                iaddr, a0.add_offset(len(bytes)), SV.SimByteValue(0))
            return self.add_logmsg(iaddr, simstate, pargs)

        if a2.is_symbolic:
            a2 = cast(SSV.SimSymbol, a2)
            if a2.is_file_pointer:
                a2 = cast(SSV.SimSymbolicFilePointer, a2)
                i = 0
                while i < a1.value - 1:
                    c = a2.fp.read(1)
                    if c == '':
                        if i == 0:
                            simstate.set_register(iaddr, 'v0', SV.simZero)
                            break
                        srcval = SV.SimByteValue(255)
                        tgtaddr = a0.add_offset(i)
                        simstate.set_memval(iaddr, tgtaddr, srcval)
                        break
                    else:
                        srcval = SV.SimByteValue(ord(c))
                        tgtaddr = a0.add_offset(i)
                        simstate.set_memval(iaddr, tgtaddr, srcval)
                        i += 1
                simstate.set_memval(
                    iaddr, a0.add_offset(a1.value - 1), SV.SimByteValue(0))

        else:
            for i in range(0, a1.value - 1):
                srcval = SV.SimByteValue(ord("t"))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
            simstate.set_memval(
                iaddr, a0.add_offset(a1.value - 1), SV.SimByteValue(0))

        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_fputc(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "fputc")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int c
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # FILE *stream
        pargs = str(a0) + ", " + str(a1)
        if simstate.simsupport.file_operations_enabled:
            if a0.is_literal and a1.is_file_pointer:
                a0 = cast(SV.SimLiteralValue, a0)
                a1 = cast(SSV.SimSymbolicFilePointer, a1)
                print("fputc: write to " + str(a1) + ": " + str(a0))
                a1.fp.write(str(a0.value))
                returnval = a0
            else:
                simstate.add_logmsg(
                    "warning",
                    self.name + ": " + str(a1) + " is not a file-pointer")
                returnval = SV.mk_simvalue(-1)
        else:
            returnval = SV.mk_simvalue(-1)
        simstate.set_register(iaddr, "v0", returnval)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_fputs(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fputs')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const char *restrict s
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # FILE *restrict stream
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        if simstate.simsupport.file_operations_enabled:
            if a1.is_file_pointer:
                a1 = cast(SSV.SimSymbolicFilePointer, a1)
                print("fputs: write to " + str(a1) + ": " + a0str)
                a1.fp.write(a0str)
                returnval = 1
            else:
                simstate.add_logmsg(
                    "warning",
                    self.name + ": " + str(a1) + " is not a file-pointer")
                returnval = -1
        else:
            returnval = -1
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(returnval))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_fileno(MIPSimStub):
    """map a stream pointer to a file descriptor."""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "fileno")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns a symbolic value in v0"""

        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        if a0.is_symbolic:
            a0 = cast(SSV.SimSymbol, a0)
            if a0.is_file_pointer:
                a0 = cast(SSV.SimSymbolicFilePointer, a0)
                fpresult = SFU.sim_fileno(a0)
                simstate.set_register(iaddr, "v0", fpresult)
                returnval = str(fpresult)
            elif a0.is_symbol:
                a0 = cast(SSV.SimSymbol, a0)
                symresult = SSV.SimSymbol(a0.name + '_fildes')
                simstate.set_register(iaddr, "v0", symresult)
                returnval = str(symresult)
            else:
                simstate.set_register(iaddr, "v0", SV.SimDoubleWordValue(-1))
                returnval = "-1"
        else:
            simstate.set_register(iaddr, "v0", SV.SimDoubleWordValue(-1))
            returnval = "-1"
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=returnval)


class MIPStub_fopen(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fopen')

    def is_io_operation(self) -> bool:
        return True

    def simulate_failure(
            self,
            iaddr: str,
            simstate: "SimulationState",
            pargs: str,
            comment: str = "") -> str:
        returnval = SV.simZero
        simstate.set_register(iaddr, 'v0', returnval)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o; returns 0 in v0."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")   # const char *restrict pathname
        a1 = self.get_arg_val(iaddr, simstate, "a1")   # const char *restrict mode
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = (
            ",".join(str(a) + ':' + str(s)
                     for (a, s) in [(a0, a0str), (a1, a1str)]))

        if simstate.simsupport.file_operations_enabled:
            if SFU.sim_file_exists(a0str) or a1str.startswith("w"):
                fp = SFU.sim_openfile(a0str, a1str)
                simstate.set_register(iaddr, "v0", fp)
                return self.add_logmsg(
                    iaddr, simstate, pargs, returnval=str(fp))
            else:
                return self.simulate_failure(iaddr, simstate, pargs, "file not found")
        else:
            return self.simulate_failure(iaddr, simstate, pargs)


class MIPStub_fopen64(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fopen64')

    def is_io_operation(self) -> bool:
        return True

    def simulate_failure(
            self,
            iaddr: str,
            simstate: "SimulationState",
            pargs: str,
            comment: str = "") -> str:
        returnval = SV.simZero
        simstate.set_register(iaddr, 'v0', returnval)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o; returns 0 in v0."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")   # const char *restrict pathname
        a1 = self.get_arg_val(iaddr, simstate, "a1")   # const char *restrict mode
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = (
            ",".join(str(a) + ':' + str(s)
                     for (a, s) in [(a0, a0str), (a1, a1str)]))

        if simstate.simsupport.file_operations_enabled:
            if SFU.sim_file_exists(a0str) or a1str.startswith("w"):
                fp = SFU.sim_openfile(a0str, a1str)
                simstate.set_register(iaddr, "v0", fp)
                return self.add_logmsg(
                    iaddr, simstate, pargs, returnval=str(fp))
            else:
                return self.simulate_failure(iaddr, simstate, pargs, "file not found")
        else:
            return self.simulate_failure(iaddr, simstate, pargs)


class MIPStub_freeaddrinfo(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'freeaddrinfo')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_fscanf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fscanf')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        result = -1
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_fstat(MIPSimStub):
    """Partially fills in the file information in the provided buffer.

    Currently only the file size is set at offset 52.

    From MIPS ABI supplement:

    struct stat {
      dev_t         st_dev;                 0
      long          st_pad1[3];             4
      ino_t         st_ino;                 16
      mode_t        st_mode;
      nlink_t       st_nlink;
      uid_t         st_uid;                 32
      gid_t         st_gid;                 36
      dev_t         st_rdev;                40
      long          st_pad2[2];             44
      off_t         st_size;                52
      long          st_pad3;                56
      timestruc_t   st_atim;
      timestruc_t   st_mtim;
      timestruc_t   st_ctim;
      long          st_blksize;
      long          st_blocks;
      char          st_fstype[_ST_FSTYPSZ];
      long          st_pad4[8];
    }
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "fstat")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int fildes
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # struct stat *buf
        pargs = str(a0) + ", " + str(a1)

        if a0.is_undefined or a1.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "fstat: some arguments are undefined: " + pargs)

        if a1.is_address:
            buf = cast(SSV.SimAddress, a1)
        elif a1.is_literal:
            buf = simstate.resolve_literal_address(iaddr, a1.literal_value)
            if buf.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "fstat: address of buf cannot be resolved: " + str(a1))
            pargs = str(a0) + ", " + str(buf)

        if a0.is_file_descriptor:
            a0 = cast(SSV.SimSymbolicFileDescriptor, a0)
            fd = a0.filedescriptor
            fdstat = os.stat(a0.filename)
            simstate.set_memval(
                iaddr, buf.add_offset(52), SV.mk_simvalue(fdstat.st_size))
            result = 0
        else:
            result = -1

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_fstat64(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fstat64')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_fwrite(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fwrite')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o, returns 1 in v0 for now."""

        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        simstate.set_register(iaddr, 'v0', SV.simOne)
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])
        return self.add_logmsg(iaddr, simstate, pargs, returnval='1')


class MIPStub_fread(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fread')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # void *restrict ptr
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # size_t size
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # size_t nitems
        a3 = self.get_arg_val(iaddr, simstate, "a3")  # FILE *restrict stream
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])
        if (
                a0.is_undefined
                or a1.is_undefined
                or a2.is_undefined
                or a3.is_undefined):
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "some arguments to fread are undefined")

        if a0.is_address:
            ptr = cast(SSV.SimAddress, a0)
        elif a0.is_literal:
            ptr = simstate.resolve_literal_address(iaddr, a0.literal_value)
            if ptr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "fread: dstaddr: " + str(a0) + " cannot be resolved")

        if a3.is_file_pointer:
            fp = cast(SSV.SimSymbolicFilePointer, a3).fp
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "fread: stream: " + str(a3) + " is not a file pointer")

        if a1.is_literal:
            size = a1.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "fread: size: " + str(a1) + " is not a literal value")

        if a2.is_literal:
            nitems = a2.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "fread: nitems: " + str(a2) + " is not a literal value")

        for i in range(0, size * nitems):
            c = fp.read(1)
            simstate.set_memval(iaddr, ptr.add_offset(i), SV.mk_simcharvalue(c))
        returnval = size * nitems
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(returnval))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_free(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'free')

    def is_memalloc_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_fork(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'fork')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        if iaddr in simstate.simsupport.forkchoices:
            result = simstate.simsupport.forkchoices[iaddr]
        else:
            result = 0
        simresult = SV.mk_simvalue(result)
        simstate.set_register(iaddr, 'v0', simresult)
        return self.add_logmsg(iaddr, simstate, '', returnval=str(result))


class MIPStub_fprintf(MIPSimStub):
    """int fprintf(FILE *restrict stream, const char *restrict format, ...);"""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "fprintf")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # FILE *restrict stream
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const char *restrict format
        fmtstring = self.get_arg_string(iaddr, simstate, "a1")
        (printstring, varargs) = self.substitute_formatstring(iaddr, simstate, 1)
        if simstate.simsupport.file_operations_enabled:
            if a0.is_file_pointer:
                a0 = cast(SSV.SimSymbolicFilePointer, a0)
                a0.fp.write(printstring)
                returnval = len(printstring)
            else:
                returnval = -1
        else:
            returnval = -1
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(returnval))
        pargs = str(a0) + ',' + str(a1) + ':' + fmtstring + " -> " + printstring
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_getaddrinfo(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getaddrinfo')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        # a0str = self.get_arg_string(iaddr, simstate,'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        if a3.is_address:
            a3 = cast(SSV.SimAddress, a3)
            simstate.set_memval(iaddr, a3, a2)
        else:
            simstate.add_logmsg(iaddr, "Not able to set side effect of getaddrinfo")
        pargs = (
            str(a0) + ',' + str(a1) + ':' + a1str + ',' + str(a2) + ',' + str(a3))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_get_current_dir_name(MIPSimStub):
    """Allocates memory on the heap to hold the absolute path name.

    Doc: https://man7.org/linux/man-pages/man3/getcwd.3.html

    get_current_dir_name() will malloc(3) an array big enough to hold
       the absolute pathname of the current working directory.  If the
       environment variable PWD is set, and its value is correct, then
       that value will be returned.  The caller should free(3) the
       returned buffer.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "get_current_dir_name")

    def is_memalloc_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        cwd = simstate.simsupport.cwd()
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        pargs = str(a0) + ", " + str(a1)
        if a0.is_literal and a0.is_defined and a1.is_literal and a1.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            a1 = cast(SV.SimLiteralValue, a1)
            if a0.value == 0 and a1.value == 0:
                base = "get_current_dir_name_" + iaddr
                buffersize = len(cwd) + 1
                address = SSV.mk_base_address(base, 0, buffersize=buffersize)
                for i in range(0, buffersize - 1):
                    tgtaddr = address.add_offset(i)
                    simstate.set_memval(iaddr, tgtaddr, SV.mk_simcharvalue(cwd[i]))
                simstate.set_memval(iaddr, address.add_offset(len(cwd)), SV.simZerobyte)
                simstate.set_register(iaddr, "v0", address)
                returnval: str = str(address)
            else:
                simstate.set_register(iaddr, "v0", SV.simZero)
                returnval = "0"
        else:
            simstate.set_register(iaddr, "v0", SV.simZero)
            returnval = "0"
        return self.add_logmsg(iaddr, simstate, pargs, returnval=returnval)


class MIPStub_getcwd(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getcwd')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        cwd = simstate.simsupport.cwd()
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        if a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            i = 0
            for c in cwd:
                simstate.set_memval(
                    iaddr, a0.add_offset(i), SV.mk_simbytevalue(ord(c)))
                i += 1
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', a0)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(a0))


class MIPStub_getenv(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "getenv")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site: str) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def is_environment_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs getenv request, returns environment variable from simstate."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        if simstate.simsupport.has_environment_variable(a0str):
            envvalue = simstate.simsupport.get_environment_variable(a0str)
            base = "getenv:" + a0str
            result: SV.SimValue = SSV.mk_string_address(base, envvalue)
            envmsg = "retrieved: " + str(result) + " for " + a0str
        else:
            result = SV.simZero
            envmsg = "no environment value found for " + a0str
        simstate.set_register(iaddr, "v0", result)
        simstate.add_logmsg("getenv", envmsg)
        pargs = str(a0) + ":" + a0str
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_gethostname(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'gethostname')

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        pargs = ','.join(str(a) for a in [a0, a1])
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_getline(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "getline")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1deref = self.get_arg_deref_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        pargs = str(a0) + "," + str(a1) + ":" + str(a1deref) + "," + str(a2)
        if a2.is_file_pointer and a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            a2 = cast(SSV.SimSymbolicFilePointer, a2)
            line = a2.fp.readline()
            result = len(line)
            if result > 0:
                site = "getline_" + iaddr
                base = site + ":" + str(self.sitecounter(site))
                sval = SSV.mk_string_address(base, line)
                simstate.set_memval(iaddr, a0, sval)
                simstate.add_logmsg(
                    "i/o", "Read line: " + line + " from " + str(a2))
            else:
                simstate.add_logmsg("i/o", "Reached eof of " + str(a2))
                result = -1
        else:
            simstate.add_logmsg("i/o", "No input read from " + str(a2))
            result = -1
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_getopt(MIPSimStub):
    """int getopt(int argc, char * const argv[], const char *optstring);

    This stub depends on the address where optarg is stored. This address should
    be set in the simsupport module.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getopt')
        self.optarg = SV.simZero
        self.optind = 1  # keeps track of the current option
        self.optopt: SV.SimValue = SV.simZero  # points to current cmdline argument
        self._sitecounters: Dict[str, int] = {}

    def is_io_operation(self) -> bool:
        return True

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site: str) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def has_argument(self, cmdstr: str, c: str) -> bool:
        cindex = cmdstr.find(c)
        if cindex < 0:
            return False
        else:
            return cmdstr[cindex+1] == ':'

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")   # int argc
        a1 = self.get_arg_val(iaddr, simstate, "a1")   # char *const argv[]
        a2 = self.get_arg_val(iaddr, simstate, "a2")   # const char *optstring
        a2str = self.get_arg_string(iaddr, simstate, "a2")
        pargs = ','.join(str(a) for a in [a0, a1]) + ',' + str(a2) + ':' + a2str

        result: int = -1
        optargaddr = simstate.simsupport.optargaddr

        # optargstate is an alternative address through which uclibc seems
        # to pass the current option back to the caller (as inferred from
        # observed program behavior)
        optargstate = simstate.simsupport.optargstate

        if not optargaddr.is_address:
            simstate.add_logmsg(
                "warning", "getopt: optargaddress has not been set")
            simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
            return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))
        else:
            optargaddr = cast(SSV.SimAddress, optargaddr)

        if optargstate.is_address:
            optargstate = cast(SSV.SimAddress, optargstate)

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "some arguments to getopt are undefined: " + pargs)

        if not a0.is_literal:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "getopt: expected a0 to be a literal: " + str(a0))
        else:
            argc = a0.literal_value

        if not a1.is_address:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "getopt: expected a1 to be an address: " + str(a1))
        else:
            argv = cast(SSV.SimAddress, a1)

        if not a2.is_address:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "getopt: expected a2 to be an address: " + str(a2))
        else:
            optstring = a2str

        if self.optind >= argc:  # no more arguments to process
            simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
            return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))

        # more arguments to process
        print("getopt. optind: " + str(self.optind) + "; argc: " + str(argc))
        argaddr = argv.add_offset(self.optind * 4)
        print("argaddr: " + str(argaddr))
        self.optopt = simstate.memval(iaddr, argaddr, 4)
        if self.optopt.is_address:
            option = self.get_string_at_address(iaddr, simstate, self.optopt)
            print("option: " + str(option) + "(" + str(len(option)) + ")")
            if option.startswith("-") and len(option) == 2:
                option = option[1]
                print("option: " + str(option))
                if self.has_argument(a2str, option):
                    self.optind += 1
                    argvaladdr = argv.add_offset(self.optind * 4)
                    nextargaddr = simstate.memval(iaddr, argvaladdr, 4)
                    if nextargaddr.is_address:
                        nextarg = self.get_string_at_address(
                            iaddr, simstate, nextargaddr)

                        if nextarg.startswith("-"):
                            site = "getopt_" + iaddr
                            base = site + ":" + str(self.sitecounter(site))
                            emptyarg = SSV.mk_string_address(base, ":")
                            simstate.set_memval(iaddr, optargaddr, emptyarg)
                        else:
                            simstate.set_memval(iaddr, optargaddr, argvaladdr)
                            self.optind += 1
                    else:
                        simstate.add_logmsg(
                            "warning",
                            "getopt: nextarg is not an address")
                else:  # there is no argument
                    self.optind += 1
                result = ord(option)
                if optargstate.is_address:
                    optargstate = cast("SSV.SimAddress", optargstate)
                    optionval = SV.mk_simvalue(ord(option) - 65)
                    simstate.set_memval(iaddr, optargstate, optionval)

            else:  # option does not start with "-"
                pass
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "getopt: optopt is not an address: " + str(self.optopt))

        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_getopt_long(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getopt_long')
        self.optarg: SV.SimValue = SV.simZero
        self.optind = 1
        self.optopt: SV.SimValue = SV.simZero

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o, returns -1 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a2str = self.get_arg_string(iaddr, simstate, 'a2')
        if a0.is_literal and a0.is_defined and a1.is_address:
            a0 = cast(SV.SimLiteralValue, a0)
            a1 = cast(SSV.SimAddress, a1)
            if self.optind < a0.value:
                argaddr = a1.add_offset(self.optind * 4)
                self.optopt = simstate.memval(iaddr, argaddr, 4)
                if self.optopt.is_string_address:
                    self.optopt = cast(SSV.SimStringAddress, self.optopt)
                    if self.optopt.stringval.startswith('-'):
                        result = ord(self.optopt.stringval[1])
                        self.optind += 1
                    else:
                        result = -1
                else:
                    result = -1
            else:
                result = -1
        else:
            result = -1
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        pargs = ','.join(str(a) for a in [a0, a1]) + ',' + str(a0) + ':' + a2str
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_getpeername(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getpeername')

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval='0')


class MIPStub_getpid(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "getpid")

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, "")


class MIPStub_getpwnam(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "getpwnam")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, "v0", SV.simZero)
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        return self.add_logmsg(iaddr, simstate, a0str, returnval="0")


class MIPStub_getpwuid(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "getpwuid")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, "v0", SV.simZero)
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        return self.add_logmsg(iaddr, simstate, str(a0), returnval="0")


class MIPStub_getrlimit64(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getrlimit64')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            simstate.set_memval(iaddr, a1, SV.simZero)
            simstate.set_memval(iaddr, a1.add_offset(4), SV.simZero)
            simstate.set_memval(iaddr, a1.add_offset(8), SV.simZero)
            simstate.set_memval(iaddr, a1.add_offset(12), SV.simZero)
        pargs = str(a0) + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_getsockname(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getsockname')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simNegOne)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_gettimeofday(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'gettimeofday')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        t = int(time.time())
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        if a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            simstate.set_memval(iaddr, a0, SV.mk_simvalue(t))
            simstate.set_memval(iaddr, a0.add_offset(4), SV.simZero)
            # simstate.set_memval(iaddr, a0.add_offset(8), SV.simZero)
            # simstate.set_memval(iaddr, a0.add_offset(12), SV.simZero)
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_getuid(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'getuid')

    def get_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_gmtime(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "gmtime")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        base = "gmtime_"
        address = SSV.mk_base_address(base, 0, buffersize=36)
        t = time.gmtime()
        print("time: " + str(t))

        def set_tm(off, tmval):
            simstate.set_memval(
                iaddr, address.add_offset(off), SV.mk_simvalue(tmval))

        set_tm(0, t.tm_sec)
        set_tm(4, t.tm_min)
        set_tm(8, t.tm_hour)
        set_tm(12, t.tm_mday)
        set_tm(16, t.tm_mon)
        set_tm(20, t.tm_year)
        set_tm(24, t.tm_wday)
        set_tm(28, t.tm_yday)
        set_tm(32, t.tm_isdst)
        simstate.set_register(iaddr, "v0", address)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_index(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'index')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        if a1.is_literal and a1.is_defined:
            a1 = cast(SV.SimLiteralValue, a1)
            a1value = str(chr(a1.value))
        else:
            a1value = "?"
        pargs = str(a0) + ':' + a0str + ',' + str(a1) + ' {' + a1value + '}'
        index = a0str.find(a1value)
        if index >= 0 and a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            result: SV.SimValue = a0.add_offset(index)
        else:
            result = SV.simZero
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_inet_addr(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'inet_addr')

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        result = int(ipaddress.IPv4Address(a0str))
        xresult = SV.mk_simvalue(result)
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr, 'v0', xresult)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(xresult))


class MIPStub_inet_aton(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'inet_aton')

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns 0 by default."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_inet_ntoa(MIPSimStub):
    """char *inet_ntoa(struct in_addr in);

    Returns a pointer to the network address in internet standard notation.
    The return value may point to static data that may be overwritten by
    subsequent calls to inet_ntoa().
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "inet_ntoa")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site: str) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        site = "inet_ntoa_" + iaddr
        base = site + ":" + str(self.sitecounter(site))
        result = SSV.mk_string_address(base, "0.0.0.0")
        simstate.set_register(iaddr, "v0", result)
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(result))


class MIPStub_inet_pton(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'inet_pton')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Fails by default."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        pargs = str(a0) + ',' + str(a1) + ':' + a1str + ',' + str(a2)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_ioctl(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'ioctl')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns 0 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_isatty(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "isatty")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        simstate.set_register(iaddr, "v0", SV.simOne)
        return self.add_logmsg(iaddr, simstate, str(a0), returnval="1")


class MIPStub___libc_current_sigrtmax(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, '__libc_current_sigrtmax')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub___libc_current_sigrtmin(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, '__libc_current_sigrtmin')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_listen(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'listen')

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_localtime(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'localtime')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        base = 'localtime_'
        address = SSV.mk_base_address(base, 0, buffersize=36)
        t = time.localtime()
        print('time: ' + str(t))

        def set_tm(off, tmval):
            simstate.set_memval(
                iaddr, address.add_offset(off), SV.mk_simvalue(tmval))

        set_tm(0, t.tm_sec)
        set_tm(4, t.tm_min)
        set_tm(8, t.tm_hour)
        set_tm(12, t.tm_mday)
        set_tm(16, t.tm_mon)
        set_tm(20, t.tm_year)
        set_tm(24, t.tm_wday)
        set_tm(28, t.tm_yday)
        set_tm(32, t.tm_isdst)
        simstate.set_register(iaddr, 'v0', address)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_lockf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'lockf')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_longjmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'longjmp')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', a1)
        if a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            newpc = simstate.memval(iaddr, a0, 4)
            newsp = simstate.memval(iaddr, a0.add_offset(4), 4)
            newra = simstate.memval(iaddr, a0.add_offset(8), 4)
            context = simstate.memval(iaddr, a0.add_offset(12), 4)
            if context.is_string_address:
                context = cast(SSV.SimStringAddress, context)
                contextstr = context.stringval
            else:
                contextstr = "?"
            simstate.set_register(iaddr, 'sp', newsp)
            simstate.set_register(iaddr, 'ra', newra)
            # simstate.restore_context(contextstr)
            if newpc.is_address:
                newpc = cast(SSV.SimAddress, newpc)
                if newpc.is_global_address:
                    newpc = cast(SSV.SimGlobalAddress, newpc)
                    simstate.set_programcounter(newpc)
                    return self.add_logmsg(
                        iaddr,
                        simstate,
                        pargs,
                        returnval=(
                            str(a1) + ' (jmpaddr:' + str(newpc)
                            + '; sp:' + str(newsp)
                            + '; ra:' + str(newra) + ')'))
                else:
                    return "newpc is not a global address: " + str(newpc)
            else:
                return "newpc is not an address: " + str(newpc)
        else:
            return "longjmp: argument is not an address: " + str(a0)


class MIPStub_malloc(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'malloc')
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site: str) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def is_memalloc_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns a symbolic address to a heap buffer in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        site = "malloc_" + iaddr
        base = site + ":" + str(self.sitecounter(site))
        if a0.is_defined and a0.is_literal:
            buffersize: Optional[int] = a0.literal_value
        else:
            buffersize = None
        address = SSV.mk_base_address(base, 0, buffersize=buffersize)
        simstate.basemem[base] = SimBaseMemory(
            simstate, base, buffersize=buffersize)
        simstate.set_register(iaddr, 'v0', address)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_mallopt(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "mallopt")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        pargs = str(a0) + ", " + str(a1)
        simstate.set_register(iaddr, "v0", SV.simOne)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="1")


class MIPStub_memcmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'memcmp')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const void *s1
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const void *s2
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # size_t n
        pargs = ", ".join(str(a) for a in [a0, a1, a2])

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcmp: some arguments are undefined: " + pargs)

        if a2.is_literal:
            n = a2.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcmp: size argument is not a literal value: " + str(a2))

        if a0.is_address:
            s1addr = cast(SSV.SimAddress, a0)
        elif a0.is_literal:
            s1addr = simstate.resolve_literal_address(iaddr, a0.literal_value)
            if s1addr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "memcmp: address of s1 cannot be resolved: " + str(a0))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcmp: invalid address for s1: " + str(a0))

        parg0 = str(s1addr)
        s1 = []
        for i in range(0, n):
            addr = s1addr.add_offset(i)
            s1val = simstate.memval(iaddr, addr, 1)
            if s1val.is_defined and s1val.is_literal:
                s1.append(s1val.literal_value)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "memcmp: value for comparison in s1 at i="
                    + str(i)
                    + " is undefined")

        if a1.is_address:
            s2addr = cast(SSV.SimAddress, a1)
        elif a1.is_literal:
            s2addr = simstate.resolve_literal_address(iaddr, a1.literal_value)
            if s2addr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "memcmp: address of s2 cannot be resolved: " + str(a1))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcmp: invalid address for s2: " + str(a1))

        parg1 = str(s2addr)
        s2 = []
        for i in range(0, n):
            addr = s2addr.add_offset(i)
            s2val = simstate.memval(iaddr, addr, 1)
            if s2val.is_defined and s2val.is_literal:
                s2.append(s2val.literal_value)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "memcmp: value for comparison in s2 at i="
                    + str(i)
                    + " is undefined")

        for i in range(0, n):
            if s1[i] < s2[i]:
                result = -1
                break
            elif s1[i] > s2[i]:
                result = 1
                break
        else:
            result = 0

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_memcpy(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'memcpy')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Copies count bytes from src to dst; returns a0 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # dst
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # src
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # count
        pargs = ", ".join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, "v0", a0)

        if (a0.is_undefined or a1.is_undefined or a2.is_undefined):
            simstate.add_logmsg(
                "warning",
                iaddr + ": memcpy: some arguments are undefined; nothing copied")
            simstate.set_register
            return self.add_logmsg(
                iaddr, simstate, pargs, returnval="nothing copied")

        if a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)

        elif a0.is_literal:
            dstaddr = cast(
                SSV.SimAddress,
                simstate.resolve_literal_address(iaddr, a0.literal_value))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcpy: destination is not a valid address: " + str(a0))

        if a1.is_address:
            srcaddr = a1

        elif a1.is_literal:
            srcaddr = cast(
                SV.SimValue,
                simstate.resolve_literal_address(iaddr, a1.literal_value))
        else:
            srcaddr = a1

        if not srcaddr.is_address:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcpy: source is not a valid address: " + str(a1))

        if a2.is_literal:
            count = a2.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "memcpy: count is not a literal: " + str(a2))

        srcaddr = cast(SSV.SimAddress, srcaddr)
        for i in range(0, count):
            srcval = cast(
                SV.SimByteValue, simstate.memval(
                    iaddr, srcaddr.add_offset(i), 1))
            tgtaddr = dstaddr.add_offset(i)
            simstate.set_memval(iaddr, tgtaddr, srcval)

        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_memmove(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'memmove')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Copies count bytes from src to dst; returns a0 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')  # dst
        a1 = self.get_arg_val(iaddr, simstate, 'a1')  # src
        a2 = self.get_arg_val(iaddr, simstate, 'a2')  # count
        if a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)
        elif a0.is_literal and a0.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            raise SU.CHBSimError(
                simstate,
                iaddr,
                'memmove: illegal destination address: ' + str(a0))

        if a2.is_defined and a2.is_literal:
            a2 = cast(SV.SimLiteralValue, a2)
            if a1.is_literal and a1.is_defined:
                a1 = cast(SV.SimLiteralValue, a1)
                raise UF.CHBError("Illegal address in memmove: " + str(a1))

            elif a1.is_address:
                a1 = cast(SSV.SimAddress, a1)
                for i in range(0, a2.value):
                    srcaddr = a1.add_offset(i)
                    srcval = simstate.memval(iaddr, srcaddr, 1)
                    tgtaddr = dstaddr.add_offset(i)
                    simstate.set_memval(iaddr, tgtaddr, srcval)
            else:
                raise UF.CHBError("Illegal address in memmove: " + str(a1))
        else:
            raise UF.CHBError("Length not known in memmove: " + str(a2))
        simstate.set_register(iaddr, 'v0', dstaddr)
        pargs = ','.join(str(a) for a in [dstaddr, a1, a2])
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_memset(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'memset')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Sets count bytes in dst to char. returns a0 in v0"""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')   # dst
        a1 = self.get_arg_val(iaddr, simstate, 'a1')   # char
        a2 = self.get_arg_val(iaddr, simstate, 'a2')   # count
        pargs = ','.join(str(a) for a in [a0, a1, a2])

        def result(returnval: SV.SimValue) -> str:
            simstate.set_register(iaddr, "v0", returnval)
            return self.add_logmsg(
                iaddr, simstate, pargs, returnval=str(returnval))

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            simstate.add_logmsg(
                "warning",
                iaddr + ": Unable to perform memset; some value is undefined")
            return result(SV.simUndefinedDW)

        if a0.is_address and a1.is_literal and a2.is_literal:
            a0 = cast(SSV.SimAddress, a0)
            a1byte = SV.mk_simvalue(a1.literal_value, size=1)
            for i in range(0, a2.literal_value):
                address = a0.add_offset(i)
                simstate.set_memval(iaddr, address, a1byte)
            return result(a0)

        simstate.add_logmsg("warning", iaddr + ": Unable to perform memset")
        return result(SV.simUndefinedDW)


class MIPStub_mkdir(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'mkdir')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const char *path
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # mode_t mode
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        if simstate.simsupport.file_operations_enabled:
            result = SFU.sim_mkdir(a0str)
            if result == 0:
                simstate.trace.add("mkdir: " + a0str + " successfully created")
            else:
                simstate.trace.add("mkdir: " + a0str + " failed")
        else:
            result = -1
            simstate.trace.add("mkdir: " + a0str + " not attempted")
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_mktemp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'mktemp')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr, 'v0', a0)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_msgget(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'msgget')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_mmap(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'mmap')

    def is_process_operation(self) -> bool:
        return True

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # void *addr
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # size_t len
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # int prot
        a3 = self.get_arg_val(iaddr, simstate, "a3")  # int flags
        a4 = self.get_stack_arg_val(iaddr, simstate, 4)  # int fildes
        a5 = self.get_stack_arg_val(iaddr, simstate, 5)  # off_t off
        base = "mmap_" + iaddr
        if a1.is_literal and a1.is_defined and a5.is_literal and a5.is_defined:
            a1 = cast(SV.SimLiteralValue, a1)
            a5 = cast(SV.SimLiteralValue, a5)
            address = SSV.mk_mapped_address(base, a5.value, a1.value)
            simstate.mappedmem[base] = SimMappedMemory(
                simstate, base, buffersize=a1.value, offset=a5.value)
            simstate.set_register(iaddr, "v0", address)
            returnval = str(address)
        else:
            simstate.set_register(iaddr, "v0", SV.mk_simvalue(-1))
            returnval = "-1"
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3, a4, a5])
        return self.add_logmsg(iaddr, simstate, pargs, returnval=returnval)


class MIPStub_open(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'open')

    def is_io_operation(self) -> bool:
        return True

    def simulate_failure(
            self,
            filename: str,
            iaddr: str,
            simstate: "SimulationState",
            pargs: str,
            comment: str = "") -> str:
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(-1))
        simstate.add_logmsg(
            "warning", "File " + filename + " was not opened (" + comment + ")")
        return self.add_logmsg(iaddr, simstate, pargs, returnval="-1")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")   # const char *path
        a1 = self.get_arg_val(iaddr, simstate, "a1")   # int oflag
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ":" + a0str + "," + str(a1)

        if simstate.simsupport.file_operations_enabled:
            if a1.is_literal:
                a1 = cast(SV.SimLiteralValue, a1)
                if SFU.sim_file_exists(a0str) or hex(a1.value) == "0x301":
                    fd = SFU.sim_openfile_fd(a0str, "w")
                    simstate.set_register(iaddr, "v0", fd)
                    return self.add_logmsg(
                        iaddr, simstate, pargs, returnval=str(fd))
                else:
                    return self.simulate_failure(
                        iaddr, a0str, simstate, pargs, "file not found")
            else:
                return self.simulate_failure(
                    a0str, iaddr, simstate, pargs, "file operations not enabled")
        else:
            return self.simulate_failure(
                a0str, iaddr, simstate, pargs, "unable to read oflag")
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(-1))
        simstate.add_logmsg("warning", "File " + a0str + " was not opened")
        return self.add_logmsg(iaddr, simstate, pargs, returnval="-1")


class MIPStub_open64(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'open64')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_openlog(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'openlog')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.add_logmsg('i/o', self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pclose(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pclose')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simNegOne)
        simstate.add_logmsg('i/o', self.name + '(' + str(a0) + ')')
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_perror(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'perror')

    def is_error_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + a0str
        simstate.add_logmsg('error', self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_popen(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'popen')

    def is_io_operation(self) -> bool:
        return True

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1) + ':' + a1str
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_printf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'printf')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o; returns 1 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simOne)
        pargs = str(a0) + ':' + a0str
        if '%s' in a0str:
            a1 = self.get_arg_val(iaddr, simstate, 'a1')
            a1str = self.get_arg_string(iaddr, simstate, 'a1')
            pargs += ',' + str(a1) + ':' + a1str
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub__setjmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, '_setjmp')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        setval = SSV.mk_global_address(int(iaddr, 16) + 4, simstate.modulename)
        if a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            simstate.set_memval(iaddr, a0, setval)
            simstate.set_memval(iaddr, a0.add_offset(4), simstate.registers['sp'])
            simstate.set_memval(iaddr, a0.add_offset(8), simstate.registers['ra'])
            # simstate.set_memval(
            #    iaddr,
            #    a0.add_offset(12),
            #    SSV.SimStringAddress(simstate.context.peek()))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Illegal address in setjmp: " + str(a0))
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_setlogmask(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'setlogmask')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_setrlimit(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'setrlimit')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_setrlimit64(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'setrlimit64')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_setsid(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "setsid")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, "v0", SV.simOne)
        return self.add_logmsg(iaddr, simstate, "", returnval="1")


class MIPStub_setsockopt(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'setsockopt')

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        a4 = self.get_stack_arg_val(iaddr, simstate, 4)
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3, a4])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_shmat(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "shmat")

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int shmid
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const void *shmaddr
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # int shmflg
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        if (
                a0.is_defined
                and a1.is_defined
                and a2.is_defined
                and a0.is_literal
                and a1.is_literal
                and a2.is_literal):
            addrval = a1.literal_value
            shmid = a0.literal_value
            memname = "shared:" + str(shmid)
            if addrval == 0:
                addr = cast(SSV.SimGlobalAddress, SSV.nullpointer)
            else:
                addr = SSV.mk_global_address(addrval, memname)

            result = simstate.simsupport.sharedmem_shmat(
                iaddr, simstate, a0.literal_value, addr, a2.literal_value)
        else:
            result = SSV.mk_undefined_global_address(memname)

        if result.is_defined and shmid in simstate.sharedmem:
            simstate.sharedmem[shmid].set_baseoffset(result.literal_value)
        else:
            simstate.add_logmsg(
                "warning",
                iaddr
                + ": attaching shared memory for shmid="
                + str(a0.literal_value)
                + " failure")

        simstate.set_register(iaddr, "v0", result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_shmctl(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "shmctl")

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int shmid
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # int cmd
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # struct shmid_ds *buf
        pargs = ",".join(str(a) for a in [a0, a1, a2])
        if (
                a0.is_defined
                and a1.is_defined
                and a2.is_defined
                and a0.is_literal
                and a1.is_literal
                and a2.is_address):
            a2 = cast(SSV.SimAddress, a2)
            returnval = simstate.simsupport.sharedmem_shmctl(
                iaddr, simstate, a0.literal_value, a1.literal_value, a2)
        else:
            returnval = -1
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(returnval))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_shmdt(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "shmdt")

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const void *shmaddr
        if a0.is_defined and a0.is_global_address:
            a0 = cast(SSV.SimGlobalAddress, a0)
            returnval = simstate.simsupport.sharedmem_shmdt(
                iaddr, simstate, a0)
        else:
            returnval = -1
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(returnval))
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(returnval))


class MIPStub_shmget(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'shmget')
        self.counter = 0

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")   # key_t key
        a1 = self.get_arg_val(iaddr, simstate, "a1")   # size_t size
        a2 = self.get_arg_val(iaddr, simstate, "a2")   # int shmflg
        pargs = ",".join(str(a) for a in [a0, a1, a2])
        if (
                a0.is_defined
                and a1.is_defined
                and a2.is_defined
                and a0.is_literal
                and a1.is_literal
                and a2.is_literal):
            shmid = simstate.simsupport.sharedmem_shmget(
                iaddr, simstate, a0.literal_value, a1.literal_value, a2.literal_value)
            if shmid in simstate.sharedmem:
                simstate.add_logmsg(
                    "warning",
                    iaddr
                    + ": Shared memory already exists for shmid="
                    + str(shmid))
            else:
                simstate.sharedmem[shmid] = SimSharedMemory(
                    simstate, shmid, hex(a0.literal_value), a1.literal_value)
        else:
            shmid = -1
            simstate.add_logmsg(
                "warning", iaddr + ": Attempt to gain access to shared memory failed")
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(shmid))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(shmid))


class MIPStub_sigaction(MIPSimStub):

    def __init__(self, name: str = 'sigaction') -> None:
        MIPSimStub.__init__(self, name)

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_sigaddset(MIPSimStub):

    def __init__(self, name: str = 'sigaddset'):
        MIPSimStub.__init__(self, name)

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = '.'.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_sigemptyset(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sigemptyset')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_signal(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'signal')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_sigprocmask(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sigprocmask')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_sleep(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sleep')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_socket(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'socket')

    def is_network_operation(self) -> bool:
        return True

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns a symbolic value in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        # returnval = SSV.mk_symbol('socket-fd',minval=0)
        returnval = SV.mk_simvalue(113)    # notable, recognizable value
        simstate.set_register(iaddr, 'v0', returnval)
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pthread_cond_init(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_cond_init')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pthread_cond_signal(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_cond_signal')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_pthread_create(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_create')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pthread_attr_init(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_attr_init')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_pthread_attr_setschedparam(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_attr_setschedparam')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pthread_attr_setschedpolicy(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_attr_setschedpolicy')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pthread_mutex_init(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_mutex_init')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) for a in [a0, a1])
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_pthread_mutex_lock(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_mutex_lock')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_pthread_mutex_unlock(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_mutex_unlock')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_pthread_self(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'pthread_self')

    def is_thread_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_putenv(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "putenv")

    def is_environment_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ":" + a0str
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_puts(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'puts')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_rand(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'rand')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(0x4321))
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_random(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'random')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(0x87654321))
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_read(MIPSimStub):
    """ssize_t read(int fildes, void *buf, size_t nbyte)"""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'read')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1v = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        if a1v.is_literal and a1v.is_defined:
            a1v = cast(SV.SimLiteralValue, a1v)
            a1 = SSV.mk_global_address(a1v.value, simstate.modulename)
        if (
                a0.is_literal
                and a0.is_defined
                and a1.is_address
                and a2.is_literal
                and a2.is_defined):
            a2 = cast(SV.SimLiteralValue, a2)
            a0 = cast(SV.SimLiteralValue, a0)
            inputbytes = simstate.simsupport.read_input(
                iaddr, a0.value, a1, a2.value)
            pargs = ','.join(str(a) for a in [a0, a1, a2])
            if len(inputbytes) > 0:
                for i in range(0, len(inputbytes)):
                    tgtaddr = a1.add_offset(i)
                    simstate.set_memval(
                        iaddr, tgtaddr, SV.mk_simbytevalue(inputbytes[i]))
            result = SV.mk_simvalue(len(inputbytes))
            simstate.set_register(iaddr, 'v0', result)
            return self.add_logmsg(
                iaddr, simstate, pargs, returnval=str(result))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Illegal address in read: " + str(a1v))


class MIPStub_realloc(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'realloc')

    def is_memalloc_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        base = 'realloc_' + iaddr
        if a1.is_literal and a1.is_defined:
            a1 = cast(SV.SimLiteralValue, a1)
            buffersize: Optional[int] = a1.value
        else:
            buffersize = None
        address = SSV.mk_base_address(base, 0, buffersize=buffersize)
        if a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            if a0.is_base_address:
                a0 = cast(SSV.SimBaseAddress, a0)
                if a0.has_buffer_size():
                    a0buffersize = cast(int, a0.buffersize)
                    a0 = cast(SSV.SimBaseAddress, a0)
                    for i in range(0, a0buffersize):
                        srcaddr = a0.add_offset(i)
                        tgtaddr = address.add_offset(i)
                        srcval = simstate.memval(iaddr, srcaddr, size=1)
                        simstate.set_memval(iaddr, tgtaddr, srcval)
        simstate.set_register(iaddr, 'v0', address)
        pargs = str(a0) + ',' + str(a1)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(address))


class MIPStub_realpath(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'realpath')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', a0)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_reboot(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "reboot")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(-1))
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_recv(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'recv')
        self.buffer: Optional[str] = None

    def is_io_operation(self) -> bool:
        return True

    def is_network_operation(self) -> bool:
        return True

    def get_network_input(
            self, iaddr: str, simstate: "SimulationState", size: int) -> str:
        if self.buffer is None:
            if simstate.simsupport.has_network_input(iaddr):
                self.buffer = simstate.simsupport.network_input(
                    iaddr, simstate, size)
        if self.buffer and len(self.buffer) > 0 and len(self.buffer) <= size:
            recv = self.buffer[:]
            self.buffer = ''
            return recv
        elif self.buffer and len(self.buffer) > 0:
            recv = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return recv
        else:
            return ''

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])

        if self.buffer and len(self.buffer) == 0:
            simstate.set_register(iaddr, 'v0', SV.simOne)
            simstate.add_logmsg('i/o', self.name + '(' + pargs + '):1')
            return self.add_logmsg(iaddr, simstate, pargs, returnval='1')

        elif simstate.simsupport.has_network_input(iaddr):
            if a1.is_literal and a1.is_defined:
                a1 = cast(SV.SimLiteralValue, a1)
                a1 = SSV.mk_global_address(a1.value, simstate.modulename)
            elif a1.is_address:
                a1 = cast(SSV.SimAddress, a1)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "Argument a1 is not an address: " + str(a1))

            if a2.is_literal and a2.is_defined:
                a2 = cast(SV.SimLiteralValue, a2)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "Lenght argument is not a literal: " + str(a0))

            networkinput = self.get_network_input(iaddr, simstate, a2.value)
            for i in range(0, len(networkinput)):
                tgtaddr = a1.add_offset(i)
                simstate.set_memval(
                    iaddr,
                    tgtaddr,
                    SV.mk_simvalue(ord(networkinput[i]), 1))
            simstate.set_register(iaddr, 'v0', SV.mk_simvalue(len(networkinput)))
            return self.add_logmsg(
                iaddr, simstate, pargs, returnval=str(len(networkinput)))
        else:
            simstate.set_register(iaddr, 'v0', SV.mk_simvalue(-1))
            return self.add_logmsg(iaddr, simstate, pargs, returnval='-1')


class MIPStub_recvfrom(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'recvfrom')
        self.buffer: Optional[str] = None

    def is_network_operation(self) -> bool:
        return True

    def is_io_operation(self) -> bool:
        return True

    def get_network_input(
            self, iaddr: str, simstate: "SimulationState", size: int) -> str:
        if self.buffer is None:
            if simstate.simsupport.has_network_input(iaddr):
                self.buffer = simstate.simsupport.network_input(
                    iaddr, simstate, size)

        self.buffer = cast(str, self.buffer)
        if len(self.buffer) > 0 and len(self.buffer) <= size:
            recv = self.buffer
            self.buffer = None
            return recv
        elif len(self.buffer) > 0:
            recv = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return recv
        else:
            return ''

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        a4 = self.get_stack_arg_val(iaddr, simstate, 4)
        a5 = self.get_stack_arg_val(iaddr, simstate, 5)
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3, a4, a5])
        if self.buffer and len(self.buffer) == 0:
            simstate.set_register(iaddr, 'v0', SV.simOne)
            simstate.add_logmsg('i/o', self.name + '(' + pargs + '):1')
            return self.add_logmsg(iaddr, simstate, pargs, returnval='1')
        elif (simstate.simsupport.has_network_input(iaddr)
              and a1.is_address
              and a2.is_literal
              and a2.is_defined):
            a1 = cast(SSV.SimAddress, a1)
            a2 = cast(SV.SimLiteralValue, a2)
            networkinput = self.get_network_input(iaddr, simstate, a2.value)
            for i in range(0, len(networkinput)):
                tgtaddr = a1.add_offset(i)
                simstate.set_memval(
                    iaddr, tgtaddr, SV.mk_simvalue(ord(networkinput[i]), 1))
            simstate.set_register(iaddr, 'v0', SV.mk_simvalue(len(networkinput)))
            return self.add_logmsg(
                iaddr, simstate, pargs, returnval=str(len(networkinput)))
        else:
            simstate.set_register(iaddr, 'v0', SV.mk_simvalue(-1))
            return self.add_logmsg(iaddr, simstate, pargs, returnval='-1')


class MIPStub_remove(MIPSimStub):
    """Removes a file."""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "remove")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ":" + a0str
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0")


class MIPStub_rename(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "rename")

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = str(a0) + ":" + a0str + ", " + str(a1) + ":" + a1str
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0")


class MIPStub_sched_get_priority_max(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sched_get_priority_max')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_sched_get_priority_min(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sched_get_priority_min')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_sched_yield(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sched_yield')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_select(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'select')
        self.count = 0

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns the total number of bits set."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        a4 = self.get_stack_arg_val(iaddr, simstate, 4)
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3, a4])
        if self.count == 0 or self.count == 1:
            result = SV.simOne
            self.count += 1
        else:
            result = SV.simZero
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_semctl(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "semctl")

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int semid
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # int semnum
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # int cmd, ...
        pargs = ", ".join(str(a) for a in [a0, a1, a2])
        if (
                a0.is_defined
                and a1.is_defined
                and a2.is_defined
                and a0.is_literal
                and a1.is_literal
                and a2.is_literal):
            semid = a0.literal_value
            semnum = a1.literal_value
            cmd = a2.literal_value
            result = simstate.simsupport.semaphore_semctl(
                iaddr, simstate, semid, semnum, cmd)
        else:
            simstate.add_logmsg("warning", iaddr + ": semctl arguments undefined")

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_semget(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "semget")

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # key_t key
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # int nsems
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # int semflg
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        if (
                a0.is_defined
                and a1.is_defined
                and a2.is_defined
                and a0.is_literal
                and a1.is_literal
                and a2.is_literal):
            key = a0.literal_value
            nsems = a1.literal_value
            semflg = a2.literal_value
            result = simstate.simsupport.semaphore_semget(
                iaddr, simstate, key, nsems, semflg)
        else:
            simstate.add_logmsg("warning", iaddr + ": semget arguments undefined")
            result = -1

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_semop(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'semop')

    def is_sharedmem_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int semid
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # struct sembuf *sops
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # size_t nsops
        pargs = ','.join(str(a) for a in [a0, a1, a2])

        if (
                a0.is_defined
                and a1.is_defined
                and a2.is_defined
                and a0.is_literal
                and (a1.is_literal or a1.is_address)
                and a2.is_literal):
            semid = a0.literal_value
            if a1.is_literal:
                sops = cast(
                    SSV.SimAddress,
                    simstate.resolve_literal_address(iaddr, a1.literal_value))
            else:
                sops = cast(SSV.SimAddress, a1)
            nsops = a2.literal_value
            result = simstate.simsupport.semaphore_semop(
                iaddr, simstate, semid, sops, nsops)
        else:
            simstate.add_logmsg(
                "warning",
                iaddr + ": semop: some arguments are undefined")
            result = -1

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_send(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'send')

    def is_io_operation(self) -> bool:
        return True

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3])
        simstate.set_register(iaddr, 'v0', a2)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(a2))


class MIPStub_sendto(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sendto')

    def is_io_operation(self) -> bool:
        return True

    def is_network_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        a4 = self.get_stack_arg_val(iaddr, simstate, 4)
        a5 = self.get_stack_arg_val(iaddr, simstate, 5)
        pargs = ','.join(str(a) for a in [a0, a1, a2, a3, a4, a5])
        simstate.set_register(iaddr, 'v0', SV.simOne)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_setenv(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'setenv')

    def is_environment_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o; returns 0 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = (
            str(a0) + ':' + a0str + ',' + str(a1) + ':' + a1str + ',' + str(a2))
        simstate.simsupport.set_environment_variable(a0str, a1str)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPSimStub_sprintf_like(MIPSimStub):

    def __init__(self, name: str) -> None:
        MIPSimStub.__init__(self, name)

    def write_string_to_buffer(
            self, iaddr: str, simstate: "SimulationState", s: str) -> None:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        if a0.is_symbol:
            simstate.add_logmsg(
                'free sprintf',
                '  to dst: ' + str(a0) + '; str: ' + str(s))
            return
        elif a0.is_literal and a0.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            dstaddr = cast(
                SSV.SimAddress, simstate.resolve_literal_address(iaddr, a0.value))
            if not dstaddr.is_defined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "sprintf: Address not recognized as a global: " + str(a0))
        elif a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)

        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                'Illegal destination address in sprintf: ' + str(a0))

        for i in range(0, len(s)):
            srcval = SV.SimByteValue(ord(s[i]))
            tgtaddr = dstaddr.add_offset(i)
            simstate.set_memval(iaddr, tgtaddr, srcval)
        simstate.set_memval(iaddr, dstaddr.add_offset(len(s)), SV.SimByteValue(0))

    def get_logmsg(
            self,
            iaddr: str,
            simstate: "SimulationState",
            varargs: List[str],
            s: str) -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str + ',' + ','.join(varargs)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(len(s)))

    def set_returnval(
            self, iaddr: str, simstate: "SimulationState", s: str) -> None:
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(len(s)))

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        return "to be overridden"


class MIPStub_snprintf(MIPSimStub):
    """int snprintf(char *restrict s, size_t n, const char *restrict format, ...);"""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "snprintf")

    def write_string_to_buffer(
            self, iaddr: str, simstate: "SimulationState", s: str) -> None:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        if a0.is_symbol:
            simstate.add_logmsg(
                'free sprintf',
                '  to dst: ' + str(a0) + '; str: ' + str(s))
        elif a0.is_literal and a0.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            dstaddr = cast(
                SSV.SimAddress, simstate.resolve_literal_address(iaddr, a0.value))
            if not dstaddr.is_defined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "snprintf: Address not recognized as a global: " + str(a0))
        elif a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)

        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                'Illegal destination address in snprintf: ' + str(a0))

        for i in range(0, len(s)):
            srcval = SV.SimByteValue(ord(s[i]))
            tgtaddr = dstaddr.add_offset(i)
            simstate.set_memval(iaddr, tgtaddr, srcval)
        simstate.set_memval(iaddr, dstaddr.add_offset(len(s)), SV.SimByteValue(0))

    def set_returnval(
            self, iaddr: str, simstate: "SimulationState", s: str) -> None:
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(len(s)))

    def get_logmsg(
            self,
            iaddr: str,
            simstate: "SimulationState",
            varargs: List[str],
            s: str) -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        a2str = self.get_arg_string(iaddr, simstate, "a2")
        pargs = (
            str(a0)
            + ','
            + str(a1)
            + ","
            + str(a2)
            + ':'
            + a2str
            + ','
            + ','.join(varargs))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(len(s)))

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a2str = self.get_arg_string(iaddr, simstate, 'a2')
        (printstring, varargs) = self.substitute_formatstring(iaddr, simstate, 2)
        self.write_string_to_buffer(iaddr, simstate, printstring)
        self.set_returnval(iaddr, simstate, printstring)
        pvarargs = ", ".join(varargs)
        pargs = (
            str(a0)
            + ", "
            + str(a1)
            + ", "
            + str(a2)
            + ":"
            + a2str
            + " -> "
            + printstring)
        pargs = pargs + ", " + pvarargs
        return self.add_logmsg(
            iaddr, simstate, pargs, returnval=str(len(printstring)))


class MIPStub_sprintf(MIPSimStub):
    """int sprintf(char *restrict s, const char *restrict format, ...);"""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "sprintf")

    def write_string_to_buffer(
            self, iaddr: str, simstate: "SimulationState", s: str) -> None:
        a0 = self.get_arg_val(iaddr, simstate, "a0")

        if a0.is_symbol:
            simstate.add_logmsg(
                'free sprintf',
                '  to dst: ' + str(a0) + '; str: ' + str(s))
            return

        if a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)
        elif a0.is_literal:
            dstaddr = simstate.resolve_literal_address(iaddr, a0.literal_value)

        if dstaddr.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "sprintf: Destination address cannot be resolved: " + str(a0))

        for i in range(0, len(s)):
            srcval = SV.mk_simcharvalue(s[i])
            tgtaddr = dstaddr.add_offset(i)
            simstate.set_memval(iaddr, tgtaddr, srcval)
        simstate.set_memval(iaddr, dstaddr.add_offset(len(s)), SV.simZerobyte)

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # char *restrict s
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const char *restrict format
        a1str = self.get_arg_string(iaddr, simstate, "a1")

        if a0.is_undefined or a1.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "some argument to sprintf is undefined")

        (printstring, varargs) = self.substitute_formatstring(iaddr, simstate, 1)
        self.write_string_to_buffer(iaddr, simstate, printstring)
        simstate.set_register(iaddr, "v0", SV.mk_simvalue(len(printstring)))
        pargs = ", ".join([str(a0), a1str] + varargs) + " -> " + printstring
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(len(printstring)))


class MIPStub_srand(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'srand')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(0x12345678))
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_sscanf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'sscanf')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        result = -1
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_stat(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'stat')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + a0str + ',' + str(a1)
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(-1))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strcasecmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strcasecmp')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        try:
            a0str = self.get_arg_string(iaddr, simstate, 'a0')
            a0strlc = a0str.lower()
            a1strlc = a1str.lower()
            if a0strlc == a1strlc:
                result = 0
            elif a0strlc < a1strlc:
                result = -1
            else:
                result = 1
        except Exception as e:
            result = 1
            print('Error in strcasecmp')
            a0str = '*** error ****'
        if iaddr == '0x403948':
            result = 0
        resultval = SV.mk_simvalue(result)
        simstate.set_register(iaddr, 'v0', resultval)
        pargs = ','.join(str(a)
                         + ':'
                         + str(v) for (a, v) in [(a0, a0str), (a1, a1str)])
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(resultval))


class MIPStub_strchr(MIPSimStub):
    """char *strchr(const char *s, int c);

    Return a pointer to the byte, or a null pointer if the byte was not found.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strchr")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        pargs = ",".join(str(a) for a in [a0, a1])

        if a0.is_address and a1.is_literal and a1.is_defined:
            a0 = cast(SSV.SimAddress, a0)
            a1 = cast(SV.SimLiteralValue, a1)
            i = 0
            while True:
                c = simstate.memval(iaddr, a0.add_offset(i), 1)
                if c.is_literal and c.is_defined:
                    c = cast(SV.SimLiteralValue, c)
                    if c.value == a1.value:
                        returnval: SV.SimValue = a0.add_offset(i)
                        break
                    elif c.value == 0:
                        returnval = SV.simZero
                        break
                    else:
                        i += 1
                else:
                    returnval = SV.simUndefinedDW
                    break
            simstate.set_register(iaddr, 'v0', returnval)
            return self.add_logmsg(
                iaddr, simstate, pargs, returnval=str(returnval))
        else:
            returnval = SV.simZero
        if a1.is_literal and a1.is_defined:
            a1 = cast(SV.SimLiteralValue, a1)
            pa1 = "'" + chr(a1.value) + "'"
        else:
            pa1 = str(a1)
        pargs = str(a0) + ',' + pa1
        simstate.set_register(iaddr, 'v0', returnval)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_strncasecmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strncasecmp')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Compares the two strings up to count, and returns the result in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        if a2.is_literal and a2.is_defined:
            a2 = cast(SV.SimLiteralValue, a2)
            count = a2.value
            if a0str.lower()[:count] == a1str.lower()[:count]:
                result = 0
            elif a0str.lower()[:count] < a1str.lower()[:count]:
                result = -1
            else:
                result = 1
            resultval = SV.SimDoubleWordValue(result)
        else:
            resultval = SV.simUndefinedDW
        simstate.set_register(iaddr, 'v0', resultval)
        pargs = (
            str(a0)
            + ': "'
            + a0str
            + '", '
            + str(a1)
            + ': "'
            + a1str
            + '", '
            + 'count:'
            + str(a2))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(resultval))


class MIPStub_strcmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strcmp')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Compares the two arguments and returns the result in v0."""
        a0 = self.get_arg_val(iaddr, simstate, "a0")   # str1
        a1 = self.get_arg_val(iaddr, simstate, "a1")   # str2
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        if a0str == a1str:
            result = 0
        elif a0str < a1str:
            result = -1
        else:
            result = 1
        simstate.set_register(iaddr, 'v0', SV.SimDoubleWordValue(result))
        pargs = ','.join(str(a) + ':' + str(v)
                         for (a, v) in [(a0, a0str), (a1, a1str)])
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_strncmp(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strncmp')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Compares the two strings up to count and returns the result in v0."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const char *s1
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const char *s2
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # size_t n
        pargs = ", ".join(str(a) for a in [a0, a1, a2])

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strncmp: some arguments are undefined: " + pargs)

        if a2.is_literal:
            n = a2.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strncmp: size argument is not a literal: " + str(a2))

        s1 = self.get_arg_string(iaddr, simstate, "a0")
        s2 = self.get_arg_string(iaddr, simstate, "a1")
        pargs = s1 + ", " + s2 + ", " + str(n)

        if len(s1) >= n and len(s2) >= n:
            if s1[:n] == s2[:n]:
                result = 0
            elif s1[:n] < s2[:n]:
                result = -1
            else:
                result = 1

        elif len(s1) == len(s2):
            if s1 == s2:
                result = 0
            elif s1 < s2:
                result = -1
            else:
                result = 1

        else:
            if len(s1) < len(s2):
                result = -1
            else:
                result = 1

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_strcat(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strcat')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = str(a0) + "," + a0str + ", " + str(a1) + ":" + a1str
        if a0.is_address and a1.is_address:
            a0 = cast(SSV.SimAddress, a0)
            a1 = cast(SSV.SimAddress, a1)
            dstaddr = a0.add_offset(len(a0str))
            for i in range(0, len(a1str)):
                srcval = SV.SimByteValue(ord(a1str[i]))
                tgtaddr = dstaddr.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
            simstate.set_memval(
                iaddr, dstaddr.add_offset(len(a1str)), SV.SimByteValue(0))
        simstate.set_register(iaddr, 'v0', a0)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strcpy(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strcpy')

    def get_dst_arg_index(self) -> int:
        return 0

    def get_src_arg_index(self) -> int:
        return 1

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Copies characters from src to dst up to and including null terminator."""
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        returnmsg = ""

        if a0.is_undefined or a1.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strcpy: some arguments are undefined")

        if a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)

        elif a0.is_literal:
            dstaddr = simstate.resolve_literal_address(iaddr, a0.literal_value)
            if dstaddr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "strcpy: illegal destination address: " + str(a0))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strcpy: illegal destination address: " + str(a0))

        if a1.is_symbol:
            simstate.add_logmsg(
                "free strcpy", "src:" + str(a1) + " to dst: " + str(a0))
        else:
            for i in range(0, len(a1str)):
                srcval = SV.SimByteValue(ord(a1str[i]))
                tgtaddr = dstaddr.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
            simstate.set_memval(
                iaddr, dstaddr.add_offset(len(a1str)), SV.SimByteValue(0))
            returnmsg = "copied " + str(len(a1str)) + " chars to " + str(dstaddr)
        simstate.set_register(iaddr, "v0", dstaddr)
        pargs = str(dstaddr) + ',' + str(a1) + ':' + a1str
        return self.add_logmsg(iaddr, simstate, pargs, returnval=returnmsg)


class MIPStub_strdup(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strdup")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site: str) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def is_string_operation(self) -> bool:
        return True

    def is_memalloc_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns a pointer to a duplicated string in v0."""

        a0 = self.get_arg_val(iaddr, simstate, "a0")
        if a0.is_string_address:
            a0 = cast(SSV.SimStringAddress, a0)
            s = a0.stringval
            site = "strdup_" + iaddr
            base = site + ":" + str(self.sitecounter(site))
            buffersize = len(s) + 1
            address = SSV.mk_base_address(base, 0, buffersize=buffersize)
            simstate.basemem[base] = SimBaseMemory(
                simstate, base, buffersize=buffersize)
            for i in range(0, buffersize-1):
                simstate.set_memval(
                    iaddr,
                    address.add_offset(i),
                    SV.mk_simvalue(ord(s[i]), size=1))
            simstate.set_memval(
                iaddr, address.add_offset(buffersize - 1), SV.simZero)
            result = address

        elif a0.is_symbol:
            a0 = cast(SSV.SimSymbol, a0)
            site = "strdup_" + iaddr
            base = site + ":" + str(self.sitecounter(site))
            contents = a0.name + '_duplicate'
            buffersize = len(contents) + 1
            address = SSV.mk_base_address(base, 0, buffersize=buffersize)
            simstate.basemem[base] = SimBaseMemory(
                simstate, base, buffersize=buffersize)
            for i in range(0, buffersize-1):
                simstate.set_memval(
                    iaddr,
                    address.add_offset(i),
                    SV.mk_simvalue(ord(contents[i]), size=1))
            result = address
        else:
            a0str = self.get_arg_string(iaddr, simstate, 'a0')
            site = "strdup_" + iaddr
            base = site + ":" + str(self.sitecounter(site))
            address = SSV.mk_base_address(base, 0, buffersize=len(a0str))
            for i in range(0, len(a0str)):
                simstate.set_memval(
                    iaddr,
                    address.add_offset(i),
                    SV.mk_simbytevalue(ord(a0str[i])))
            simstate.set_memval(
                iaddr, address.add_offset(len(a0str)), SV.mk_simbytevalue(0))
            result = address
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(result))


class MIPStub_strerror(MIPSimStub):
    """char *strerror(int errnum);

    Return a pointer to the generated message string. The application shall not
    modify the string returned. The returned string pointer might be invalidated
    or the string content might be overwritten by a subsequent call to strerror.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strerror")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        site = "strerror_" + iaddr
        base = site + ":" + str(self.sitecounter(site))
        rval = SSV.mk_string_address(base, "strerror-" + str(a0))
        simstate.set_register(iaddr, "v0", rval)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_strftime(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strftime")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        a2str = self.get_arg_string(iaddr, simstate, "a2")
        a3 = self.get_arg_val(iaddr, simstate, "a3")

        pargs = str(a0) + ", " + str(a1) + ", " + str(a2) + ":" + a2str + ", " + str(a3)
        result = SV.mk_simvalue(len(a2str))
        simstate.set_register(iaddr, "v0", result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_stristr(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'stristr')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = ','.join(str(a) + ':' + s for (a, s) in [(a0, a0str), (a1, a1str)])
        index = a0str.lower().find(a1str.lower())
        if index >= 0 and a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            result: SV.SimValue = a0.add_offset(index)
        else:
            result = SV.simZero
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_strlcpy(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strlcpy")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        parglist = [str(a) for a in [a0, a1, a2]]

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strlcpy: some arguments are undefined ("
                + ", ".join(parglist)
                + ")")

        if a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)

        elif a0.is_literal:
            dstaddr = simstate.resolve_literal_address(iaddr, a0.literal_value)
            if dstaddr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "strlcpy: invalid destination address: " + str(a0))

        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strlcpy: destination address not recognized: " + str(a0))

        if a2.is_literal:
            count = a2.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strlcpy: size is not valid: " + str(a2))

        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = (
            str(dstaddr)
            + ", "
            + a1str
            + ", "
            + str(a2)
            + ")")

        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            for i in range(0, count - 1):
                srcaddr = a1.add_offset(i)
                srcval = cast(
                    SV.SimByteValue, simstate.memval(iaddr, srcaddr, 1))
                tgtaddr = dstaddr.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
                if srcval.value == 0:
                    break
            else:
                # strlcpy always null-terminates
                tgtaddr = dstaddr.add_offset(count - 1)
                simstate.set_memval(iaddr, tgtaddr, SV.simZero)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strlcpy: invalid source address: " + str(a1))

        # return value is the length of the string it tries to create
        a1_len = SV.mk_simvalue(len(a1str))
        simstate.set_register(iaddr, "v0", a1_len)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strlen(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strlen')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns the length of the first argument in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        result = SV.SimDoubleWordValue(len(a0str))
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(
            iaddr, simstate, str(a0) + ':' + a0str, returnval=str(result))


class MIPStub_strncat(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strncat')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strncpy(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strncpy')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # char *restrict s1
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # const char *restrict s2
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # size_t n
        parglist = [str(a) for a in [a0, a1, a2]]

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strncpy: some arguments are undefined ("
                + ", ".join(parglist)
                + ")")

        if a0.is_address:
            dstaddr = cast(SSV.SimAddress, a0)

        elif a0.is_literal:
            dstaddr = simstate.resolve_literal_address(iaddr, a0.literal_value)
            if dstaddr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "strncpy: invalid destination address: " + str(a0))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strncpy: destination address not recognized: " + str(a0))

        if a2.is_literal:
            count = a2.literal_value
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strncpy: size is not valid: " + str(a2))

        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = (
            str(dstaddr)
            + ", "
            + str(a1)
            + ":"
            + a1str
            + ", "
            + str(a2)
            + ")")

        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            for i in range(0, count):
                srcaddr = a1.add_offset(i)
                srcval = cast(
                    SV.SimByteValue, simstate.memval(iaddr, srcaddr, 1))
                tgtaddr = dstaddr.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
                if srcval.value == 0:
                    break
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strncpy: invalid source address: " + str(a1))

        simstate.set_register(iaddr, "v0", dstaddr)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strrchr(MIPSimStub):
    """char *strrchr(const char *s, int c);

    Locate the last occurrence of c in the string pointed to by s and return
    a pointer to the byte or a null pointer if c does not occur in the string.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strrchr")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")

        if a0.is_address and a1.is_literal and a1.is_defined:
            a0 = cast(SSV.SimAddress, a0)
            a1 = cast(SV.SimLiteralValue, a1)
            i = len(a0str)
            while i >= 0:
                c = simstate.memval(iaddr, a0.add_offset(i), 1)
                if c.is_literal and c.is_defined:
                    c = cast(SV.SimLiteralValue, c)
                    if c.value == a1.value:
                        break
                    else:
                        i -= 1
                else:
                    break
            if i >= 0:
                returnval: SV.SimValue = a0.add_offset(i)
            else:
                returnval = SV.simZero
        else:
            returnval = SV.simZero
        simstate.set_register(iaddr, 'v0', returnval)
        if a1.is_literal and a1.is_defined:
            a1 = cast(SV.SimLiteralValue, a1)
            pa1 = "'" + chr(a1.value) + "'"
        else:
            pa1 = str(a1)
        pargs = str(a0) + ':' + a0str + ',' + pa1
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(returnval))


class MIPStub_strsep(MIPSimStub):
    """extract token from string

    char *strsep(char **stringp, const char *delim);

    Description:
    If *stringp is NULL, the strsep() function returns NULL and does
    nothing else. Otherwise, this function finds the first token in
    the string *stringp that is delimited by one of the bytes in the
    string delim. This token is terminated by overwriting the
    delimiter with a null byte ('\0'), and *stringp is updated to
    point past the token. In case no delimiter was found, the token
    is taken to be the entire string *stringp, and *stringp is made
    NULL.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strsep')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        a0derefstr = 'NULL'
        if a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            a0deref = self.get_arg_deref_val(iaddr, simstate, 'a0')
            a0derefstr = self.get_arg_deref_string(iaddr, simstate, 'a0')
            if a0deref.is_address:
                a0deref = cast(SSV.SimAddress, a0deref)
                for c in a1str:
                    index = a0derefstr.find(c)
                    if index >= 0:
                        tokenptr = a0deref.add_offset(index+1)
                        simstate.set_memval(
                            iaddr,
                            a0deref.add_offset(index),
                            SV.mk_simvalue(0, size=1))
                        simstate.set_memval(iaddr, a0, tokenptr)
                        break
                else:
                    simstate.set_memval(iaddr, a0, SV.simZero)
            else:
                simstate.set_memval(iaddr, a0, SV.simZero)

        a1ordstr = '{' + ','.join(str(ord(c)) for c in a1str) + '}'
        pargs = (
            str(a0) + ':&' + a0derefstr + ',' + str(a1) + ':' + a1str + a1ordstr)
        simstate.set_register(iaddr, 'v0', a0)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strstr(MIPSimStub):
    """char *strstr(const char *s1, const char *s2);

    Locate the first occurrence in the string pointed to by s1 of the sequence
    of bytes in the string pointed to by s2. Return a pointer to the located
    string or a null pointer if the string is not found.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strstr")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        pargs = (
            ",".join(str(a) + ":" + s for (a, s) in [(a0, a0str), (a1, a1str)]))

        if a0.is_undefined or a1.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "some argument to strstr is undefined")

        if a0.is_address:
            addr: SV.SimValue = cast(SV.SimValue, a0)
        elif a0.is_literal:
            addr = simstate.resolve_literal_address(iaddr, a0.literal_value)

        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "argument to strstr is not recognized as an address: " + str(a0))

        if addr.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "src string address could not be resolved: " + str(a0))

        index = a0str.find(a1str)
        if index >= 0:
            saddr = cast(SSV.SimAddress, addr)
            result: SV.SimValue = saddr.add_offset(index)
        else:
            result = SV.simZero
        simstate.set_register(iaddr, "v0", result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_strtof(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strtof')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        pargs = str(a0) + ':' + a0str + str(a1)
        fstr = ''
        for c in a0str:
            if c.isdigit() or c == '.':
                fstr += c
            else:
                break
        result = SV.mk_floatvalue(float(fstr))
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_strtok(MIPSimStub):
    """char *strtok(char *restrict s, const char *restrict sep);

    A sequence of calls breaks the string pointed to by s into a sequence of
    tokens, each of which is delimited by a byte from the string pointed to by
    sep. The first call in the sequence has s as its first argument and is
    followed by calls with a null pointer as their first argument.

    The first call in the sequence searches the string pointed to by s for the
    first byte that is not contained in the current separator string pointed
    to by sep. If no such byte is found, then there are no tokens in the string
    pointed to by s and strtok() shall return a null pointer. If such a byte is
    found, it is the start of the first token.
    """

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strtok')
        self._state: Optional[SSV.SimStringAddress] = None

    @property
    def state(self) -> SSV.SimStringAddress:
        if self._state is not None:
            return self._state
        else:
            raise UF.CHBError("strtok state has not been set")

    def has_state(self) -> bool:
        return self._state is not None

    def set_state(
            self,
            iaddr: str,
            simstate: "SimulationState",
            tgtstring: str) -> SSV.SimStringAddress:
        saddr = SSV.mk_string_address("strtok:" + tgtstring, tgtstring)
        self._state = saddr
        return saddr

    def update_state(
            self,
            iaddr: str,
            simstate: "SimulationState",
            index: int) -> None:
        if self._state is None:
            return
        sepaddress = self._state.add_offset(index)
        simstate.set_memval(iaddr, sepaddress, SV.simZerobyte)
        self._state = self._state.add_offset(index + 1)

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1str = self.get_arg_string(iaddr, simstate, "a1")

        result: SV.SimValue = SV.simZero

        if a0.is_address:
            a0str = self.get_arg_string(iaddr, simstate, "a0")
            if a0str == "":
                result = SV.simZero
            else:
                result = cast(SV.SimValue, self.set_state(iaddr, simstate, a0str))
            pargs = str(a0) + ":" + a0str + "," + str(a1) + ":" + a1str

        elif a0.is_literal and a0.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            if a0.value == 0:
                pargs = str(a0) + "," + str(a1) + ":" + a1str
                if self.has_state():
                    result = cast(SV.SimValue, self.state)
                else:
                    pass
            else:
                a0str = self.get_arg_string(iaddr, simstate, "a0")
                result = cast(SV.SimValue, self.set_state(iaddr, simstate, a0str))
                pargs = str(a0) + ":" + a0str + "," + str(a1) + ":" + a1str
        else:
            raise SU.CHBSimError(
                simstate, iaddr, "Undefined value in strtok: " + str(a0))

        if self.has_state():
            tgtstring = simstate.get_string_from_memaddr(iaddr, self.state)
        else:
            tgtstring = ""

        # find separator (assume single-character separator for now)
        index = tgtstring.find(a1str)
        if index > 0:
            self.update_state(iaddr, simstate, index)
        else:
            self._state = None
        simstate.set_register(iaddr, "v0", result)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strtok_r(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strtok_r')

    def is_string_operation(self) -> bool:
        return True

    def simulate_first_token(
            self,
            iaddr: str,
            simstate: "SimulationState",
            srcaddr: SSV.SimAddress,
            s: str,
            sep: str,
            stateaddr: SSV.SimAddress) -> str:
        minpos = len(s)
        for c in sep:
            pos = s.find(c)
            if pos == -1:
                continue
            if pos < minpos:
                minpos = pos
        if minpos == len(s):
            result = srcaddr
            simstate.set_memval(iaddr, stateaddr, SV.simZero)
            pargs = str(srcaddr) + ':' + s + ',' + sep + ',' + str(stateaddr)
            simstate.set_register(iaddr, 'v0', result)
            return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))
        else:
            result = srcaddr
            simstate.set_memval(
                iaddr, srcaddr.add_offset(minpos), SV.SimByteValue(0))
            simstate.set_memval(iaddr, stateaddr, srcaddr.add_offset(minpos + 1))
            pargs = str(srcaddr) + ':' + s + ',' + sep + ',' + str(stateaddr)
            simstate.set_register(iaddr, 'v0', result)
            return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))

    def simulate_next_token(
            self,
            iaddr: str,
            simstate: "SimulationState",
            sep: str,
            a2: SSV.SimAddress) -> str:
        s = self.get_arg_deref_string(iaddr, simstate, 'a2')
        minpos = len(s)
        for c in sep:
            pos = s.find(c)
            if pos == -1:
                continue
            if pos < minpos:
                minpos = pos
        if minpos == len(s):
            result = self.get_arg_deref_val(iaddr, simstate, 'a2')
            simstate.set_memval(iaddr, a2, SV.SimByteValue(0))
            pargs = '0, ' + sep + ',' + str(a2)
            simstate.set_register(iaddr, 'v0', result)
            return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))
        else:
            result = self.get_arg_deref_val(iaddr, simstate, 'a2')
            if result.is_address:
                result = cast(SSV.SimAddress, result)
                simstate.set_memval(
                    iaddr, result.add_offset(minpos), SV.SimByteValue(0))
                simstate.set_memval(iaddr, a2, result.add_offset(minpos+1))
            else:
                simstate.add_logmsg(iaddr, "strtok: result is not an address")
            pargs = '0, ' + sep + ', ' + str(a2)
            simstate.set_register(iaddr, 'v0', result)
            return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Returns 0 in v0."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        if a0.is_literal and a0.is_defined and a2.is_address:
            a0 = cast(SV.SimLiteralValue, a0)
            a2 = cast(SSV.SimAddress, a2)
            if a0.value == 0:
                return self.simulate_next_token(iaddr, simstate, a1str, a2)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "Unexpected literal value in strtok: " + str(a0))
        elif a0.is_address and a2.is_address:
            a0 = cast(SSV.SimAddress, a0)
            a2 = cast(SSV.SimAddress, a2)
            a0str = self.get_arg_string(iaddr, simstate, 'a0')
            return self.simulate_first_token(iaddr, simstate, a0, a0str, a1str, a2)
        else:
            a0str = self.get_arg_string(iaddr, simstate, 'a0')
            simstate.set_register(iaddr, 'v0', SV.simZero)
            pargs = (str(a0) + ': "' + a0str + '", '
                     + str(a1) + ': "' + a1str + '", '
                     + str('state:' + str(a2)))
            return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_strtol(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "strtol")

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const char *restrict nptr
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # char **restrict endptr
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # int base
        parglist = [str(a) for a in [a0, a1, a2]]

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strtol: some arguments are undefined: " + ", ".join(parglist))

        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ":" + a0str + ", " + ", ".join(parglist[1:])

        if (
                len(a0str) > 0
                and a1.is_literal
                and a2.is_literal
                and a1.literal_value == 0   # no endptr
                and (a2.literal_value == 0 or a2.literal_value == 10)):
            negate = False
            if a0str.startswith("+"):
                a0str = a0str[1:]
            if a0str.startswith("-"):
                a0str = a0str[1:]
                negate = True
            if a0str.isdecimal():
                result = int(a0str)
            elif a0str.startswith("0x") or a0str.startswith("0X"):
                result = int(a0str, 16)
            elif a0str.startswith("0"):
                result = int("0o" + a0str[1:], 8)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "strtol: representation not recognized: " + a0str)
            if negate:
                result = -result
            else:
                pass
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strtol: argument combination not implemented for "
                + "("
                + ", ".join(pargs)
                + ")")

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_strtoul(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'strtoul')

    def is_string_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # const char *restrict str
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # char **restring endptr
        a2 = self.get_arg_val(iaddr, simstate, 'a2')  # int base
        parglist = [str(a) for a in [a0, a1, a2]]

        if a0.is_undefined or a1.is_undefined or a2.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strtoul: some arguments are undefined "
                + "("
                + ", ".join(parglist)
                + ")")

        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ":" + a0str + ", " + ", ".join(parglist[1:])

        if (
                len(a0str) > 0
                and a1.is_literal
                and a2.is_literal
                and a1.literal_value == 0    # no endptr
                and (a2.literal_value == 0 or a2.literal_value == 10)):
            negate = False
            if a0str.startswith("+"):
                a0str = a0str[1:]
            if a0str.startswith("-"):
                a0str = a0str[1:]
                negate = True
            if a0str.isdecimal():
                result = int(a0str)
            elif a0str.startswith("0x") or a0str.startswith("0X"):
                result = int(a0str, 16)
            elif a0str.startswith("0"):
                result = int("0o" + a0str[1:], 8)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "strtol: representation not recognized: " + a0str)
            if negate:
                result = SU.max32 - result
            else:
                pass
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "strtol: argument combination not implemented for "
                + "("
                + ", ".join(pargs)
                + ")")

        simstate.set_register(iaddr, "v0", SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_syslog(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'syslog')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        pargs = str(a0) + ',' + str(a1) + ':' + a1str
        if a1str == '%s':
            a2 = self.get_arg_val(iaddr, simstate, 'a2')
            a2str = self.get_arg_string(iaddr, simstate, 'a2')
            pargs += ',' + str(a2) + ':' + a2str
        simstate.add_logmsg('i/o', self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_system(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'system')

    def is_system_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')  # cmdline string
        if a0.is_literal and a0.is_defined:
            a0val = a0.literal_value
            if a0val == 0:
                pargs = 'NULL'
            else:
                pargs = self.get_arg_string(iaddr, simstate, 'a0')
        else:
            pargs = self.get_arg_string(iaddr, simstate, "a0")
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_tcgetattr(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "tcgetattr")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        pargs = str(a0) + ", " + str(a1)
        simstate.set_register(iaddr, "v0", SV.simZero)
        if a1.is_address:
            a1 = cast(SSV.SimAddress, a1)
            simstate.set_memval(iaddr, a1, SV.simZero)
            simstate.set_memval(iaddr, a1.add_offset(4), SV.simZero)
            simstate.set_memval(iaddr, a1.add_offset(8), SV.simZero)
            simstate.set_memval(iaddr, a1.add_offset(12), SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0")


class MIPStub_tcsetattr(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "tcsetattr")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a2 = self.get_arg_val(iaddr, simstate, "a2")
        pargs = ", ".join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0")


class MIPStub_time(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'time')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        result = int(time.time())
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
        return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(result))


class MIPStub_tolower(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'tolower')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        if a0.is_literal and a0.is_defined:
            a0 = cast(SV.SimLiteralValue, a0)
            result = ord(str(chr(a0.value)).lower()[0])
            simstate.set_register(iaddr, 'v0', SV.mk_simvalue(result))
            return self.add_logmsg(iaddr, simstate, str(a0), returnval=str(result))
        else:
            return self.add_logmsg(iaddr, simstate, str(a0), returnval="?")


class MIPStub_umask(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'umask')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_unlink(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'unlink')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a0str = self.get_arg_string(iaddr, simstate, 'a0')
        pargs = str(a0) + ':' + a0str
        simstate.set_register(iaddr, 'v0', SV.mk_simvalue(0))
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_unsetenv(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "unsetenv")

    def is_environment_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        simstate.set_register(iaddr, "v0", SV.simZero)
        pargs = str(a0) + ":" + a0str
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0")


class MIPStub_usleep(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'usleep')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_vfork(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "vfork")

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        if iaddr in simstate.simsupport.forkchoices:
            result = simstate.simsupport.forkchoices[iaddr]
        else:
            result = 0
        simresult = SV.mk_simvalue(result)
        simstate.set_register(iaddr, 'v0', simresult)
        return self.add_logmsg(iaddr, simstate, '', returnval=str(result))


class MIPStub_vsnprintf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'vsnprintf')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Copies the string of the second argument to the dst argument."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        a2str = self.get_arg_string(iaddr, simstate, 'a2')
        a3 = self.get_arg_val(iaddr, simstate, 'a3')
        printstring = a2str
        if a0.is_symbol:
            simstate.add_logmsg(
                'free vsprintf', ' to dst: ' + str(a0) + '; str: ' + printstring)
        elif a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            for i in range(0, len(printstring)):
                srcval = SV.SimByteValue(ord(printstring[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
            simstate.set_memval(
                iaddr, a0.add_offset(len(printstring)), SV.mk_simvalue(0, size=1))
        else:
            simstate.add_logmsg(
                iaddr,
                "No address to write to in vsnprintf: " + str(a0))
        simstate.set_register(iaddr, 'v0', SV.SimDoubleWordValue(len(printstring)))
        pargs = (
            str(a0) + ',' + str(a1) + ',' + str(a2) + ':' + a2str + ',' + str(a3))
        return self.add_logmsg(
            iaddr, simstate, pargs, returnval=str(len(printstring)))


class MIPStub_vsprintf(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'vsprintf')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Copies the string of the second argument to the dst argument."""
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a1str = self.get_arg_string(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        printstring = a1str
        if a0.is_symbol:
            simstate.add_logmsg(
                'free vsprintf', ' to dst: ' + str(a0) + '; str: ' + printstring)
        elif a0.is_address:
            a0 = cast(SSV.SimAddress, a0)
            for i in range(0, len(printstring)):
                srcval = SV.SimByteValue(ord(printstring[i]))
                tgtaddr = a0.add_offset(i)
                simstate.set_memval(iaddr, tgtaddr, srcval)
            simstate.set_memval(
                iaddr, a0.add_offset(len(printstring)), SV.mk_simvalue(0, size=1))
        simstate.set_register(iaddr, 'v0', SV.SimDoubleWordValue(len(printstring)))
        pargs = (str(a0) + ',' + str(a1) + ':' + a1str + ',' + str(a2))
        return self.add_logmsg(
            iaddr, simstate, pargs, returnval=str(len(printstring)))


class MIPStub_waitpid(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'waitpid')

    def is_process_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.set_register(iaddr, 'v0', a0)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(a0))


class MIPStub_write(MIPSimStub):
    """ssize_t write(int fildes, const void *buf, size_t nbyte);"""

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'write')

    def is_io_operation(self) -> bool:
        return True

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        """Logs i/o, returns a2 in v0 for now."""
        a0 = self.get_arg_val(iaddr, simstate, "a0")  # int fildes
        a1 = self.get_arg_val(iaddr, simstate, "a1")  # void *buf
        a2 = self.get_arg_val(iaddr, simstate, "a2")  # size_t nbyte
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        if a0.is_literal:
            simstate.add_logmsg(
                "i/o", "write: Not a valid file descriptor: " + str(a0))
            result: SV.SimValue = SV.mk_simvalue(-1)

        else:
            a0 = cast(SSV.SimSymbolicValue, a0)
            if (
                    a0.is_file_descriptor
                    and a2.is_literal
                    and a2.is_defined
                    and a1.is_address):
                a0 = cast(SSV.SimSymbolicFileDescriptor, a0)
                a1 = cast(SSV.SimAddress, a1)
                a2 = cast(SV.SimLiteralValue, a2)
                for i in range(0, a2.value):
                    tgtaddr = a1.add_offset(i)
                    srcval = simstate.memval(iaddr, tgtaddr, 1)
                    if srcval.is_literal and srcval.is_defined:
                        srcval = cast(SV.SimLiteralValue, srcval)
                        a0.filedescriptor.write(chr(srcval.value))
                result = a2
                simstate.add_logmsg(
                    "i/o",
                    "Successfully wrote " + str(a2) + " bytes to " + str(a0))

            else:
                result = SV.mk_simvalue(-1)
                msg = "write: "
                if not a0.is_file_descriptor:
                    msg += "a0: " + str(a0) + " is not a file descriptor"
                elif not a1.is_address:
                    msg += "a1: " + str(a1) + " is not an address"
                elif not a2.is_literal:
                    msg += "a2: " + str(a2) + " is not a literal"
                elif not a2.is_defined:
                    msg += "a2: " + str(a2) + " is undefined"
                simstate.add_logmsg(iaddr, msg)
        simstate.set_register(iaddr, 'v0', result)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_isLanSubnet(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'isLanSubnet')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, str(a0))


class MIPStub_uloop_init(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'uloop_init')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, 'v0', SV.simZero)
        return self.add_logmsg(iaddr, simstate, '')


class MIPStub_msglogd(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, 'msglogd')

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, 'a0')
        a1 = self.get_arg_val(iaddr, simstate, 'a1')
        a2 = self.get_arg_val(iaddr, simstate, 'a2')
        pargs = ','.join(str(a) for a in [a0, a1, a2])
        simstate.add_logmsg('i/o', self.name + '(' + pargs + ')')
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_config_commit(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "config_commit")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.set_register(iaddr, "v0", SV.simZero)
        simstate.add_logmsg("config", "commit")
        return self.add_logmsg(iaddr, simstate, "", returnval="0")


class MIPStub_config_get(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "config_get")
        self._sitecounters: Dict[str, int] = {}

    @property
    def sitecounters(self) -> Dict[str, int]:
        return self._sitecounters

    def sitecounter(self, site) -> int:
        self.sitecounters.setdefault(site, 0)
        self.sitecounters[site] += 1
        return self.sitecounters[site]

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        site = "config_get_" + iaddr
        base = site + ":" + str(self.sitecounter(site))
        if simstate.simsupport.configvalues.config_has(a0str):
            configval = simstate.simsupport.configvalues.config_get(a0str)
            result: SV.SimValue = SSV.mk_string_address(base, configval)
            configmsg = "retrieved: " + str(result) + " for " + a0str
        else:
            result = SSV.mk_string_address(base, "")
            configmsg = "no config value found for " + a0str
        simstate.set_register(iaddr, "v0", result)
        simstate.add_logmsg("config", configmsg)
        pargs = str(a0) + ":" + a0str
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(result))


class MIPStub_config_set(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "config_set")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        simstate.simsupport.configvalues.config_set(a0str, a1str)
        simstate.set_register(iaddr, "v0", SV.simZero)
        pargs = str(a0) + ":" + a0str + ", " + str(a1) + ":" + a1str
        configmsg = "set: " + a0str + " to " + a1str
        simstate.add_logmsg("config", configmsg)
        return self.add_logmsg(iaddr, simstate, pargs, returnval="0x0")


class MIPStub_config_match(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "config_match")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        configvalues = simstate.simsupport.configvalues
        if configvalues.config_has(a0str):
            result = configvalues.config_match(a0str, a1str)
            if result:
                configmsg = "matched value for " + a0str + " with " + a1str
                resultval = SV.simOne
            else:
                configmsg = "no match for " + a0str + " with " + a1str
                resultval = SV.simZero
        else:
            resultval = SV.simOne
            configmsg = "config key " + a0str + " not found"
        pargs = str(a0) + ":" + a0str + ", " + str(a1) + ":" + a1str
        simstate.set_register(iaddr, "v0", resultval)
        simstate.add_logmsg("config", configmsg)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(resultval))


class MIPStub_config_invmatch(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "config_match")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        a1 = self.get_arg_val(iaddr, simstate, "a1")
        a1str = self.get_arg_string(iaddr, simstate, "a1")
        configvalues = simstate.simsupport.configvalues
        if configvalues.config_has(a1str):
            result = configvalues.config_match(a1str, a0str)
            if result:
                configmsg = "inverse matched value for " + a1str + " with " + a0str
                resultval = SV.simOne
            else:
                configmsg = "no inverse match for " + a1str + " with " + a0str
                resultval = SV.simZero
        else:
            resultval = SV.simOne
            configmsg = "config key " + a1str + " not found"
        pargs = str(a0) + ":" + a0str + ", " + str(a1) + ":" + a1str
        simstate.add_logmsg("config", configmsg)
        simstate.set_register(iaddr, "v0", resultval)
        return self.add_logmsg(iaddr, simstate, pargs, returnval=str(resultval))


class MIPStub_config_unset(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "config_unset")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        a0 = self.get_arg_val(iaddr, simstate, "a0")
        a0str = self.get_arg_string(iaddr, simstate, "a0")
        pargs = str(a0) + ":" + a0str
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, pargs)


class MIPStub_init_libconfig(MIPSimStub):

    def __init__(self) -> None:
        MIPSimStub.__init__(self, "init_libconfig")

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        simstate.add_logmsg("config", "init_libconfig()")
        simstate.set_register(iaddr, "v0", SV.simZero)
        return self.add_logmsg(iaddr, simstate, "", returnval="0")
