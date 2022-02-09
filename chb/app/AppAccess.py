# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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
"""Access point for most analysis results."""

from abc import ABC, abstractmethod
from typing import (
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Generic,
    Tuple,
    Type,
    TYPE_CHECKING,
    TypeVar,
    Union,
    overload)

from chb.api.CallTarget import CallTarget, IndirectTarget
from chb.api.InterfaceDictionary import InterfaceDictionary

from chb.app.AppResultData import AppResultData
from chb.app.AppResultMetrics import AppResultMetrics
from chb.app.BDictionary import BDictionary
from chb.app.Callgraph import Callgraph, mk_tgt_callgraph_node, mk_app_callgraph_node
from chb.app.Function import Function
from chb.app.FunctionInfo import FunctionInfo
from chb.app.FunctionsData import FunctionsData
from chb.app.JumpTables import JumpTables
from chb.app.SystemInfo import SystemInfo
from chb.app.StringXRefs import StringsXRefs

from chb.bctypes.BCDictionary import BCDictionary
from chb.bctypes.BCFiles import BCFiles

from chb.elfformat.ELFHeader import ELFHeader

from chb.models.ModelsAccess import ModelsAccess

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.peformat.PEHeader import PEHeader

from chb.userdata.UserData import UserData

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.Instruction import Instruction

HeaderTy = TypeVar('HeaderTy', PEHeader, ELFHeader, Union[PEHeader, ELFHeader])


class AppAccess(ABC, Generic[HeaderTy]):
    def __init__(
            self,
            path: str,
            filename: str,
            fileformat: Type[HeaderTy],
            deps: List[str] = []) -> None:
        """Initializes access to analysis results."""
        self._path = path
        self._filename = filename
        self._deps = deps  # list of summary jars registered as dependencies
        self._header_ty: Type[HeaderTy] = fileformat  # currently supported: elf, pe

        self._userdata: Optional[UserData] = None

        self._header: Optional[HeaderTy] = None

        # functions
        self._appresultdata: Optional[AppResultData] = None
        self._functioninfos: Dict[str, FunctionInfo] = {}

        # callgraph
        self._callgraph: Optional[Callgraph] = None

        # summaries
        self.models = ModelsAccess(self.dependencies)

        # application-wide dictionaries
        self._bcdictionary: Optional[BCDictionary] = None
        self._bdictionary: Optional[BDictionary] = None
        self._interfacedictionary: Optional[InterfaceDictionary] = None
        self._bcfiles: Optional[BCFiles] = None

        self._systeminfo: Optional[SystemInfo] = None

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def path(self) -> str:
        return self._path

    @property
    def dependencies(self) -> Sequence[str]:
        return self._deps

    # Architecture and file format ---------------------------------------------

    @property
    def fileformat(self) -> str:
        return self._header_ty.fmt_name()

    @property
    def elf(self) -> bool:
        return self._header_ty == ELFHeader

    @property
    def pe(self) -> bool:
        return self._header_ty == PEHeader

    @property
    def is_mips(self) -> bool:
        return False

    @property
    def is_arm(self) -> bool:
        return False

    @property
    def is_x86(self) -> bool:
        return False

    # Dictionaries  ------------------------------------------------------------

    @property
    def bcdictionary(self) -> BCDictionary:
        if self._bcdictionary is None:
            x = UF.get_bcdictionary_xnode(self.path, self.filename)
            self._bcdictionary = BCDictionary(self, x)
        return self._bcdictionary

    @property
    def bdictionary(self) -> BDictionary:
        if self._bdictionary is None:
            x = UF.get_bdictionary_xnode(self.path, self.filename)
            self._bdictionary = BDictionary(self, x)
        return self._bdictionary

    @property
    def interfacedictionary(self) -> InterfaceDictionary:
        if self._interfacedictionary is None:
            x = UF.get_interface_dictionary_xnode(self.path, self.filename)
            self._interfacedictionary = InterfaceDictionary(self, x)
        return self._interfacedictionary

    @property
    def bcfiles(self) -> BCFiles:
        if self._bcfiles is None:
            x = UF.get_bc_files_xnode(self.path, self.filename)
            self._bcfiles = BCFiles(self, x)
        return self._bcfiles

    # File format --------------------------------------------------------------
    @property
    def header(self) -> HeaderTy:
        if self._header is None:
            x = self._header_ty.get_xnode(self.path, self.filename)
            self._header = self._header_ty(
                self.path, self.filename, x, self.dependencies)
        return self._header

    # Systeminfo ---------------------------------------------------------------

    @property
    def systeminfo(self) -> SystemInfo:
        if self._systeminfo is None:
            xinfo = UF.get_systeminfo_xnode(self.path, self.filename)
            self._systeminfo = SystemInfo(self.bdictionary, xinfo)
        return self._systeminfo

    @property
    def stringsxrefs(self) -> StringsXRefs:
        return self.systeminfo.stringsxrefs

    @property
    def jumptables(self) -> JumpTables:
        return self.systeminfo.jumptables

    # Functions ----------------------------------------------------------------

    @property
    def appresultdata(self) -> AppResultData:
        if self._appresultdata is None:
            x = UF.get_resultdata_xnode(self.path, self.filename)
            self._appresultdata = AppResultData(x)
        return self._appresultdata

    @property
    def appfunction_addrs(self) -> Sequence[str]:
        """Return a list of all application function addresses."""
        return self.appresultdata.function_addresses()

    def has_function(self, faddr: str) -> bool:
        return faddr in self.appfunction_addrs

    @property
    def functionsdata(self) -> FunctionsData:
        return self.systeminfo.functionsdata

    def has_function_name(self, faddr: str) -> bool:
        return self.systeminfo.has_function_name(faddr)

    def function_name(self, faddr: str) -> str:
        """Return one of the function names, if it has at least one."""

        return self.systeminfo.function_name(faddr)

    def function_names(self, faddr: str) -> Sequence[str]:
        """Return all function names."""

        return self.systeminfo.function_names(faddr)

    @property
    @abstractmethod
    def functions(self) -> Mapping[str, Function]:
        """Return a mapping of function address to function object."""
        ...

    def function(self, faddr: str) -> Function:
        """Return the function object object for the given address."""

        if faddr in self.functions:
            return self.functions[faddr]
        else:
            raise UF.CHBError("Function not found for " + faddr)

    def is_app_function_name(self, name: str) -> bool:
        return self.systeminfo.is_app_function_name(name)

    def is_unique_app_function_name(self, name: str) -> bool:
        return self.systeminfo.is_unique_app_function_name(name)

    def function_address_from_name(self, name: str) -> str:
        return self.systeminfo.function_address_from_name(name)

    def find_enclosing_function(self, iaddr: str) -> Optional[Function]:
        for f in self.functions.values():
            if f.has_instruction(iaddr):
                return f
        else:
            return None

    def function_info(self, faddr: str) -> FunctionInfo:
        if faddr not in self._functioninfos:
            xnode = UF.get_function_info_xnode(self.path, self.filename, faddr)
            self._functioninfos[faddr] = FunctionInfo(
                self.interfacedictionary, faddr, xnode)
        return self._functioninfos[faddr]

    # Instructions -----------------------------------------------------------

    def load_instructions(self) -> Mapping[str, Mapping[str, Sequence["Instruction"]]]:
        """Return a mapping from function address to block address to instructions."""

        result: Dict[str, Mapping[str, Sequence["Instruction"]]] = {}
        for (faddr, fn) in self.functions.items():
            if len(fn.load_instructions()) > 0:
                result[faddr] = fn.load_instructions()
        return result

    def store_instructions(self) -> Mapping[str, Mapping[str, Sequence["Instruction"]]]:
        """Return a mapping from function address to block address to instructions."""

        result: Dict[str, Mapping[str, Sequence["Instruction"]]] = {}
        for (faddr, fn) in self.functions.items():
            if len(fn.store_instructions()) > 0:
                result[faddr] = fn.store_instructions()
        return result

    def call_instructions(self) -> Mapping[str, Mapping[str, Sequence["Instruction"]]]:
        """Return a mapping from function address to block address to instructions."""

        result: Dict[str, Mapping[str, Sequence["Instruction"]]] = {}
        for (faddr, fn) in self.functions.items():
            if len(fn.call_instructions()) > 0:
                result[faddr] = fn.call_instructions()
        return result

    # Callgraph ----------------------------------------------------------------

    def callgraph(self) -> Callgraph:
        if self._callgraph is None:
            cg = Callgraph()
            callinstrs = self.call_instructions()
            for faddr in callinstrs:
                fname: Optional[str] = None
                if self.has_function_name(faddr):
                    fname = self.function_name(faddr)
                srcnode = mk_app_callgraph_node(faddr, fname)
                for baddr in callinstrs[faddr]:
                    for instr in callinstrs[faddr][baddr]:
                        calltgt = instr.call_target
                        if calltgt.is_indirect:
                            calltgt = cast(IndirectTarget, calltgt)
                            dstnodes = [
                                mk_tgt_callgraph_node(instr.iaddr, t)
                                for t in calltgt.targets]
                            for d in dstnodes:
                                cg.add_edge(srcnode, d)
                        else:
                            dstnode = mk_tgt_callgraph_node(instr.iaddr, calltgt)
                            cg.add_edge(srcnode, dstnode)
            self._callgraph = cg
        return self._callgraph

    # Address space ----------------------------------------------------------

    @property
    @abstractmethod
    def max_address(self) -> str:
        """Return the maximum address referenced in the image (in hex)."""
        ...

    # Global variables ---------------------------------------------------------

    def global_refs(self) -> Tuple[Mapping[str, Sequence[XVariable]],
                                   Mapping[str, Sequence[XXpr]]]:
        lhsresult = {}
        rhsresult = {}
        for (faddr, fn) in self.functions.items():
            (lhsgrefs, rhsgrefs) = fn.global_refs()
            if len(lhsgrefs) > 0:
                lhsresult[faddr] = lhsgrefs
            if len(rhsgrefs) > 0:
                rhsresult[faddr] = rhsgrefs
        return (lhsresult, rhsresult)

    # Misc ---------------------------------------------------------------------

    '''
    # returns a dictionary of faddr -> string list
    def get_strings(self):
        result = {}
        def f(faddr,fn):
            result[faddr] = fn.get_strings()
        self.iter_functions(f)
        return result


    def get_md5_profile(self):
        """Creates a dictionary of function md5s.

        Structure:
        -- md5hash -> faddr -> instruction count
        """
        result = {}
        def get_md5(faddr,f):
            md5 = f.get_md5_hash()
            result.setdefault(md5,{})
            result[md5][faddr] = mf = {}
            mf['instrs'] = f.get_instruction_count()
            if f.has_name(): mf['names'] = f.get_names()
        self.iter_functions(get_md5)
        profile = {}
        profile['path'] = self.path
        profile['filename'] = self.filename
        profile['imagebase'] = self.peheader.image_base
        profile['md5s'] = result
        return profile

    def get_calls_to_app_function(self,tgtaddr):
        """Returns a dictionary faddr -> Asm/MIPSInstruction list."""
        result = {}
        def f(faddr,fn):
            calls = fn.get_calls_to_app_function(tgtaddr)
            if len(calls) > 0:
                result[faddr] = calls
        self.iter_functions(f)
        return result

    def get_app_calls(self):
        """Returns a dictionary faddr -> Asm/MIPSInstruction."""
        result = {}
        def f(faddr,fn):
            appcalls = fn.get_app_calls()
            if len(appcalls) > 0:
                result[faddr] = appcalls
        self.iter_functions(f)
        return result

    def get_jump_conditions(self):
        """Returns a dictionary faddr -> iaddr -> { data }."""
        result = {}
        def f(faddr,fn):
            jumpconditions = fn.get_jump_conditions()
            if len(jumpconditions) > 0:
                result[faddr] = jumpconditions
        self.iter_functions(f)
        return result

    def get_call_instructions(self):
        """Returns a dictionary faddr -> Asm/MIPSInstruction."""
        result = {}
        def f(faddr,fn):
            appcalls = fn.get_call_instructions()
            if len(appcalls) > 0:
                result[faddr] = appcalls
        self.iter_functions(f)
        return result

    def get_dll_calls(self):
        result = {}
        def f(faddr,fn):
            dllcalls = fn.get_dll_calls()
            if len(dllcalls) > 0:
                result[faddr] = dllcalls
        self.iter_functions(f)
        return result

    def get_ioc_arguments(self):
        dllcalls = self.get_dll_calls()
        result = {}  # ioc -> role-name -> (faddr,iaddr,arg-value)
        problems = {}
        def setproblem(p,dll,fname,faddr,iaddr,params=None,args=None):
            problems.setdefault(p,{})
            problems[p].setdefault(dll,{})
            problems[p][dll].setdefault(fname,[])
            problems[p][dll][fname].append((faddr,iaddr,params,args))
        for faddr in dllcalls:
            for instr in dllcalls[faddr]:
                tgt = instr.get_call_target().get_stub()
                args =  instr.get_call_arguments()
                dll = tgt.get_dll()
                fname = tgt.get_name()
                if self.models.has_dll_summary(dll,fname):
                    summary =  self.models.get_dll_summary(dll,fname)
                    params = summary.get_stack_parameters()
                    if not params is None:
                        if len(args) == len(params):
                            for (param,arg) in zip(params,args):
                                iocroles = [r for r in param.roles() if r.is_ioc()]
                                for r in iocroles:
                                    ioc = r.get_ioc_name()
                                    result.setdefault(ioc,{})
                                    result[ioc].setdefault(r.name,[])
                                    result[ioc][r.name].append((faddr,instr.iaddr,arg))
                        else:  #  len(args) != len(params)
                            setproblem('argument mismatch',dll,fname,faddr,iaddr,
                                           params=len(params),args=len(args))
                    else:   # no parameters
                        setproblem('no parameters',dll,fname,faddr,instr.iaddr)
                else:  # no summary
                    setproblem('no summary',dll,fname,faddr,instr.iaddr)
        return (result,problems)

    def get_unresolved_calls(self):
        result = {}
        def f(faddr,fn):
            unrcalls = fn.get_unresolved_calls()
            if len(unrcalls) > 0:
                result[faddr] = unrcalls
        self.iter_functions(f)
        return result

    # Feature extraction -------------------------------------------------------

    def get_branch_predicates(self):
        result = {}
        def f(faddr,fn):
            predicates = fn.get_branch_predicates()
            if len(predicates) > 0:
                result[faddr] = predicates
        self.iter_functions(f)
        return result

    def get_structured_lhs_variables(self):
        result = {}
        def f(faddr,fn):
            lhsvars = fn.get_structured_lhs_variables()
            if len(lhsvars) > 0:
                result[faddr] = lhsvars
        self.iter_functions(f)
        return result

    def get_structured_lhs_instructions(self):
        result = {}
        def f(faddr,fn):
            lhsinstrs = fn.get_structured_lhs_instructions()
            if len(lhsinstrs) > 0:
                result[faddr] = lhsinstrs
        self.iter_functions(f)
        return result

    def get_structured_rhs_expressions(self):
        result = {}
        def f(faddr,fn):
            rhsxprs = fn.get_structured_rhs_expressions()
            if len(rhsxprs) > 0:
                result[faddr] = rhsxprs
        self.iter_functions(f)
        return result

    def get_return_expressions(self):
        result = {}
        def f(faddr,fn):
            retxprs = fn.get_return_expressions()
            if len(retxprs) > 0:
                result[faddr] = retxprs
        self.iter_functions(f)
        return result

    def get_fn_ioc_arguments(self):
        result = {}
        def f(faddr,fn):
            iocargs = fn.get_ioc_arguments()
            if len(iocargs) > 0:
                result[faddr] = iocargs
        self.iter_functions(f)
        return result

    # Global variables ---------------------------------------------------------

    # returns a dictionary of faddr -> gvar -> count
    def get_global_variables(self):
        result = {}
        def f(faddr,fn):
            result[faddr] = fn.get_global_variables()     # gvar -> count
        self.iter_functions(f)
        return result

    '''

    # Result Metrics -----------------------------------------------------------

    @property
    def result_metrics(self) -> AppResultMetrics:
        x = UF.get_resultmetrics_xnode(self.path, self.filename)
        h = UF.get_resultmetrics_xheader(self.path, self.filename)
        return AppResultMetrics(self.filename, x, h)

    # User data -----------------------------------------------------------

    @property
    def userdata(self) -> UserData:
        if self._userdata is None:
            x = UF.get_user_system_data_xnode(self.path, self.filename)
            self._userdata = UserData(x)
        return self._userdata
