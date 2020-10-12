# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

import chb.util.fileutil as UF

from chb.app.BDictionary import BDictionary
from chb.api.InterfaceDictionary import InterfaceDictionary
from chb.asm.X86Dictionary import X86Dictionary
from chb.mips.MIPSDictionary import MIPSDictionary

from chb.models.ModelsAccess import ModelsAccess

from chb.app.FunctionsData import FunctionsData
from chb.app.AppResultData import AppResultData
from chb.app.AppResultMetrics import AppResultMetrics
from chb.app.StringXRefs import StringsXRefs
from chb.app.JumpTable import JumpTable

from chb.userdata.UserData import UserData

from chb.peformat.PEHeader import PEHeader
from chb.elfformat.ELFHeader import ELFHeader

from chb.asm.AsmFunction import AsmFunction
from chb.mips.MIPSFunction import MIPSFunction
from chb.app.FunctionInfo import FunctionInfo

class  AppAccess(object):

    def __init__(self,path,filename,initialize=True,deps=[],mips=False):
        """Initializes access to analysis results."""
        self.path = path
        self.filename = filename
        self.deps = deps           # list of summary jars registered as dependencies
        self.mips = mips

        self.bdictionary = None          # BDictionary
        self.interfacedictionary = None  # InterfaceDictionary
        self.x86dictionary = None        # X86Dictionary
        self.mipsdictionary = None       # MIPSDictionary

        self.userdata = None             # UserData

        self.peheader = None
        self.elfheader = None

        self.resultdata = None     # AppResultData
        self.functions = {}        # faddr -> AsmFunction / MIPSFunction
        self.functioninfos = {}    # faddr -> FunctionInfo
        self.functionnames = None    # name -> function address

        self.models = ModelsAccess(self,dlljars=self.deps)
        
        if initialize and UF.has_bdictionary_file(self.path,self.filename):
            self._get_bdictionary()
            self._get_interface_dictionary()
            if self.mips:
                self._get_mips_dictionary()
            else:
                self._get_x86_dictionary()
            self._get_system_info()
            self._get_user_data()

    # Functions ----------------------------------------------------------------

    def get_function_addresses(self):
        self._get_results()
        return self.resultdata.get_function_addresses()

    def has_function(self,faddr):
        return faddr in self.get_function_addresses()

    def get_function(self,faddr):
        if not faddr in self.functions:
            xnode = UF.get_function_results_xnode(self.path,self.filename,faddr)
            if self.mips:
                self.functions[faddr] = MIPSFunction(self,xnode)
            else:
                self.functions[faddr] = AsmFunction(self,xnode)
        return self.functions[faddr]

    def has_function_name(self,faddr):
        return self.has_function(faddr) and self.get_function(faddr).has_name()

    def get_function_name(self,faddr):
        if self.has_function_name(faddr):
            return self.get_function(faddr).get_names()[0]

    def is_app_function_name(self,name):
        if self.functionnames is None: self._initialize_functionnames()
        return name in self.functionnames

    def is_unique_app_function_name(self,name):
        return (self.is_app_function_name(name)
                    and len(self.functionnames[name]) == 1)

    def get_app_function_address(self,name):
        if self.is_unique_app_function_name(name):
            return self.functionnames[name][0]

    def get_function_info(self,faddr):
        if not faddr in self.functioninfos:
            xnode = UF.get_function_info_xnode(self.path,self.filename,faddr)
            self.functioninfos[faddr] = FunctionInfo(self,xnode)
        return self.functioninfos[faddr]

    def iter_functions(self,f):
        for faddr in self.get_function_addresses():
            f(faddr,self.get_function(faddr))

    def find_function(self,iaddr):
        for faddr in self.get_function_addresses():
            f = self.get_function(faddr)
            if f.has_instruction(iaddr):
                return f
        return None

    # Misc ---------------------------------------------------------------------
    
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
        profile['imagebase'] = self.get_pe_header().get_image_base()
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
                                iocroles = [ r for r in param.get_roles() if r.is_ioc() ]
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


    # Result Metrics -----------------------------------------------------------

    def get_result_metrics(self):
        x = UF.get_resultmetrics_xnode(self.path,self.filename)
        h = UF.get_resultmetrics_xheader(self.path,self.filename)
        return AppResultMetrics(self,x,h)

    def get_result_metrics_summary(self):
        return self.get_result_metrics().summary()

    # PE data ------------------------------------------------------------------

    def get_pe_header(self):
        self._get_pe_header()
        return self.peheader

    # ELF data  ----------------------------------------------------------------

    def get_elf_header(self):
        self._get_elf_header()
        return self.elfheader

    # Initialization -----------------------------------------------------------

    def _get_pe_header(self):
        if self.peheader is None:
            x = UF.get_pe_header_xnode(self.path,self.filename)
            self.peheader = PEHeader(self,x)

    def _get_elf_header(self):
        if self.elfheader is None:
            x = UF.get_elf_header_xnode(self.path,self.filename)
            self.elfheader = ELFHeader(self,x)

    def _get_user_data(self):
        if self.userdata is None:
            x = UF.get_user_system_data_xnode(self.path,self.filename)
            self.userdata = UserData(self,x)

    def _get_bdictionary(self):
        if self.bdictionary is None:
            x = UF.get_bdictionary_xnode(self.path,self.filename)
            self.bdictionary = BDictionary(self,x)

    def _get_interface_dictionary(self):
        if self.interfacedictionary is None:
            x = UF.get_interface_dictionary_xnode(self.path,self.filename)
            self.interfacedictionary = InterfaceDictionary(self,x)

    def _get_x86_dictionary(self):
        if self.x86dictionary is None:
            x = UF.get_x86_dictionary_xnode(self.path,self.filename)
            self.x86dictionary = X86Dictionary(self,x)

    def _get_mips_dictionary(self):
        if self.mipsdictionary is None:
            x = UF.get_mips_dictionary_xnode(self.path,self.filename)
            self.mipsdictionary = MIPSDictionary(self,x)

    def _get_system_info(self):
        s = UF.get_systeminfo_xnode(self.path,self.filename)
        self.functionsdata = FunctionsData(self,s.find('functions-data'))
        self.stringxrefs = StringsXRefs(self,s.find('string-xreferences'))
        jtnode = s.find('jumptables')
        if not jtnode is None:
            self._get_jump_tables(jtnode)

    def _get_jump_tables(self,jtnode):
        for x in jtnode.findall('jt'):
            self.jumptables[ x.get('start') ] = JumpTable(self,x)

    def _get_results(self):
        if self.resultdata is None:
            x = UF.get_resultdata_xnode(self.path,self.filename)
            self.resultdata = AppResultData(self,x)

    def _initialize_functionnames(self):
        self.functionnames = {}
        def f(faddr,fn):
            if fn.has_name():
                fnames = fn.get_names()
                for fname in fnames:
                    self.functionnames.setdefault(fname,[])
                    self.functionnames[fname].append(faddr)
        self.iter_functions(f)
