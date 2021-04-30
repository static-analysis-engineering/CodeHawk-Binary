# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

import os
import xml.etree.ElementTree as ET
import zipfile

from typing import Dict, List, Optional, Set, TYPE_CHECKING

import chb.models.DllEnumDefinitions as E
import chb.models.DllFunctionSummary as DF
import chb.models.DllFunctionSummaryLibrary as DL
import chb.models.DllFunctionSummaryRef as DFR
import chb.models.FunctionSummary as F
import chb.models.FunctionSummaryLibrary as L
import chb.models.JniFunctionSummary as JF
import chb.models.JniFunctionSummaryLibrary as JL
import chb.models.SOFunctionSummary as SF
import chb.models.SOFunctionSummaryLibrary as SL

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.models.ModelsAccess


class SummaryCollection:
    """Represents all summary entities in a single jar file."""

    def __init__(
            self,
            models: "chb.models.ModelsAccess.ModelsAccess",
            jarfilename: str) -> None:
        self.models = models
        self._jarfilename = jarfilename
        self.jarfile = zipfile.ZipFile(self.jarfilename, "r")
        self._filenames: List[str] = []
        self._directorynames: List[str] = []
        self.dlllibraries: Dict[str, DL.DllFunctionSummaryLibrary] = {}
        self.solibraries: Dict[str, SL.SOFunctionSummaryLibrary] = {}
        self.jnilibraries: Dict[str, JL.JniFunctionSummaryLibrary] = {}
        self._dllenumdefinitions: Dict[str, E.DllEnumDefinitions] = {}

    @property
    def jarfilename(self) -> str:
        return self._jarfilename

    @property
    def filenames(self) -> List[str]:
        if len(self._filenames) == 0:
            for info in self.jarfile.infolist():
                self._filenames.append(info.filename)
        return self._filenames

    @property
    def directorynames(self) -> List[str]:
        if len(self._directorynames) == 0:
            result: Set[str] = set([])
            for f in self.filenames:
                result.add(os.path.dirname(f))
            self._directorynames = list(result)
        return self._directorynames

    @property
    def enumdefinitions(self) -> Dict[str, E.DllEnumDefinitions]:
        if len(self._dllenumdefinitions) == 0:
            for filename in self.filenames:
                if os.path.dirname(filename) == "constants":

                    # extract enum name from filename
                    basename = os.path.basename(filename)
                    enumname = ""
                    if basename.endswith("_constants.xml"):
                        enumname = basename[:-14]
                    elif basename.endswith("_flags.xml"):
                        enumname = basename[:-10]
                    elif basename.endswith("_types.xml"):
                        enumname = basename[:-10]
                    else:
                        continue
                    try:
                        xnode = self._get_summary_xnode(
                            filename, "symbolic-constants")
                        self._dllenumdefinitions[enumname] = E.DllEnumDefinitions(
                            self, enumname, xnode)
                    except Exception:
                        print("Problem with loading " + filename)
                        continue
                    else:
                        continue
        return self._dllenumdefinitions

    def has_dll_enum_definition(self, name: str) -> bool:
        return name in self.enumdefinitions

    def has_dll_enum_value(self, name: str, v: int) -> bool:
        if name in self.enumdefinitions:
            return self.enumdefinitions[name].has_name(v)
        return False

    def get_dll_enum_value(self, name: str, v: int) -> str:
        if self.has_dll_enum_value(name, v):
            return self.enumdefinitions[name].get_name(v)
        else:
            raise UF.CHBError("No name found for type "
                              + name
                              + " and value "
                              + str(v))

    def get_enum_constant(self, name: str, v: int) -> str:
        if self.has_dll_enum_value(name, v):
            return self.get_dll_enum_value(name, v)
        else:
            return str(v)

    def get_dll_enum_definition(self, name: str) -> Dict[str, E.DllEnumValue]:
        if self.has_dll_enum_definition(name):
            return self.enumdefinitions[name].constants
        return {}

    @property
    def dlls(self) -> List[str]:
        result: List[str] = []
        for d in self.directorynames:
            if d.endswith("_dll") or d.endswith("_drv"):
                result.append(d[:-4])
        return result

    @property
    def has_so_functions(self) -> bool:
        if "so_functions" in self.solibraries:
            return True
        if "so_functions" in self.directorynames:
            self.solibraries["so_functions"] = SL.SOFunctionSummaryLibrary(
                self, "so_functions", "so_functions")
            return True
        return False

    def has_dll(self, dll: str) -> bool:
        if dll in self.dlllibraries:
            return True
        else:
            filename1: str = dll.lower().replace(".", "_")
            filename2: str = filename1 + "_dll"
            if filename1 in self.directorynames:
                self.dlllibraries[dll] = DL.DllFunctionSummaryLibrary(
                    self, filename1, dll)
                return True
            if filename2 in self.directorynames:
                self.dlllibraries[dll] = DL.DllFunctionSummaryLibrary(
                    self, filename2, dll)
                return True
        return False

    def has_dll_function_summary(self, dll: str, fname: str) -> bool:
        if dll in self.dlllibraries or self.has_dll(dll):
            return self.dlllibraries[dll].has_function_summary(fname)
        else:
            return False

    def has_so_function_summary(self, fname: str) -> bool:
        if self.has_so_functions:
            return self.solibraries["so_functions"].has_function_summary(fname)
        return False

    def get_dll_function_summary(self, dll: str, fname: str) -> F.FunctionSummary:
        if dll in self.dlllibraries:
            return self.dlllibraries[dll].get_function_summary(fname)
        else:
            raise UF.CHBError("No function summary found for " + dll + ":" + fname)

    def get_so_function_summary(self, fname: str) -> F.FunctionSummary:
        return self.solibraries["so_functions"].get_function_summary(fname)

    def get_all_function_summaries_in_dll(self, dll: str) -> List[F.FunctionSummary]:
        if self.has_dll(dll):
            return self.dlllibraries[dll].get_all_function_summaries()
        else:
            return []

    def get_all_so_function_summaries(self) -> List[F.FunctionSummary]:
        if self.has_so_functions:
            return self.solibraries["so_functions"].get_all_function_summaries()
        else:
            return []

    def retrieve_function_summary(
            self,
            flib: L.FunctionSummaryLibrary,
            fname: str) -> Optional[F.FunctionSummary]:
        if flib.is_dll:
            return self.retrieve_dll_function_summary(flib, fname)
        elif flib.is_shared_object:
            return self.retrieve_so_function_summary(flib, fname)
        elif flib.is_jni:
            return self.retrieve_jni_function_summary(flib, fname)
        else:
            raise UF.CHBError("Library type of " + flib.name + " not recognized")

    def retrieve_ref_function_summary_xnode(
            self, kind: str, libname: str, fname: str) -> ET.Element:
        if kind == "dll":
            return self.retrieve_ref_dll_function_summary_xnode(libname, fname)
        elif kind == "so":
            return self.retrieve_ref_so_function_summary_xnode(libname, fname)
        elif kind == "jni":
            return self.retrieve_ref_jni_function_summary_xnode(libname, fname)
        else:
            raise UF.CHBError("Reference kind not recognized: "
                              + kind
                              + " for function summary "
                              + fname)

    def retrieve_all_function_summaries(
            self,
            flib: L.FunctionSummaryLibrary) -> List[F.FunctionSummary]:
        libdir = flib.directory
        result: List[F.FunctionSummary] = []
        for filename in self.filenames:
            if (os.path.dirname(filename) == libdir
                and filename.endswith(".xml")
                and not filename.endswith("_ordinal_table.xml")):
                xnode = self._get_summary_xnode(filename, flib.libfun_xmltag)
                if flib.is_dll:
                    xname = xnode.get("name")
                    if xname:
                        xreferto = xnode.find("refer-to")
                        if xreferto is not None:
                            dllsumref = DFR.DllFunctionSummaryRef(flib, xname, xnode)
                            result.append(dllsumref)
                        else:
                            dllsum = DF.DllFunctionSummary(flib, xname, xnode)
                            result.append(dllsum)
                if flib.is_shared_object:
                    xname = xnode.get("name")
                    if xname:
                        sosum = SF.SOFunctionSummary(flib, xname, xnode)
                        result.append(sosum)

        return result

    def retrieve_dll_function_summary(
            self,
            dll: L.FunctionSummaryLibrary,
            fname: str) -> Optional[F.FunctionSummary]:
        filename = os.path.join(dll.directory, fname + ".xml")
        if filename in self.filenames:
            xnode = self._get_summary_xnode(filename, "libfun")
            xreferto = xnode.find("refer-to")
            if xreferto is not None:
                return DFR.DllFunctionSummaryRef(dll, fname, xnode)
            else:
                return DF.DllFunctionSummary(dll, fname, xnode)
        else:
            return None

    def retrieve_ref_dll_function_summary_xnode(
            self, dll: str, fname: str) -> ET.Element:
        filename = os.path.join(dll + "_dll", fname + ".xml")
        if filename in self.filenames:
            return self._get_summary_xnode(filename, "libfun")
        else:
            raise UF.CHBError("Reference file not found for dll "
                              + dll
                              + " and function "
                              + fname)

    def retrieve_so_function_summary(
            self,
            sofunctions: L.FunctionSummaryLibrary,
            fname: str) -> Optional[F.FunctionSummary]:
        filename = os.path.join("so_functions", fname + ".xml")
        if filename in self.filenames:
            xnode = self._get_summary_xnode(filename, "libfun")
            return SF.SOFunctionSummary(sofunctions, fname, xnode)
        else:
            return None

    def retrieve_ref_so_function_summary_xnode(
            self, flib: str, fname: str) -> ET.Element:
        filename = os.path.join("so_functions", fname + ".xml")
        if filename in self.filenames:
            return self._get_summary_xnode(filename, "libfun")
        else:
            raise UF.CHBError("Reference file not found for so function "
                              + fname)

    def retrieve_jni_function_summary(
            self,
            jnilib: L.FunctionSummaryLibrary,
            index: str) -> Optional[F.FunctionSummary]:
        filename = os.path.join("jni", "jni_" + index + ".xml")
        if filename in self.filenames:
            xnode = self._get_summary_xnode(filename, "jnifun")
            return JF.JniFunctionSummary(jnilib, index, xnode)
        else:
            return None

    def retrieve_ref_jni_function_summary_xnode(
            self, flib: str, fname: str) -> ET.Element:
        # requires more elaborate matching
        raise UF.CHBError("Retrieval of jni references not implemented yet")

    def _get_summary_xnode(self, filename: str, tag: str) -> ET.Element:
        zfile = self.jarfile.read(filename).decode('utf-8')
        try:
            xnode = ET.fromstring(str(zfile)).find(tag)
        except ET.ParseError as e:
            raise UF.CHBError("Parse error in file summary file "
                              + filename
                              + ": "
                              + str(e))
        except UnicodeEncodeError as e:
            raise UF.CHBError('Unicode error in summary file '
                              + filename
                              + ": "
                              + str(e))
        if xnode:
            return xnode
        else:
            raise UF.CHBError('Unable to load summary for '
                              + filename
                              + ": "
                              + tag
                              + " not found")
