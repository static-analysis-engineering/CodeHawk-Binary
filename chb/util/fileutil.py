# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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
"""File Utilities.

All intermediate and final results are saved in xml/json files with
fixed names derived from the name of the executable. The functions
in this file parse the xml/json files and return the top functional
xml element of these files (xml) or the dicitionary (json). The filenames
themselves can be retrieved as well.

File-naming schema:

When an executable is analyzed two artefacts are created in the directory
of the executable named x:
- x.ch          a directory that holds all (intermediate) analysis results
- x.chx.tar.gz  a file that contains the executable content in xml form

The structure of the directory x.ch is:

analysis:
- a/x_functions.xml
    x_bcdict.xml            cil types
    x_bdict.xml             basic types
    x_ixdict.xml            interface types
    x_global_state.xml
    x_system_info.xml
    x_functions.jar
    x_asm.log
    x_orphan.log
    x_bdict.log
    functions/x_a/x_a_finfo.xml   for every function address a
                  x_a_vars.xml
                  x_a_invs.xml
                  x_a_tinvs.xml

artifacts obtained from parsed c files
- c/x_bc_files.xml
    functions/x_sub_a_bc.xml   for a function address a (without 0x)
    functions/x_name_bc.xml    for a given function name

results:
- r/x_app.xml
    x_results.xml
    functions/x_a.xml   for every function address a

executable content:
- x/x_section.xml    for every section in the executable
    x_pe_header.xml  (for PE files)
    x_elf_header.xml (for ELF files)
    x_info.json      (contains info about original executable file)

user data:
- u/x_system_info_u.xml
    classes/x_classname_cppclass_u.xml (optional, per classname)
    functions/x_a_u.xml (optional, per function address a)
    structconstants/x_structname_structconstant_u.xml  (optional)
    structs/x_structname_struct_u.xml (optional)

The user data is typically generated automatically from some json input files
or otherwise.

"""

import json
import os
import subprocess
import shutil
import xml.etree.ElementTree as ET

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from chb.util.Config import Config


config = Config()


class CHError(Exception):

    def __init__(self, msg: str) -> None:
        Exception.__init__(self, msg)
        self.msg = msg

    def wrap(self) -> str:
        lines: List[str] = []
        lines.append('*' * 80)
        lines.append(self.__str__())
        lines.append('*' * 80)
        return '\n'.join(lines)


class CHBError(CHError):

    def __init__(self, msg: str) -> None:
        CHError.__init__(self, msg)


class CHBAnalyzerNotFoundError(CHBError):

    def __init__(self, location: str) -> None:
        CHBError.__init__(self,
                          "Binary Analyzer executable not found at " + location)


class CHBFileNotFoundError(CHBError):

    def __init__(self, filename: str) -> None:
        CHBError.__init__(self, "File " + filename + " not found")
        self.filename = filename


class CHBDirectoryNotFoundError(CHBError):

    def __init__(self, dirname: str) -> None:
        CHBError.__init__(self, "Directory " + dirname + " not found")
        self.dirname = dirname


class CHBResultsFileNotFoundError(CHBError):

    def __init__(self, filename: str) -> None:
        self.filename = filename

    def __str__(self) -> str:
        return ("Results file: "
                + self.filename
                + " not found; please run analysis first")


class CHBExecutableContentNotFoundErro(CHBFileNotFoundError):

    def __init__(
            self,
            path: str,
            file: str,
            absfilename: str,
            tarfilename: str) -> None:
        CHBFileNotFoundError.__init__(self, absfilename)
        self.path = path
        self.file = file
        self.tarfilename = tarfilename

    def __str__(self) -> str:
        return (CHBFileNotFoundError.__str__(self)
                + "; no tar file found: ;"
                + self.tarfilename)


class CHBXmlParseError(CHBError):

    def __init__(
            self,
            filename: str,
            errorcode: int,
            position: Tuple[int, int]) -> None:
        CHBError.__init__(self, "Xml parse  error")
        self.filename = filename
        self.errorcode = errorcode
        self.position = position

    def __str__(self) -> str:
        return ("XML parse error in "
                + self.filename
                + " (errorcode: "
                + str(self.errorcode)
                + ") at position  "
                + str(self.position))


class CHBXmlRootElementNotFoundError(CHBError):

    def __init__(self, filename: str, roottag: str) -> None:
        self.filename = filename
        self.roottag = roottag

    def __str__(self) -> str:
        return ('Root element tag name: '
                + self.roottag
                + ' not found in file: '
                + self.filename)


class CHBJSONParseError(CHBError):

    def __init__(self, filename: str, e: Exception):
        CHBError.__init__(self, 'JSON parse error')
        self.filename = filename
        self.valueerror = e

    def __str__(self) -> str:
        return ("JSON parse error in file: "
                + self.filename
                + ": "
                + str(self.valueerror))


class CHBJSONFormatError(CHBError):

    def __init__(self, filename: str, msg: str) -> None:
        self.filename = filename
        self.msg = msg

    def __str__(self) -> str:
        return (self.msg + " in " + self.filename)


class CHBFunctionNotFoundError(CHBError):

    def __init__(self, filename: str, faddr: str) -> None:
        self.filename = filename
        self.faddr = faddr

    def __str__(self) -> str:
        return ('Function ' + self.faddr + " not found in " + self.filename)


class CHBSummaryNotFoundError(CHBError):

    def __init__(self, fname: str, dll: Optional[str] = None) -> None:
        self.fname = fname
        self.dll = dll

    def __str__(self) -> str:
        pdll: str = '' if self.dll is None else " in dll: " + self.dll
        return ("Summary not found: " + self.fname + pdll)


class CHBSummaryUnicodeDecodeError(CHBError):

    def __init__(self, dll: str, fname: str, error: str) -> None:
        self.dll = dll
        self.fname = fname
        self.error = error

    def __str__(self) -> str:
        return ("Unicode decode error in summary for "
                + self.dll
                + ":"
                + self.fname
                + ": "
                + str(self.error))


class CHBNotImplementedError(CHBError):

    def __init__(self, module: str, methodname: str, msg: str) -> None:
        self.module = module
        self.methodname = methodname
        self.msg = msg

    def __str__(self) -> str:
        return (
            self.module
            + ": "
            + self.methodname
            + " not yet implemented; "
            + self.msg)


def get_path_filename(name: str) -> Tuple[str, str]:
    """Returns the path and filename of the target executable indicated by name."""
    name = os.path.abspath(name)
    return (os.path.dirname(name), os.path.basename(name))


def get_command_processor() -> str:
    cmdlinedir = os.path.join(config.chbdir, "cmdline")
    return os.path.join(cmdlinedir, "chkx")


def check_executable(path: str, xfile: str) -> bool:
    """Returns true if executable content is available in xml (packed or unpacked).

    If content is available only in the gzipped tar file, content will be unpacked.
    """
    if not os.path.isdir(path):
        raise CHBError(
            "Directory: "
            + path
            + " for executable: "
            + xfile
            + " not found")

    # executable content has been extracted and unpacked
    xdir = get_executable_dir(path, xfile)
    if os.path.isdir(xdir):
        return True

    filename = os.path.join(path, xfile)
    # executable content has not yet been  extracted from executable
    if not os.path.isfile(get_executable_targz_filename(path, xfile)):
        if os.path.isfile(filename):
            return False
        else:
            raise CHBFileNotFoundError(filename)

    # try to unpack executable content
    return unpack_tar_file(path, xfile)


def has_analysis_results(path: str, xfile: str) -> bool:
    filename = get_resultmetrics_filename(path, xfile)
    return os.path.isfile(filename)


def has_asm_results(path: str, xfile: str) -> bool:
    filename = get_arm_asm_filename(path, xfile)
    return os.path.isfile(filename)


def check_analysis_results(path: str, xfile: str) -> None:
    """Raises an exception if analysis results are not present."""
    filename = get_resultmetrics_filename(path, xfile)
    if not os.path.isfile(filename):
        xfilename = os.path.join(path, xfile)
        raise CHBResultsFileNotFoundError(xfilename)
    return


def check_analyzer() -> None:
    """Raises an exception if the analyzer is not present"""
    if not os.path.isfile(config.chx86_analyze):
        raise CHBAnalyzerNotFoundError(config.chx86_analyze)


def get_locale_file() -> Dict[str, Any]:
    """Loads a file with table headers."""
    filename = os.path.join(config.utildir, "localetable.json")
    if not os.path.isfile(filename):
        raise CHBFileNotFoundError(filename)
    try:
        with open(filename, "r") as fp:
            return json.load(fp)
    except ValueError as e:
        raise CHBJSONParseError(filename, e)


def get_locale_tables(
        categories: List[str] = [],
        tables: List[Tuple[str, str]] = []) -> Dict[str, Any]:
    """Returns a dictionary with table headers."""
    result: Dict[str, Any] = {}
    localefile = get_locale_file()
    for c in categories:
        if c in localefile:
            for t in localefile[c]:
                result[t] = localefile[c][t]
    for (c, t) in tables:
        if c in localefile and t in localefile[c]:
            result[t] = localefile[c][t]
    return result


def get_summaries_dir() -> str:
    return config.summariesdir


def get_tests_dir() -> str:
    return config.testsdir


def get_ch_dir(path: str, xfile: str) -> str:
    return os.path.join(path, xfile + ".ch")


def get_analysis_dir(path: str, xfile: str) -> str:
    adir = os.path.join(path, xfile + ".ch")
    return os.path.join(adir, "a")


def get_executable_dir(path: str, xfile: str) -> str:
    xdir = os.path.join(path, xfile + ".ch")
    return os.path.join(xdir, "x")


def get_executable_targz_filename(path: str, xfile: str) -> str:
    return os.path.join(path, xfile + ".chx.tar.gz")


def get_c_dir(path: str, xfile: str) -> str:
    xdir = os.path.join(path, xfile + ".ch")
    return os.path.join(xdir, "c")


def get_c_functions_dir(path: str, xfile: str) -> str:
    return os.path.join(get_c_dir(path, xfile), "functions")


def get_results_dir(path: str, xfile: str) -> str:
    rdir = os.path.join(path, xfile + ".ch")
    return os.path.join(rdir, "r")


def get_statistics_dir(path: str, xfile: str) -> str:
    cdir = os.path.join(path, xfile + ".ch")
    sdir = os.path.join(cdir, "s")
    if not os.path.isdir(sdir):
        os.makedirs(sdir)
    return sdir


def get_userdata_dir(path: str, xfile: str) -> str:
    cdir = os.path.join(path, xfile + ".ch")
    return os.path.join(cdir, "u")


def get_userdata_structs_dir(path: str, xfile: str) -> str:
    udir = get_userdata_dir(path, xfile)
    return os.path.join(udir, "structs")


def has_extract(path: str, xfile: str) -> bool:
    return os.path.isfile(get_executable_targz_filename(path, xfile))


def has_results(path: str, xfile: str) -> bool:
    return os.path.isfile(get_resultmetrics_filename(path, xfile))


def get_chb_filename(fdir: str, xfile: str, suffix: str) -> str:
    xxfile = xfile.replace(".", "_")
    return os.path.join(fdir, xxfile + "_" + suffix)


def get_chb_function_filename(
        fdir: str,
        xfile: str,
        fname: str,
        suffix: str) -> str:
    xxfile = xfile.replace(".", "_")
    ffdir = os.path.join(fdir, "functions")
    ffdir = os.path.join(ffdir, xxfile + "_" + fname)
    return os.path.join(ffdir, xxfile + "_" + fname + "_" + suffix)


def get_chb_function_top_filename(
        fdir: str, xfile: str, fname: str, suffix: str) -> str:
    xxfile = xfile.replace(".", "_")
    ffdir = os.path.join(fdir, "functions")
    if not os.path.isdir(ffdir):
        os.makedirs(ffdir)
    return os.path.join(ffdir, xxfile + "_" + fname + suffix)


def get_chb_struct_top_filename(
        fdir: str, xfile: str, sname: str, suffix: str) -> str:
    xxfile = xfile.replace(".", "_")
    ffdir = os.path.join(fdir, "structs")
    if not os.path.isdir(ffdir):
        os.makedirs(ffdir)
    return os.path.join(ffdir, xxfile + "_" + sname + suffix)


def get_chb_xnode(filename: str, tagname: str) -> ET.Element:
    if os.path.isfile(filename):
        try:
            tree = ET.parse(filename)
            node = tree.getroot().find(tagname)
        except ET.ParseError as e:
            raise CHBXmlParseError(filename, e.code, e.position)
        if node is None:
            raise CHBXmlRootElementNotFoundError(filename, tagname)
        else:
            return node
    else:
        raise CHBFileNotFoundError(filename)


def get_chb_xheader(filename: str) -> ET.Element:
    return get_chb_xnode(filename, "header")


def get_chb_json(filename: str) -> Dict[str, Any]:
    if os.path.isfile(filename):
        try:
            with open(filename, "r") as fp:
                return json.load(fp)
        except ValueError as e:
            raise CHBJSONParseError(filename, e)
        except Exception as e:
            raise CHBError('Error in reading json file: '
                           + filename
                           + ': '
                           + str(e))
    else:
        raise CHBFileNotFoundError(filename)


def get_global_state_filename(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "global_state.xml")


def get_global_state_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_global_state_filename(path, xfile)
    return get_chb_xnode(filename, "global-state")


def get_systeminfo_filename(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "system_info.xml")


def get_systeminfo_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_systeminfo_filename(path, xfile)
    return get_chb_xnode(filename, "system-info")


def get_bcdictionary_filename(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "bcdict.xml")


def get_bcdictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_bcdictionary_filename(path, xfile)
    return get_chb_xnode(filename, "bcdictionary")


def get_bc_files_filename(path: str, xfile: str) -> str:
    fdir = get_c_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "bcfiles.xml")


def get_bc_files_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_bc_files_filename(path, xfile)
    return get_chb_xnode(filename, "bcfiles")


def get_bc_function_file_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_c_dir(path, xfile)
    return get_chb_function_top_filename(fdir, xfile, fname, "_bc.xml")


def get_bc_function_file_xnode(path: str, xfile: str, fname: str) -> ET.Element:
    filename = get_bc_function_file_filename(path, xfile, fname)
    return get_chb_xnode(filename, "bcfunction")


def get_bdictionary_filename(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "bdict.xml")


def has_bdictionary_file(path: str, xfile: str) -> bool:
    return os.path.isfile(get_bdictionary_filename(path, xfile))


def get_bdictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_bdictionary_filename(path, xfile)
    return get_chb_xnode(filename, "bdictionary")


def get_interface_dictionary_filename(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "ixdict.xml")


def get_interface_dictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_interface_dictionary_filename(path, xfile)
    return get_chb_xnode(filename, "interface-dictionary")


def get_functionsjar_filename(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "functions.jar")


def get_functions_dir(path: str, xfile: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return os.path.join(fdir, "functions")


def get_function_info_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_function_filename(fdir, xfile, fname, "finfo.xml")


def get_function_info_xnode(path: str, xfile: str, fname: str) -> ET.Element:
    filename = get_function_info_filename(path, xfile, fname)
    return get_chb_xnode(filename, "function-info")


def get_function_vars_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_function_filename(fdir, xfile, fname, "vars.xml")


def get_function_vars_xnode(path: str, xfile: str, fname: str) -> ET.Element:
    filename = get_function_vars_filename(path, xfile, fname)
    return get_chb_xnode(filename, "function")


def get_function_invs_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_function_filename(fdir, xfile, fname, "invs.xml")


def get_function_invs_xnode(path: str, xfile: str, fname: str) -> ET.Element:
    filename = get_function_invs_filename(path, xfile, fname)
    return get_chb_xnode(filename, "function")


def get_function_varinvs_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_analysis_dir(path, xfile)
    return get_chb_function_filename(fdir, xfile, fname, "varinvs.xml")


def get_function_varinvs_xnode(path: str, xfile: str, fname: str) -> ET.Element:
    filename = get_function_varinvs_filename(path, xfile, fname)
    return get_chb_xnode(filename, "function")


def get_pe_header_filename(path: str, xfile: str) -> str:
    fdir = get_executable_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "pe_header.xml")


def get_pe_header_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_pe_header_filename(path, xfile)
    return get_chb_xnode(filename, "pe-header")


def get_pe_section_filenames(path: str, xfile: str) -> List[str]:
    fdir = get_executable_dir(path, xfile)
    xxfile = xfile.replace(".", "_")
    prefix = xxfile + "_section"
    result: List[str] = []
    for f in os.listdir(fdir):
        if f.startswith(prefix):
            result.append(os.path.join(fdir, f))
    return result


def get_pe_section_xnodes(path: str, xfile: str) -> List[ET.Element]:
    result: List[ET.Element] = []
    filenames = get_pe_section_filenames(path, xfile)
    for f in filenames:
        result.append(get_chb_xnode(f, "raw-section"))
    return result


def get_elf_header_filename(path: str, xfile: str) -> str:
    fdir = get_executable_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "elf_header.xml")


def get_elf_header_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_elf_header_filename(path, xfile)
    return get_chb_xnode(filename, "elf-header")


def get_elf_dictionary_filename(path: str, xfile: str) -> str:
    fdir = get_executable_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "elf_dictionary.xml")


def get_elf_dictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_elf_dictionary_filename(path, xfile)
    return get_chb_xnode(filename, "elf-dictionary")


def get_elf_section_filename(path: str, xfile: str, index: str) -> str:
    fdir = get_executable_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "section_" + str(index) + ".xml")


def get_elf_section_xnode(path: str, xfile: str, index: str) -> ET.Element:
    filename = get_elf_section_filename(path, xfile, index)
    return get_chb_xnode(filename, "raw-section")


def get_x86_dictionary_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "x86dict.xml")


def get_x86_dictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_x86_dictionary_filename(path, xfile)
    return get_chb_xnode(filename, "x86dictionary")


def get_mips_dictionary_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "mipsdict.xml")


def get_mips_dictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_mips_dictionary_filename(path, xfile)
    return get_chb_xnode(filename, "mips-dictionary")


def get_mips_asm_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "mips_asm.xml")


def get_mips_asm_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_mips_asm_filename(path, xfile)
    return get_chb_xnode(filename, "mips-assembly-instructions")


def get_arm_dictionary_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "armdict.xml")


def get_arm_dictionary_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_arm_dictionary_filename(path, xfile)
    return get_chb_xnode(filename, "arm-dictionary")


def get_arm_dictionary_opcode_tests_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_arm_dictionary_filename(path, xfile)
    return get_chb_xnode(filename, "arm_opcode_strings")


def get_arm_asm_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "arm_asm.xml")


def get_arm_asm_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_arm_asm_filename(path, xfile)
    return get_chb_xnode(filename, "arm-assembly-instructions")


def get_resultmetrics_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "metrics.xml")


def get_resultmetrics_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_resultmetrics_filename(path, xfile)
    return get_chb_xnode(filename, "results")


def get_resultmetrics_xheader(path: str, xfile: str) -> ET.Element:
    filename = get_resultmetrics_filename(path, xfile)
    return get_chb_xheader(filename)


def get_resultdata_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "data.xml")


def get_resultdata_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_resultdata_filename(path, xfile)
    return get_chb_xnode(filename, "application-results")


def get_md5profile_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "md5.json")


def get_md5profile_json(path: str, xfile: str) -> Dict[str, Any]:
    filename = get_md5profile_filename(path, xfile)
    return get_chb_json(filename)


def get_xinfo_filename(path: str, xfile: str) -> str:
    fdir = get_executable_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "xinfo.json")


def get_xinfo_json(path: str, xfile: str) -> Dict[str, Any]:
    filename = get_xinfo_filename(path, xfile)
    return get_chb_json(filename)


def save_xinfo_json(path: str, xfile: str, d: Dict[str, Any]) -> None:
    filename = get_xinfo_filename(path, xfile)
    with open(filename, "w") as fp:
        json.dump(d, fp, indent=3)


def get_results_summary_filename(path: str, xfile: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "summary.json")


def save_results_summary(path: str, xfile: str, d: Dict[str, Any]) -> None:
    filename = get_results_summary_filename(path, xfile)
    with open(filename, "w") as fp:
        json.dump(d, fp, sort_keys=True, indent=3)


def get_function_results_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_results_dir(path, xfile)
    return get_chb_function_top_filename(fdir, xfile, fname, ".xml")


def get_function_results_xnode(path: str, xfile: str, fname: str) -> ET.Element:
    filename = get_function_results_filename(path, xfile, fname)
    return get_chb_xnode(filename, "application-results")


def get_user_system_data_filename(path: str, xfile: str) -> str:
    fdir = get_userdata_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "system_u.xml")


def get_user_system_data_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_user_system_data_filename(path, xfile)
    return get_chb_xnode(filename, "system-info")


def get_cfg_replacement_texts(path: str, xfile: str) -> Dict[str, Any]:
    fdir = get_userdata_dir(path, xfile)
    filename = get_chb_filename(fdir, xfile, "cfg_replacements.json")
    if os.path.isfile(filename):
        try:
            with open(filename, "r") as fp:
                d = json.load(fp)
        except ValueError as e:
            raise CHBJSONParseError(filename, e)
        return d
    return {}


def get_annotation_system_data_filename(path: str, xfile: str) -> str:
    fdir = get_userdata_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "system_a.xml")


def get_user_function_summary_filename(path: str, xfile: str, fname: str) -> str:
    fdir = get_userdata_dir(path, xfile)
    return get_chb_function_top_filename(fdir, xfile, fname, "_u.xml")


def get_user_function_summary_xnode(
        path: str,
        xfile: str,
        fname: str) -> ET.Element:
    filename = get_user_function_summary_filename(path, xfile, fname)
    return get_chb_xnode(filename, "function-summary")


def get_user_struct_filename(path: str, xfile: str, sname: str) -> str:
    fdir = get_userdata_dir(path, xfile)
    return get_chb_struct_top_filename(fdir, xfile, sname, "_struct_u.xml")


def get_ida_unresolved_calls_filename(path: str, xfile: str) -> str:
    fdir = get_userdata_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "unr_ida.xml")


def get_ida_unresolved_calls_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_ida_unresolved_calls_filename(path, xfile)
    return get_chb_xnode(filename, "functions")


def get_xref_filename(path: str, xfile: str, infotype: str) -> str:
    xxfile = xfile.replace(".", "_")
    udir = get_userdata_dir(path, xfile)
    return os.path.join(udir, xxfile + '_' + infotype + "_x.json")


def get_disassembly_statistics_filename(path: str, xfile: str) -> str:
    fdir = get_statistics_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "disassembly.xml")


def get_disassembly_statistics_xnode(path: str, xfile: str) -> ET.Element:
    filename = get_disassembly_statistics_filename(path, xfile)
    return get_chb_xnode(filename, "disassembly")


def get_features_filename(path: str, xfile: str) -> str:
    fdir = get_statistics_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "features.json")


def get_fn_features_filename(path: str, xfile: str) -> str:
    fdir = get_statistics_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "fn_features.json")


def get_fn_map_filename(path: str, xfile: str) -> str:
    fdir = get_statistics_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "fn_map.json")


def get_fn_featuremap_filename(path: str, xfile: str) -> str:
    fdir = get_statistics_dir(path, xfile)
    return get_chb_filename(fdir, xfile, "feature_map.json")


def get_summaries_list() -> Dict[str, Any]:
    """Get function summaries from file."""
    summariesfile = os.path.join(get_summaries_dir(), "summaries.json")
    if os.path.isfile(summariesfile):
        try:
            with open(summariesfile, "r") as fp:
                return json.load(fp)
        except ValueError as e:
            raise CHBJSONParseError(summariesfile, e)
        except Exception as e:
            raise CHBError("Error in reading summaries list")
    return {}


def unpack_tar_file(path: str, xfile: str) -> bool:
    """Unzip tar file."""
    xdir = get_executable_dir(path, xfile)
    targzfile = get_executable_targz_filename(path, xfile)

    # tar.gz file has already been extracted
    if os.path.isdir(xdir):
        return True

    # there is no tar.gz file
    if not (os.path.isfile(targzfile)):
        return False

    # unpack the tar.gz.file
    cwd = os.getcwd()
    os.chdir(path)              # temporary change in directory
    cmd: List[str] = ["tar", "xfz", targzfile]
    result = subprocess.call(cmd, cwd=path, stderr=subprocess.STDOUT)
    os.chdir(cwd)
    if result != 0:
        raise CHBError(
            "Error in extracting tar.gz file: "
            + " ".join(cmd)
            + ". return code: "
            + str(result))
    else:
        print('Successfully extracted ' + targzfile)
    return os.path.isdir(xdir)


def file_has_registered_options(md5: str) -> bool:
    for f in config.commandline_options:
        filename = config.commandline_options[f]
        if os.path.isfile(filename):
            try:
                with open(filename, "r") as fp:
                    options = json.load(fp)
                if md5 in options:
                    return True
            except Exception as e:
                print("*" * 80)
                print("Error reading options file " + filename + ": " + str(e))
                print("*" * 80)
                exit(1)
            else:
                pass
        else:
            print("*" * 80)
            print("Registered option file " + filename + " not found")
            print("*" * 80)
            exit(1)
    return False


def file_has_registered_userdata(md5: str) -> bool:
    for f in config.registered_userdata:
        filename = config.registered_userdata[f]
        if os.path.isfile(filename):
            try:
                with open(filename, "r") as fp:
                    userdatafile = json.load(fp)
                if "executables" in userdatafile:
                    xuserdata = userdatafile["executables"]
                    if md5 in xuserdata:
                        return True
            except Exception as e:
                print("*" * 80)
                print(
                    "Error reading userdata file "
                    + filename
                    + ": "
                    + str(e))
                print("*" * 80)
                exit(1)
            else:
                pass
        else:
            print("*" * 80)
            print("Registered userdata file " + filename + " not found")
            print("*" * 80)
            exit(1)
    return False


def get_file_registered_options(md5: str) -> Dict[str, Any]:
    if file_has_registered_options(md5):
        for f in config.commandline_options:
            filename = config.commandline_options[f]
            with open(filename, "r") as fp:
                options = json.load(fp)
            if md5 in options:
                return options[md5]
            else:
                pass
        else:
            print("*" * 80)
            print("Error in getting registered options for " + md5)
            print("*" * 80)
            exit(1)
    else:
        print("*" * 80)
        print("No registered options found for " + md5)
        print("*" * 80)
        exit(1)


def get_file_registered_userdata(md5: str) -> Dict[str, Any]:
    if file_has_registered_userdata(md5):
        for f in config.registered_userdata:
            filename = config.registered_userdata[f]
            with open(filename, "r") as fp:
                userdatafile = json.load(fp)
            if md5 in userdatafile["executables"]:
                xuserdata = userdatafile["executables"][md5]
                if "userdata" in xuserdata:
                    return xuserdata["userdata"]
                else:
                    return {}
            else:
                pass
        else:
            print("*" * 80)
            print("Error in getting registered userdata for " + md5)
            print("*" * 80)
            exit(1)
    else:
        print("*" * 80)
        print("No registered userdata found for " + md5)
        print("*" * 80)
        exit(1)

    return {}


def get_simsupport(kind: str, tag: str) -> Dict[str, Any]:
    if kind in config.simulation_support:
        filename = config.simulation_support[kind]
        if os.path.isfile(filename):
            try:
                with open(filename, "r") as fp:
                    simsupport = json.load(fp)
            except Exception as e:
                raise CHBError("Error loading " + filename + ": " + str(e))

            if tag in simsupport["simsupport"]:
                return simsupport["simsupport"][tag]
            else:
                raise CHBError(
                    "File " + filename + " does not provide data for " + tag)
        else:
            raise CHBError(
                "File " + filename + " not found")
    else:
        raise CHBError(
            "No simulation support file found for " + kind)


def get_tests() -> Mapping[str, Mapping[str, Mapping[str, Sequence[str]]]]:
    testsdir = get_tests_dir()
    x86dir = os.path.join(testsdir, "x86")
    arm32dir = os.path.join(testsdir, "arm32")
    mips32dir = os.path.join(testsdir, "mips32")
    x86pedir = os.path.join(x86dir, "pe")
    x86elfdir = os.path.join(x86dir, "elf")
    arm32elfdir = os.path.join(arm32dir, "elf")
    mips32elfdir = os.path.join(mips32dir, "elf")

    result: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
    """Returns a dictionary of architecture, fileformat, suite, test."""

    result["x86"] = {}
    result["arm32"] = {}
    result["mips32"] = {}
    result["x86"]["pe"] = {}
    result["x86"]["elf"] = {}
    result["arm32"]["pe"] = {}
    result["arm32"]["elf"] = {}
    result["mips32"]["pe"] = {}
    result["mips32"]["elf"] = {}

    for suite in os.listdir(x86pedir):
        result["x86"]["pe"][suite] = []
        for test in os.listdir(os.path.join(x86pedir, suite)):
            if test.endswith("chx.tar.gz"):
                result["x86"]["pe"][suite].append(test[:-11])
    for suite in os.listdir(x86elfdir):
        result["x86"]["elf"][suite] = []
        for test in os.listdir(os.path.join(x86elfdir, suite)):
            if test.endswith("chx.tar.gz"):
                result["x86"]["elf"][suite].append(test[:-11])
    for suite in os.listdir(arm32elfdir):
        result["arm32"]["elf"][suite] = []
        for test in os.listdir(os.path.join(arm32elfdir, suite)):
            if test.endswith("chx.tar.gz"):
                result["arm32"]["elf"][suite].append(test[:-11])

    return result


def get_test_filename(
        arch: str,
        fileformat: str,
        suite: str,
        test: str,
        fullnames: bool = False) -> str:
    """Return absolute filename, given suite and test numbers only."""

    testsdir = get_tests_dir()

    archdir = os.path.join(testsdir, arch)
    ffdir = os.path.join(archdir, fileformat)

    if fullnames:
        suitedir = os.path.join(ffdir, suite)
    else:
        suitedir = os.path.join(ffdir, "suite_" + suite)

    if fullnames:
        testname = test
    else:
        if fileformat == "pe":
            testname = "test_" + test + ".exe"
        else:
            testname = "test_" + test

    testfilename = os.path.join(suitedir, testname)
    if os.path.isfile(testfilename):
        return testfilename
    else:
        raise CHBError("Requested testfile: " + testfilename + " not found")


def save_test_files(
        desc: str,
        arch: str,
        fileformat: str,
        suite: str,
        test: str,
        files: Mapping[str, str],
        xinfo: Mapping[str, str]) -> str:

    testsdir = get_tests_dir()

    archdir = os.path.join(testsdir, arch)
    ffdir = os.path.join(archdir, fileformat)
    suitedir = os.path.join(ffdir, "suite_" + suite)

    if fileformat == "pe":
        testname = "test_" + test + ".exe"
    else:
        testname = "test_" + test

    testdir = os.path.join(suitedir, testname + ".ch")
    if os.path.isdir(testdir):
        raise CHBError("Test directory already exists. Quit")

    testfilename = os.path.join(suitedir, testname)
    with open(testfilename, "w") as fp:
        fp.write(testname + ": " + desc)

    xdir = os.path.join(testdir, "x")
    os.makedirs(xdir)

    for (name, content) in files.items():
        filename = os.path.join(xdir, name)
        with open(filename, "w") as fp:
            fp.write(content)

    xinfoname = os.path.join(xdir, testname + "_xinfo.json")
    with open(xinfoname, "w") as fp:
        json.dump(xinfo, fp, indent=2)

    cwd = os.getcwd()
    os.chdir(suitedir)   # temporary change directory
    targzfile = testname + ".chx.tar.gz"
    cmd: List[str] = ["tar", "cfz", targzfile, testname + ".ch"]
    result = subprocess.call(cmd, cwd=suitedir, stderr=subprocess.STDOUT)
    os.chdir(cwd)
    return (
        "Saved "
        + ", ".join(files.keys())
        + " and "
        + xinfoname
        + " and "
        + targzfile)
