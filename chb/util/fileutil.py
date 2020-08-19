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

"""File Utilities.

All intermediate and final results are saved in xml/json files with
fixed names derived from the name of the executable. The functions
in this file parse the xml/json files and return the top functional
xml element of these files (xml) or the dicitionary (json). The filenames
themselves can be retrieved as well.
"""

import json
import os
import subprocess
import shutil
import xml.etree.ElementTree as ET

from chb.util.Config import Config

config = Config()

class CHError(Exception):

    def wrap(self):
        lines = []
        lines.append('*' * 80)
        lines.append(self.__str__())
        lines.append('*' * 80)
        return '\n'.join(lines)

class CHBError(CHError):

    def __init__(self,msg):
        CHError.__init__(self,msg)

class CHBAnalyzerNotFoundError(CHBError):

    def __init__(self,location):
        CHBError.__init__(self,'Binary Analyzer executable not found at ' + location)

class CHBFileNotFoundError(CHBError):

    def __init__(self,filename):
        CHBError.__init__(self,'File ' + filename + ' not found')
        self.filename = filename

class CHBDirectoryNotFoundError(CHBError):

    def __init__(self,dirname):
        CHBError.__init__(self,'Directory ' + dirname + ' not found')
        self.dirname = dirname

class CHBResultsFileNotFoundError(CHBError):

    def __init__(self,filename):
        self.filename = filename

    def __str__(self):
        return ('Results file: ' +  self.filename + ' not found; please run analysis first')

class CHBExecutableContentNotFoundErro(CHBFileNotFoundError):

    def __init__(self,path,file,absfilename,tarfilename):
        CHBFileNotFoundError.__init__(self,absfilename)
        self.path = path
        self.file = file
        self.tarfilename = tarfilename

    def __str__(self):
        return (CHBFileNotFoundError.__str__(self)
                    + '; no tar file found: ;' + self.tarfilename)

class CHBXmlParseError(CHBError):

    def __init__(self,filename,errorcode,position):
        CHBError.__init__(self,'Xml parse  error')
        self.filename = filename
        self.errorcode = errorcode
        self.position = position

    def __str__(self):
        return ('XML parse error in ' + filename + ' (errorcode: '
                    + str(self.errorcode) + ') at position  '
                    + str(self.position))

class CHBXmlRootElementNotFoundError(CHBError):

    def __init__(self,filename,roottag):
        self.filename = filename
        self.roottag = roottag

    def __str__(self):
        return ('Root element tag name: ' + self.roottag
                    + ' not found in file: ' + self.filename)

class CHBJSONParseError(CHBError):

    def __init__(self,filename,e):
        CHBError.__init__(self,'JSON parse error')
        self.filename = filename
        self.valueerror = e

    def __str__(self):
        return ('JSON parse error in file: ' + self.filename + ': '
                    + str(self.valueerror))

class CHBJSONFormatError(CHBError):

    def __init__(self,filename,msg):
        self.filename = filename
        self.msg = msg

    def __str__(self):
        return (self.msg + ' in ' + self.filename)

class CHBFunctionNotFoundError(CHBError):

    def __init__(self,filename,faddr):
        self.filename = filename
        self.faddr = faddr

    def __str__(self):
        return ('Function ' + self.faddr + ' not found in ' + self.filename)

class CHBSummaryNotFoundError(CHBError):

    def __init__(self,fname,dll=None):
        self.fname = fname
        self.dll = dll

    def __str__(self):
        pdll = '' if dll is None else ' in dll: ' + dll
        return ('Summary not found: ' + self.fname + pdll)

class CHBSummaryUnicodeDecodeError(CHBError):

    def __init__(self,dll,fname,error):
        self.dll = dll
        self.fname = fname
        self.error = error

    def __str__(self):
        return ('Unicode decode error in summary for ' + self.dll + ':'
                    + self.fname + ': ' + str(self.error))

class CHBShortCutNameError(CHBError):

    def __init__(self,name):
        CHBError.__init__(self,'Expected the separator '
                              + config.atsc_separator
                              + ' in short-cut name: ' + name)

class CHBArchitectureIndexNotFoundError(CHBError):

    def __init__(self,arch):
        self.arch = arch

    def __str__(self):
        return ('No analysis target index file found for architecture: '
                    + arch)

class CHBAnalysisTargetFileIndexNotFoundError(CHBError):

    def __init__(self,arch,index):
        self.arch = arch
        self.index = index

    def __str__(self):
        return ('Analysis target file index: ' + self.index
                    + ' not found for architecture: ' + self.arch)
        

class CHBAnalysisTargetIndexFileNotFoundError(CHBFileNotFoundError):

    def __init__(self,filename):
        CHBFileNotFoundError.__init__(self,filename)

    def  __str__(self):
        return ('Analysis target index file: ' + self.filename
                    + ' not found')

class CHBAnalysisTargetExecutableIndexNotFoundError(CHBError):

    def __init__(self,filename,atxi):
        self.filename = filename
        self.atxi =  atxi

    def __str__(self):
        return ('Index: ' + self.atxi
                    + ' not found in analysis target index file: '
                    + self.filename)


# Retrieve path and filename of executable -------------------------------------
#
# Short-cut names
# ---------------
# analysistargettable: architecture -> analysistargetindex (in ConfigLocal.py)
# analysistargetindex: atfi (analysis-target-file-index) -> ati_filename
#
# the ati_filename points to the ati-file:
# ati-file: atxi (analysis-target-executable-index) -> analysis-target-record
#
# analysis-target-record:
#  - 'file': filename of the analysis target (executable)
#  - 'path': path to the analysis target (relative to the path of the ati-file)
#  - 'md5' : md5 hash of the analysis target
#  - ..... (other meta data, as convenient)
#
# a short-cut name (atsc) is specified as
#     <atfi><atsc-separator><atxi>, e.g.: mw:V001, assuming ':'
# as atsc-separator.
# the <atfi>  can be omitted if the atfi is 'default', that is,
#    default:bind9 can be written as :bind9
#
# 
# ------------------------------------------------------------------------------

def get_analysis_target_index(arch):
    """Returns the dictionary indexed by arch in the analysistargettable."""
    return config.analysistargettable.get(arch,{})

def get_atfi_executables(arch,atfi):
    """Returns a dictionary: atxi -> xrecord, obtained from the analysis target index."""
    ati = get_analysis_target_index(arch)
    if atfi in ati:
        ati_filename = ati[atfi]
        if os.path.isfile(ati_filename):
            try:
                with open(ati_filename,'r') as fp:
                    d = json.load(fp)
            except ValueError as e:
                raise CHBJSONParseError(ati_filename,e)
            if 'executables' in d:
                return d['executables']
    return {}

def get_analysis_target_executables(arch):
    """Returns a dictionary: atfi -> (ati_filepath,atxi->xrecord)."""
    ati = get_analysis_target_index(arch)
    result = {}
    for atfi in ati:
        result[atfi] = (os.path.dirname(ati[atfi]),
                            get_atfi_executables(arch,atfi))
    return result

def get_analysis_target_executables_to_string(arch,sortby=None):
    """Returns a formatted string that lists all executables with their status."""
    d = get_analysis_target_executables(arch)
    lines = []
    for atfi in d:
        (basepath,xindex) = d[atfi]
        if len(xindex) == 0: continue

        lines.append('-' * 80)
        lines.append(atfi + ': ' + basepath)
        lines.append('-' * 80)
        maxnamelen = max([ len(str(x)) for x in xindex ]) + 3
        atxis = sorted(xindex.keys())
        if sortby == 'size':
            atxis = sorted(atxis,key=lambda x:int(xindex[x]['size']))
        for x in atxis:
            xrec = xindex[x]
            path = os.path.join(basepath,xrec['path']) if 'path' in xrec else basepath
            xfile = xrec['file']
            xsize = str(xrec['size']) if 'size' in xrec else '?'
            hasextract = '+'.center(10) if has_extract(path,xfile) else ' '.ljust(10)
            hasresults = '+'.center(10) if has_results(path,xfile) else ' '.ljust(10)
            clusters = ' (' + ','.join(c for c in xrec['clusters']) + ')' if 'clusters' in xrec else ''
            rfilename = os.path.join(xrec['path'],xrec['file'])
            lines.append('  ' + x.ljust(maxnamelen) + hasextract
                             + hasresults + xsize.rjust(10)
                             + '  ' + rfilename  + clusters)
    return '\n'.join(lines)

def is_atsc(name):
    """Returns true if the name is a valid shortcut name."""
    return name.count(config.atsc_separator) == 1

def mk_atsc(atfi,atxi):
    """Returns a fully qualified shortcut name."""
    return atfi + config.atsc_separator + atxi

def get_atfi(atsc):
    """Returns the analysis target file index from a shortcut name."""
    if is_atsc(atsc):
        return atsc.split(config.atsc_separator)[0]
    raise CHBShortCutNameError(atsc)

def get_atxi(atsc):
    """Returns the analysis target executable index from a shortcut name."""
    if is_atsc(atsc):
        return atsc.split(config.atsc_separator)[1]
    raise CHBShortCutNameError(atsc)

def get_analysis_target_index_filename(arch,atfi):
    "Returns the filename associated with index atfi for architecture arch."""
    analysistargettable = config.analysistargettable
    if not arch in analysistargettable:
        raise CHBAnalysisTargetFileIndexNotFoundError(arch)
    analysistargetindex = analysistargettable[arch]
    if not atfi in analysistargetindex:
        raise CHBAnalysisTargetFileIndexNotFoundError(arch,atfi)
    analysistargetindexfilename = analysistargetindex[atfi]
    if os.path.isfile(analysistargetindexfilename):
        return analysistargetindexfilename
    raise CHBAnalysisTargetIndexFileNotFoundError(analysistargetindexfilename)

def get_path_file_record(arch,name):
    """Returns the basepath and record associated with  the shortcut name for architecture arch"""
    atfi_atxi = name.split(config.atsc_separator)
    if not len(atfi_atxi) == 2:
        raise CHBShortCutNameError(name)
    atfi = atfi_atxi[0]
    atxi = atfi_atxi[1]
    if atfi == '': atfi = 'default'
    filename = get_analysis_target_index_filename(arch,atfi)
    try:
        with open(filename,'r') as fp:
            analysistargetindex = json.load(fp)
    except ValueError as e:
        raise CHBJSONParseError(filename,e)
    if not 'executables' in analysistargetindex:
        raise CHBJSONFormatError(filename,'Expected to find key: executables')
    if atxi in analysistargetindex['executables']:
        return (os.path.dirname(filename),analysistargetindex['executables'][atxi])
    else:
        raise CHBAnalysisTargetExecutableIndexNotFoundError(filename,atxi)

def get_path_filename(arch,name):
    """Returns the path and filename of the target executable indicated by name."""
    if is_atsc(name):
        (path,frec) = get_path_file_record(arch,name)
        return (os.path.join(path,frec['path']),frec['file'])
    else:
        name = os.path.abspath(name)
        return (os.path.dirname(name),os.path.basename(name))

def get_path_filename_deps(arch,name):
    """Returns the path, filename, and dependencies of the target executable indicated by name."""
    def get_dependencies(path,frec): return  []    # TODO
    if is_atsc(name):
        (path,frec) = get_path_file_record(arch,name)
        deps = get_dependencies(path,frec)
        return (os.path.join(path,frec['path']),frec['file'],deps)
    else:
        name = os.path.abspath(name)
        return (os.path.dirname(name),os.path.basename(name),[])

# Check presence of executable content -----------------------------------------

def check_executable(path,xfile):
    """Returns true if executable content is available in xml (packed or unpacked).

    If content is available only in the gzipped tar file, content will be unpacked.
    """
    if not os.path.isdir(path):
        raise CHBError('Directory: ' + path + ' for executable: ' + xfile
                           + ' not found')

    # executable content has been extracted and unpacked
    xdir = get_executable_dir(path,xfile)
    if os.path.isdir(xdir):
        return True

    filename =  os.path.join(path,xfile)
    # executable content has not yet been  extracted from executable
    if not os.path.isfile(get_executable_targz_filename(path,xfile)):
        if os.path.isfile(filename):
            return False
        else:
            raise CHBFileNotFoundError(filename)

    # try to unpack executable content
    return unpack_tar_file(path,xfile)

# Check presence of analysis results ------------------------------------------

def check_analysis_results(path,xfile):
    """Raises an exception if analysis results are not present."""
    filename = get_resultmetrics_filename(path,xfile)
    if not os.path.isfile(filename):
        xfilename = os.path.join(path,xfile)
        raise CHBResultsFileNotFoundError(xfilename)
    return

# Check presence of analyzer ---------------------------------------------------

def check_analyzer():
    if not os.path.isfile(config.chx86_analyze):
        raise CHBAnalyzerNotFoundError(config.chx86_analyze)

# Locale table -----------------------------------------------------------------

def get_locale_file():
    filename = os.path.join(config.utildir,'localetable.json')
    if not os.path.isfile(filename):
        raise CHBFileNotFoundError(filename)
    try:
        with open(filename,'r') as fp:
            return json.load(fp)
    except ValueError as e:
        raise CHBJSONParseError(filename,e)

def get_locale_tables(categories=[],tables=[]):
    result = {}
    localefile = get_locale_file()
    for c in categories:
        if c in localefile:
            for t in localefile[c]:
                result[t] = localefile[c][t]
    for (c,t) in tables:
        if c in localefile and t in localefile[c]:
            result[t] = localefile[c][t]
    return result

# Directory names --------------------------------------------------------------

def get_summaries_dir():
    return config.summariesdir

def get_ch_dir(path,xfile):
    return os.path.join(path,xfile  + '.ch')

def get_analysis_dir(path,xfile):
    adir = os.path.join(path,xfile + '.ch')
    return os.path.join(adir,'analysis')

def get_executable_dir(path,xfile):
    xdir = os.path.join(path,xfile + '.ch')
    return os.path.join(xdir,'x')

def get_executable_targz_filename(path,xfile):
    return os.path.join(path,xfile + '.chx.tar.gz')

def get_results_dir(path,xfile):
    rdir = os.path.join(path,xfile + '.ch')
    return os.path.join(rdir,'results')

def get_statistics_dir(path,xfile):
    statsdir = os.path.join(path,xfile + '.chs')
    if not os.path.isdir(statsdir):
        os.makedirs(statsdir)
    return statsdir

def get_userdata_dir(path,xfile):
    return os.path.join(path,xfile + '.chu')

def has_extract(path,xfile):
    return os.path.isfile(get_executable_targz_filename(path,xfile))

def has_results(path,xfile):
    return os.path.isfile(get_resultmetrics_filename(path,xfile))

# Generic file names and file formats

def get_chb_filename(fdir,xfile,suffix):
    xxfile = xfile.replace('.','_')
    return os.path.join(fdir,xxfile + '_' + suffix)

def get_chb_function_filename(fdir,xfile,fname,suffix):
    xxfile = xfile.replace('.','_')
    ffdir = os.path.join(fdir,'functions')
    ffdir = os.path.join(ffdir,xxfile  + '_' + fname)
    return os.path.join(ffdir,xxfile + '_' + fname + '_' + suffix)

def get_chb_function_top_filename(fdir,xfile,fname,suffix):
    xxfile = xfile.replace('.','_')
    ffdir = os.path.join(fdir,'functions')
    return os.path.join(ffdir,xxfile + '_' + fname + suffix)

def get_chb_xnode(filename,tagname):
    if os.path.isfile(filename):
        try:
            tree = ET.parse(filename)
            node = tree.getroot().find(tagname)
        except ET.ParseError as e:
            raise CHBXmlParseError(filename,e.code,e.position)
        if node is None:
            raise CHBXmlRootElementNotFoundError(filename,tagname)
        else:
            return node
    else:
        raise CHBFileNotFoundError(filename)

def get_chb_xheader(filename): return get_chb_xnode(filename,'header')

def get_chb_json(filename):
    if os.path.isfile(filename):
        try:
            with open(filename,'r') as fp:
                return json.load(fp)
        except ValueError as e:
            raise CHBJSONParseError(filename,e)
        except Exception as e:
            raise CHBError('Error in reading json file: '  + filename
                               + ': ' + str(e))
    else:
        raise CHBFileNotFoundError(filename)

# Analysis directory -----------------------------------------------------------

def get_global_state_filename(path,xfile):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'global_state.xml')

def get_global_state_xnode(path,xfile):
    filename = get_global_state_filename(path,xfile)
    return get_chb_xnode(filename,'global-state')

def get_systeminfo_filename(path,xfile):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'system_info.xml')

def get_systeminfo_xnode(path,xfile):
    filename = get_systeminfo_filename(path,xfile)
    return get_chb_xnode(filename,'system-info')

def get_bdictionary_filename(path,xfile):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'bdict.xml')

def has_bdictionary_file(path,xfile):
    return os.path.isfile(get_bdictionary_filename(path,xfile))

def get_bdictionary_xnode(path,xfile):
    filename = get_bdictionary_filename(path,xfile)
    return get_chb_xnode(filename,'bdictionary')

def get_interface_dictionary_filename(path,xfile):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'ixdict.xml')

def get_interface_dictionary_xnode(path,xfile):
    filename = get_interface_dictionary_filename(path,xfile)
    return get_chb_xnode(filename,'interface-dictionary')

def get_functionsjar_filename(path,xfile):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'functions.jar')

def get_functions_dir(path,xfile):
    fdir = get_analysis_dir(path,xfile)
    return os.path.join(fdir,'functions')

def get_function_info_filename(path,xfile,fname):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_function_filename(fdir,xfile,fname,'finfo.xml')

def get_function_info_xnode(path,xfile,fname):
    filename = get_function_info_filename(path,xfile,fname)
    return get_chb_xnode(filename,'function-info')

def get_function_vars_filename(path,xfile,fname):
    fdir = get_analysis_dir(path,xfile)
    return get_chb_function_filename(fdir,xfile,fname,'vars.xml')

def get_function_vars_xnode(path,xfile,fname):
    filename = get_function_vars_filename(path,xfile,fname)
    return get_chb_xnode(filename,'function')

def get_function_invs_filename(path,xfile,fname):
    fdir = get_analysis_dir(path,xfile)
    return  get_chb_function_filename(fdir,xfile,fname,'invs.xml')

def get_function_invs_xnode(path,xfile,fname):
    filename = get_function_invs_filename(path,xfile,fname)
    return get_chb_xnode(filename,'function')

# Executable directory: PE -----------------------------------------------------

def get_pe_header_filename(path,xfile):
    fdir = get_executable_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'pe_header.xml')

def get_pe_header_xnode(path,xfile):
    filename = get_pe_header_filename(path,xfile)
    return get_chb_xnode(filename,'pe-header')

def get_pe_section_filenames(path,xfile):
    fdir = get_executable_dir(path,xfile)
    xxfile = xfile.replace('.','_')
    prefix = xxfile + '_section'
    result = []
    for f in os.listdir(fdir):
        if f.startswith(prefix):
            result.append(os.path.join(fdir,f))
    return result

def get_pe_section_xnodes(path,xfile):
    result = []
    filenames = get_pe_section_filenames(path,xfile)
    for f in filenames:
        result.append(get_chb_xnode(f,'raw-section'))
    return result

# Executable directory: ELF ----------------------------------------------------

def get_elf_header_filename(path,xfile):
    fdir = get_executable_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'elf_header.xml')

def get_elf_header_xnode(path,xfile):
    filename = get_elf_header_filename(path,xfile)
    return get_chb_xnode(filename,'elf-header')

def get_elf_dictionary_filename(path,xfile):
    fdir = get_executable_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'elf_dictionary.xml')

def get_elf_dictionary_xnode(path,xfile):
    filename = get_elf_dictionary_filename(path,xfile)
    return get_chb_xnode(filename,'elf-dictionary')

def get_elf_section_filename(path,xfile,index):
    fdir = get_executable_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'section_' + str(index)  + '.xml')

def get_elf_section_xnode(path,xfile,index):
    filename = get_elf_section_filename(path,xfile,index)
    return get_chb_xnode(filename,'raw-section')

# Results directory ------------------------------------------------------------

def get_x86_dictionary_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'x86dict.xml')

def get_x86_dictionary_xnode(path,xfile):
    filename = get_x86_dictionary_filename(path,xfile)
    return get_chb_xnode(filename,'x86dictionary')

def get_mips_dictionary_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'mipsdict.xml')

def get_mips_dictionary_xnode(path,xfile):
    filename = get_mips_dictionary_filename(path,xfile)
    return get_chb_xnode(filename,'mips-dictionary')

def get_mips_asm_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'mips_asm.xml')

def get_mips_asm_xnode(path,xfile):
    filename = get_mips_asm_filename(path,xfile)
    return get_chb_xnode(filename,'mips-assembly-instructions')

def get_resultmetrics_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'metrics.xml')

def get_resultmetrics_xnode(path,xfile):
    filename = get_resultmetrics_filename(path,xfile)
    return get_chb_xnode(filename,'results')

def get_resultmetrics_xheader(path,xfile):
    filename = get_resultmetrics_filename(path,xfile)
    return get_chb_xheader(filename)

def get_resultdata_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'data.xml')

def get_resultdata_xnode(path,xfile):
    filename = get_resultdata_filename(path,xfile)
    return get_chb_xnode(filename,'application-results')

def get_md5profile_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return  get_chb_filename(fdir,xfile,'md5.json')

def get_md5profile_json(path,xfile):
    filename = get_md5profile_filename(path,xfile)
    return get_chb_json(filename)

def get_results_summary_filename(path,xfile):
    fdir = get_results_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'summary.json')

def save_results_summary(path,xfile,d):
    filename = get_results_summary_filename(path,xfile)
    with open(filename,'w') as fp:
        json.dump(d,fp,sort_keys=True,indent=3)

def get_function_results_filename(path,xfile,fname):
    fdir = get_results_dir(path,xfile)
    return get_chb_function_top_filename(fdir,xfile,fname,'.xml')

def get_function_results_xnode(path,xfile,fname):
    filename = get_function_results_filename(path,xfile,fname)
    return get_chb_xnode(filename,'application-results')

# Userdata directory -----------------------------------------------------------

def get_user_system_data_filename(path,xfile):
    fdir = get_userdata_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'system_u.xml')

def get_user_system_data_xnode(path,xfile):
    filename = get_user_system_data_filename(path,xfile)
    return get_chb_xnode(filename,'system-info')

def get_cfg_replacement_texts(path,xfile):
    fdir = get_userdata_dir(path,xfile)
    filename = get_chb_filename(fdir,xfile,'cfg_replacements.json')
    if os.path.isfile(filename):
        try:
            with open(filename,'r') as fp:
                d = json.load(fp)
        except ValueError as e:
            raise CHBJSONParseError(filename,e)
        return d
    return {}

def get_annotation_system_data_filename(path,xfile):
    fdir = get_userdata_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'system_a.xml')

def get_user_function_summary_filename(path,xfile,fname):
    fdir = get_userdata_dir(path,xfile)
    return get_chb_function_top_filename(fdir,xfile,fnnname,'_u.xml')

def get_user_function_summary_xnode(path,xfile,fname):
    filename = get_user_function_summary_filename(path,xfile,fname)
    return get_chb_xnode(filename,'function-summary')

def get_ida_unresolved_calls_filename(path,xfile):
    fdir = get_userdata_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'unr_ida.xml')

def get_ida_unresolved_calls_xnode(path,xfile):
    filename = get_ida_unresolved_calls_filename(path,xfile)
    return get_chb_xnode(filename,'functions')

def get_xref_filename(path,xfile,infotype):
    xxfile = xfile.replace('.','_')
    udir = get_userdata_dir(path,xfile)
    return os.path.join(udir,xxfile + '_' + infotype + '_x.json')

# Statistics directory ---------------------------------------------------------

def get_disassembly_statistics_filename(path,xfile):
    fdir = get_statistics_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'disassembly.xml')

def get_disassembly_statistics_xnode(path,xfile):
    filename = get_disassembly_statistics_filename(path,xfile)
    return get_chb_xnode(filename,'disassembly')

def get_features_filename(path,xfile):
    fdir = get_statistics_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'features.json')

def get_fn_features_filename(path,xfile):
    fdir = get_statistics_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'fn_features.json')

def get_fn_map_filename(path,xfile):
    fdir = get_statistics_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'fn_map.json')

def get_fn_featuremap_filename(path,xfile):
    fdir = get_statistics_dir(path,xfile)
    return get_chb_filename(fdir,xfile,'feature_map.json')

# Function summaries -----------------------------------------------------------

def get_summaries_list():
    summariesfile  = os.path.join(get_summaries_dir(),'summaries.json')
    if os.path.isfile(summariesfile):
        try:
            with open(summariesfile,'r') as fp:
                return json.load(fp)
        except ValueError as e:
            raise CHBJSONParseError(summariesfile,e)
        except Exception as e:
            raise CHBError('Error in reading summaries list')
    return {}
    
# Unzip tar file ---------------------------------------------------------------

def unpack_tar_file(path,xfile):
    xdir = get_executable_dir(path,xfile)
    targzfile = get_executable_targz_filename(path,xfile)

    # tar.gz file has already been extracted
    if os.path.isdir(xdir): return True

    # there is no tar.gz file
    if not (os.path.isfile(targzfile)): return False

    # unpack the tar.gz.file
    os.chdir(path)
    cmd = [ 'tar', 'xfz', targzfile ]
    result =  subprocess.call(cmd,cwd=path,stderr=subprocess.STDOUT)
    if result != 0:
        raise CHBError('Error in extracting tar.gz file: ' + ' '.join(cmd)
                           + '. return code: ' + str(result))
    else:
        print('Successfully extracted ' + targzfile)
    return os.path.isdir(xdir)


if __name__ == '__main__':

    # analysis target shortcut names
    atscs = [ 'mw:V001',  'mw:V001:00', 'V001.iexe' ]

    for atsc in atscs:
        try:
            print(atsc + '. atfi: ' + get_atfi(atsc)
                      + '; atxi: ' + get_atxi(atsc))
        except CHBError as e:
            print(str(e.wrap()))

    # path-filename
    names = [ ':V006', 'fileutil.py', 'pe:bind9', ':Vxxx' ]

    for name in names:
        try:
            (path,filename) = get_path_filename('x86-pe',name)
            print(name + ': ' + path + ', ' + filename)
        except CHBError as e:
            print(str(e.wrap()))
        try:
            (dpath,dfilename,_) = get_path_filename_deps('x86-pe',name)
            print(name + ': ' + dpath + ', ' + dfilename)
        except CHBError as e:
            print(str(e.wrap()))

    # filenames

    atsc = ':V006'
    fname = '0x10052fc'
    (path,xfile) = get_path_filename('x86-pe',atsc)

    print(get_global_state_filename(path,xfile))
    print(str(get_global_state_xnode(path,xfile)))
    print(get_systeminfo_filename(path,xfile))
    print(str(get_systeminfo_xnode(path,xfile)))
    print(get_bdictionary_filename(path,xfile))
    print(str(get_bdictionary_xnode(path,xfile)))
    print(get_interface_dictionary_filename(path,xfile))
    print(str(get_interface_dictionary_xnode(path,xfile)))
    print(get_functionsjar_filename(path,xfile))
    print(get_functions_dir(path,xfile))
    print(get_function_info_filename(path,xfile,fname))
    print(str(get_function_info_xnode(path,xfile,fname)))
    print(get_function_vars_filename(path,xfile,fname))
    print(str(get_function_vars_xnode(path,xfile,fname)))
    print(get_function_invs_filename(path,xfile,fname))
    print(str(get_function_invs_xnode(path,xfile,fname)))

    for f in get_pe_section_filenames(path,xfile):
        print('  ' + str(f))

    for x in get_pe_section_xnodes(path,xfile):
        print('  ' + str(x))

    print(get_x86_dictionary_filename(path,xfile))
    print(str(get_x86_dictionary_xnode(path,xfile)))
    print(get_resultmetrics_filename(path,xfile))
    print(str(get_resultmetrics_xnode(path,xfile)))
    print(get_resultdata_filename(path,xfile))
    print(str(get_resultdata_xnode(path,xfile)))
    print(get_md5profile_filename(path,xfile))
    print(get_results_summary_filename(path,xfile))
    print(get_function_results_filename(path,xfile,fname))
    print(str(get_function_results_xnode(path,xfile,fname)))

    atsc = ':Vde3'
    (path,xfile) = get_path_filename('x86-pe',atsc)

    print(check_executable(path,xfile))
              
    print(str(get_analysis_target_index('x86-pe')))
    print(str(get_analysis_target_index('x86-elf')))

    print(get_analysis_target_executables_to_string('x86-pe'))
    print(get_analysis_target_executables_to_string('x86-elf'))
