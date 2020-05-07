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

import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from chb.util.Config import Config

import chb.util.fileutil as UF
import chb.util.xmlutil as UX

class AnalysisManager(object):
    """Sets up the command-line arguments for and invokes the Binary Analyzer."""

    def __init__(self,path,filename,deps=[],specializations=[]):
        """Initializes the analyzer location and target file location

        Arguments:
        path: path of the directory that holds the target executable
        filename: filename of the target executable
        deps: list of summary jars
        """
        self.path = path
        self.filename = filename
        self.deps = deps
        self.specializations = specializations
        self.config = Config()
        self.chx86_analyze = self.config.chx86_analyze
        self.chsummaries = self.config.summaries
        self.fnsanalyzed = []

    # Extraction and directory preparation -------------------------------------

    def extract_executable(self,chcmd='-extract',elf=False):
        os.chdir(self.path)
        xdir = UF.get_executable_dir(self.path,self.filename)
        print('xdir: ' + xdir)
        self._makedir(xdir)
        cmd = [ self.chx86_analyze, chcmd, '-summaries', self.chsummaries ]
        for d in self.deps:
            cmd.extend([ '-summaries', d ])
        cmd.append(self.filename)
        p = subprocess.call(cmd,stderr=subprocess.STDOUT)
        if not (p == 0):
            shutil.rmtree(os.path.join(self.filename + '.ch', 'x'))
            return p

        # create userdata directory
        udir = UF.get_userdata_dir(self.path,self.filename)
        fndir = os.path.join(udir,'functions')
        self._makedir(udir)
        self._makedir(fndir)
        self._make_userdata_file()

        # create analysis directory
        adir = UF.get_analysis_dir(self.path,self.filename)
        fndir = os.path.join(adir,'functions')
        self._makedir(adir)
        self._makedir(fndir)

        # create results directory
        rdir = UF.get_results_dir(self.path,self.filename)
        fndir = os.path.join(rdir,'functions')
        self._makedir(rdir)
        self._makedir(fndir)

        return  p

    def save_extract(self):
        os.chdir(self.path)
        xdir = os.path.join(self.filename + '.ch','x')
        tarfilename =  self.filename + '.chx.tar.gz'
        if os.path.isfile(tarfilename): os.remove(tarfilename)
        tarcmd = [ 'tar', 'cfz', tarfilename, xdir ]
        subprocess.call(tarcmd,cwd=self.path,stderr=subprocess.STDOUT)

    # Disassembly --------------------------------------------------------------

    def disassemble(self,elf=False,mips=False,save_xml=False,timeout=None,verbose=False):
        os.chdir(self.path)
        cmd = [ self.chx86_analyze, '-summaries', self.chsummaries ]
        for d in self.deps:
            cmd.extend([ '-summaries', d ])
        for s in self.specializations:
            cmd.extend([ '-specialization', s ])
        chcmd = '-disassemble_elf' if elf else '-disassemble'
        chcmd = '-disassemble_mips' if mips else chcmd
        if verbose: cmd.append('-verbose')
        cmd.extend([ chcmd, self.filename ])
        if sys.version_info > (3, 0) and timeout:
            try:
                result = subprocess.call(cmd,stderr=subprocess.STDOUT,timeout=timeout)
                print(result)
            except subprocess.TimeoutExpired:
                print(str(cmd) + ' timed out!')
        else:
            result = subprocess.call(cmd,stderr=subprocess.STDOUT)
            print(result)

    # Analysis -----------------------------------------------------------------

    def analyze(self,iterations=10,extract=False,resetfiles=False,elf=False,mips=False,
                    verbose=False,ignore_stable=False,save_asm=False,
                    mem=False,timeout=None):
        """Create and invoke the command to analyze to the Binary Analyzer."""
        self.fnsanalyzed = []
        self._analysis_setup(self.filename,extract,resetfiles,elf,mips)
        result = self._analyze_until_stable(
            self.filename,iterations,elf,ignore_stable,mips=mips,
            asm=save_asm,mem=mem,timeout=timeout,verbose=verbose)
        return result
                    

    def _makedir(self,name):
        if os.path.isdir(name): return
        os.makedirs(name)

    def _make_userdata_file(self):
        ufilename = UF.get_user_system_data_filename(self.path,self.filename)
        if os.path.exists(ufilename):
            print('File: ' + os.path.basename(ufilename)
                      + ' already exists; skip file creation')
            return
        ufile = open(ufilename,'w')
        root = UX.get_codehawk_xml_header(self.filename,'system-userdata')
        tree = ET.ElementTree(root)
        snode = ET.Element('system-info')
        root.append(snode)
        tags = [ 'settings', 'data-blocks', 'function-entry-points', 'function-names',
                     'non-returning-functions', 'esp-adjustments' ]
        children = [ ET.Element(t) for t in tags ]
        snode.extend(children)
        ufile.write(UX.doc_to_pretty(tree))

    def _analysis_setup(self,filename,extract,resetfiles,elf=False,mips=False):
        if extract: self.extract_executable(filename,elf)
        if resetfiles: self.reset_files()

    def _get_results(self,filename):
        xresults = UF.get_resultmetrics_xnode(self.path,filename)
        isstable = xresults.get('stable','no')
        run = xresults.find('runs')[0]
        ftotals = xresults.find('function-totals')
        prec = ftotals.find('prec')
        disassembly = xresults.find('disassembly')
        index = run.get('index')
        fnsanalyzed = run.get('fns-analyzed')
        self.fnsanalyzed.append(fnsanalyzed)
        esp = prec.get('esp')
        reads = prec.get('reads')
        writes = prec.get('writes')
        pcoverage = disassembly.get('pcoverage')
        rtime = run.get('time')
        ttime = xresults.get('time')
        columnwidths = [ 3, 10, 10, 10, 10, 10, 10, 10 ]
        r = [ index, fnsanalyzed, esp, reads, writes, pcoverage, rtime, ttime ]
        line = [ str(r[i]).rjust(columnwidths[i]) for i in range(len(columnwidths)) ]
        line = ''.join(line)
        if len(self.fnsanalyzed) == 4:
            if self.fnsanalyzed[0] == self.fnsanalyzed[3]:
                isstable = 'yes'
            else:
                self.fnsanalyzed = self.fnsanalyzed[1:]
        return (isstable,line)

    def _save_asm(self,asm,elf,timeout,cmd,filename):
        if asm and not elf:
            cmd = cmd[:-2]
            cmd.extend([ '-analyze_a', filename ])
            result = self._call_analysis(cmd,timeout=timeout)
            (isstable,results)  = self._get_results(filename)
            print(results)

    def _print_analysis_header(self):
        columnwidths = [ 6, 10, 10, 10, 10, 10, 10, 10 ]
        header1 = [ 'run', 'functions', 'esp', 'reads', 'writes', '%coverage',
                        'time', 'total time' ]
        header2 = [ '', 'analyzed', '%prec', '%prec', '%prec', '', '(sec)',
                        '(sec)' ]
        print('-' * 80)
        print( ''.join([ header1[i].center(columnwidths[i]) for i in range(len(columnwidths)) ]))
        print( ''.join([ header2[i].center(columnwidths[i]) for i in range(len(columnwidths)) ]))
        print('-' * 80)

    def _call_analysis(self,cmd,timeout=None):
        if sys.version_info < (3,0) and timeout:
            try:
                result = subprocess.call(cmd,cwd=self.path,
                                             stderr=subprocess.STDOUT,
                                             timeout=timeout)
                return result
            except subprocess.TimeoutExpired:
                print(str(cmd) + ' timed out (' + str(timeout) + ')!')
                return 600
        else:
            result = subprocess.check_call(cmd,cwd=self.path,stderr=subprocess.STDOUT)
            return result
                   
    def _analyze_until_stable(self,filename,iterations,elf=False,ignore_stable=False,
                                  mips=False,asm=False,mem=False,timeout=None,
                                  verbose=False):
        os.chdir(self.path)
        functionsjarfile = UF.get_functionsjar_filename(self.path,filename)
        analysisdir = UF.get_analysis_dir(self.path,filename)
        if elf:
            chcmd = '-analyze_elf'
        elif mips:
            chcmd = '-analyze_mips'
        else:
            chcmd = '-analyze'
        cmd = [ self.chx86_analyze, '-summaries', self.chsummaries ]
        for d in self.deps:
            cmd.extend([ '-summaries', d ])
        for s in self.specializations:
            cmd.extend([ '-specialization', s ])
        if ignore_stable: cmd.append('-ignore_stable')
        if verbose: cmd.append('-verbose')
        cmd.extend([ chcmd, filename ])
        jarcmd = [ 'jar', 'cf',  functionsjarfile, '-C', analysisdir, 'functions']
        print('Analyzing ' +  filename + ' (max ' + str(iterations) + ' iterations)')
        self._print_analysis_header()
        result = self._call_analysis(cmd,timeout=timeout)
        if result != 0: return result
        (isstable,results) = self._get_results(filename)
        print(results)

        count = 2
        while True:
            if mem: self.check_pause_analysis()

            if isstable == 'yes' and not ignore_stable:
                self._save_asm(asm,elf,timeout,cmd,filename)
                return True
            
            subprocess.call(jarcmd,stderr=subprocess.STDOUT)
            if count > iterations:
                self._save_asm(asm,elf,timeout,cmd,filename)
                return False

            result = self._call_analysis(cmd,timeout=timeout)
            if result != 0: return result

            count += 1
            (isstable,results) = self._get_results(filename)
            print(results)
            
                
    
        
if __name__ == '__main__':

    atsc = ':V006'
    (path,filename) = UF.get_path_filename('x86-pe',atsc)
    am = AnalysisManager(path,filename)
    am._make_userdata_file()

    atsc = ':Vde3'
    (path,filename) = UF.get_path_filename('x86-pe',atsc)
    am = AnalysisManager(path,filename)
    try:
        if not UF.check_executable(path,filename):
            am.extract_executable(chcmd='-extracthex')
            am.save_extract()
    except UF.CHBError as e:
        print(str(e.wrap()))
    am.disassemble()

    am.analyze()
