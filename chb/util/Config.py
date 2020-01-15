# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma and Andrew McGraw
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

localconfig = False

if os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(__file__)),'ConfigLocal.py')):
    import chb.util.ConfigLocal as ConfigLocal
    localconfig = True

class Config():

    def __init__(self):

        # general settings
        self.utildir = os.path.dirname(os.path.abspath(__file__))
        self.accdir = os.path.dirname(self.utildir)
        self.rootdir = os.path.dirname(self.accdir)
        self.testsdir = os.path.join(self.rootdir,'tests')
        self.projects = os.path.join(self.testsdir,'projects.json')
        self.bindir = os.path.join(self.accdir,'bin')
        self.binariesdir = os.path.join(self.bindir,'binaries')
        self.summariesdir = os.path.join(self.accdir,'summaries')
        self.summaries = os.path.join(self.summariesdir,'bchsummaries.jar')
        
        # platform-settings
        if os.uname()[0] == 'Linux': self.platform = 'linux'
        elif os.uname()[0] == 'Darwin': self.platform = 'mac'

        if self.platform == 'linux':
            self.chx86_analyze = os.path.join(self.binariesdir,'chx86_analyze_linux')
        else:
            self.chx86_analyze = os.path.join(self.binariesdir,'chx86_analyze_mac')

        # optional: set architecture-specific analysis targets to provide
        #   shortcuts to filenames, and to maintain meta data on analysis targets
        #   (see example in ConfigLocal.template), and description in fileutil.py
        self.analysistargettable = {}
        self.atsc_separator = ':'  # analysis_target_shortcut_name separator

        # reference features
        self.reference_features = {}
            
        # personalization
        if localconfig: ConfigLocal.getLocals(self)

    def __str__(self):
        lines = []
        analyzerfound = ' (found)' if os.path.isfile(self.chx86_analyze) else ' (not found)'
        summariesfound = ' (found)' if os.path.isfile(self.summaries) else  ' (not found)'
        lines.append('Analyzer configuration:')
        lines.append('-----------------------')
        lines.append('  analyzer : ' + self.chx86_analyze + analyzerfound)
        lines.append('  summaries: ' + self.summaries + summariesfound)
        if len(self.analysistargettable) > 0:
            lines.append('\nAnalysis target index files:')
            lines.append('----------------------------')
            for arch in self.analysistargettable:
                lines.append('  ' + arch + ':')
                archtargets = self.analysistargettable[arch]
                for ati_key in archtargets:
                    lines.append('    '  + ati_key + ': ' + archtargets[ati_key])
        return '\n'.join(lines)

if __name__ == '__main__':

    print(str(Config()))
