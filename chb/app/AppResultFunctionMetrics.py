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


class AppResultFunctionMetrics(object):
    '''Analysis metrics for a single assembly function.'''

    def __init__(self,imetrics,xnode):
        self.imetrics = imetrics
        self.xnode = xnode
        self.metrics = xnode.find('fmetrics')
        self.faddr = self.xnode.get('a')

    def get_time(self): return float(self.xnode.get('time'))

    def get_xprec(self): return self.metrics.find('prec')

    def get_espp(self): return float(self.get_xprec().get('esp'))

    def get_readsp(self): return float(self.get_xprec().get('reads'))

    def get_writesp(self): return float(self.get_xprec().get('writes'))

    def get_xmem_acc(self): return self.metrics.find('memacc')

    def get_reads(self): return int(self.get_xme_macc().get('reads','0'))

    def get_writes(self): return int(self.get_xmem_acc().get('writes','0'))

    def get_xcfg(self): return self.metrics.find('cfg')

    def get_instrs(self): return int(self.get_xcfg().get('instrs','0'))

    def get_blocks(self): return int(self.get_xcfg().get('bblocks','0'))

    def get_loop_count(self): return int(self.get_xcfg().get('loops',0))

    def get_loop_depth(self): return int(self.get_xcfg().get('loopdepth',0))

    def get_complexity(self): return int(self.get_xcfg().get('cfgc'))

    def get_vcomplexity(self): return float(self.get_xcfg().get('vc-complexity'))

    def get_xcalls(self): return self.metrics.find('calls')

    def get_calls(self): return int(self.get_xcalls().get('count','0'))

    def get_dll_calls(self): return int(self.get_xcalls().get('dll','0'))

    def get_app_calls(self): return int(self.get_xcalls().get('app','0'))

    def get_unresolved_calls(self): return int(self.get_xcalls().get('unr','0'))

    def get_inlined_calls(self): return int(self.get_xcalls().get('inlined','0'))

    def get_static_dll_calls(self): return int(self.get_xcalls().get('staticdll','0'))

    def get_xvars(self): return self.metrics.find('vars')

    def get_variable_count(self): return int(self.get_xvars().get('count','0'))

    def get_name(self): return self.xnode.get('name','no name found')

    def has_name(self): return 'name' in self.xnode.attrib

    def as_dictionary(self):
        result = {}
        result['faddr'] = self.faddr
        result['time'] = str(self.get_time())
        result['espp'] = str(self.get_espp())
        result['readsp'] = str(self.get_readsp())
        result['writesp'] = str(self.get_writesp())
        result['instrs'] = self.get_instrs()
        result['blocks'] = self.get_blocks()
        result['complexity'] = self.get_complexity()
        result['callcount'] = self.get_calls()
        result['dllcallcount'] = self.get_dll_calls()
        result['appcallcount'] = self.get_app_calls()
        result['unrcallcount'] = self.get_unresolved_calls()
        result['name'] = self.get_name()
        result['hasname'] = self.has_name()
        return result

    def metrics_to_string(self,shownocallees=False,space='   '):
        callcount = ''
        name = ''
        unrc = ''
        if shownocallees and (not self.has_name()):
            if self.get_calls() == 0:
                callcount = ' (no callees)'
        if self.has_name():
            name = ' (' + self.get_name() + ')'
        if self.get_unresolved_calls() > 0:
            unrc = str(self.get_unresolved_calls())
        return (str(self.faddr).ljust(10) + space
                    + '{:6.1f}'.format(self.get_espp()) + space
                    + '{:6.1f}'.format(self.get_readsp()) + space
                    + '{:6.1f}'.format(self.get_writesp()) + space
                    + unrc.rjust(6) + space
                    + str(self.get_blocks()).rjust(6) + space
                    + str(self.get_instrs()).rjust(6) + space
                    + '{:8.3f}'.format(self.get_time()) + name + callcount)

    
                                   
