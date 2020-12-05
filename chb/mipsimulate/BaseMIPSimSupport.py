# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
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
"""Basic class for user-supplied simulation information."""

import chb.simulate.SimValue as SV

class BaseMIPSimSupport(object):

    def __init__(self,startaddr,enable_file_operations=False):
        """Hex address of starting point of the simulation."""
        self.startaddr = startaddr
        self.enable_file_operations = enable_file_operations

    def do_initialization(self,simstate): pass

    def get_target_address(self):
        """If relevant, return a hex address that must be reached."""
        return None

    def get_step_count(self):
        """Return the number of instructions to be simulated."""
        return 100

    def get_environment(self):
        """Return dictionary of key-value pairs of environment variables."""
        return {}

    def has_network_input(self,iaddr):
        """Return true if there is network input configured for this address."""
        return False

    def get_network_input(self,iaddr,simstate,size):
        """Return network input."""
        raise UF.CHBError('No network input configured for address ' + iaddr)

    def get_supplemental_library_stubs(self):
        """Return dictionary of hex-address,name pairs of library functions.

        Sometimes library functions are not captured correctly.
        """
        return {}

    def get_lib_stubs(self):
        """Return dictionary of name-stubinvocation pairs of imported functions.
        
        Can include both stubs for library functions from libraries other than 
        libc, or stubs of libc functions that override the default libc stubs.
        """
        return {}

    def get_app_stubs(self):
        """Return diction of hexaddr-stubinvocation pairs of application functions.

        Intended to stub out application functions that take a lot of execution
        steps without much relevant modification of state.
        """
        return {}

    def get_app_stubs(self):
        """Return dictionary of hexaddress-stubinvocation pairs of application
        functions to provide shortcuts."""
        return {}

    def get_patched_globals(self):
        """Return dictionary of hexaddress,hexvalue pairs of global addresses
        and values."""
        return {}

    def get_branch_decision(self,iaddr,simstate):
        """Return True/False to indicate which branch to take."""
        return False

    def check_target_path(self,iaddr):
        """Provide a target path that must be followed."""
        return None

    def get_ctype_toupper(self):
        """Return the global access address for __ctype_toupper (as encountered statically)."""
        return None
