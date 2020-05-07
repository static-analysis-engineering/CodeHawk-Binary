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


class InputConstraint(object):

    def __init__(self):
        pass

    def is_env_test(self): return False
    def is_env_absent(self): return False
    def is_string_starts_with(self): return False
    def is_string_not_starts_with(self): return False
    def is_string_equals(self): return False
    def is_string_not_equals(self): return False
    def is_string_contains(self): return False
    def is_string_not_contains(self): return False


class EnvironmentTestConstraint(InputConstraint):

    def __init__(self,name):
        InputConstraint.__init__(self)
        self.name = name

    def is_env_test(self): return True

    def __str__(self):
        return 'env(' + self.name + ')'

class EnvironmentAbsentConstraint(InputConstraint):

    def __init__(self,name):
        InputConstraint.__init__(self)
        self.name = name

    def is_env_absent(self): return True

    def __str__(self):
        return '!env(' + self.name + ')'

class StringEqualsConstraint(InputConstraint):

    def __init__(self,kvalue,cvalue,case_insensitive=False):
        InputConstraint.__init__(self)
        self.kvalue = kvalue
        self.cvalue = cvalue
        self.case_insensitive = case_insensitive

    def is_string_equals(self): return True

    def __str__(self):
        predicate = 'equalsIgnoreCase' if self.case_insensitive else 'equals'
        return predicate +  '(' + str(self.kvalue) + ',' + str(self.cvalue) + ')'

class StringNotEqualsConstraint(InputConstraint):

    def __init__(self,kvalue,cvalue,case_insensitive=False):
        InputConstraint.__init__(self)
        self.kvalue = kvalue
        self.cvalue = cvalue
        self.case_insensitive = case_insensitive

    def is_string_not_equals(self): return True

    def __str__(self):
        predicate = 'equalsIgnoreCase' if self.case_insensitive else 'equals'
        return '!' + predicate +  '(' + str(self.kvalue) + ',' + str(self.cvalue) + ')'

class StringStartsWithConstraint(InputConstraint):

    def __init__(self,kvalue,cvalue,length=None,case_insensitive=False):
        InputConstraint.__init__(self)
        self.kvalue = kvalue
        self.cvalue = cvalue
        self.length = length
        self.case_insensitive = case_insensitive

    def is_string_starts_with(self): return True

    def __str__(self):
        predicate = 'startswithIgnoreCase' if self.case_insensitive else 'startswith'
        return predicate + '(' + str(self.kvalue) + ',' + str(self.cvalue) + ')'

        
class StringNotStartsWithConstraint(InputConstraint):

    def __init__(self,kvalue,cvalue,length=None,case_insensitive=False):
        InputConstraint.__init__(self)
        self.kvalue = kvalue
        self.cvalue = cvalue
        self.length = length
        self.case_insensitive = case_insensitive

    def is_string_not_starts_with(self): return True

    def __str__(self):
        predicate = 'startswithIgnoreCase' if self.case_insensitive else 'startswith'
        return '!' + predicate  + '(' + str(self.kvalue) + ',' + str(self.cvalue) + ')'

class StringContainsConstraint(InputConstraint):

    def __init__(self,kvalue,cvalue):
        InputConstraint.__init__(self)
        self.kvalue = kvalue
        self.cvalue = cvalue

    def is_string_contains(self): return True

    def __str__(self):
        return 'contains(' +  str(self.kvalue) + ',' + str(self.cvalue) + ')'

class StringNotContainsConstraint(InputConstraint):

    def __init__(self,kvalue,cvalue):
        InputConstraint.__init__(self)
        self.kvalue = kvalue
        self.cvalue = cvalue

    def is_string_not_contains(self): return True

    def __str__(self):
        return '!contains(' + str(self.kvalue) + ',' + str(self.cvalue) + ')'

class InputConstraintValue(object):

    def __init__(self):
        pass

    def is_env_value(self): return False
    def is_string_suffix_value(self): return False
    def is_command_line_argument(self): return False
    def is_constraint_value_expr(self): return False

class EnvironmentInputValue(InputConstraintValue):

    def __init__(self,name):
        InputConstraintValue.__init__(self)
        self.name = name

    def is_env_value(self): return True

    def __str__(self):
        return 'env(' + self.name + ')'

class StringSuffixValue(InputConstraintValue):

    def __init__(self,strkonstraint,charcode,lastpos=False):
        InputConstraintValue.__init__(self)
        self.strkonstraint = strkonstraint
        self.charcode = charcode
        self.lastpos = lastpos

    def is_string_suffix_value(self): return True

    def __str__(self):
        pos = 'lastpos' if self.lastpos else 'pos'
        return 'suffix(' + str(self.strkonstraint) + ',' + pos + '(' + self.charcode + '))'

class CommandLineArgument(InputConstraintValue):

    def __init__(self,argindex):
        InputConstraintValue.__init__(self)
        self.argindex = argindex

    def is_command_line_argument(self): return True

    def __str__(self):
        return 'cmdline-arg(' + str(self.argindex) + ')'

class InputConstraintValueExpr(InputConstraintValue):

    def __init__(self,op,x,y):
        InputConstraintValue.__init__(self)
        self.op = op
        self.x = x
        self.y = y

    def is_constraint_value_expr(self): return True

    def __str__(self):
        return str(self.x) + str(self.op) + str(self.y)
