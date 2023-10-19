#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Support functions for the summaries subcommand in the command-line interpreter."""

import argparse

from typing import List, NoReturn

from chb.models.FunctionSummary import FunctionSummary
from chb.models.ModelsAccess import ModelsAccess


def summariescommand(args: argparse.Namespace) -> NoReturn:
    print("The summaries command provides access to function summaries")
    print("for library functions, and other summary entities, such as")
    print("data structures and enums")
    print("\nIt has the following subcommands")
    print("  stats         output some statistics on summaries provided")
    print("  dlls          list dlls included")
    print("  enums         list enums included")
    print("\nPer dll")
    print("  dll-functions list the functions in a given dll")
    print("\nFor shared objects")
    print("  so-functions  list functions in shared-objects")
    print("\nIndividual summary")
    print("  dll-function  output signature and semantics for a dll function")
    print("  so-function   output signature and semantics for an so function")
    print("\nIndividual enum definition")
    print("  enum          list names/values of the values defined in the enum")
    print("\nIndicators of compromise")
    print("  ioc-types     list categories of IOCs used (not implemented yet)")
    print("  ioc-roles     list IOC roles used for given arguments (not implemented yet)")
    print("-" * 80)
    exit(0)


def summaries_stats_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments: none

    models = ModelsAccess()

    print(models.stats)
    exit(0)


def summaries_dlls_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments: none

    models = ModelsAccess()

    modeldlls = models.dlls()
    for jar in modeldlls:
        print(jar)
        print("-" * 80)
        for dll in sorted(modeldlls[jar]):
            print("  " + dll)
        print("-" * 80)
    exit(0)


def summaries_enums_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments: none

    models = ModelsAccess()

    enums = models.enum_definitions()
    for enumtype in enums:
        print("\n" + enumtype)
        print(str(enums[enumtype]))

    exit(0)


def summaries_dll_functions_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    dll: str = args.dll

    models = ModelsAccess()

    if models.has_dll(dll):
        dllfunctions = models.all_function_summaries_in_dll(dll)

        print("Functions in " + dll + " (" + str(len(dllfunctions)) + ")")
        print("=" * 80)
        for f in sorted(dllfunctions, key=lambda f: f.name):
            print("  " + f.name)
        print("=" * 80)

    else:
        print("*" * 80)
        print("Dll " + dll + " not found")
        print("  -- try")
        print("       > chkx summaries dlls")
        print("     to see a list of dlls included")
        print("*" * 80)

    exit(0)


def summaries_so_functions_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments: none

    models = ModelsAccess()

    # returns a dictionary with so-functions for different jars
    sofunctions = models.all_so_function_summaries()
    for jar in sorted(sofunctions):
        print("\nShared object functions from "
              + jar
              + " ("
              + str(len(sofunctions[jar]))
              + ")")
        print("=" * 80)
        pdrcounter = 0
        pdwcounter = 0
        for f in sorted(sofunctions[jar], key=lambda f: f.name):
            summary = models.so_function_summary(f.name)
            prec = summary.semantics.preconditions
            pdread = len([p for p in prec if p.is_deref_read])
            pdwrite = len([p for p in prec if p.is_deref_write])
            print("  " + str(pdread).rjust(6) + str(pdwrite).rjust(6) + "  " + f.name)
            if pdread > 0:
                pdrcounter += 1
            if pdwrite > 0:
                pdwcounter += 1
        print("=" * 80)

    total = sum(len(sofunctions[jar]) for jar in sofunctions)
    print(
        "\nTotal: "
        + str(total)
        + " summaries (with deref-read: "
        + str(pdrcounter)
        + "; with deref-write: "
        + str(pdwcounter)
        + ")")
    exit(0)


def summaries_dll_function_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    dll: str = args.dll
    fname: str = args.function

    models = ModelsAccess()

    if models.has_dll(dll):
        if models.has_dll_function_summary(dll, fname):
            summary = models.dll_function_summary(dll, fname)
            print("Function summary for dll function: " + fname)
            print(str(summary))
            print("=" * 80)
            exit(0)
        else:
            print("*" * 80)
            print("Function "
                  + fname
                  + " not found in dll "
                  + dll)
            print("  -- try")
            print("       > chkx summaries dll-functions " + dll)
            print("     to see a list of functions included in " + dll)
            print("*" * 80)
            exit(0)
    else:
        print("*" * 80)
        print("Dll " + dll + " not found")
        print("  -- try")
        print("       > chkx summaries dlls")
        print("     to see a list of dlls included")
        print("*" * 80)
        exit(0)


def summaries_so_function_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    fname: str = args.function

    models = ModelsAccess()

    if models.has_so_function_summary(fname):
        summary = models.so_function_summary(fname)
        print("Function summary for shared-object function: " + fname)
        print(str(summary))
        print("=" * 80)
        exit(0)
    else:
        print("*" * 80)
        print("Function "
              + fname
              + " not found in so_functions")
        print("  -- try")
        print("       > chkx summaries so-functions")
        print("     to see a list of shared-object functions included")
        print("*" * 80)
        exit(0)


def summaries_enum_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    name: str = args.name

    models = ModelsAccess()

    if models.has_dll_enum_definition(name):
        enumdef = models.dll_enum_definition(name)
        print("Values for enum type " + name)
        print("=" * 80)
        for s in sorted(enumdef):
            print("  " + str(enumdef[s]))
        print("=" * 80)
        exit(0)
    else:
        print("*" * 80)
        print("Enum type "
              + name
              + " not found")
        print("  -- try")
        print("       > chkx summaries enums")
        print("     to see a list of enum types included")
        print("*" * 80)
        exit(0)


def summaries_ioc_types_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments: none

    print("~" * 80)
    print("Not yet implemented")
    print("~" * 80)
    exit(0)


def summaries_ioc_roles_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments: none

    print("~" * 80)
    print("Not yet implemented")
    print("~" * 80)
    exit(0)
