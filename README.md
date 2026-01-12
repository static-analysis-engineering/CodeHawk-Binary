# CodeHawk-Binary
CodeHawk Binary Analyzer for malware analysis and general reverse
engineering

This repository contains the command-line interface (in python) to
run the CodeHawk Binary Analyzer and report its results. The command-line
interface can be invoked as follows (adjust paths for actual location):

```
> export PYTHONPATH=$HOME/CodeHawk-Binary
> export PATH=$HOME/CodeHawk-Binary/chb/cmdline:$PATH
> chkx
```

This will show an [overview](doc/cli-output.txt) of the commands available.

At present the analyzer supports x86 (32-bits), both ELF and PE32, mips32,
and arm32 (both ARM and Thumb-2) binaries (ELF only); arm32 is stil under active
development and thus somewhat experimental.

### Requirements

Ensure you have `zip` installed.

The command-line interface requires python3.5 or higher.

Build instructions for the CodeHawk Binary Analyzer are available
[here](https://github.com/static-analysis-engineering/codehawk/tree/master/CodeHawk).
Upon completion copy the analyzer, `chx86_analyze`, from the `CodeHawk/_build/install/default/bin/`
directory to the appropriate directory in `chb/bin/binaries`, or point the Config.py
(or ConfigLocal.py) in `chb/util/` to its location.

You can check the configuration with
```
> chkx info
Analyzer configuration:
-----------------------
  analyzer : /home/myname/codehawk/CodeHawk/_build/install/default/bin/chx86_analyze (found)
  summaries: /home/myname/codehawk/CodeHawk/CHB/bchsummaries/bchsummaries.jar (found)
```

and check whether it works correctly by running some tests:
```
> chkx test runall
 --ok--  arm32 elf   suite_001   test_001
 --ok--  x86   elf   suite_001   test_001
 --ok--  x86   elf   suite_001   test_002
 --ok--  x86   elf   suite_001   test_003
 --ok--  x86   elf   suite_001   test_004
 --ok--  x86   elf   suite_001   test_005
 --ok--  x86   pe    suite_001   test_001.exe
 --ok--  x86   pe    suite_001   test_002.exe
 --ok--  x86   pe    suite_001   test_003.exe
 --ok--  x86   pe    suite_001   test_004.exe
 --ok--  x86   pe    suite_001   test_005.exe
All 11 tests passed.
```


### Quick Start

```
> cd
> git clone https://github.com/static-analyis-engineering/CodeHawk-Binary.git
> export PYTHONPATH=$HOME/CodeHawk-Binary
> export PATH=$HOME/CodeHawk-Binary/chb/cmdline:$PATH
> 
```

To disassmble an x86, arm32, or mips32 executable:
```
> chkx analyze -d mybinary
...
```

This will show some statistics on the disassembly, but will not perform any
analysis. It usually is a good first step, especially if the the binary is
large, to check if disassembly succeeded. If this looks okay, analysis can be
performed with (use --reset to remove any previous intermediate results):

```
> chkx analyze mybinary --reset
....
> chkx results stats mybinary
```

The following commands are available to see more detailed results:
```
    results stats <xname>         output a summary of results with one line per function
    results functions <xname> ... output a listing of annotated assembly functions
    results function <xname> <fn> output a listing of a single annotated assembly function
    results cfg <xname> <fn> ...  produce a control flow graph for a function (in pdf)
    results cfgpaths <xname> <fn> ... find paths throug a cfg with a given target

    results appcalls <xname>      output a listing of application calls
    results dllcalls <xname>      output a listing of dll calls (PE32 only)
    results stringargs <xname>    output a listing of calls with string arguments
    results iocs <xname>          output a listing of indicators of compromise encountered
```

Finally, it is usually a good idea to reset the analysis results when re-analyzing
a binary that was analyzed before:

```
> chkx analyze mybinary --reset
```

to avoid inconsistent intermediate results.
