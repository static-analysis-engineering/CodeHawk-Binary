# CodeHawk-Binary
CodeHawk Binary Analyzer for malware analysis and general reverse
engineering

### quick start

Try it out on a smallish PE 32-bit executable, located in, say, ~/executables/p.exe:
```
> cd
> git clone https://github.com/kestreltechnology/CodeHawk-Binary.git
> export PYTHONPATH=$HOME/CodeHawk-Binary
> cd CodeHawk-Binary/chb/cmdline/pe32
> python chx86_disassemble_file.py ~/executables/p.exe
```
The invocation of the disassembler will extract the executable content
from the executable, and save it in multiple xml files, which are
packaged into a .tar.gz file. Once this file exists, it will be the
basis for all further analysis; the original executable can be removed
(much like an .idb file obviates the need for the executable when
using IDA Pro).

At this point no analysis has yet been performed. To run the analyzer
on the same executable:
```
> python chx86_analyze_file.py ~/executables/p.exe
```
which will perform an iterative analysis until analysis stabilizes or
a maximum number of iterations is reached (default 12 iterations).
Analysis results are saved in xml files and can be accessed via a
variety of other scripts, e.g., to see an overview of the functions
and a summary of the analysis statistics:
```
> python chx86_show_resultmetrics.py ~/executables/p.exe
```
or, to view a list of the calls to dll library functions:
```
> python chx86_report_dllcalls.py ~/executables/p.exe
```
The annotated assembly code of any one or more functions can be viewed
with the script:
```
> python chx86_show_functions.py ~/executables/p.exe --assembly --esp \
     --functions <address-1-in-hex>...<address-n-in-hex>
```
by specifying the addresses of the functions in hexadecimal in a
space-separated list.

A more detailed description of all of the scripts, with example
output, is available [here](chb/cmdline/pe32/README.md).
