## Scripts

### General-purpose scripts

Example output is shown for the executable V001.iexe in the repository
CodeHawk-Binary-X86-PE-Targets/targets/mw/vshare/V001

#### chx86_analyze_file.py
Analyzes a single executable or dll and saves the results in the associated results directory.
If the executable has never been analyzed or disassembled before, this script will first
extract the executable content into xml and save it in a tar.gz file. It will also create
directories for the executable content, intermediate analysis results, and final results.
Progress in terms of rounds and high-level statistics is printed to
the console. [example output](example_output/analysis_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


- keyword arguments:
  - *--asm*: save assembly code listing in analysis directory;
  - *--reset*: remove all analysis (intermediate) results and start fresh;
  - *--iterations* n: perform maximally n analysis rounds (default: 12)
  - *--extracthex*: take input from executable in hex form;
  - *--verbose*: print informational messages from the analyzer

#### chx86_disassemble_file.py
Disassembles a single executable or dll and prints out some statistics regarding the
executable to the console, including number of instructions, number of functions,
percent coverage, etc.
If the executable has never been analyzed or disassembled before, this script will first
extract the executable content into xml and save it in a tar.gz file. It will also create
directories for the executable content, intermediate analysis results,
and final results. An assembly listing like the one produced by
objdump is saved in the analysis directory. No analysis is performed.
[example output](example_output/disassembly_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


- keyword arguments:
  - *--xml*: save disassembly statistics in the toplevel directory;
  - *--reset*: remove all analysis (intermediate) results and start fresh
  - *--extracthex*: take input from executable in hex form

#### chx86_show_resultmetrics.py
Prints analysis statistics per function and summary disassembly and
analysis statistics for the
executable. By default the functions are sorted by the esp precision
(the fraction of instructions for which the location of the stack
pointer is known). [example output](example_output/resultmetrics_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


- keyword arguments:
  - *--nocallees*: indicate functions that have no callees
  - *--sortbytime*: sort the list of functions by analysis time
  - *--sortbyaddress*: sort the list functions by their address
  
#### chx86_report_appcalls.py
Prints for each application function (that has callers) its callers
and the arguments passed (if available).
[example output](example_output/appcalls_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


#### chx86_report_dllcalls.py
Prints for each call to a dll function the call site and arguments passed
to the dll function (if available).
[example output](example_output/dllcalls_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


- keyword arguments:
  - *--aggregate*: aggregate the arguments per function per parameter


#### chx86_show_functions.py
Prints a listing of one or more assembly functions annotated with
analysis
results. [example output](example_output/showfunctions_output.txt)
- positional arguments:
  - *filename*: absolute or relative filenname (or shortcut name)


- keyword arguments:
  - *--functions*: a list of function addresses in hexadecimal (e.g.,
  0x4057e0)
  - *--assebly*: print the assembly instruction
  - *--bytes*: print the raw bytes for each instruction
  - *--callers*: print a list of call sites where this function is
  called.
  - *--esp*: print esp offset from the return address, if available
  - *--bytestring*: print the function as a hex-encoded string of raw
  bytes
  - *--hash*: print the md5 hash of the function


#### chx86_show_pedata.py
Prints the PE Header information and the import tables, with an
indication for each of the imported library functions whether a
function summary is available. [example output](example_output/pedata_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


- keyword arguments:
  - *--headeronly*: print only the PE header
  - *--imports*: print only the import tables
  - *--headers*: print only the section headers
  - *--sections*: print all sections in hexadecimal
  - *--section*: print the section at the given virtual address
  - *--extracthex*: executable is in hex format (if not yet extracted)


### Scripts for malware analysis

#### chx86_report_iocs.py
Prints a list of indicators of compromise, organized by categories.
[example output](example_output/iocs_output.txt)
- positional arguments:
  - *filename*: absolute or relative filename (or shortcut name)


- keyword arguments:
  - *--verbose*: show call site locations for iocs
  - *--constants*: only show constant values (no variables)

#### chx86_list_executables.py
Lists the executables that are part of the projects defined in the
index files indicated in the analysistargettable in util/Config.py for the x86-pe
architecture. For each executable the
following information is provided:
- name to refer to when invoking scripts (key)
- has the executable been parsed (is chx.tar.gz file present?)
- has the executable been analyzed (is ch/results/.._results.xml present?)
- size of executable in bytes
- name of executable
