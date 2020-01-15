### Configuration

To configure your own version of the analyzer and/or set the locations of your
analysis targets, copy ConfigLocal.template and ConfigLocal.py, and adapt
the paths to your configuration. To verify your settings:
```
> export PYTHONPATH=$HOME/CodeHawk-Binary
> python Config.py
```

which should print out something like:

```
Analyzer configuration:
-----------------------
  analyzer : /Users/henny/gitrepo/codehawk/CodeHawk/CHB/bchcmdline/chx86_analyze (found)
  summaries: /Users/henny/repo/CodeHawk/CHB/bchsummaries/bchsummaries.jar (found)

Analysis target index files:
----------------------------
  x86-pe:
    default: /Users/henny/CLAIM/svn/CLAIM/malware/CodeHawk/mwc-00/mwc-00.json
    pe: /Users/henny/gitrepo/CodeHawk-Binary-X86-PE-Targets/targets/mw/mw-json
  mips-elf:
    default: /Users/henny/gitrepo/CodeHawk-Binary-MIPS-ELF-Targets/targets/mips.json
  x86-elf:
    default: /Users/henny/gitrepo/CodeHawk-Binary-X86-ELF-Targets/targets/elf.json
    stonesoup-mc: /Users/henny/CodeHawk-Binary-X86-ELF-Targets/targets/stonesoup-mc/stonesoup-mc.json
```
