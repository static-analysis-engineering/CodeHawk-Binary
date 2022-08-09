## Structure Checking

PIR provides many different types of interrelated pieces of information,
potentially provided by different parties, from different sources, and by
different tools. To be useful, this information should be consistent and
complete.

The following visitor classes provide definitions and implementations of
different aspects of consistency and completeness.

### Provenance Checker (not yet provided)

The Provenance Checker checks the three components of the provenance for
consistency and completeness. It is constructed with the three components
of the provenance and is invoked with the root of the high-level and the
root of the low-level ast.


### Storage Checker

The Storage Checker checks that each lvalue reference in either high-level
or low-level ast has an associated storage location. It is implemented as
a visitor class that takes as input the storage mapping and the root of
an ast, and reports all lvalues in the ast that are not represented in the
storage mapping.