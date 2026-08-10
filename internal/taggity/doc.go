/*
Package taggity holds the domain types shared by every other package.

# The prime directive

Under-reporting is the only unacceptable failure. Over-reporting that a version
is affected is recoverable: a maintainer disputes it and the range narrows.
Under-reporting means a downstream scanner stays silent and someone runs
vulnerable code believing they are safe.

Every rule below follows from that.

# The NotVulnerable invariant

Exactly one place in this repository may assign [NotVulnerable]: the code
presence check, when the symbol was found and the vulnerable construct was
not. Absence of the construct is the only genuinely negative evidence
available.

Every other path returns [Unknown]: no tag, missing file, unparseable version,
unresolved symbol, ambiguous symbol, parse failure. A failure to answer is not
evidence of safety.

This invariant is enforced mechanically by TestNotVulnerableAssignedOnce, not
by review. If a second assignment is ever needed, the test must be changed
deliberately and the reason recorded, because the change removes the only
structural guarantee against under-reporting.

# Reproducibility over accuracy

There is no reliable ground truth in this domain: NVD and GHSA are themselves
frequently wrong, and independent tools disagree on the same vulnerability with
no arbiter. A tool that emitted "VULNERABLE (confidence: high)" would be making
an unfalsifiable claim.

Taggity therefore does not claim to be right. It claims to be reproducible:
here is exactly what was checked, here is how to repeat it, and here is where
it was uncertain. Every verdict carries [Evidence] sufficient for a stranger to
re-derive it by hand.
*/
package taggity
