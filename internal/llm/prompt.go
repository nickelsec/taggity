package llm

import (
	"fmt"
	"strings"
)

// The drafting instructions.
//
// Two things carry most of the weight here. The first is polarity: a fix that
// adds a guard needs `indicates: fixed`, which inverts how every verdict in a
// report reads, and it is the field most often wrong. The corpus is close to an
// even split, nine danger-shaped against seven guard-shaped, so there is no
// safe default to fall back on and the distinction has to be taught.
//
// The second is that a rule must name something the fix *changed*. A rule
// naming a token present on both sides of the fix matches every version forever
// and proves nothing, which is the most common way a plausible-looking spec is
// useless.
const draftSystem = `You write taggity specs. A spec asks one structural
question about one symbol in one file, which taggity then evaluates against
many released versions.

Answer with YAML only. No prose, no code fences, no explanation.

THE RULE MUST NAME SOMETHING THE FIX CHANGED.

taggity compares versions. A rule naming code that is identical before and
after the fix matches every version forever and proves nothing. Before choosing
a call target, ask: does this token appear on only one side of the fix?

  Fix DELETED a dangerous call   -> calls: <the deleted call>
                                    indicates: vulnerable
  Fix ADDED a validating call    -> calls: <the added call>
                                    indicates: fixed
  Fix CHANGED a parameter default -> defaults: {param: old_value}

POLARITY INVERTS THE WHOLE REPORT.

indicates: vulnerable means a match is the bug.
indicates: fixed means a match is the FIX, so VULNERABLE in the report means
the version is patched. Choose it whenever the rule names something the fix
added.

SYMBOL, NOT LINE NUMBER.

A line number tells you where to read. It never goes in the spec: line 43 today
was line 38 three releases ago. Name the enclosing function or Class.method.

SCOPE.

The rule only sees calls in that symbol's own body. A call in a nested function
belongs to the nested function. If the vulnerable call is in a helper, name the
helper.

WHEN THE SAME CODE LIVES IN SEVERAL FILES.

Use signal.code_any with one entry per location. taggity reports the version as
affected if any of them matches, and a location it cannot read yields UNKNOWN
rather than a clean bill of health.`

// draftExamples are graded specs from the corpus: every one survived a real
// audit against a real repository.
//
// Four, covering what actually varies. The first two are deliberately almost
// identical in shape and opposite in polarity, because that is the distinction
// most often got wrong.
const draftExamples = `EXAMPLES

1. The fix DELETED a dangerous call. Tryton replaced safe_eval, which evaluates
   a Python expression, with ast.literal_eval.

package:
  ecosystem: PyPI
  name: trytond
repo: https://github.com/tryton/trytond
signal:
  code:
    file: trytond/ir/cron.py
    symbol: Cron._callback
    rule:
      calls: safe_eval
      indicates: vulnerable

2. The fix ADDED a guard. Lektor added a path check to an editor session. Same
   shape as 1, opposite polarity, because _is_valid_path exists only after the
   fix.

package:
  ecosystem: PyPI
  name: lektor
repo: https://github.com/lektor/lektor
signal:
  code:
    file: lektor/editor.py
    symbol: make_editor_session
    rule:
      calls: _is_valid_path
      indicates: fixed

3. The fix CHANGED A DEFAULT. PyYAML's load() constructs a Loader in every
   version, so no calls rule can tell the versions apart. The default is what
   moved.

package:
  ecosystem: PyPI
  name: pyyaml
repo: https://github.com/yaml/pyyaml
signal:
  code:
    file: lib/yaml/__init__.py
    symbol: load
    rule:
      defaults:
        Loader: Loader

4. THE SAME CODE IN TWO PLACES. pycsw moved CSW request handling into another
   module between major lines, so one file answers for only part of the range.

package:
  ecosystem: PyPI
  name: pycsw
repo: https://github.com/geopython/pycsw
signal:
  code_any:
    - file: pycsw/server.py
      symbol: Csw.getrecords
      rule:
        calls: self._cql_update_queryables_mappings
        indicates: vulnerable
    - file: pycsw/ogc/csw/csw2.py
      symbol: Csw2.getrecords
      rule:
        calls: self.parent._cql_update_queryables_mappings
        indicates: vulnerable`

// buildDraftPrompt assembles the user half of a drafting request.
//
// The fix diff goes last and is called out, because it is the strongest signal
// available: it shows which token changed, which is the one thing a source file
// alone cannot show.
func buildDraftPrompt(req DraftRequest) string {
	var b strings.Builder

	b.WriteString("VULNERABILITY\n")
	b.WriteString(req.Describe)
	b.WriteString("\n\nPACKAGE\n")
	fmt.Fprintf(&b, "ecosystem: %s\nname: %s\nrepo: %s\n",
		orDefault(req.Ecosystem, "PyPI"), req.Package, req.Repo)
	if req.Advisory != "" {
		fmt.Fprintf(&b, "advisory: %s\n", req.Advisory)
	}

	for path, src := range req.Sources {
		fmt.Fprintf(&b, "\nSOURCE %s\n%s\n", path, src)
	}

	if req.Diff != "" {
		b.WriteString("\nTHE FIX\n")
		b.WriteString("This patch is what changed. Name a token that appears on " +
			"only one side of it.\n\n")
		b.WriteString(req.Diff)
		b.WriteString("\n")
	}

	b.WriteString("\nWrite the spec. YAML only.")
	return b.String()
}

// The instructions for explaining a version that could not be answered.
//
// The constraint is stated twice and in the response shape, because it is the
// one thing that would break the architecture if a model talked its way past
// it. A wrong file is recoverable, since the engine checks it and finds
// nothing. A verdict is not.
const locateSystem = `A taggity check could not answer for one version. Say why,
and if the code moved, say where it went.

Answer in exactly this form:

WHY: <one or two sentences>
FILE: <repository-relative path, or - if you have no proposal>
SYMBOL: <function or Class.method, or - if you have no proposal>

YOU DO NOT DECIDE WHETHER THE VERSION IS VULNERABLE.

Never say vulnerable, not vulnerable, affected or safe. taggity re-checks
whatever you name and decides for itself. You are narrowing a search.

"-" for FILE and SYMBOL is a good answer when there is nowhere else to look. A
version that predates the feature has no moved file, and inventing a plausible
path wastes a check. Say so in WHY instead.

Common causes worth distinguishing:
  the file does not exist yet, and neither does the feature
  the file exists but the code moved to another module
  the symbol was renamed
  the code was inlined into its caller, so no symbol holds it`

// buildLocatePrompt assembles the user half of a locate request.
func buildLocatePrompt(req LocateRequest) string {
	var b strings.Builder

	fmt.Fprintf(&b, "VERSION %s\nTAGGITY GAVE UP BECAUSE: %s\n\nTHE SPEC\n%s\n",
		req.Version, req.Reason, req.Spec)

	if len(req.Tree) > 0 {
		b.WriteString("\nFILES AT THIS VERSION\n")
		b.WriteString(strings.Join(req.Tree, "\n"))
		b.WriteString("\n")
	}
	for path, src := range req.Sources {
		fmt.Fprintf(&b, "\nSOURCE %s\n%s\n", path, src)
	}

	b.WriteString("\nWHY, FILE, SYMBOL.")
	return b.String()
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
