# Norm IR v0

Norm IR is the format rule packs are written in. A pack turns a code's provisions into rules a machine can evaluate. Every rule keeps a link to the exact section, table row, or clause it came from and to the law that adopted it. One evaluator runs every pack, in any domain.

v0 covers what the research mode needs: answering code questions from a project profile, citing the official source of every answer, and saying which open facts an answer still depends on. The first packs are the 2024 IBC egress starter set and Austin's amendments to it, in [`packs/`](../packs). The reference evaluator is [`engine/normir`](../engine/normir).

## Design rules

1. **Rules are data, not programs.** Conditions and values are expression trees the evaluator can inspect. That is what lets it prune branches, report open facts, diff two editions, and later search for repairs. Code is used only to measure facts, never to decide.
2. **Every rule cites its source.** Each table, term, and norm has `cite.section` and an `https` `cite.url`. Each branch of a table carries the row label as printed. The validator rejects a rule without them.
3. **Adoption is explicit.** A jurisdiction's pack `extends` the model code pack and lists what the adopting law deletes, replaces, and redirects. Answers report, for every cited provision, whether the city changed it.
4. **Unknown is an answer.** Missing facts leave a residual, the part of the rule that still depends on them. The evaluator never guesses a value.
5. **Interpretations are visible.** Where the text leaves a choice to the formalizer, such as which table row wins or how to round, the element says so in `interpretation`.
6. **Copyrighted text stays at the source.** A package declares `text_policy`. Under `link-only`, packs store rule logic, values, short row labels, and links, and the validator rejects any `quote`. Under `public`, as for an adopting ordinance, quotes are allowed.

## Packages

A package is a directory:

```text
packs/austin-2024/
  package.yaml        metadata, adoption, deletions, redirects, patches
  ch10-egress.yaml    elements: predicates, tables, terms, norms
```

`package.yaml` fields:

| Field | Meaning |
|---|---|
| `package`, `version`, `title` | Identity. Names are unique across a chain. |
| `extends` | Name of the base package, a sibling directory. |
| `text_policy` | `link-only` or `public`. |
| `adoption` | For a jurisdiction: `instrument`, `codified_at`, `passed`, `effective`, `url`. |
| `deleted` | Provisions the adopting law deletes, as written in it. `103+` means "103 plus subsections". `Chapter 9` and `Table 1004.5` match whole chapters and tables. A bare number matches only that provision, so deleting `1010.1.2` leaves `1010.1.2.1` in force. |
| `redirects` | Where a deleted provision's subject now lives, such as Austin's pointer from Chapter 9 to its Fire Code. |
| `patches` | `op: replace` with `kind` and `name`: this package's element of that name replaces the base element. Any other name collision is an error. |
| `not_formalized` | Amended provisions the pack knows about but has not encoded yet. |

## Elements

Element files have up to four lists. Every element may carry `status` (`draft` by default, or `reviewed` after a code professional approves it), `note`, `interpretation` (`by`, `note`), and `defers_to`, the referenced provisions not formalized yet that could change its result.

### Predicates

The facts rules read. A predicate is named `building.<attr>` for building-level facts or `<Type>.<attr>` for facts about an element such as `Corridor` or `Space`.

```yaml
- name: Corridor.serves_stretcher_traffic
  label: the corridor serves stretcher traffic
  type: bool            # bool | number | length | area | enum (with values)
  kind: judged          # given | measured | judged
  refers_to: ["903.3.1.1"]   # sections the fact's meaning depends on
```

`kind` records where a value comes from: stated by the applicant, measured from the model by deterministic code, or a classification a person or calibrated model makes. In research mode most facts are given; in model checks most are measured.

### Tables

Lookup tables keyed by an enum predicate, with one entry per printed row:

```yaml
- name: T1004.5
  cite: {section: "1004.5", table: "1004.5", url: https://…}
  key: Space.function
  columns: [factor, basis]
  rows:
    - {key: business, factor: 150 sqft, basis: gross, row: Business areas}
    - {key: assembly-fixed-seats, see: "1004.6", row: Assembly with fixed seats}
```

A row with `see` defers to another section. A key with no row evaluates to "not listed; the building official assigns the nearest listed function", which is what §1004.5 says.

### Terms

Named values defined by the code, such as a minimum width or a classification. A term may range over one element type with `for: {c: Corridor}`; without `for` it is building-level.

```yaml
- name: required_corridor_width
  for: {c: Corridor}
  cite: {section: "1020.3", url: https://…}
  value:
    max:
      - {term: min_corridor_width, of: c}
      - mul: [{term: egress_capacity_factor}, {fact: c.occupant_load}]
```

### Norms

Obligations a design must meet, for model checks:

```yaml
- name: "1020.3"
  modality: obligation
  for: {c: Corridor}
  cite: {section: "1020.3", url: https://…}
  require:
    ge: [{fact: c.clear_width}, {term: required_corridor_width, of: c}]
```

v0 has only obligations. Prohibitions, permissions, and exceptions as separate defeating norms come with the first chapter that needs them.

## Expressions

| Form | Meaning |
|---|---|
| `44 in`, `300 ft`, `150 sqft`, `1.2 m`, `279 mm`, `30 m2` | Quantities. Units are `in`, `ft`, `sqft`, `mm`, `m`, `m2`; comparisons check dimensions, so `1118 mm` and `44 in` compare directly. |
| `B`, `nfpa13`, `not-permitted` | Symbols. Compared with enum facts, the validator checks they are declared values. |
| `true`, `false`, numbers | Literals. |
| `{fact: c.occupant_load}` | A fact about the building or a bound element. |
| `{term: name, of: c}` | Another term; `of` binds its element. |
| `{lookup: T1004.5, key: …, column: factor}` | A table cell. |
| `all`, `any`, `not` | Logic. Arguments evaluate left to right and stop at the first deciding value. |
| `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `in` | Comparisons; `in` takes a list of symbols. |
| `max`, `min`, `mul`, `div`, `ceil` | Arithmetic. |
| `cases` | Ordered rows of `when`/`then`/`cite`, ending in `else`/`cite`. The first row whose condition holds wins. Each row cites the table row or clause it encodes. |

## Evaluation

The evaluator takes a ruleset, the known building facts, and optionally the facts of one element. It returns a value, or a residual when the value depends on open facts.

- Logic is three-valued: true, false, or residual.
- `cases` drops rows whose condition is false and records them as ruled out by the profile. It stops at the first row that is true. Rows that are still open stay, in order, so the residual reads as "72 in if …; 36 in if …; otherwise 44 in".
- `max` folds the known arguments and keeps the open ones.
- Every element and table row that contributed to the result is recorded with its citation.

An answer (`normir ask`, or `ask()` in Python) contains the value or residual, a plain-language rendering, the open facts, the rows ruled out, every citation with its `status` and its adoption status ("Not amended", "Deleted and replaced by …", "Deleted by …; see …"), the `defers_to` provisions not yet formalized, and notes on facts whose meaning moved, such as sprinkler references that Austin redirects to its Fire Code.

The same evaluation runs model checks: a norm with all facts known is true or false; with open facts it is a residual, which is the "unknown" verdict and names what would settle it.

## Subjects, vocabularies, evidence, and profiles

The same evaluator checks buildings and software. What changes between domains is data, in four layers:

| Layer | Building | Software |
|---|---|---|
| Subject (`subject:` in the base package.yaml; facts are written `<subject>.<attr>`) | `building` (the default) | `system` |
| Vocabulary: element types and descriptive attributes adapters emit | [`vocab/bim.yaml`](../vocab/bim.yaml): Stair, Door, Space | [`vocab/code.yaml`](../vocab/code.yaml): PasswordStore, Query, Cookie, Secret, ... |
| Adapters: one source in, one evidence document out | `adapters/ifc.py`; a drawing reader | `adapters/code_static`; a model reading the code |
| Profile: the jurisdiction's classifications | IBC occupancy group, 法別表第一 use, ADB purpose group | ASVS level, whether a transfer has safeguards |

An adapter's knowledge of frameworks is data too. `adapters/code_static` reads **framework models** (format in [`adapters/code_static/models.py`](../adapters/code_static/models.py)): YAML rules saying that a call, named by its import-resolved dotted path, hashes a password, sends a query, verifies a token, sets a cookie, logs, transfers data, rate-limits a route, enforces a password policy, erases a user, or is a taint source or sanitizer. The library calls with a fixed meaning ship as `models/python.yaml` and `models/javascript.yaml`. A customer passes its own with `--models`; these are tried first, checked against the vocabulary when loaded, and every observation they produce carries `model: <id>@<version>`, with the file's sha256 recorded in the source. A repository under review never supplies its own model, because a model can declare a sanitizer and so clear a finding.

A pack predicate is named after the vocabulary attribute it reads. Where a pack uses its own name, it says which attribute it reads with `vocab: <Type>.<attr>`, as `Stair.people_served` does in `uk-adb-v2`.

An **evidence document** (format in [`engine/normir/evidence.py`](../engine/normir/evidence.py)) lists observations: each fact is a list of `{value, source, at}`. Several documents are reconciled into one: observations of the same fact are pooled, so each fact is a value set, and elements from different sources are matched by id, or for code by file and nearby line. A fact no source mentions stays open. Several values from one source are a range (a door leaf width allows a range of clear widths); values from different sources that differ are a **conflict**, reported as a finding whether or not a verdict depends on it.

`evidence.run(pack, evidence, profile)` evaluates each norm on each element of its type for every combination of values in the sets: **pass** or **fail** when all combinations agree (certified), **uncertain** when they disagree (the facts that flip it are named with their sources), **unknown** when a fact the norm reads is open. `summarize` rolls elements up to one verdict per norm.

## Validation

`normir validate <package>` checks the package and everything it extends:

- every table, term, and norm has `cite.section` and an `https` `cite.url`; every `cases` row has a `cite`; every table row has its printed `row` label;
- every fact resolves to a declared predicate through `building` or a `for` variable;
- every symbol compared with an enum fact is one of its values;
- terms, tables, and columns exist, and `of` binds the element type the term expects;
- table keys are unique and declared; missing keys are reported;
- no term depends on itself;
- patches replace something that exists, and nothing else collides;
- `link-only` packages store no `quote`.

## Limits of v0

- One occupancy group per building; no mixed occupancies or separated portions. Ambulatory care is asked of the building rather than of a suite.
- No defeasible exceptions, priorities, or interpretation sets yet; an interpretation choice is a note plus the order of `cases` rows.
- No time dimension in the evaluator. A pack is one edition as adopted; editions are separate packages.
- No aggregation over elements (sums, counts, the largest of): a stair's occupant load from the spaces it serves is derived outside the pack and given as evidence or profile facts.
- Value sets are enumerated, not solved, so a norm reading many multi-valued facts is capped at 4,096 combinations.
- No proof replay. The citation trace is the explanation.

## Coverage: 2024 IBC Chapter 10 as adopted by Austin

| Section | Status |
|---|---|
| 1004.5 Areas without fixed seating, Table 1004.5 | Formalized, base and Austin substitute |
| 1005.3.1 Stairways | Formalized; Exception 2 not yet |
| 1005.3.2 Other egress components | Formalized; Exception 2 not yet |
| 1017.2 Limitations, Table 1017.2 | Formalized; footnote a modifications not yet |
| 1017.3 Measurement | Encoded as the definition of the measured travel distance fact |
| 1011.2 Stairway width and capacity | Formalized; Exceptions 2 and 3 not yet |
| 1011.5.2 Riser height and tread depth | Formalized for rectangular treads; exceptions and winders not yet |
| 1020.3 Width and capacity, Table 1020.3 | Formalized |
| 202 Ambulatory care facility | Formalized at building level |
| 1010.1.2, 1010.3.3 | Austin substitute text; not formalized |
| All other Chapter 10 sections | Not formalized |
