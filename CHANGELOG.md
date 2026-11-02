# shortloop change log

Running log of changes, newest first. Each entry records the **problem** that
prompted it, the **change** made, and **why** — so we can retrace decisions
(especially the volume-vs-recall trade-offs) later.

---

## 2026-10-20 — Skip CSS/image short names by default

**Problem.** shortloop spent candidate generation and ffuf requests trying to
recover the full names of CSS files and images (`STYLE~1.CSS`, `LOGO~1.PNG`, …).
These are low-value static assets — recovering `somehashedname.css` tells a
pentester nothing — but they still drew the full fan-out and landed in the
unconfirmed/last-chance list, adding noise and request volume.

**Change.**
- Added `ASSET_EXT_PREFIXES` (keyed by the 3-char extension prefix an 8.3 name
  exposes: `css`, `png`, `jpg`, `jpe`=jpeg, `gif`, `bmp`, `ico`, `svg`,
  `tif`=tiff, `web`=webp) and `_is_asset_shortname()`.
- In `scan_directory`, right after the `--only` filter, short names whose
  extension marks them as CSS/image are dropped before candidate generation, the
  Claude pass, and unconfirmed tracking — so nothing fires at them and they don't
  clutter the unconfirmed report. The skip is logged (`skipping N css/image short
  name(s): …`).
- `--resolve-assets` restores the old behaviour (try to recover them too).

**Why.** Static assets are rarely worth a request on an IIS short-name hunt, and
skipping them cuts volume and noise with no loss of signal. Matching on the
3-char extension prefix keeps code/config files safe: `.CS` (C# source) and `.JS`
are *not* treated as assets — only the css/image set is. Default-on because that
is the common want; the flag is there for the rare case you do want them.

---

## 2026-10-20 — Stop recursing into files (page.aspx treated as a directory)

**Problem.** On an IIS/ASP.NET target (`insurance.example.com`) shortloop was
running shortscan against `forgotpassword.aspx/`, `logoff.aspx/`,
`navigation.aspx/`, `transfer.aspx/` — i.e. recursing into *pages* as if they
were directories. Two things combined: (1) for a name shortscan already resolved,
`build_candidates` probed it both as `page.aspx` **and** `page.aspx/`; (2) IIS/
ASP.NET serves the trailing-slash form (`page.aspx/`) as PathInfo and returns
200/301/403, which `classify()`'s "ends in `/` → directory" rule read as a
directory. So every resolved `.aspx` page got queued for recursion and burned a
shortscan (and a depth level) on a file.

**Change.**
- Added `FILE_EXTS` (a curated set of extensions that denote a file — `aspx`,
  `ashx`, `config`, `js`, `pdf`, `zip`, …) and `_looks_like_file()`.
- `classify()` now keeps a name a **file** even when its trailing-slash form is
  accepted or it 30x-redirects to `name/`, whenever the name ends in a known file
  extension. Names with no extension, or a dotted name whose extension is *not* a
  known file type (e.g. a real dir called `my.app`), still follow the normal
  directory logic — the override is deliberately conservative.
- `build_candidates` only adds the `fn + "/"` directory probe for a resolved full
  name when that name has no file extension, so a resolved page isn't fired as a
  directory at all.

**Why.** Recursing into a file is always wrong: it wastes a shortscan and a
recursion level per page, inflates runtime, and on deep trees can crowd out real
directories. Gating on a known-file-extension set fixes it without risking real
directories that merely contain a dot, since those fall through unchanged.

---

## 2026-10-20 — Drive the Claude pass through `claude -p`, not the API SDK

**Problem.** The reasoning pass (added in the entry below) called the Anthropic
API through the `anthropic` Python SDK, gated on an `--claude-key` /
`ANTHROPIC_API_KEY`. That meant a second credential to manage and a `pip install
anthropic` dependency, when the operator already has an authenticated `claude`
CLI sitting on `PATH`.

**Change.** Replaced the SDK client with a non-interactive `claude -p` subprocess
call:
- `Claude.guess()` now builds one text prompt (role/instructions + the
  directory's short-name descriptors, since `-p` has no separate system field),
  pipes it to `claude -p --output-format text [--model ...]` on stdin, and parses
  the JSON array out of stdout. CLI-missing / non-zero-exit / timeout / unparsable
  reply all return no guesses → clean fallback to ffuf.
- Flags changed: dropped `--claude-key` and `--no-claude`; the pass is now an
  explicit opt-in `--claude` (no key to gate on). Added `--claude-bin` (default
  `claude`), `--claude-timeout` (default 120s). `--claude-model` now passes
  straight to `claude --model` (alias like `opus`/`sonnet`/`haiku` or a full id;
  empty = the CLI's configured default) instead of a hard-coded `claude-opus-5-5`.
- Dropped the `anthropic` package dependency entirely; the lazy import is gone.

**Why.** Reusing the CLI's existing auth removes a credential and a dependency,
and respects whatever model/subscription the operator already configured Claude
Code with. The collision-filter + fallback architecture is unchanged — only the
transport to Claude moved from SDK to CLI.

---

## 2026-10-20 — Optional Claude reasoning pass before the ffuf fan-out

**Problem.** The candidate generator is blind to context: it expands every
truncated stem the same way whether the directory is a procurement portal or a
photo gallery. A truncated `CONTRA~1` next to `INVOIC~1` and `VENDOR~1` is almost
certainly `contract*`/`contractmanagement`, but recovering it still meant firing
the full curated (or `--compound-stems`/`--loud`) fan-out and hoping the compound
fell out. There was no way to spend a cheap reasoning step up front to turn the
*set* of short names in a directory into a few high-probability guesses.

**Change.** Added an optional LLM pre-pass, gated entirely on a key being
present:
- `build_claude()` / `Claude` wrap the `anthropic` SDK; enabled by `--claude-key`
  **or** `ANTHROPIC_API_KEY` (flag wins), disabled by `--no-claude`. Model is
  `--claude-model` (default `claude-opus-5-5`), volume bounded by
  `--claude-max-guesses` (default 150). The `anthropic` import is lazy, so the
  tool still runs without the package when no key is used.
- In `scan_directory`'s non-seed branch, `claude_first_pass()` hands *all* of a
  directory's short names to Claude at once (the set reveals the app's domain),
  gets back a prioritized guess list, **8.3-collision-filters** each guess with
  the existing `custom_matches()` (so a guess only fires at a short name it could
  complete, and `unconfirmed_shortnames()` one-to-one matching stays honest),
  fires them at ffuf first, records/recurses hits, and returns only the short
  names left unresolved. Those leftovers flow into the normal `build_candidates`
  fan-out → custom pass → last-chance, unchanged.
- Any failure (missing package, network, rate limit, unparsable reply) logs and
  returns no guesses, i.e. falls back to pure ffuf. No key → the pass never runs
  and behaviour is byte-identical to before.

**Why.** On the IIS targets we hit (contract/claims/document portals), the real
names are domain compounds the generator can't cheaply reach, but a human — or a
model — guesses them instantly from the sibling names. Spending one small,
reasoned request per directory to try those first can resolve the high-value name
in a handful of ffuf requests instead of thousands, while the brute-force path
remains the guaranteed fallback for everything the model misses. Cost is opt-in
and capped; recall never drops because nothing is removed from the fan-out —
Claude only gets first crack.

---

## 2026-10-19 — `--only` short-name filter + single-directory targeting

**Problem.** The tool always shortscans a directory and fuzzes *every* short
name it finds, then recurses into every confirmed subdir. With `--compound-stems`
now able to generate ~15k candidates per truncated stem, there was no way to aim
that firepower at a single target (e.g. just `CONTRA~1.ZIP`) without also
blowing it on every other short name in the directory. "Scan only this one
directory/name" wasn't expressible.

**Change.**
- Added `--only PATTERN...`: keep only the short names whose label matches a
  case-insensitive `fnmatch` glob (`'CONTRA*'`, `'*.ZIP'`, `'CONTRA~1.ZIP'`);
  the rest of the directory is skipped. Applied right after `run_shortscan`, so
  it governs candidate generation, ffuf, unresolved tracking and recursion.
  Logs `--only: k/n short name(s) match` when it filters.
- Clarified that `--max-depth 0` already scans just the given directory with no
  recursion, and documented the `--max-depth 0` + `--only` combo for targeting a
  single name. Seeded default-directory contents are unaffected by `--only`.

**Why.** Short-name recovery is often about one specific high-value name (a
backup `.zip`, a config). Letting the operator pass the directory URL plus a
label glob turns the whole pipeline — including the expensive compound/loud
passes — into a scalpel instead of running the full directory every time.

---

## 2026-10-19 — Expand COMMON_SUFFIXES with business/document/healthcare terms

**Problem.** The curated suffix list skewed toward generic web/CRUD words and
was missing the vocabulary these targets actually use — notably `management`
(so `contract`+`management` couldn't be built even with `--compound-stems`),
plus contract/finance/procurement and healthcare/claims terms.

**Change.** Grew `COMMON_SUFFIXES` from 228 to 344 words: added `management`,
`agreement(s)`, `contract(s)`, `proposal(s)`, `quote(s)`, `statement(s)`,
`invoice`-adjacent finance terms (`ledger`, `audit`, `expense`, `payroll`,
`reimbursement`, `amendment`, `addendum`, `rfp`/`rfq`/`sow`/`nda`/`msa`/`po`,
…), and a healthcare/claims block (`provider(s)`, `prescription(s)`,
`authorization(s)`, `eligibility`, `benefit(s)`, `formulary`, `result(s)`, …).

**Why.** These are exactly the second words in real app compounds on the kind of
IIS targets we hit (contract/claims/document portals), so they directly raise
recall for both branch (1) prefix+suffix and `--compound-stems`. Cost is linear:
~340 vs ~230 words. The startup line reports the live count.

---

## 2026-10-19 — `--compound-stems`: suffix the dictionary matches, not just the prefix

**Problem.** On `wrapup.example.com`, `CONTRA~1` and `EXPORT~1` (dirs) and
`CONTRA~1.ZIP` stayed unresolved even though the curated pass already tests the
bare dictionary words `contract(s)`, `contractor(s)`, `export(s)` — i.e. the
real names are *compounds* (`contractmanagement`, `exportdata`, `contract_...`),
not plain words. But `candidate_stems` only ever appends the common-suffix words
to the **bare 6-char prefix** (`contra`+word). The longer dictionary matches
(`contract`, `contractor`) got no suffixing at all, so a compound built on a
word longer than 6 chars was structurally impossible to generate — even `--loud`
couldn't reach it (its 38k words are appended to the prefix, not to the match).

**Change.** Added `--compound-stems` (opt-in): branch (2b) in `candidate_stems`
glues each curated `COMMON_SUFFIXES` word onto every dictionary match, with the
joiners `("", "_")` (`contract` -> `contractmanager`, `contract_manager`),
still bounded by `MAX_COMPOUND_NAME`. It deliberately uses the small curated
suffix list (never the loud union) so volume stays bounded, and logs a line at
startup when active.

**Why.** App directory/file names are overwhelmingly `<real word><suffix>`
compounds where the base word is longer than the 6 visible chars — the one shape
the generator couldn't produce. This fills that gap with targeted candidates:
`CONTRA~1` goes 1,392 -> ~15k candidates (15 matches x 228 suffixes x 2 joiners)
— a real jump, but well under `--loud`'s 38k and every candidate is a plausible
`contract*`/`contractor*` compound rather than a random dictionary word. Off by
default because of the multiplier; turn it on for a stubborn truncated stem.

---

## 2026-10-19 — Add .well-known validation dirs to the custom list

**Problem.** The custom pass (below) didn't cover `PKI-VA~1`, which on the
certs.example.com run was `.well-known/pki-validation/` — the standard ACME/SSL
domain-validation directory. It's extension-less, so it fell through to the
loud retry (76k requests) for a name that's effectively a constant.

**Change.** Added `pki-validation` and its HTTP-01 sibling `acme-challenge` to
`CUSTOM_NAMES`. Both are extension-less, so `custom_matches` only pairs them
with *dir-like* short names (no ext). Also made the custom pass probe a dir-like
match in **both** forms (`name` and `name/`), mirroring `build_candidates`, so a
hit classifies as a DIR (via the 301→`name/` redirect or the direct `name/`
probe) and recursion continues into it — a bare `403` on `name` alone would
otherwise be logged as a file and not recursed.

**Why.** `pki-validation` dedots to stem `pki-va`, an exact match for
`PKI-VA~1`; two targeted requests resolve it instead of the 76k loud fan-out,
and classifying it as a directory lets the loop descend (these folders can hold
left-behind validation tokens).

---

## 2026-10-19 — Custom full-name pass before the loud last-chance retry

**Problem.** On a real run (`certs.example.com`) two short names stayed
unresolved and went straight to the loud retry: `WEB~1.CON` (really
`web.config`) and `DEFAUL~1.CS` (really a `Default.*.cs` code-behind). The
candidate generator can never build these — `candidate_stems` only emits
*dot-free* stems, so a name with an internal dot / double extension
(`default.aspx.cs`) or a long extension truncated to 3 chars (`web.config` →
`.CON`) is impossible for it, even under `--loud`. So the loud pass spent
38k + 76k requests on names it structurally could not produce.

**Change.**
- Added a built-in `CUSTOM_NAMES` list of real ASP.NET/IIS full filenames
  (`web.config`, `web.conf`, `default.aspx.cs`, `default.aspx.designer.cs`,
  `default.master.cs`, `defaultcontroller.cs`, …).
- New **phase 2** between the curated scan and the loud retry: for each
  *unresolved* short name, fire only the custom entries whose reconstructed
  8.3 name collides with it (`custom_matches` / `_name_83`: dedot the base, take
  the first 6 chars for the stem, final extension for the ext, compared against
  the short name's complete/truncated stem+ext). Re-check with the same honest
  one-to-one matching; anything still unresolved flows into the loud phase as
  before. Directories a custom hit exposes get a normal `drain()`.
- `--custom-wordlists FILE...` merges extra full-name files into the built-in
  list; `--no-custom` skips the pass. Runs regardless of `--loud` (the loud
  pass can't build these names either).

**Why.** These specific names are both high-value (config files, source
code-behind) and unreachable by the fan-out, so a handful of targeted requests
lands them for pennies and removes them from the expensive loud retry — in the
certs.example.com run, the root's two leftovers become 15 candidates instead of
38,779, and only the genuinely unknown `PKI-VA~1` still needs loud.

---

## 2026-10-16 — `--last-chance` loud retry + unconfirmed reporting

**Problem.** shortscan regularly finds short names the curated pass can't crack
(e.g. `PRODUC~1 -> 7804 candidates` with no ffuf hit). That short name proves a
file/dir *exists*, but the operator got no signal about it — it silently
vanished. And there was no targeted way to spend extra requests only on the
names that actually failed.

**Change.**
- Track per-short-name candidate sets; after the ffuf pass, compute which short
  names got no confirmed hit (`unconfirmed_shortnames`, greedy one-to-one match
  so `~1/~2/~3` collisions are honest — 3 `PORTAL~` + 1 confirmed name ⇒ 2
  reported unresolved).
- `--last-chance`: retry **only** those unresolved short names with the full
  loud suffix list, then re-check. Seeded known dirs are exempt (trusted).
- Anything still unresolved is printed at the end under an "unconfirmed" banner
  (`url [LABEL]`), and written to `<output>.unconfirmed` when `-o` is set.
- Refactored hit recording/queueing into an `emit()` helper reused by both the
  main and retry passes.

**Why.** A short name that shortscan sees but we can't complete is real,
actionable intel (there IS a file there) — it should never disappear silently.
`--last-chance` concentrates the expensive loud fan-out on exactly the names
that need it instead of running loud across the whole target.

**Follow-up (same day) — deferred to end-of-run + interactive.** The retry was
originally inline (per directory, only if `--last-chance` was set at launch).
Problem: you don't know whether you want the loud retry until you've seen what
didn't resolve. Reworked so the whole curated scan runs first; then, if any
short names are unresolved, the loud retry happens as a single end-of-run pass
whose decision is: `--last-chance` = auto-run, `--no-last-chance` = always skip,
otherwise prompt `[y/N]` when attached to a terminal (non-TTY with no flag =
skip). Directories newly discovered during the retry are fed back through the
normal scan (`drain()`), so recursion depth isn't lost. Refactored the
per-directory work into `scan_directory()` + `drain()` to support this.

**Redirect note (same investigation).** Confirmed ffuf intentionally does *not*
follow redirects (no `-r`): the 30x → `.../name/` redirect is the signal
`classify()` uses to tell directories from files, and a 302 already confirms
existence. Following redirects would break classification for no gain, so it
was left off by design.

---

## 2026-10-16 — Curated common-suffix list (branch #1), `--loud`, length cap

**Problem.** Every *unresolved* truncated 6-char stem (e.g. `SHIPPI~1`,
`VIEWOR~1`, `ORDERD~1`) generated ~38k candidates because branch #1 of
`candidate_stems` appended all 38,267 raft-small words to the prefix. But
inspection showed the real names — `shipping`, `vieworder`, `orderdetails` —
are recovered by branch #2 (whole dictionary words that *start with* the
prefix), NOT by prefix+suffix concatenation. `shippi` + `ng` = `shipping` can't
come from a word list because `ng` isn't a word. So the 38k fan-out was almost
pure waste for normal English-word names; it only earns its keep for compounds
whose cut lands on a word boundary and whose full form isn't in any list
(e.g. `streem` + `alert` = `streemalert`, a custom app name).

**Change.**
- Added a curated built-in `COMMON_SUFFIXES` list (~210 words people actually
  tack on: `admin, info, details, report, upload, alert, shipping, ...`) and
  made it the **default** source for branch #1, replacing the 38k raft list.
- Added `--loud` / `--full-suffixes` to union the full `--suffix-wordlists`
  file(s) back in for maximum recall when wanted.
- Added `MAX_COMPOUND_NAME = 24` to skip absurdly long `prefix+suffix`
  compounds (trims the long tail, mostly under `--loud`).

**Why.** Branch #2 (the dictionary prefix-match) is what actually lands the hits
and costs nothing extra, so shrinking branch #1 to common words drops a
truncated stem from ~38k candidates to a few hundred (~100–150x fewer requests)
with negligible recall loss. `--loud` preserves the old behavior on demand.

**Follow-up (same day).** Documented the curated-list behavior and `--loud` in
README.md: rewrote the stem recovery description (dictionary prefix-match is
primary, prefix+suffix is secondary), added a "Candidate volume & `--loud`"
section, and updated the options table.

---

## 2026-10-16 — Trust shortscan's resolved full name (skip the fan-out)

**Problem.** At the web root, `ASPNET~1 -> 76716 candidates (shortscan:
ASPNET_CLIENT)`: shortscan had already *resolved* the real name, yet
`build_candidates` still generated the full 38k×exts wordlist fan-out and only
then added the known name. Same for `REPORT~1 -> REPORTING`, `TEMPLA~1 ->
TEMPLATES`, etc. — each ballooned to ~78k for nothing.

**Change.** `build_candidates` now short-circuits: if `sn.fullname` is set, it
returns just `{fullname, fullname/}` (verify as file + dir) and skips the
wordlist generation entirely.

**Why.** If shortscan resolved the name, recovery is already done — the only
thing left is to confirm existence and file-vs-dir, which the two probes cover.
Every `(shortscan: …)` entry collapses from ~78k to 2 candidates. Unresolved
short names still fan out normally.

---

## 2026-10-16 — Seed known ASP.NET default directories instead of fuzzing

**Problem.** Recursing into `aspnet_client/` and `system_web/` wasted huge
request volume, and the real children — .NET version folders like `4_0_30319`
(8.3 name `40303~1`) — **can't be rebuilt from dictionary words** at all, so the
loop couldn't descend into them regardless.

**Change.** Added `seed_candidates()` plus `KNOWN_DIR_CONTENTS`,
`DOTNET_VERSIONS`, `DOTNET_VERSION_CONTENTS`. When the loop recurses into a
known default directory it tests the curated real child names directly and
skips the wordlist fan-out:
- `aspnet_client/` → `system_web`, `system_web_extensions`
- `system_web/` (+ `_extensions`) → the real .NET version folders
- a version folder (regex `\d+(?:_\d+)+`) → static client scripts
  (`WebUIValidation.js`, `SmartNav.js`, …) and `crystalreportviewers*`
Anything shortscan fully resolves on its own is still tested inside a seeded dir.

**Why.** These dirs ship with every IIS/ASP.NET install and have small, known
contents. Seeding reaches the high-value targets (notably the Crystal Reports
viewer dirs, tied to old path-traversal CVEs) that fuzzing would never recover,
while cutting requests from tens of thousands to ~20 per directory.

**Follow-up (same day).** Expanded the Crystal Reports viewer dirs back to older
Business Objects versions (`crystalreportviewers`, `8`, `82`, `85`, `9`, `10`,
`102`, `11`, `115`, `12`, `13`, `14`) — old clients run old stacks, and the
extra probes are cheap.

---

## 2026-10-16 — Pin truncated extensions to a curated set (`MAIN_EXT`)

**Problem.** A truncated extension (`.XYZ`, len 4) fanned out to *every*
extension in the raft list starting with those 3 chars. `.PHP` → 26 exts,
`.HTM` → ~36, `.CON` → 10 (`.config`, `.conf`, plus noise like `.contact.php`,
`.contrib`). That multiplier compounded the stem explosion — e.g.
`REWRIT~1.CON` hit ~383k candidates. The raft extension list is also full of
junk entries.

**Change.** Added `MAIN_EXT`, a curated map from the 3-char truncation to the
real extension(s): `.php→.php`, `.htm→.html`, `.asp→.aspx`,
`.con→.config/.conf`, plus `.asa→.asax`, `.ash→.ashx`, `.asm→.asmx`,
`.asc→.ascx`, `.mas→.master`, `.res→.resx`, `.svc`, `.dll`, `.xml`, `.jso→.json`,
and other common web/IIS extensions. A truncated prefix in the map resolves to
just those; anything unlisted still fans out across the wordlist.

**Why.** On a web/IIS target the real extension is almost always the one obvious
choice, so pinning kills the junk-extension multiplier (e.g. `REWRIT~1.CON`
~383k → ~77k) while the fallback keeps exotic extensions covered.

*Trade-off noted:* pinning means we no longer test variants like `.php5`,
literal `.htm`, or classic `.asp`. Add them to `MAIN_EXT` if a target needs them.
