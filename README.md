# shortloop

Recursive IIS 8.3 short-name → full-name recovery. Chains **shortscan** and
**ffuf** in a loop to show the real impact of an IIS tilde-enumeration finding.

```
shortscan ──► candidate generation (raft wordlists + numbers) ──► ffuf ──► recurse
   ▲                                                                         │
   └──────────────── every confirmed DIRECTORY feeds back in ───────────────┘
```

## How it works

1. **shortscan** (`--output json --norecurse`) enumerates 8.3 short names on a
   directory, e.g. `STREEM~1` (dir) or `CONFIG~1.ASP` (file).
2. For each short name we expand the known prefixes into real candidate names:
   - **stem**: `len==6` means the first 6 chars are known and the tail is not.
     Recovery is two-pronged:
     1. **dictionary prefix-match** — whole names that begin with the prefix
        (`shipping` from `shippi`, `orderdetails` from `orderd`, `streaming`
        from `stream`). This lands most real English-word names and costs no
        extra requests beyond what matches.
     2. **prefix + suffix word** — for compounds whose cut lands on a word
        boundary and whose full form isn't in any list (`streem` + `alert` →
        `streemalert`). By default this uses a small curated common-suffix list
        (`COMMON_SUFFIXES`, ~340 words), *not* a 38k wordlist — see
        [Candidate volume & `--loud`](#candidate-volume----loud).

     Plus the bare prefix itself and numeric completions. `len<6` means the stem
     is already complete.
   - **ext**: `.XYZ` (len 4) is truncated. Known prefixes are pinned to a curated
     set of the real extensions that start with them (`MAIN_EXT` in the script —
     `.PHP` → `.php`, `.HTM` → `.html`, `.ASP` → `.aspx`, `.CON` → `.config`/`.conf`,
     `.ASA` → `.asax`, etc.); any prefix *not* in that table fans out to every
     extension starting with those 3 chars. Shorter means the extension is known
     exactly. No extension → it's probed as both a directory and an ext-less file.
   - If shortscan already resolved a `fullname`, it's seeded straight in.
3. **ffuf** fires the candidate set at the live server. `-ac` auto-calibration
   drops wildcard noise; the response tells us file vs directory
   (a directory 301-redirects to `.../name/`, or a `name/` probe returns 200/403).
4. Every confirmed **directory** becomes the next shortscan target. Repeat to
   `--max-depth`.

### Known directories (seeded, not fuzzed)

Some directories ship with every IIS/ASP.NET install and have a small, known set
of contents whose 8.3 short names can't be rebuilt from dictionary words (a .NET
version folder like `4_0_30319` → `40303~1`). When shortloop recurses **into** one
of these, it tests the real child names directly and **skips the wordlist fan-out**:

| directory | seeded children |
|---|---|
| `aspnet_client/` | `system_web`, `system_web_extensions` |
| `system_web/` (and `system_web_extensions/`) | .NET version folders (`4_0_30319`, `2_0_50727`, `3_5`, …) |
| a version folder (`4_0_30319/`, …) | static client scripts (`WebUIValidation.js`, `SmartNav.js`, …) and `crystalreportviewers*` (high-value: old path-traversal CVEs) |

Edit `DOTNET_VERSIONS` / `DOTNET_VERSION_CONTENTS` / `KNOWN_DIR_CONTENTS` in the
script to adjust. Anything shortscan fully resolves on its own is still tested
even inside a seeded directory.

### Candidate volume & `--loud`

An unresolved truncated 6-char stem is the expensive case. The real name is
usually either a whole dictionary word starting with the prefix (handled by the
**dictionary prefix-match**, which actually lands the hit) or a compound of two
common words. `shippi` + `ng` = `shipping` can never come from a word list
(`ng` isn't a word), so appending all 38k raft words to the prefix is almost
pure waste for normal names — it only helps for boundary compounds like
`streem` + `alert`.

So by default the **prefix + suffix word** step uses a small curated list,
`COMMON_SUFFIXES` (~340 words people actually append: `admin`, `details`,
`report`, `alert`, `shipping`, …). This cuts a truncated stem from ~38k
candidates to a few hundred — roughly **100–150× fewer requests** — with
negligible recall loss, because the dictionary prefix-match is untouched.

- **`--loud`** (alias `--full-suffixes`) unions the full `--suffix-wordlists`
  file(s) back into the curated list for maximum recall, at ~150× the request
  volume. Use it on a target you're already hammering, or when a short name
  refuses to resolve and you suspect an uncommon tail word.
- Compounds longer than `MAX_COMPOUND_NAME` (24 chars) are skipped — real names
  rarely run a 6-char prefix plus a 14-letter word.
- **`--compound-stems`** closes a different gap: the suffix words are normally
  only appended to the bare 6-char *prefix* (`contra`+word), never to the longer
  **dictionary matches** (`contract`, `contractor`). So an app compound whose
  base word runs past 6 chars — `contractmanager`, `contract_manager`,
  `exportdata` — can't be built by any pass, including `--loud`. With this flag,
  each curated suffix is also glued onto every dictionary match (joiners `""`
  and `"_"`), bounded by `MAX_COMPOUND_NAME`. It uses the small curated list (not
  the loud union), but still multiplies by the match count — e.g. a truncated
  `CONTRA~1` goes from ~1.4k to ~15k candidates. Off by default; reach for it on
  a stubborn truncated stem where the real name is clearly a compound.

The startup line reports which mode is active, e.g.
`loaded 344 suffix words (curated), …` vs `… (loud), …`.

Other big volume levers: `MAIN_EXT` extension pinning (above), shortloop trusting
any name shortscan already resolved (it verifies that one name instead of
fuzzing), and **skipping CSS/image short names** — by default a short name whose
extension is `css`/`png`/`jpg`/`gif`/`ico`/`svg`/… is treated as a low-value
static asset and not resolved at all (`--resolve-assets` turns resolution back
on). Code/config extensions like `.cs` and `.js` are *not* treated as assets.

### Custom full-name pass (before loud)

Some real names can never come out of the candidate generator, because it only
builds **dot-free** stems. A file with an internal dot or a double extension
(`default.aspx.cs` → short name `DEFAUL~1.CS`) or a long extension truncated to
three chars (`web.config` → `WEB~1.CON`) is structurally impossible for it to
produce — even under `--loud`.

So before the expensive loud retry, shortloop runs a **custom full-name pass**
over the unresolved short names: a small curated list (`CUSTOM_NAMES` in the
script — `web.config`, `web.conf`, `default.aspx.cs`,
`default.aspx.designer.cs`, `default.master.cs`, `defaultcontroller.cs`,
plus extension-less dirs like `pki-validation` / `acme-challenge`, …).
Extension-less entries only ever match **dir-like** short names, and are probed
as both a file and a directory so a hit is classified correctly and recursed.
Only the entries whose reconstructed 8.3 name **collides** with an unresolved
short name are fired (dedot the base → first 6 chars for the stem, final
extension for the ext, matched against the short name's known stem/ext), so it
costs a handful of requests, not thousands. Anything it lands is removed from
the loud retry; anything it misses falls through unchanged.

- `--custom-wordlists FILE...` merges extra full-name files into the built-in list.
- `--no-custom` skips the pass entirely.
- It runs regardless of `--loud` (the loud fan-out can't build these names either).

Example: in a run where the root left `WEB~1.CON` and `DEFAUL~1.CS` unresolved,
the custom pass fires 15 targeted candidates instead of the ~38k loud set, and
only a genuinely unknown short name like `PKI-VA~1` still needs the loud retry.

### `--last-chance` and unconfirmed short names

shortscan often finds a short name the curated pass can't complete (e.g.
`PRODUC~1 -> 7804 candidates` with no hit). That short name still *proves a file
or directory exists* — we just couldn't recover its full name. shortloop never
drops that signal:

- After the ffuf pass, each short name with no confirmed hit is tracked.
  Matching is one-to-one, so `~1/~2/~3` collisions stay honest — three `PORTAL~`
  entries with a single confirmed `portal*` name leave **two** reported as
  unresolved.
- The **loud retry** runs *only* on those unresolved short names (a targeted
  desperation pass), then re-checks. Known seeded directories are exempt, and
  any directory newly discovered during the retry is scanned normally, so
  recursion depth isn't lost.
- Whatever is still unresolved is printed at the end under an **unconfirmed**
  banner as `url [SHORT~1.EXT]`, and written to `<output>.unconfirmed` when
  `-o` is set. These are high-value leads: a confirmed file exists, name unknown.

**You don't decide up front.** The curated scan runs to completion first; only
then, if anything is unresolved, is the loud retry considered:

| situation | what happens |
|---|---|
| neither flag, at a terminal | you're **asked** `[y/N]` after the run |
| `--last-chance` | retry runs automatically, no prompt |
| `--no-last-chance` | never retries, never prompts — just lists unresolved |
| neither flag, not a terminal (piped/cron) | skipped (can't prompt) |

```bash
python3 shortloop.py https://target/                 # run, then get asked
python3 shortloop.py https://target/ --last-chance   # run + auto-retry, no prompt
python3 shortloop.py https://target/ -o found.txt    # asked; leftovers -> found.txt.unconfirmed
```

### Redirects

ffuf is run **without** following redirects, on purpose. A directory reveals
itself by 301-redirecting `name` → `name/`, and that redirect is exactly the
signal `classify()` uses to separate directories from files; a 302 also already
confirms a resource exists. Following redirects would destroy the file-vs-dir
distinction for no gain, so it stays off.

### Claude-guided first pass (optional)

With `--claude`, shortloop runs an **LLM reasoning pass before the ffuf fan-out**
on each directory. It shells out to the `claude` CLI non-interactively
(`claude -p`), so it reuses whatever auth your Claude Code install is already
configured with — **no API key and no extra Python packages**. shortscan's short
names are handed to Claude *as a set* — the siblings and the directory path
usually betray the app's domain (`CONTRA~1` + `INVOIC~1` + `VENDOR~1` → a
procurement app), which sharply narrows what each truncated name probably is.
Claude returns a small, prioritized list of real-name guesses; those are
**8.3-collision-filtered** against each short name (same `custom_matches` test
the custom pass uses, so a guess only fires at a short name it could actually
complete and one-to-one resolution stays honest), fired at ffuf **first**, and
anything confirmed is recorded and recursed like any other hit.

Only the short names Claude *doesn't* resolve fall through to the normal
`build_candidates` → ffuf fan-out (and then the custom and last-chance passes).
So it's strictly "try the cheap, reasoned guesses first; brute-force the rest."

- Enabled by `--claude` (off by default). Without it, the step never runs and
  it's pure ffuf, byte-for-byte as before.
- `--claude-bin` (default `claude`) points at the CLI; `--claude-model` is
  passed straight to `claude --model` (an alias like `opus`/`sonnet`/`haiku`, or
  a full id — empty uses the CLI's configured default); `--claude-max-guesses`
  (default 150) bounds the pre-ffuf volume; `--claude-timeout` (default 120s)
  caps a single `claude -p` call.
- Any failure — CLI missing, non-zero exit, timeout, unparsable reply — logs a
  warning and falls back to ffuf; it never aborts a run.

Requires the `claude` CLI on `PATH` (already authenticated) **only** when the
pass is used.

```bash
# reason first, then brute-force the leftovers
python3 shortloop.py https://target/ --claude

# force the Opus alias and cap guesses
python3 shortloop.py https://target/ --claude --claude-model opus --claude-max-guesses 100
```

## Usage

```bash
python3 shortloop.py http://target/app/ -o found.txt
```

### Targeting a specific directory or short name

The positional URL is the starting directory, and `--max-depth` controls how far
it recurses from there. To scan **one directory** and nothing it discovers, pass
that directory and `--max-depth 0`. To focus on **one short name** inside it
(e.g. throw `--compound-stems`' volume at just the `.zip`), add `--only`:

```bash
# just this directory, no recursion
python3 shortloop.py https://target/reports/ --max-depth 0

# only the contract archive, with full compound firepower
python3 shortloop.py https://target/ --max-depth 0 --only 'CONTRA~1.ZIP' --compound-stems

# every .zip short name on the start directory
python3 shortloop.py https://target/ --max-depth 0 --only '*.ZIP'
```

`--only` filters the names shortscan reports; seeded default-directory contents
(`aspnet_client/`, …) are unaffected.

Common options:

| flag | meaning |
|---|---|
| `-o FILE` | append confirmed URLs to FILE as they're found |
| `--claude` | enable the Claude reasoning pass (via `claude -p`, using the CLI's own auth): reasoned guesses tried before the ffuf fan-out, leftovers fall back to brute forcing. Off by default |
| `--claude-bin PATH` | path to the `claude` CLI (default `claude`) |
| `--claude-model ID` | model passed to `claude --model` (alias or full id; empty = CLI default) |
| `--claude-max-guesses N` | cap guesses Claude proposes per directory (default 150) |
| `--claude-timeout N` | max seconds for a single `claude -p` call (default 120) |
| `--max-depth N` | recursion depth (default 4; `0` = scan only the given directory) |
| `--only PATTERN...` | only process short names whose label matches a case-insensitive glob (`'CONTRA*'`, `'*.ZIP'`); skip the rest. Pair with `--max-depth 0` to target one name |
| `-H 'Header: v'` | extra request header (repeatable) |
| `-x http://127.0.0.1:8080` | proxy through Burp |
| `-t N` / `--rate N` | threads / ffuf req-per-sec cap |
| `--no-numbers` | disable numeric candidates |
| `--max-number N` / `--year-start` / `--year-end` | tune numeric range |
| `--no-number-matches` | numbers on the bare prefix only (lower volume) |
| `--loud` / `--full-suffixes` | union the full `--suffix-wordlists` file(s) into the curated list for max recall (~150× volume); off by default |
| `--compound-stems` | also append the curated suffix words to the dictionary stem matches (not just the bare prefix), reaching compounds like `contract`+`manager` / `export`+`data`; higher volume, off by default |
| `--resolve-assets` | also try to recover CSS/image full names; by default short names with a `css`/`png`/`jpg`/`gif`/`ico`/`svg`/… extension are skipped as low-value static assets |
| `--last-chance` | auto-run the end-of-run loud retry on unresolved short names (otherwise you're prompted at a terminal) |
| `--no-last-chance` | never retry and never prompt; just list the unresolved short names |
| `--custom-wordlists ...` | extra file(s) of full real names (`web.config`, `Default.aspx.cs`) fired at unresolved short names before the loud retry; merged with the built-in `CUSTOM_NAMES` |
| `--no-custom` | skip the custom full-name pass before the loud retry |
| `--suffix-wordlists ...` | full word list appended after the prefix **when `--loud` is set** (default raft-small-words); ignored otherwise — the default uses the curated `COMMON_SUFFIXES` |
| `--stem-wordlists ...` / `--ext-wordlists ...` | swap the dictionary prefix-match / extension lists (defaults: raft-medium) |

## Numbers

Numeric candidates are only ever attached to something that already matches the
short-name prefix (never standalone), to keep request volume sane:

- `prefix + digits`  (`backup` → `backup1`, `backup07`, `backup99`)
- `prefix + years`   (`backup` → `backup2024`)
- `matched word + light number set` (toggle with `--no-number-matches`)

## Requires

`shortscan`, `ffuf`, Python 3, and SecLists at `/opt/SecLists`. The optional
[Claude-guided first pass](#claude-guided-first-pass-optional) additionally needs
the authenticated `claude` CLI on `PATH` — only when `--claude` is used.
```
go install github.com/bitquark/shortscan/cmd/shortscan@latest
go install github.com/ffuf/ffuf/v2@latest
```
