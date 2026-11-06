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
     exactly. No extension → the bare `name` is probed (a directory reveals
     itself by 301-redirecting to `name/`; `--probe-dirs` also fires `name/`).
   - If shortscan already resolved a `fullname`, it's seeded straight in.
3. **ffuf** fires the candidate set at the live server, in **two tiers** (see
   [Tiered fan-out](#tiered-fan-out)). `-ac` auto-calibration drops wildcard
   noise; the response tells us file vs directory (a directory 301-redirects to
   `.../name/`).
4. Every confirmed **directory** becomes the next shortscan target. Repeat to
   `--max-depth`.

### Tiered fan-out

The candidate set for a truncated short name is dominated by the suffix
compounds and numeric completions (hundreds of candidates), but most real
word-names are recovered by the cheap **dictionary prefix-match**. So shortloop
fires in two tiers per directory and only pays for the expensive part when it
has to:

- **Tier 1** (cheap, high-hit): the shortscan `fullname` if any, the bare 6-char
  prefix, the dictionary prefix-matches, and any **run-global confirmed
  vocabulary** (names confirmed elsewhere this run whose 8.3 collides here — the
  same app reuses its vocabulary across directories, so these are retried first
  on recursion). Usually a handful to a few dozen candidates.
- **Tier 2** (the fan-out): the prefix+suffix compounds, `--compound-stems`, and
  numeric completions — fired **only at the short names tier 1 didn't resolve**,
  and deduped against what tier 1 already sent.

A name that resolves to a plain dictionary word (`streaming`, `orderdetails`)
never pays for tier 2 at all — e.g. `STREAM~1` drops from ~1,300 candidates to
~9. The end-of-run summary prints the **total candidate requests fired** so you
can see the effect.

Two defaults further trim tier 2's volume (both reversible):

- An extension-less short name fires only the **bare** `name` probe, not
  `name/`; a real directory reveals itself by 301-redirecting `name` → `name/`,
  so the slash probe is redundant and doubles the count. `--probe-dirs` restores
  it for a server where `name` 404s but `name/` answers.
- `--number-matches` (appending numbers to *every* dictionary match, not just
  the bare prefix) is **off by default** — it multiplies by the match count and
  is a large, low-hit volume driver.

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
  each curated suffix is also glued onto every dictionary match with each
  **joiner**, bounded by `MAX_COMPOUND_NAME`. It uses the small curated list (not
  the loud union), but still multiplies by the match count — e.g. a truncated
  `CONTRA~1` goes from ~1.4k to ~15k candidates. Off by default; reach for it on
  a stubborn truncated stem where the real name is clearly a compound.
  - **`--compound-joiners`** sets the joiners (default `'' '_' '-'`, i.e.
    `contractmanagement` / `contract_management` / `contract-management`). Pass
    the token `empty` for direct concatenation and `space` for `%20`, e.g.
    `--compound-joiners empty _ space`. A real spaced name — `Contract
    Management.pdf` — strips its spaces for the 8.3 short name, so it collapses to
    the **same** `CONTRA~1` as `contractmanagement` and is reachable over HTTP
    only as `contract%20management.pdf`. `%20` is **not** in the default set (it's
    another ×1.3 on an already heavy pass); add it on document-heavy targets
    where spaced names are likely.

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
(`default.aspx.cs` → short name `DEFAUL~1.CS`), a long extension truncated to
three chars (`web.config` → `WEB~1.CON`), or a **leading-dot dotfile**
(`.gitignore` → short name `GITIGN~1`, `.env` → `ENV~1`) is structurally
impossible for it to produce — even under `--loud`. (Windows drops the leading
dot before deriving the 8.3 name, so a dotfile is extension-less and the
generator would only ever build `gitignore`, never `.gitignore`.)

So before the expensive loud retry, shortloop runs a **custom full-name pass**
over the unresolved short names: a small curated list (`CUSTOM_NAMES` in the
script — `web.config`, `web.conf`, `default.aspx.cs`,
`default.aspx.designer.cs`, `default.master.cs`, `defaultcontroller.cs`,
dotfiles like `.gitignore` / `.gitconfig` / `.env` / `.htaccess` and
source-control dirs like `.git` / `.svn` / `.vs`,
plus extension-less dirs like `pki-validation` / `acme-challenge`, …).
Extension-less entries (including dotfiles) only ever match **dir-like** short
names, and are probed
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

### Confirmed but unservable (server-blocked extensions)

Some short names can never be confirmed by ffuf no matter how many candidates you
throw at them — not because the name is hard to guess, but because IIS/ASP.NET
**refuses to serve the extension at all**. `.config`, `.cs`, `.vb`, `.master`,
`.asax`, `.ascx`, `.resx`, `.csproj`, … are mapped to `System.Web.HttpForbiddenHandler`
(or denied by IIS Request Filtering), so a direct request returns a block page —
*"This type of page is not served."* or an HTTP 404.7 — instead of the file.

The catch that makes brute force pointless here: **the block fires on the
extension, not the file**. A request for a random non-existent `whatever.config`
returns the *same* block page as a real `web.config`. So the response proves
nothing about existence and never reveals the full name — ffuf can neither fetch
these nor tell which candidate is real. shortscan's 8.3 enumeration is the only
proof the file is there.

So before the fan-out, shortloop detects which of these extensions **this
particular server** actually blocks, with **one control request per extension**
(a guaranteed-nonexistent `shortloop-nx-<rand>.<ext>`, matched purely on the
block-page body signature). Then:

- **extension blocked** → before writing anything off, shortloop still fires each
  blocked short name's **best-guess name(s) once, with normal matching** — a
  reachability check, because a *specific* file can occasionally be served even
  when a random one isn't (source-disclosure quirks, a static mapping, a
  `<location>` override, a served backup). `web.config` in particular turns up
  viewable in odd setups. Anything that actually responds is recorded and
  recursed like any other hit. Only the short names that *still* don't resolve
  are set aside as **unservable**: confirmed to exist (shortscan saw it), full
  name not recoverable over HTTP. Those are excluded from the broad fan-out and
  from the custom and loud `--last-chance` passes (all of which would just
  re-hit the same block — thousands of requests that structurally cannot
  confirm). They're reported in their own end-of-run bucket, with the best-guess
  hints from the candidate generator, and written to `<output>.unservable` when
  `-o` is set:

  ```
  ==> 2 unservable - exist (shortscan) but the extension is server-blocked; name not fetchable over HTTP
    https://target/app/  [PACKAG~1.CON]  .config blocked  ~ packages.config, package.config, ...
    https://target/app/  [MAIN~1.MAS]    .master blocked  ~ main.master
  ```

- **extension not blocked** (a misconfigured server that really does serve
  `.config`) → the control comes back clean and those short names stay in the
  normal pipeline, so an unexpectedly-served copy is still confirmed and recursed
  like any other hit. No recall is lost.

The hints are the generator's best completions (dictionary prefix-matches on the
stem, plus the bare stem, with the blocked extension pinned on) — e.g.
`PACKAG~1.CON` → `packages.config`. They are **reported, not asserted**: the
server can't tell us which one is real, so shortloop never claims a specific
confirmed name for an unservable short name.

- Cheap: zero extra requests in directories with no protected-extension short
  names; otherwise one control request per distinct protected extension, plus —
  only when an extension is actually blocked — a few best-guess names per blocked
  short name for the reachability check. Still a tiny fraction of the fan-out and
  loud retry it replaces.
- The regex probe uses `ffuf -mmode and -mc all -mr <signature>` (and no `-ac`),
  so a wildcard-200 server can't produce a false "blocked", and the block page
  can't be auto-calibrated away as noise.
- **`--no-unservable-check`** disables the probe entirely; protected short names
  then flow through the normal pipeline and land in **unconfirmed** as before.

The real prize for a blocked `.config` is usually a **served backup** that
bypasses the extension block — `packages.config.bak` / `.old` / `.txt` are served
normally and leak the full contents. Those surface as *different* short names
(`.BAK`, `.OLD`, `.TXT`) and go through the normal confirmation path.

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

### Manual insertion-point fuzzing (`--insertion-point`)

Sometimes shortscan proves a file exists but the candidate generator can't
rebuild the name, because the unknown tail isn't a dictionary word —
`REQUIR~1.ZIP` (`require` + something), `DELETE~1.BAT`. When you can see the
**shape** of the real name, `--insertion-point` lets you fuzz just the unknown
span yourself instead of relying on the wordlist fan-out.

It takes a relative template under the base URL with the literal keyword `FUZZ`
marking the spot. Each `--insertion-wordlist` entry is substituted for `FUZZ`,
and the results go through the **same** pipeline as everything else — file-vs-
directory classification, `-o` recording, and recursion into any directory the
fuzz turns up (honouring `--max-depth`). shortscan and the candidate generator
are skipped entirely; this is a pure, operator-driven ffuf pass.

```bash
# complete require<tail>.zip against the directory that reported REQUIR~1.ZIP
python3 shortloop.py https://target/_resources/ \
    --insertion-point 'requireFUZZ.zip' --max-depth 0

# a .bat whose tail you want to brute from a custom list
python3 shortloop.py https://target/_resources/ \
    --insertion-point 'deleteFUZZ.bat' --insertion-wordlist ./tails.txt --max-depth 0

# the FUZZ can sit anywhere in the template: prefix, middle, or extension
python3 shortloop.py https://target/ --insertion-point 'FUZZ.bak'
```

- The keyword is the literal, case-sensitive string `FUZZ` (ffuf's convention).
- A template that doesn't look like a file (no known extension) is also probed
  as a directory, so `backupFUZZ` finds both `backup01` and a `backup01/` dir.
- Default wordlist is raft-small-words; override with `--insertion-wordlist`.
- `--max-depth 0` keeps it a one-shot; a higher depth shortscans any directory
  the fuzz discovers, rejoining the normal recursive pipeline.

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
| `--insertion-point TEMPLATE` | manual fuzz mode: skip shortscan/candidate-gen and fire a wordlist at a single insertion point, where `FUZZ` marks the spot (`'requireFUZZ.zip'`). Hits are classified/recorded/recursed like any other. See [Manual insertion-point fuzzing](#manual-insertion-point-fuzzing---insertion-point) |
| `--insertion-wordlist FILE...` | wordlist(s) substituted into the `--insertion-point` `FUZZ` keyword (default raft-small-words) |
| `-H 'Header: v'` | extra request header (repeatable) |
| `-x http://127.0.0.1:8080` | proxy through Burp |
| `-t N` / `--rate N` | threads / ffuf req-per-sec cap |
| `--no-numbers` | disable numeric candidates |
| `--max-number N` / `--year-start` / `--year-end` | tune numeric range |
| `--number-matches` | also append numbers to every dictionary match, not just the bare prefix (off by default — large, low-hit volume driver) |
| `--probe-dirs` | also fire the explicit `name/` directory probe for extension-less names; off by default (a dir 301-redirects `name` → `name/`, so the slash probe is usually redundant and doubles the count) — see [Tiered fan-out](#tiered-fan-out) |
| `--loud` / `--full-suffixes` | union the full `--suffix-wordlists` file(s) into the curated list for max recall (~150× volume); off by default |
| `--compound-stems` | also append the curated suffix words to the dictionary stem matches (not just the bare prefix), reaching compounds like `contract`+`manager` / `export`+`data`; higher volume, off by default |
| `--compound-joiners JOINER...` | joiners between stem match and suffix under `--compound-stems` (default `'' '_' '-'`); tokens `empty` = direct concat, `space` = `%20` for spaced names, e.g. `--compound-joiners empty _ space` |
| `--resolve-assets` | also try to recover CSS/image full names; by default short names with a `css`/`png`/`jpg`/`gif`/`ico`/`svg`/… extension are skipped as low-value static assets |
| `--last-chance` | auto-run the end-of-run loud retry on unresolved short names (otherwise you're prompted at a terminal) |
| `--no-last-chance` | never retry and never prompt; just list the unresolved short names |
| `--custom-wordlists ...` | extra file(s) of full real names (`web.config`, `Default.aspx.cs`) fired at unresolved short names before the loud retry; merged with the built-in `CUSTOM_NAMES` |
| `--no-custom` | skip the custom full-name pass before the loud retry |
| `--no-unservable-check` | skip the server-blocked-extension probe; by default short names whose extension IIS refuses to serve (`.config`/`.cs`/`.master`/…) are detected with one control request each and reported as [unservable](#confirmed-but-unservable-server-blocked-extensions) instead of being fuzzed and loud-retried in vain |
| `--suffix-wordlists ...` | full word list appended after the prefix **when `--loud` is set** (default raft-small-words); ignored otherwise — the default uses the curated `COMMON_SUFFIXES` |
| `--stem-wordlists ...` / `--ext-wordlists ...` | swap the dictionary prefix-match / extension lists (defaults: raft-medium) |

## Numbers

Numeric candidates are only ever attached to something that already matches the
short-name prefix (never standalone), to keep request volume sane:

- `prefix + digits`  (`backup` → `backup1`, `backup07`, `backup99`)
- `prefix + years`   (`backup` → `backup2024`)
- `matched word + light number set` — **off by default**, enable with
  `--number-matches` (it multiplies by the dictionary-match count)

Numeric candidates live in [tier 2](#tiered-fan-out), so they only fire at short
names the cheap tier-1 pass didn't already resolve.

## Requires

`shortscan`, `ffuf`, Python 3, and SecLists at `/opt/SecLists`. The optional
[Claude-guided first pass](#claude-guided-first-pass-optional) additionally needs
the authenticated `claude` CLI on `PATH` — only when `--claude` is used.
```
go install github.com/bitquark/shortscan/cmd/shortscan@latest
go install github.com/ffuf/ffuf/v2@latest
```
