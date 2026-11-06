#!/usr/bin/env python3
"""
shortloop - recursive IIS short-name (8.3 "tilde") -> full-name recovery.

Pipeline, repeated to a depth limit:

  shortscan (--output json)            discover 8.3 short names on a directory
        |
        v
  candidate generation                 for each short name, expand the known
                                       stem/ext prefixes into real candidate
                                       names using the raft wordlists (+ numbers)
        |
        v
  ffuf                                 fire the candidates at the live server and
                                       keep only what the server confirms
        |
        v
  recurse                              any confirmed DIRECTORY becomes a new
                                       shortscan target -> rinse and repeat

Why ffuf does the recovery (not shortscan's own autocomplete):
  shortscan tells us a file exists whose 8.3 name is e.g. STREEM~1 (dir) or
  CONFIG~1.TXT (file). The 8.3 name only reveals the first <=6 chars of the
  stem and the first <=3 chars of the extension. ffuf, driven against the real
  server, both recovers the missing characters AND tells us empirically whether
  the result is a file or a directory (a directory 301-redirects to .../name/).

Reading shortscan's JSON `result` objects (confirmed against shortscan v0.9.2):
  shortfile : recovered stem, UPPERCASE, <=6 chars.
              len == 6  -> TRUNCATED, real stem is >= 6 chars -> must fuzz tail
              len <  6  -> stem is COMPLETE, we know it exactly
  shortext  : recovered extension INCLUDING the dot, e.g. ".ASP"
              len == 4 (".XYZ") -> TRUNCATED ext, real ext starts with xyz
              len <  4           -> ext COMPLETE (e.g. ".TX" == real ext "tx")
              ""                 -> no extension seen -> directory or ext-less file
  shorttilde: "~1", "~2" ... (collision index)
  fullname  : only set if shortscan itself resolved the name; if so we trust it
              and verify just that one name, skipping the wordlist fan-out.
"""

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# small console helpers
# --------------------------------------------------------------------------- #

_USE_COLOR = sys.stdout.isatty()


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def blue(s):   return _c("34;1", s)
def green(s):  return _c("32;1", s)
def yellow(s): return _c("33;1", s)
def red(s):    return _c("31;1", s)
def dim(s):    return _c("2", s)


def log(msg, depth=0):
    print(f"{dim('  ' * depth + '|')} {msg}", flush=True)


def banner(msg, depth=0):
    print(f"{'  ' * depth}{blue('==>')} {msg}", flush=True)


# --------------------------------------------------------------------------- #
# shortscan result model
# --------------------------------------------------------------------------- #

@dataclass(eq=False)
class ShortName:
    # eq=False keeps identity-based __eq__/__hash__ so instances stay hashable
    # (usable as dict keys / set members in the tiered fan-out). We always key on
    # the exact objects produced per directory, so identity is the right notion.
    baseurl: str          # directory URL, guaranteed to end with "/"
    shortfile: str        # stem, uppercase, <=6
    shortext: str         # extension incl. leading dot, uppercase, or ""
    shorttilde: str       # "~1"
    fullname: str = ""    # pre-resolved by shortscan, if any

    @property
    def stem_complete(self):
        return len(self.shortfile) < 6

    @property
    def stem_prefix(self):
        return self.shortfile.lower()

    @property
    def ext_complete(self):
        # non-empty and shorter than ".XYZ" -> we know the whole extension
        return self.shortext not in ("", ".") and len(self.shortext) < 4

    @property
    def ext_truncated(self):
        return len(self.shortext) == 4  # ".XYZ"

    @property
    def is_dir_like(self):
        # no extension at all -> treat as possible directory / ext-less file
        return self.shortext in ("", ".")

    def label(self):
        return f"{self.shortfile}{self.shorttilde}{self.shortext}"


# --------------------------------------------------------------------------- #
# wordlists
# --------------------------------------------------------------------------- #

SECLISTS = "/opt/SecLists/Discovery/Web-Content"

# A compound candidate (prefix + suffix word) longer than this is almost never a
# real name -- cap it to trim the long tail, especially under --loud.
MAX_COMPOUND_NAME = 24

# Default joiners used when gluing a common-suffix word onto a dictionary stem
# match under --compound-stems (contract+management -> contractmanagement,
# contract_management, contract-management). "", "_" and "-" are by far the most
# common on Windows/IIS. Overridable with --compound-joiners.
COMPOUND_JOINERS = ("", "_", "-")

# Friendly tokens for joiners that are awkward to pass literally on a shell:
# an empty string (direct concatenation) and a URL-encoded space. A real spaced
# name like "contract management" strips its spaces for the 8.3 short name, so it
# collapses to the same short name as "contractmanagement" and is reachable only
# by requesting "contract%20management".
JOINER_TOKENS = {"empty": "", "none": "", "cat": "", "space": "%20"}


def normalize_joiners(raw):
    """Map friendly tokens (empty/none/cat -> "", space -> %20) to real joiner
    strings, leaving anything else literal, and dedupe while preserving order."""
    out, seen = [], set()
    for j in raw:
        j = JOINER_TOKENS.get(j.lower(), j)
        if j not in seen:
            seen.add(j)
            out.append(j)
    return out

# Curated common-suffix list: the words people actually tack onto a name to form
# a compound directory/file (streem + ALERT, order + DETAILS, ...). This is the
# default for branch #1 of candidate_stems, replacing the ~38k raft fan-out.
# Normal English-word names (shipping, portal, orderdetails) are recovered by the
# dictionary prefix-match (branch #2), NOT by this list, so keeping it small
# costs almost no recall. --loud unions the full raft list back in.
COMMON_SUFFIXES = sorted(set([
    # CRUD / actions
    "add", "edit", "new", "delete", "remove", "create", "update", "view",
    "list", "search", "save", "submit", "cancel", "confirm", "print", "export",
    "import", "upload", "download", "send", "process", "manage", "approve",
    "review", "validate", "generate", "run", "exec",
    # entities (singular + plural)
    "user", "users", "order", "orders", "item", "items", "product", "products",
    "customer", "customers", "account", "accounts", "member", "members",
    "client", "clients", "employee", "employees", "invoice", "invoices",
    "payment", "payments", "report", "reports", "file", "files", "document",
    "documents", "image", "images", "photo", "photos", "message", "messages",
    "email", "emails", "contact", "contacts", "address", "addresses",
    "category", "categories", "group", "groups", "role", "roles", "task",
    "tasks", "event", "events", "job", "jobs", "note", "notes", "ticket",
    "tickets", "request", "requests", "record", "records", "transaction",
    "transactions", "patient", "patients", "survey", "surveys", "project",
    "projects", "template", "templates", "form", "forms", "page", "pages",
    # attributes / parts
    "info", "information", "detail", "details", "data", "summary", "status",
    "type", "types", "name", "names", "id", "code", "codes", "key", "keys",
    "value", "values", "number", "date", "dates", "time", "history", "config",
    "configuration", "settings", "setting", "option", "options", "profile",
    "profiles", "field", "fields", "index", "home", "main", "default",
    "master", "header", "footer", "content", "title", "map", "maps",
    # app / platform terms
    "admin", "portal", "dashboard", "login", "logout", "signin", "signup",
    "register", "auth", "authentication", "session", "security", "access",
    "permission", "permissions", "api", "service", "services", "handler",
    "module", "component", "controller", "model", "helper", "util", "utils",
    "utility", "utilities", "common", "shared", "core", "base", "lib",
    "library", "resource", "resources", "asset", "assets", "static", "public",
    "private", "internal", "external", "test", "temp", "backup", "old",
    "archive", "dev", "staging", "prod", "cache", "tmp",
    # domain-ish (business / healthcare, common in these targets)
    "alert", "alerts", "notification", "notifications", "schedule",
    "scheduler", "appointment", "appointments", "billing", "claim", "claims",
    "shipping", "tracking", "inventory", "catalog", "cart", "checkout",
    "support", "help", "faq", "feedback", "about", "policy", "policies",
    "terms", "privacy", "mgr", "manager", "mgmt", "management",
    # business / documents / finance (contracts, invoicing, procurement) --
    # the shapes behind names like contractmanagement, exportstatement, etc.
    "agreement", "agreements", "contract", "contracts", "proposal",
    "proposals", "quote", "quotes", "quotation", "estimate", "estimates",
    "statement", "statements", "receipt", "receipts", "purchase", "purchases",
    "vendor", "vendors", "supplier", "suppliers", "shipment", "shipments",
    "delivery", "deliveries", "return", "returns", "refund", "refunds",
    "credit", "credits", "ledger", "journal", "audit", "audits", "compliance",
    "certificate", "certificates", "cert", "certs", "license", "licenses",
    "permit", "permits", "renewal", "renewals", "registration", "registrations",
    "application", "applications", "approval", "approvals", "submission",
    "submissions", "requisition", "requisitions", "procurement", "expense",
    "expenses", "budget", "budgets", "forecast", "forecasts", "revenue",
    "sales", "payroll", "timesheet", "timesheets", "disbursement",
    "reimbursement", "amendment", "amendments", "addendum", "exhibit",
    "exhibits", "attachment", "attachments", "appendix", "manifest", "roster",
    "listing", "listings", "catalogue", "rfp", "rfq", "sow", "nda", "msa", "po",
    # healthcare / claims (common in these targets)
    "provider", "providers", "prescription", "prescriptions", "diagnosis",
    "treatment", "treatments", "encounter", "encounters", "referral",
    "referrals", "authorization", "authorizations", "eligibility", "benefit",
    "benefits", "coverage", "copay", "formulary", "lab", "labs", "result",
    "results", "specimen", "enrollment", "enrollments",
]))


def _read_lines(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    out.append(w)
    except FileNotFoundError:
        log(red(f"wordlist not found: {path}"))
    return out


def load_wordlists(args):
    """Build the suffix, stem and extension corpora (all lowercase)."""
    # suffixes: appended after the known 6-char prefix (streem + alert). Default
    # to the small curated list; --loud unions in the full --suffix-wordlists
    # file(s) for max recall at ~150x the request volume.
    suffixes = set(COMMON_SUFFIXES)
    if args.loud:
        for p in args.suffix_wordlists:
            for w in _read_lines(p):
                suffixes.add(w.lower())

    # stems: whole dictionary names, used for prefix matching (streaming)
    stems = set()
    for p in args.stem_wordlists:
        for w in _read_lines(p):
            stems.add(w.lower())
    # derive stems from the files list (strip the extension)
    for p in args.file_wordlists:
        for w in _read_lines(p):
            base = w.rsplit(".", 1)[0].lower()
            if base:
                stems.add(base)

    exts = set()
    for p in args.ext_wordlists:
        for w in _read_lines(p):
            w = w.lower()
            if not w.startswith("."):
                w = "." + w
            exts.add(w)

    suffixes = sorted(suffixes)
    stems = sorted(stems)
    exts = sorted(exts)
    mode = "loud" if args.loud else "curated"
    log(dim(f"loaded {len(suffixes)} suffix words ({mode}), {len(stems)} stems, "
            f"{len(exts)} extensions"))
    if args.compound_stems:
        shown = [("''" if j == "" else j) for j in args.compound_joiners]
        log(dim(f"compound-stems on: suffixing {len(COMMON_SUFFIXES)} curated "
                f"words onto each dictionary match (joiners {', '.join(shown)})"))
    return suffixes, stems, exts


def load_loud_suffixes(args):
    """The full suffix corpus (curated + the --suffix-wordlists files), used for
    the --last-chance loud retry on short names the curated pass couldn't crack."""
    suffixes = set(COMMON_SUFFIXES)
    for p in args.suffix_wordlists:
        for w in _read_lines(p):
            suffixes.add(w.lower())
    return sorted(suffixes)


# --------------------------------------------------------------------------- #
# candidate generation
# --------------------------------------------------------------------------- #

def _numeric_suffixes(args):
    """Suffixes to append to a prefix-matching base (digits + years)."""
    sfx = []
    for n in range(0, args.max_number + 1):
        sfx.append(str(n))
        if n < 100:                       # also zero-padded 2-digit forms
            sfx.append(f"{n:02d}")
    for y in range(args.year_start, args.year_end + 1):
        sfx.append(str(y))
    # keep unique, stable
    seen, out = set(), []
    for s in sfx:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _dict_matches(sn, stems):
    """Whole dictionary words that start with a truncated 6-char prefix
    (streaming from stream). Empty when the stem is already complete."""
    if sn.stem_complete:
        return []
    pref = sn.stem_prefix
    return [w for w in stems if w.startswith(pref) and len(w) > len(pref)]


def candidate_stems_tier1(sn, stems):
    """Tier-1 (cheap, high-hit) stem candidates: the bare prefix plus the whole
    dictionary words that start with it. The dictionary prefix-match lands most
    real English-word names (streaming, orderdetails, shipping), so firing these
    FIRST means a name that resolves here never pays for the tier-2 fan-out
    below. A complete stem is itself the only candidate."""
    if sn.stem_complete:
        return {sn.stem_prefix}
    return {sn.stem_prefix, *_dict_matches(sn, stems)}


def candidate_stems_tier2(sn, stems, suffixes, args):
    """Tier-2 (expensive fan-out) stem candidates, fired ONLY at short names that
    tier 1 left unresolved:
        (1) prefix + every suffix word   (streem + alert = streemalert)
        (2b) optional compound completion on the dictionary matches
        (3)/(4) numeric completions (prefix+digits/years, optionally on matches)
    Empty for a complete stem -- once the stem is known exactly there is nothing
    left to fan out."""
    if sn.stem_complete:
        return set()

    pref = sn.stem_prefix
    out = set()

    # (1) the core IIS short-name technique: complete the known prefix with each
    #     word from the suffix list  ->  streem + alert -> streemalert
    #     (skip absurdly long compounds -- real names rarely run this long)
    out.update(pref + w for w in suffixes
               if len(pref) + len(w) <= MAX_COMPOUND_NAME)

    # (2b) compound completion ON the dictionary matches (opt-in): glue the
    #      curated common-suffix words onto each matched word, so we can reach
    #      app-style compounds like contract+management -> contractmanagement /
    #      contract_management, or export+data. Branch (1) only ever suffixes the
    #      bare 6-char prefix, so these are otherwise unreachable. Deliberately
    #      uses the small COMMON_SUFFIXES (never the loud union) to keep volume
    #      bounded -- it already multiplies by the number of matches.
    matched = _dict_matches(sn, stems)
    if args.compound_stems:
        for m in matched:
            for w in COMMON_SUFFIXES:
                for j in args.compound_joiners:
                    cand = m + j + w
                    if len(cand) <= MAX_COMPOUND_NAME:
                        out.add(cand)

    # (3)/(4) numeric completions
    if not args.no_numbers:
        for s in _numeric_suffixes(args):
            out.add(pref + s)                      # streem1, streem2024, ...
        if args.number_matches:
            light = [str(n) for n in range(0, 10)] + \
                    [str(y) for y in range(args.year_start, args.year_end + 1)]
            for w in matched:
                for s in light:
                    out.add(w + s)
    return out


def candidate_stems(sn, stems, suffixes, args):
    """Full stem candidate set (tier 1 u tier 2). Used by the single-pass loud
    last-chance retry, where the whole set is fired at once by design."""
    return candidate_stems_tier1(sn, stems) | candidate_stems_tier2(
        sn, stems, suffixes, args)


# Truncated 3-char extensions pinned to a short, curated set of the real
# extensions that start with them, instead of fanning out across every (often
# junky) wordlist entry that shares the prefix. Keyed by the 3-char truncation
# shortscan reports (".XYZ"). This is the big candidate-count lever: ".PHP"
# becomes only ".php", ".CON" becomes just the two real IIS configs, etc.
# Anything not listed here still falls back to the wordlist fan-out.
MAIN_EXT = {
    # ASP.NET / classic ASP / IIS
    ".asp": [".aspx"],
    ".asa": [".asax"],
    ".asc": [".ascx"],
    ".ash": [".ashx"],
    ".asm": [".asmx"],
    ".mas": [".master"],
    ".svc": [".svc"],
    ".res": [".resx"],
    ".con": [".config", ".conf"],
    ".dll": [".dll"],
    ".pdb": [".pdb"],
    ".bat": [".bat"],
    ".cmd": [".cmd"],
    # other server-side pages
    ".php": [".php"],
    ".htm": [".html"],
    ".jsp": [".jsp"],
    ".cfm": [".cfm"],
    # config / data / backups
    ".xml": [".xml"],
    ".jso": [".json"],
    ".ini": [".ini"],
    ".txt": [".txt"],
    ".csv": [".csv"],
    ".bak": [".bak"],
    ".log": [".log"],
    ".sql": [".sql"],
    ".mdf": [".mdf"],
    ".zip": [".zip"],
    ".inc": [".inc"],
    # static
    ".css": [".css"],
    ".ico": [".ico"],
}


def candidate_exts(sn, exts, probe_dirs=False):
    """
    Return extension candidates for one short name.

    Special sentinels:
      ""      -> test the bare stem (ext-less file, or a directory via redirect)
      "/"     -> test the stem as an explicit directory  (stem + "/")
    Otherwise a real extension including the leading dot, e.g. ".aspx".

    For an extension-less (dir-like) short name we fire only the BARE stem by
    default. A real directory reveals itself by 301-redirecting name -> name/,
    which classify() already keys on, so the explicit name/ probe is redundant
    and doubles the request count for the most common short-name shape.
    --probe-dirs restores it for the rare server where name 404s but name/ answers.
    """
    if sn.is_dir_like:
        return {"", "/"} if probe_dirs else {""}
    if sn.ext_complete:
        return {sn.shortext.lower()}     # we know the whole extension
    pref = sn.shortext.lower()
    # truncated ext (".XYZ"): if it's a known prefix, pin it to its hand-picked
    # extension(s) (.php -> .php, .con -> .config/.conf) to keep volume sane.
    if pref in MAIN_EXT:
        return set(MAIN_EXT[pref])
    # otherwise the bare 3-char ext is itself valid, plus any longer extension
    # that starts with it (.asp -> .asp, .aspx, .ashx, ...)
    out = {pref}
    out.update(e for e in exts if e.startswith(pref))
    return out


def _fullname_candidates(sn):
    """The one resolved name shortscan already handed us (plus a dir probe when
    it has no file extension). None when shortscan didn't resolve it."""
    if not sn.fullname:
        return None
    fn = sn.fullname.lower()
    cands = {fn}
    if not _looks_like_file(fn):
        cands.add(fn + "/")
    return cands


def _cross_stems_exts(stem_set, cex):
    """Cartesian product stem x ext -> relative candidate names."""
    names = set()
    for st in stem_set:
        for ex in cex:
            names.add(st + "/" if ex == "/" else st + ex)
    return names


def build_candidates(sn, suffixes, stems, exts, args):
    """Full single-pass candidate set (tier 1 u tier 2). Used by the loud
    last-chance retry; the normal pass uses the tiered builders below."""
    # if shortscan already resolved the full name, trust it and skip the whole
    # wordlist fan-out -- there's nothing left to guess, just verify the one name.
    fc = _fullname_candidates(sn)
    if fc is not None:
        return sorted(fc)
    cst = candidate_stems(sn, stems, suffixes, args)
    cex = candidate_exts(sn, exts, args.probe_dirs)
    return sorted(_cross_stems_exts(cst, cex))


def build_candidates_tier1(sn, stems, exts, args):
    """Tier-1 relative candidate names (cheap, fired first): the shortscan
    fullname if any, else bare prefix + dictionary prefix-matches crossed with
    the extension candidates."""
    fc = _fullname_candidates(sn)
    if fc is not None:
        return set(fc)
    cex = candidate_exts(sn, exts, args.probe_dirs)
    return _cross_stems_exts(candidate_stems_tier1(sn, stems), cex)


def build_candidates_tier2(sn, stems, suffixes, exts, args):
    """Tier-2 relative candidate names (the fan-out), fired only at short names
    tier 1 didn't resolve. Empty when shortscan already gave the full name."""
    if sn.fullname:
        return set()
    cex = candidate_exts(sn, exts, args.probe_dirs)
    return _cross_stems_exts(candidate_stems_tier2(sn, stems, suffixes, args), cex)


# --------------------------------------------------------------------------- #
# manual insertion-point fuzzing (bypasses shortscan/candidate generation)
# --------------------------------------------------------------------------- #
#
# When shortscan proves a file exists but the generator can't rebuild its name
# (REQUIR~1.ZIP, DELETE~1.BAT: the tail isn't a dictionary word), the operator
# usually has a good guess at the SHAPE -- "require<something>.zip". This mode
# lets them fuzz just the unknown span: a relative template with the literal
# keyword FUZZ marking the insertion point ("requireFUZZ.zip"), each wordlist
# entry substituted in, then fired through the SAME ffuf -> classify -> emit path
# as everything else (so file/dir detection, -o recording and recursion into any
# discovered directory all still apply).

FUZZ_KEYWORD = "FUZZ"


def build_insertion_candidates(template, words):
    """Expand a FUZZ-marked template into concrete relative candidate names by
    substituting each wordlist entry for the FUZZ keyword. A non-file-looking
    expansion also gets a trailing-slash directory probe, mirroring
    build_candidates, so a directory hit is classified and recursed correctly."""
    names = set()
    for w in words:
        w = w.strip()
        if not w:
            continue
        name = template.replace(FUZZ_KEYWORD, w)
        names.add(name)
        if not name.endswith("/") and not _looks_like_file(name):
            names.add(name + "/")
    return sorted(names)


# --------------------------------------------------------------------------- #
# known default directories (seed real names instead of fuzzing wordlists)
# --------------------------------------------------------------------------- #
#
# Some directories ship with every IIS/ASP.NET install and have a known, small,
# predictable set of contents. Their 8.3 short names (e.g. a .NET version folder
# like 4_0_30319 -> "40303~1") can't be rebuilt from dictionary words, and
# fuzzing 38k random names there is wasted effort. So when we recurse INTO one of
# these directories we test the real child names directly and skip the wordlist
# fan-out entirely.

# Real .NET Framework version folders found under system_web / its siblings.
DOTNET_VERSIONS = [
    "1_0_3705", "1_1_4322",
    "2_0_50727",
    "3_0", "3_5",
    "4_0_30319", "4_5", "4_6", "4_7", "4_8",
]

# Contents of a .NET version folder: static client scripts plus the Crystal
# Reports viewer dirs. crystalreportviewers* is the high-value find (old
# directory-traversal / file-disclosure CVEs).
DOTNET_VERSION_CONTENTS = [
    "webuivalidation.js", "webforms.js", "smartnav.js", "smartnav.htm",
    "menustandards.js", "focus.js", "webparts.js",
    # Crystal Reports / Business Objects viewer dirs, oldest -> newest. Folder
    # name tracks the product version (CR 8.5 -> 85, XI -> 11, XI R2 -> 115,
    # 2008 -> 12, 2010 -> 13). Kept broad on purpose: old clients run old stacks.
    "crystalreportviewers",                        # very old / unversioned
    "crystalreportviewers8", "crystalreportviewers82", "crystalreportviewers85",
    "crystalreportviewers9",
    "crystalreportviewers10", "crystalreportviewers102",
    "crystalreportviewers11", "crystalreportviewers115",
    "crystalreportviewers12", "crystalreportviewers13", "crystalreportviewers14",
]

# directory final path-segment (lowercase) -> curated list of expected children
KNOWN_DIR_CONTENTS = {
    "aspnet_client": ["system_web", "system_web_extensions"],
    "system_web": DOTNET_VERSIONS,
    "system_web_extensions": DOTNET_VERSIONS,
}

# a .NET version folder name, e.g. "4_0_30319", "3_5"
_DOTNET_VERSION_RE = re.compile(r"\d+(?:_\d+)+")


def seed_candidates(url):
    """
    If `url`'s directory is a known ASP.NET default directory, return a curated
    list of expected child names (each probed as both a file and a directory)
    instead of fuzzing the wordlists. Returns None when we have no seed for it.
    """
    seg = url.rstrip("/").rsplit("/", 1)[-1].lower()
    names = KNOWN_DIR_CONTENTS.get(seg)
    if names is None and _DOTNET_VERSION_RE.fullmatch(seg):
        names = DOTNET_VERSION_CONTENTS
    if not names:
        return None
    out = set()
    for n in names:
        n = n.lower()
        out.add(n)            # file / ext-less probe
        out.add(n + "/")      # directory probe
    return sorted(out)


# --------------------------------------------------------------------------- #
# custom full-name list (targeted pass before the loud last-chance retry)
# --------------------------------------------------------------------------- #
#
# A short, curated list of real ASP.NET/IIS filenames that the wordlist fan-out
# simply cannot build:
#   * an internal dot / double extension -- default.aspx.cs -> short DEFAUL~1.CS
#   * a long extension truncated to 3 chars -- web.config -> short WEB~1.CON
#   * a leading-dot dotfile -- .gitignore -> short GITIGN~1 (the leading dot is
#     dropped by Windows, so it's extension-less; candidate_stems would only ever
#     emit "gitignore", never ".gitignore")
# candidate_stems only ever emits dot-free stems, so these never appear in the
# normal OR the loud pass. We fire them at the UNRESOLVED short names (filtered
# by 8.3 match) BEFORE paying for the loud fan-out: it's a few requests instead
# of tens of thousands, and it's more likely to land these specific names.
CUSTOM_NAMES = [
    "web.config", "web.conf",
    "default.aspx.cs", "default.aspx.designer.cs",
    "default.ashx.cs", "default.asmx.cs",
    "default.master.cs", "default.master.designer.cs",
    "default.ascx.cs",
    "defaultcontroller.cs", "defaulthandler.cs", "defaultmodule.cs",
    "defaultmodel.cs", "defaultmembershipprovider.cs", "defaultroleprovider.cs",
    # dotfiles: a leading-dot name is extension-less to Windows 8.3 (GITIGN~1 for
    # .gitignore, ENV~1 for .env), so the generator can never build it. These are
    # high value -- source-control metadata, secrets, server config -- and leak
    # readily when IIS serves the raw file. Extension-less, so they only match
    # dir-like short names and get probed as both a file and a directory.
    ".gitignore", ".gitattributes", ".gitmodules", ".gitconfig", ".git",
    ".env", ".env.local", ".env.production", ".env.development",
    ".htaccess", ".htpasswd", ".dockerignore", ".editorconfig",
    ".npmrc", ".yarnrc", ".ds_store",
    ".vs", ".vscode", ".svn", ".hg", ".idea",
    # .well-known validation dirs (extension-less -> only match dir-like short
    # names). pki-validation is the standard ACME/SSL domain-validation folder
    # (short name PKI-VA~1); acme-challenge is its HTTP-01 sibling.
    ".well-known", "pki-validation", "acme-challenge",
]


def load_custom_names(args):
    """Built-in CUSTOM_NAMES plus any --custom-wordlists files (all lowercase)."""
    if args.no_custom:
        return []
    names = set(CUSTOM_NAMES)
    for p in args.custom_wordlists:
        for w in _read_lines(p):
            names.add(w.lower())
    return sorted(names)


def _name_83(name):
    """Derive the (stem, ext) 8.3 fragments a Windows short name would expose for
    a full filename: stem = first 6 chars of the base with all dots removed; ext
    = the final extension including the dot (or "" when there is none).

    Leading dots are stripped first, because Windows drops them before deriving
    the short name -- which is exactly why a dotfile like ".gitignore" shows up as
    the extension-less short name GITIGN~1 (stem "gitign", no ext), and ".env" as
    ENV~1, rather than as a file whose extension is ".gitignore"."""
    name = name.strip().lower().lstrip(".")
    if "." in name:
        base, last = name.rsplit(".", 1)
        ext = "." + last
    else:
        base, ext = name, ""
    stem = base.replace(".", "")[:6]
    return stem, ext


def custom_matches(sn, entry):
    """True if `entry`'s 8.3 short name would collide with short name `sn` --
    i.e. this full name is a plausible completion of that short name, so it's
    worth firing at `sn`'s directory. Keeps the custom pass tiny and keeps the
    one-to-one resolution matching honest."""
    stem, ext = _name_83(entry)
    if stem != sn.stem_prefix:
        return False
    if sn.is_dir_like:                       # short name has no extension
        return ext == ""
    if sn.ext_complete:                      # whole extension known exactly
        return ext == sn.shortext.lower()
    if sn.ext_truncated:                     # ".XYZ" -> ext must start with xyz
        return ext.startswith(sn.shortext.lower())
    return False


# --------------------------------------------------------------------------- #
# claude: optional LLM reasoning over a directory's short names
# --------------------------------------------------------------------------- #
#
# When --claude is set, we let Claude look at ALL the short names shortscan found
# in a directory at once -- the set usually betrays the app's domain (CONTRA~1 +
# INVOIC~1 + VENDOR~1 -> a procurement app) -- and propose a small, prioritized
# list of likely real names. We reach it through the `claude` CLI in -p
# (non-interactive) mode, reusing its own auth, so there's no API key or SDK
# dependency. Those guesses are fired at ffuf BEFORE the brute-force fan-out;
# only short names Claude doesn't resolve fall through to the normal candidate
# generator. No --claude (or the CLI missing/erroring/timing out) -> this step is
# skipped entirely and it's pure ffuf, exactly as before.

CLAUDE_SYSTEM = (
    "You are assisting an authorized penetration tester performing IIS 8.3 "
    "short-name (tilde) enumeration against a web server they are permitted to "
    "test. A tool has enumerated the 8.3 short names in one directory; each "
    "short name proves a real file or directory exists but only reveals the "
    "first few characters of its name. Your job is to infer the most likely "
    "real (long) names and return concrete candidates to try.\n\n"
    "Reason over the whole set together: sibling names and the directory path "
    "usually reveal the application's domain (billing, claims, contracts, "
    "patient records, etc.), which sharply narrows what each name probably is.\n\n"
    "Hard constraints for every candidate you output:\n"
    "- Base name (the filename with all dots removed, or the directory name) "
    "must satisfy the stem rule stated for a short name: if the stem is marked "
    "TRUNCATED the real base STARTS WITH that prefix and is longer; if it is an "
    "EXACT base, use it verbatim and do not extend it.\n"
    "- Extension must satisfy that short name's extension rule (exact / "
    "starts-with / none).\n"
    "- Prefer real-world file and directory names for this kind of app "
    "(including compounds like 'contractmanagement', 'exportdata', and names "
    "with internal dots or double extensions like 'default.aspx.cs').\n\n"
    "Output ONLY a JSON array of lowercase strings, most likely first, no "
    "commentary and no code fence."
)


def _describe_sn_for_claude(sn):
    """One human-readable line describing a short name's known constraints."""
    if sn.stem_complete:
        stem = f'base name is EXACTLY "{sn.stem_prefix}"'
    else:
        stem = (f'base name STARTS WITH "{sn.stem_prefix}" and is longer '
                f'(TRUNCATED at 6 chars)')
    if sn.is_dir_like:
        ext = "no extension -> a directory or an extensionless file"
    elif sn.ext_complete:
        ext = f'extension is EXACTLY "{sn.shortext.lower()}"'
    elif sn.ext_truncated:
        ext = (f'extension STARTS WITH "{sn.shortext.lower()}" (TRUNCATED '
               f'3-char extension; the real one may be longer, e.g. ".aspx" '
               f'for ".asp", ".config" for ".con")')
    else:
        ext = f'extension "{sn.shortext.lower()}"'
    extra = (f'; shortscan already recovered the full name "{sn.fullname}"'
             if sn.fullname else "")
    return f"{sn.label()}: {stem}; {ext}{extra}"


class Claude:
    """Reasoning pass driven through the `claude` CLI in non-interactive (-p)
    print mode. No API key or SDK: it reuses whatever auth the operator's claude
    CLI is already configured with, and we just pipe a prompt in and read the
    answer out."""

    def __init__(self, bin, model, max_guesses, timeout):
        self.bin = bin
        self.model = model
        self.max_guesses = max_guesses
        self.timeout = timeout

    def _prompt(self, url, shortnames):
        # The CLI takes a single text prompt, so the role/instructions and the
        # data travel together (no separate system field in -p mode).
        lines = [
            CLAUDE_SYSTEM,
            "",
            f"Target directory: {url}",
            "",
            "Short names enumerated in this directory:",
        ]
        for i, sn in enumerate(shortnames, 1):
            lines.append(f"{i}. {_describe_sn_for_claude(sn)}")
        lines += [
            "",
            f"Return a JSON array of up to {self.max_guesses} lowercase "
            "candidate full names, most likely first. Every entry must be a "
            "plausible completion of at least one short name above under its "
            "stem and extension rules.",
        ]
        return "\n".join(lines)

    def guess(self, url, shortnames):
        """Return a flat, deduped list of candidate full names (lowercase).

        Any failure (CLI missing, non-zero exit, timeout, unparsable reply)
        returns [] so the caller falls back to the normal ffuf pipeline."""
        cmd = [self.bin, "-p", "--output-format", "text"]
        if self.model:
            cmd += ["--model", self.model]
        try:
            proc = subprocess.run(cmd, input=self._prompt(url, shortnames),
                                  capture_output=True, text=True,
                                  timeout=self.timeout)
        except subprocess.TimeoutExpired:
            log(red(f"claude timed out after {self.timeout}s; "
                    "falling back to ffuf"))
            return []
        except FileNotFoundError:
            log(red(f"claude CLI not found: {self.bin}; falling back to ffuf"))
            return []
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()
            log(red(f"claude -p exited {proc.returncode} "
                    f"({tail[-1] if tail else 'no stderr'}); "
                    "falling back to ffuf"))
            return []
        return self._parse(proc.stdout)

    @staticmethod
    def _parse(text):
        text = text.strip()
        i, j = text.find("["), text.rfind("]")
        if i == -1 or j == -1 or j < i:
            return []
        try:
            arr = json.loads(text[i:j + 1])
        except json.JSONDecodeError:
            return []
        if not isinstance(arr, list):
            return []
        out, seen = [], set()
        for x in arr:
            if not isinstance(x, str):
                continue
            name = x.strip().lower()
            if name and name not in seen:
                seen.add(name)
                out.append(name)
        return out


def build_claude(args):
    """Return a configured Claude helper, or None when the pass is disabled."""
    if not args.claude:
        return None
    if not shutil.which(args.claude_bin) and not os.path.exists(args.claude_bin):
        log(red(f"--claude given but the claude CLI was not found "
                f"({args.claude_bin}); continuing without LLM reasoning"))
        return None
    return Claude(args.claude_bin, args.claude_model, args.claude_max_guesses,
                  args.claude_timeout)


# --------------------------------------------------------------------------- #
# external tools
# --------------------------------------------------------------------------- #

def run_shortscan(url, args, depth):
    """Run shortscan on one directory URL; return (shortnames, vulnerable)."""
    cmd = [
        args.shortscan_bin,
        "--output", "json",
        "--norecurse",                   # we drive recursion ourselves, via ffuf
        "-c", str(args.threads),
        "-t", str(args.timeout),
    ]
    for h in args.header:
        cmd += ["-H", h]
    cmd.append(url)

    log(dim(f"shortscan {url}"), depth)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=args.tool_timeout)
    except subprocess.TimeoutExpired:
        log(red(f"shortscan timed out on {url}"), depth)
        return [], False
    except FileNotFoundError:
        sys.exit(red(f"shortscan binary not found: {args.shortscan_bin}"))

    shortnames, vulnerable = [], False
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = obj.get("type")
        if t == "status":
            vulnerable = obj.get("vulnerable", False)
            srv = obj.get("server", "")
            if vulnerable:
                log(f"{green('vulnerable')} {dim(srv)}", depth)
            else:
                log(f"{yellow('not vulnerable')} {dim(srv)}", depth)
        elif t == "result":
            base = obj.get("baseurl", url)
            if not base.endswith("/"):
                base += "/"
            shortnames.append(ShortName(
                baseurl=base,
                shortfile=obj.get("shortfile", ""),
                shortext=obj.get("shortext", ""),
                shorttilde=obj.get("shorttilde", ""),
                fullname=obj.get("fullname", "") or "",
            ))
    return shortnames, vulnerable


def run_ffuf(baseurl, candidates, args, depth, match_regex=None):
    """Fuzz candidate names under baseurl; return list of confirmed ffuf hits.

    match_regex (optional): match purely on a response-body regex instead of the
    status codes -- used to detect the server-side "this extension is blocked"
    page, whose status (often 404) isn't in the normal match set."""
    if not candidates:
        return []

    wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    out = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        wl.write("\n".join(candidates))
        wl.close()
        out.close()

        cmd = [
            args.ffuf_bin,
            "-w", f"{wl.name}:FUZZ",
            "-u", f"{baseurl}FUZZ",
            "-t", str(args.threads),
            "-s",                        # silent; we render our own output
            "-o", out.name, "-of", "json",
        ]
        if match_regex:
            # match purely on the body signature (-mmode and + -mc all), ignoring
            # the status code, so a control name only "hits" when the response
            # actually carries the block signature -- not because the server
            # wildcard-serves everything. No -ac: the block page must not be
            # auto-calibrated away as noise.
            cmd += ["-mr", match_regex, "-mc", "all", "-mmode", "and"]
        else:
            cmd += ["-mc", args.match_codes, "-ac"]  # -ac drops wildcard noise
        if args.rate:
            cmd += ["-rate", str(args.rate)]
        for h in args.header:
            cmd += ["-H", h]
        if args.proxy:
            cmd += ["-x", args.proxy]

        log(dim(f"ffuf {len(candidates)} candidates -> {baseurl}"), depth)
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=args.tool_timeout)
        except subprocess.TimeoutExpired:
            log(red(f"ffuf timed out on {baseurl}"), depth)
            return []
        except FileNotFoundError:
            sys.exit(red(f"ffuf binary not found: {args.ffuf_bin}"))

        try:
            with open(out.name) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        return data.get("results", []) or []
    finally:
        for f in (wl.name, out.name):
            try:
                os.unlink(f)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# classify ffuf hits into files / dirs
# --------------------------------------------------------------------------- #

# Extensions that unambiguously denote a FILE, not a directory. IIS/ASP.NET
# happily serves "page.aspx/" (the trailing slash becomes PathInfo) with a
# 200/301/403, which otherwise trips the "ends in / -> directory" heuristic and
# makes shortloop recurse into a page as if it were a folder. If a name ends in
# one of these, a directory-looking signal for it is that quirk, not a real dir.
# (Conservative on purpose: an extension NOT in this set -- e.g. a directory
# literally named "my.app" -- still falls through to the normal dir logic.)
FILE_EXTS = {
    # ASP.NET / IIS
    "aspx", "asp", "ashx", "asmx", "asax", "ascx", "axd", "master", "cshtml",
    "vbhtml", "config", "cs", "vb", "dll", "pdb", "resx", "svc", "bat", "cmd",
    # other server pages / scripts
    "php", "php3", "php4", "php5", "jsp", "jspx", "do", "action", "cgi", "pl",
    "py", "rb", "sh", "cfm",
    # static web
    "html", "htm", "js", "mjs", "css", "map", "json", "xml", "rss", "txt",
    "csv", "wasm",
    # documents / archives / data
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "zip", "rar",
    "7z", "gz", "tar", "tgz", "bak", "old", "log", "mdb", "sql", "bin", "dat",
    # media / fonts
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp", "mp4", "mp3",
    "woff", "woff2", "ttf", "eot", "otf",
}


def _looks_like_file(name):
    """True when `name` (no trailing slash) ends in a known file extension, so a
    'directory' signal for it is really an IIS/ASP.NET PathInfo quirk
    (page.aspx/ -> 200) rather than a genuine directory."""
    base = name.rstrip("/").rsplit("/", 1)[-1]
    if "." not in base:
        return False
    return base.rsplit(".", 1)[-1].lower() in FILE_EXTS


# CSS and image assets, keyed by the 3-char prefix their 8.3 extension exposes
# (a 3-letter extension like "css"/"png" always shows up truncated as ".CSS"/
# ".PNG"; "jpe" = jpeg, "tif" = tiff, "web" = webp). These are low-value static
# files, so by default we don't try to recover their full names at all.
ASSET_EXT_PREFIXES = {
    "css",                                   # stylesheets
    "png", "jpg", "jpe", "gif", "bmp",       # raster images
    "ico", "svg", "tif", "web",              # icon / vector / tiff / webp
}


def _is_asset_shortname(sn):
    """True when a short name's extension marks it as a CSS or image file."""
    ext = sn.shortext.lstrip(".").lower()
    return bool(ext) and ext[:3] in ASSET_EXT_PREFIXES


# --------------------------------------------------------------------------- #
# protected (server-blocked) extensions: confirmed-but-unservable
# --------------------------------------------------------------------------- #
#
# IIS/ASP.NET refuses to serve these extensions to the web: System.Web
# .HttpForbiddenHandler ("This type of page is not served.") or IIS Request
# Filtering (HTTP 404.7, "...configured to deny the file extension"). The block
# fires on the EXTENSION, so a request for a non-existent name.config returns the
# SAME page as a real web.config -- the response proves nothing about existence
# and never reveals the full name. So ffuf can neither fetch nor recover these;
# shortscan's 8.3 enumeration is the only proof the file is there. We detect the
# ones this server actually blocks (one control request per extension), then
# report the matching short names as "unservable" (exist per shortscan, name not
# HTTP-recoverable) instead of wasting the fan-out and the loud retry on them.
PROTECTED_EXTS = {
    "config", "cs", "vb", "master", "ascx", "asax", "skin", "browser",
    "sitemap", "resx", "resources", "csproj", "vbproj", "vjsproj", "webinfo",
    "licx", "exclude", "refresh", "compiled", "vsdisco", "rules", "cd", "dd",
    "ad", "soap", "mdf", "ldf", "mdb", "java", "jsl", "cer",
}

# Response-body signatures for the two server-side blocks above (ffuf -mr regex).
FORBIDDEN_SIGNATURE = (
    r"(This type of page is not served"
    r"|request filtering module is configured to deny the file extension"
    r"|HTTP Error 404\.7"
    r"|HTTP Error 404\.3)"
)


def protected_ext_of(sn):
    """If short name `sn`'s extension resolves to a server-blocked ASP.NET type,
    return that extension (e.g. "config", "master", "cs"); else None. Mirrors
    candidate_exts' pinning so a truncated ".CON" -> ".config" is recognised."""
    if sn.is_dir_like:
        return None
    if sn.ext_complete:
        ext = sn.shortext.lstrip(".").lower()
        return ext if ext in PROTECTED_EXTS else None
    # truncated ".XYZ": prefer the hand-pinned real extension(s), else the bare
    # 3-char prefix itself may already be a protected extension.
    pref = sn.shortext.lower()
    pinned = MAIN_EXT.get(pref)
    if pinned:
        for e in pinned:
            e = e.lstrip(".").lower()
            if e in PROTECTED_EXTS:
                return e
        return None
    bare = pref.lstrip(".")
    return bare if bare in PROTECTED_EXTS else None


def probe_blocked_exts(url, exts, args, depth):
    """Fire one guaranteed-nonexistent control name per extension and see which
    ones come back with a server-block signature. Returns the subset of `exts`
    the server refuses to serve (so a real file of that type is unfetchable and
    its full name unrecoverable over HTTP)."""
    if not exts:
        return set()
    token = os.urandom(4).hex()
    controls = {f"shortloop-nx-{token}.{ext}".lower(): ext for ext in exts}
    hits = run_ffuf(url, sorted(controls), args, depth,
                    match_regex=FORBIDDEN_SIGNATURE)
    blocked = set()
    for h in hits:
        name = ((h.get("input") or {}).get("FUZZ", "") or "").lower()
        if name in controls:
            blocked.add(controls[name])
    return blocked


def unservable_hints(sn, stems, ext, limit=5):
    """Best-guess full names for an unservable short name (informational only):
    the bare stem plus dictionary words that start with a truncated stem, each
    with the blocked extension -- e.g. PACKAG~1.CON -> packages.config, ..."""
    pref = sn.stem_prefix
    if sn.stem_complete:
        bases = [pref]
    else:
        matched = sorted(w for w in stems
                         if w.startswith(pref) and len(w) > len(pref))
        bases = [pref] + matched
    seen, out = set(), []
    for b in bases:
        name = f"{b}.{ext}"
        if name not in seen:
            seen.add(name)
            out.append(name)
        if len(out) >= limit:
            break
    return out


def classify(hits, baseurl):
    """
    Split ffuf results into confirmed files and directories.

    directory signals:
      * the candidate ended in "/" and the server accepted it (200/301/302/403)
      * the candidate had no slash but 30x-redirected to .../name/
    ...but a name ending in a known file extension (page.aspx) is kept a FILE
    even when the server accepts its trailing-slash form, so we never recurse
    into a page as if it were a directory.
    Returns (files, dirs) where each entry is (relative_name, status).
    dirs' relative_name has NO trailing slash.
    """
    files, dirs = {}, {}
    for h in hits:
        name = (h.get("input") or {}).get("FUZZ", "")
        if not name:
            continue
        status = h.get("status", 0)
        redirect = (h.get("redirectlocation") or "").rstrip()

        if name.endswith("/"):
            if status in (200, 301, 302, 307, 308, 403):
                base = name[:-1]
                # "page.aspx/" accepted -> it's still the file, not a directory
                if _looks_like_file(base):
                    files[base.lower()] = status
                else:
                    dirs[base.lower()] = status
            continue

        looks_dir = (
            status in (301, 302, 307, 308)
            and (redirect.lower().rstrip("/").endswith(name.lower())
                 and redirect.endswith("/"))
        )
        if looks_dir and not _looks_like_file(name):
            dirs[name.lower()] = status
        else:
            files[name.lower()] = status
    return files, dirs


def unconfirmed_shortnames(sn_candsets, confirmed_names):
    """
    Decide which short names the ffuf pass failed to recover.

    `sn_candsets` is a list of (ShortName, set-of-candidate-basenames). We greedily
    match each confirmed name to a short name that could have produced it -- most
    specific (smallest candidate set) first, and each confirmed name consumed only
    once -- and return the short names left with no match. Consuming names once is
    what makes ~1/~2/~3 collisions honest: three PORTAL~ entries with a single
    confirmed portal* name leave two short names reported as unrecovered.
    """
    pool = set(confirmed_names)
    leftover = []
    for sn, cset in sorted(sn_candsets, key=lambda t: len(t[1])):
        match = next((n for n in cset if n in pool), None)
        if match is not None:
            pool.discard(match)
        else:
            leftover.append(sn)
    return leftover


# --------------------------------------------------------------------------- #
# main recursion loop
# --------------------------------------------------------------------------- #

def normalize_url(u):
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    if not u.endswith("/"):
        u += "/"
    return u


def _ask_last_chance(n):
    """Interactive y/N prompt offered at the end of a run (TTY only)."""
    try:
        ans = input(
            f"\n{blue('==>')} {yellow(str(n))} short name(s) unresolved. Retry "
            f"them with the full loud suffix list now? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "yes")


def main():
    args = parse_args()

    for b in (args.shortscan_bin, args.ffuf_bin):
        if not shutil.which(b) and not os.path.exists(b):
            sys.exit(red(f"required tool not found on PATH: {b}"))

    suffixes, stems, exts = load_wordlists(args)
    custom_names = load_custom_names(args)
    claude = build_claude(args)
    if claude is not None:
        mdl = args.claude_model or "cli default"
        log(dim(f"claude reasoning enabled (claude -p, model {mdl}, "
                f"<= {args.claude_max_guesses} guesses/dir)"))

    start = normalize_url(args.url)
    queue = [(start, 0)]
    visited = set()
    confirmed_urls = []          # flat list, in discovery order
    confirmed_seen = set()
    unconfirmed = []             # (url, depth, ShortName) seen by shortscan but
                                 # not recovered
    unservable = []              # (url, depth, ShortName, ext, hints) exist per
                                 # shortscan but the extension is server-blocked
    vocab = set()                # run-global confirmed relative names (basenames,
                                 # lowercased, no trailing slash): the same app
                                 # reuses its vocabulary across directories, so
                                 # these are retried first (tier 1) on recursion
    requests_fired = [0]         # running tally of candidates sent to ffuf

    def record(url):
        if url not in confirmed_seen:
            confirmed_seen.add(url)
            confirmed_urls.append(url)
            if args.output:
                with open(args.output, "a") as fh:
                    fh.write(url + "\n")

    def emit(files, dirs, depth, url):
        """Record + log confirmed hits and queue any directories for recursion."""
        for name, status in sorted(files.items()):
            full = url + name
            record(full)
            vocab.add(name.lower())              # seed run-global vocabulary
            log(f"{green('FILE')} [{status}] {full}", depth)
        for name, status in sorted(dirs.items()):
            full = url + name + "/"
            record(full)
            vocab.add(name.lower())
            log(f"{green('DIR ')} [{status}] {full}", depth)
            if depth + 1 <= args.max_depth and full not in visited:
                queue.append((full, depth + 1))

    def candset(cands):
        return {c.rstrip("/").lower() for c in cands}

    def fire(url, candidates, depth, **kw):
        """run_ffuf wrapper that tallies how many candidates we send."""
        requests_fired[0] += len(candidates)
        return run_ffuf(url, candidates, args, depth, **kw)

    def vocab_matches(sn):
        """Confirmed names seen elsewhere this run whose 8.3 collides with `sn` --
        cheap, high-signal tier-1 candidates on a recursive same-app scan."""
        return {v for v in vocab if custom_matches(sn, v)}

    def claude_first_pass(url, shortnames, depth):
        """Ask Claude for targeted guesses, ffuf them, record hits, and return
        the short names still unresolved (to hand to the normal fan-out)."""
        guesses = claude.guess(url, shortnames)
        if not guesses:
            return shortnames

        # Attribute each guess to the short name(s) it could complete, via the
        # same 8.3 collision test the custom pass uses -- this both drops guesses
        # that can't match anything here and keeps one-to-one resolution honest.
        retry_sets, cand_pool = [], set()
        for sn in shortnames:
            cands = set()
            for g in guesses:
                if custom_matches(sn, g):
                    cands.add(g)
                    if sn.is_dir_like:
                        cands.add(g + "/")        # also probe as a directory
            retry_sets.append((sn, candset(cands)))
            cand_pool.update(cands)

        if not cand_pool:
            log(dim(f"claude: {len(guesses)} guess(es), none matched a short "
                    f"name here -> ffuf fan-out"), depth)
            return shortnames

        log(f"{blue('claude')} {len(guesses)} guess(es) -> {len(cand_pool)} "
            f"matched candidate(s) for {len(shortnames)} short name(s)", depth)
        hits = fire(url, sorted(cand_pool), depth)
        files, dirs = classify(hits, url)
        emit(files, dirs, depth, url)

        unresolved = unconfirmed_shortnames(retry_sets, set(files) | set(dirs))
        resolved = len(shortnames) - len(unresolved)
        if resolved:
            log(f"{green('claude resolved')} {resolved}/{len(shortnames)} "
                f"short name(s); {len(unresolved)} -> ffuf fan-out", depth)
        else:
            log(dim("claude guesses confirmed nothing -> ffuf fan-out"), depth)
        return unresolved

    def scan_directory(url, depth):
        """Run shortscan + ffuf on one directory; record hits, collect leftovers."""
        shortnames, vulnerable = run_shortscan(url, args, depth)

        # --only: restrict to the short names whose label matches a pattern, so
        # firepower (especially --compound-stems) lands on just the target(s).
        if args.only and shortnames:
            kept = [sn for sn in shortnames
                    if any(fnmatch.fnmatch(sn.label().lower(), p.lower())
                           for p in args.only)]
            if len(kept) != len(shortnames):
                log(dim(f"--only: {len(kept)}/{len(shortnames)} short name(s) "
                        f"match {args.only}"), depth)
            shortnames = kept

        # Don't spend effort recovering CSS/image full names -- they're low-value
        # static assets. Dropped before candidate generation, the Claude pass and
        # unconfirmed tracking, so nothing fires at them (--resolve-assets re-ON).
        if not args.resolve_assets and shortnames:
            assets = [sn for sn in shortnames if _is_asset_shortname(sn)]
            if assets:
                shortnames = [sn for sn in shortnames
                              if not _is_asset_shortname(sn)]
                log(dim(f"skipping {len(assets)} css/image short name(s): "
                        + ", ".join(sn.label() for sn in assets)), depth)

        seeds = seed_candidates(url)

        if seeds is not None:
            # known default directory: test its curated contents directly and
            # skip the broad wordlist fan-out (the names here can't be rebuilt
            # from dictionary words anyway). No tiering / unconfirmed tracking --
            # these are trusted seed names, fired in one pass.
            all_candidates = set(seeds)
            log(f"{green('known dir')} -> seeding {len(seeds)} expected name(s), "
                f"{dim('skipping wordlist fan-out')}", depth)
            for sn in shortnames:
                if sn.fullname:
                    fn = sn.fullname.lower()
                    all_candidates.add(fn)
                    all_candidates.add(fn + "/")
                    log(f"{yellow(sn.label())} {dim('(shortscan: ' + sn.fullname + ')')}",
                        depth)
            if all_candidates:
                hits = fire(url, sorted(all_candidates), depth)
                files, dirs = classify(hits, url)
                emit(files, dirs, depth, url)
            return

        # ------------------------- normal directory ------------------------- #
        if not shortnames:
            if vulnerable:
                log(dim("vulnerable but no short names recovered"), depth)
            return

        if True:
            # Server-blocked extensions (.config/.cs/.master/...): IIS/ASP.NET
            # refuses them for ANY name, so ffuf can neither fetch nor recover the
            # real one -- shortscan already proved the file exists. Detect which
            # of these extensions THIS server actually blocks (one control request
            # each) and set the matching short names aside as "unservable" instead
            # of burning the fan-out and the loud retry on them. A server that
            # does NOT block the extension leaves them in the normal pipeline, so
            # an unexpectedly-served copy can still be confirmed.
            if not args.no_unservable_check:
                prot_exts = {protected_ext_of(sn) for sn in shortnames
                             if protected_ext_of(sn)}
                if prot_exts:
                    log(dim("probing " + ", ".join("." + e for e in
                            sorted(prot_exts)) + " for server-side blocking"),
                        depth)
                    blocked = probe_blocked_exts(url, prot_exts, args, depth)
                    if blocked:
                        blk = [sn for sn in shortnames
                               if protected_ext_of(sn) in blocked]
                        kept = [sn for sn in shortnames
                                if protected_ext_of(sn) not in blocked]

                        # The control proves the extension is blocked for a random
                        # name, but a SPECIFIC file can still occasionally be
                        # reachable (source-disclosure quirks, a static mapping, a
                        # <location> override, a served backup). So fire each
                        # blocked short name's best-guess name(s) ONCE with normal
                        # matching before writing it off -- a served copy is
                        # recorded and recursed like any other hit.
                        reach_sets, reach_pool = [], set()
                        for sn in blk:
                            hints = unservable_hints(sn, stems,
                                                     protected_ext_of(sn))
                            reach_sets.append((sn, candset(hints)))
                            reach_pool.update(hints)
                        still = blk
                        if reach_pool:
                            log(dim(f"reachability check: {len(reach_pool)} "
                                    f"best-guess name(s) for {len(blk)} "
                                    f"server-blocked short name(s)"), depth)
                            rhits = fire(url, sorted(reach_pool), depth)
                            rf, rd = classify(rhits, url)
                            emit(rf, rd, depth, url)
                            still = unconfirmed_shortnames(reach_sets,
                                                           set(rf) | set(rd))

                        for sn in still:
                            pe = protected_ext_of(sn)
                            hints = unservable_hints(sn, stems, pe)
                            unservable.append((url, depth, sn, pe, hints))
                            msg = (f".{pe} server-blocked; exists per shortscan, "
                                   f"name not fetchable")
                            log(f"{yellow('UNSERVABLE')} "
                                f"{yellow(sn.label())} {dim(msg)}", depth)
                        shortnames = kept
                        if not shortnames:
                            return

            # Claude first (when enabled): a small, reasoned guess list tried
            # before the brute-force fan-out. Whatever it confirms is already
            # recorded; only the leftovers fall through to the wordlists below.
            pending = shortnames
            if claude is not None:
                pending = claude_first_pass(url, shortnames, depth)
                if not pending:
                    return                      # Claude resolved everything here

            # Tiered fan-out. sn_cands[sn] accumulates every candidate actually
            # fired at that short name, so one-to-one resolution stays honest
            # across both tiers; `fired` dedups tier 2 against tier 1.
            sn_cands = {sn: set() for sn in pending}
            fired = set()
            confirmed_now = set()

            # ----- tier 1: cheap, high-hit candidates fired at ALL names ----- #
            # shortscan fullname + bare prefix + dictionary prefix-matches + any
            # run-global confirmed vocabulary. The dictionary prefix-match lands
            # most real word-names, so whatever resolves here never pays for the
            # tier-2 fan-out.
            t1_pool = set()
            for sn in pending:
                c = build_candidates_tier1(sn, stems, exts, args)
                c |= vocab_matches(sn)
                sn_cands[sn] |= candset(c)
                t1_pool |= c
                # list every short name shortscan found (restores the per-name
                # visibility the single-pass version printed)
                log(f"{yellow(sn.label())} -> {len(c)} tier-1 candidate(s)"
                    + (f"  {dim('(shortscan: ' + sn.fullname + ')')}"
                       if sn.fullname else ""),
                    depth)
            if t1_pool:
                hits = fire(url, sorted(t1_pool), depth)
                files, dirs = classify(hits, url)
                emit(files, dirs, depth, url)
                confirmed_now |= set(files) | set(dirs)
                fired |= {x.rstrip("/").lower() for x in t1_pool}

            unresolved = unconfirmed_shortnames(
                [(sn, sn_cands[sn]) for sn in pending], confirmed_now)
            log(dim(f"tier 1: {len(t1_pool)} candidate(s) -> "
                    f"{len(pending) - len(unresolved)}/{len(pending)} short "
                    f"name(s) resolved"), depth)

            # ----- tier 2: the expensive fan-out, ONLY for the leftovers ----- #
            if unresolved:
                t2_pool = set()
                for sn in unresolved:
                    c = build_candidates_tier2(sn, stems, suffixes, exts, args)
                    c = {x for x in c if x.rstrip("/").lower() not in fired}
                    sn_cands[sn] |= candset(c)
                    t2_pool |= c
                    log(f"{yellow(sn.label())} -> {len(c)} tier-2 candidate(s)",
                        depth)
                if t2_pool:
                    hits = fire(url, sorted(t2_pool), depth)
                    files, dirs = classify(hits, url)
                    emit(files, dirs, depth, url)
                    confirmed_now |= set(files) | set(dirs)

            # short names still unresolved after both tiers -> last-chance bucket
            for sn in unconfirmed_shortnames(
                    [(sn, sn_cands[sn]) for sn in pending], confirmed_now):
                unconfirmed.append((url, depth, sn))
                log(f"{red('UNRESOLVED')} {yellow(sn.label())} "
                    f"{dim('(exists, full name not recovered)')}", depth)

    def drain():
        while queue:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            banner(f"depth {depth}  {url}", depth)
            scan_directory(url, depth)

    # ---- insertion-point mode: manual targeted fuzz, no shortscan ---------- #
    # When set, skip shortscan/candidate generation on the start directory and
    # fuzz a single operator-specified insertion point instead. Any directory the
    # fuzz turns up is still shortscanned normally by drain() (honouring
    # --max-depth), and the custom/last-chance phases below are naturally skipped
    # because they only fire on shortscan's unconfirmed short names (none here).
    if args.insertion_point:
        if FUZZ_KEYWORD not in args.insertion_point:
            sys.exit(red(f"--insertion-point must contain the keyword "
                         f"'{FUZZ_KEYWORD}', e.g. 'requireFUZZ.zip'"))
        queue.clear()                    # don't shortscan the start dir itself
        words = []
        for pth in args.insertion_wordlist:
            words += _read_lines(pth)
        cands = build_insertion_candidates(args.insertion_point, words)
        banner(f"insertion point  {start}{args.insertion_point}  "
               f"({len(cands)} candidate(s) from {len(words)} word(s))")
        if not cands:
            log(red("no candidates generated (empty wordlist?)"))
        else:
            hits = fire(start, cands, 0)
            files, dirs = classify(hits, start)
            emit(files, dirs, 0, start)
        drain()                          # recurse into any directory it found

    # ---- phase 1: normal (curated) recursive scan -------------------------- #
    if not args.insertion_point:
        drain()

    # ---- phase 2: custom full-name pass on unresolved short names ---------- #
    # A cheap, targeted shot before the loud retry: a curated list of real
    # ASP.NET/IIS filenames the wordlist fan-out can't build (web.config,
    # Default.aspx.cs). Only entries whose 8.3 name matches an unresolved short
    # name are fired, so it stays tiny (a handful of requests) and keeps
    # resolution honest. Runs regardless of --loud, since the loud pass can't
    # build these names either.
    if unconfirmed and custom_names:
        pending, unconfirmed = unconfirmed, []
        by_dir = {}
        for u, d, sn in pending:
            by_dir.setdefault((u, d), []).append(sn)
        for (u, d), sns in by_dir.items():
            retry_sets, retry_cands = [], set()
            for sn in sns:
                cands = set()
                for e in custom_names:
                    if custom_matches(sn, e):
                        cands.add(e)
                        if sn.is_dir_like:
                            cands.add(e + "/")   # also probe as a directory
                retry_cands.update(cands)
                retry_sets.append((sn, candset(cands)))
            if not retry_cands:
                # nothing in the custom list matches here -- leave for the loud pass
                unconfirmed.extend((u, d, sn) for sn in sns)
                continue
            banner(f"custom-list  {u}", d)
            log(f"{yellow('custom')} {len(sns)} unresolved short name(s) -> "
                f"{len(retry_cands)} curated name(s)", d)
            hits = fire(u, sorted(retry_cands), d)
            files, dirs = classify(hits, u)
            emit(files, dirs, d, u)
            for sn in unconfirmed_shortnames(retry_sets, set(files) | set(dirs)):
                unconfirmed.append((u, d, sn))
        drain()  # a custom hit could expose a new directory

    # ---- phase 3: last chance on the short names nothing confirmed --------- #
    # Deferred to here on purpose: you decide AFTER seeing what didn't resolve,
    # not up front. --last-chance auto-runs it, --no-last-chance always skips,
    # otherwise we ask (when attached to a terminal). --loud already used the
    # full list, so there's nothing stronger to retry with.
    if unconfirmed and not args.loud:
        if args.no_last_chance:
            go = False
        elif args.last_chance:
            go = True
        elif sys.stdin.isatty() and sys.stdout.isatty():
            go = _ask_last_chance(len(unconfirmed))
        else:
            go = False

        if go:
            loud_suffixes = load_loud_suffixes(args)
            log(dim(f"last-chance: {len(loud_suffixes)} loud suffix words"))
            pending, unconfirmed = unconfirmed, []
            by_dir = {}
            for u, d, sn in pending:
                by_dir.setdefault((u, d), []).append(sn)
            for (u, d), sns in by_dir.items():
                retry_sets, retry_cands = [], set()
                for sn in sns:
                    cands = build_candidates(sn, loud_suffixes, stems, exts, args)
                    retry_cands.update(cands)
                    retry_sets.append((sn, candset(cands)))
                banner(f"last-chance  {u}", d)
                log(f"{yellow('retry')} {len(sns)} unresolved short name(s) -> "
                    f"{len(retry_cands)} candidates", d)
                hits = fire(u, sorted(retry_cands), d)
                files, dirs = classify(hits, u)
                emit(files, dirs, d, u)
                for sn in unconfirmed_shortnames(retry_sets, set(files) | set(dirs)):
                    unconfirmed.append((u, d, sn))
                    log(f"{red('STILL UNRESOLVED')} {yellow(sn.label())}", d)
            # directories discovered during the retry get a normal scan too
            drain()

    # ---- summary ----------------------------------------------------------- #
    print()
    banner(f"done - {len(confirmed_urls)} confirmed URL(s)")
    log(dim(f"{requests_fired[0]} candidate request(s) fired"))
    if args.output:
        log(f"written to {args.output}")
    elif confirmed_urls:
        for u in confirmed_urls:
            print(u)

    if unconfirmed:
        # dedupe (url, label), keep discovery order
        seen, rows = set(), []
        for u, _d, sn in unconfirmed:
            key = (u, sn.label())
            if key not in seen:
                seen.add(key)
                rows.append(key)
        print()
        hint = "" if (args.last_chance or args.loud) else "  (try --last-chance)"
        banner(f"{len(rows)} unconfirmed - shortscan saw these, "
               f"full name not recovered{hint}")
        for u, label in rows:
            print(f"  {u}  [{label}]")
        if args.output:
            unc_path = args.output + ".unconfirmed"
            with open(unc_path, "w") as fh:
                for u, label in rows:
                    fh.write(f"{u}\t{label}\n")
            log(f"unconfirmed written to {unc_path}")

    if unservable:
        # confirmed to exist (shortscan) but the extension is server-blocked, so
        # ffuf can't fetch or recover the full name -- a separate, higher-confidence
        # category than the generic "unconfirmed" above. dedupe (url, label).
        seen, rows = set(), []
        for u, _d, sn, ext, hints in unservable:
            key = (u, sn.label())
            if key not in seen:
                seen.add(key)
                rows.append((u, sn.label(), ext, hints))
        print()
        banner(f"{len(rows)} unservable - exist (shortscan) but the extension is "
               f"server-blocked; name not fetchable over HTTP")
        for u, label, ext, hints in rows:
            tail = f"  {dim('~ ' + ', '.join(hints))}" if hints else ""
            print(f"  {u}  [{label}]  .{ext} blocked{tail}")
        if args.output:
            uns_path = args.output + ".unservable"
            with open(uns_path, "w") as fh:
                for u, label, ext, hints in rows:
                    fh.write(f"{u}\t{label}\t{ext}\t{','.join(hints)}\n")
            log(f"unservable written to {uns_path}")


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser(
        description="Recursive IIS short-name -> full-name recovery "
                    "(shortscan + ffuf).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("url", help="target base URL, e.g. http://host/app/")

    g = p.add_argument_group("output")
    g.add_argument("-o", "--output", help="write confirmed URLs to this file "
                   "(appended live)")

    g = p.add_argument_group("recursion")
    g.add_argument("--max-depth", type=int, default=4,
                   help="how deep to recurse into discovered directories "
                        "(0 = scan only the given directory, no recursion)")
    g.add_argument("--only", nargs="+", metavar="PATTERN",
                   help="only process short names whose label matches one of "
                        "these case-insensitive glob patterns (e.g. 'CONTRA*', "
                        "'*.ZIP', 'CONTRA~1.ZIP'); everything else in the "
                        "directory is skipped. Pair with --max-depth 0 to focus "
                        "on a single directory's target name(s)")

    g = p.add_argument_group("wordlists")
    g.add_argument("--loud", "--full-suffixes", dest="loud", action="store_true",
                   help="union the full --suffix-wordlists file(s) into the "
                        "curated common-suffix list for max recall (~150x the "
                        "requests); off by default")
    g.add_argument("--last-chance", action="store_true",
                   help="auto-run the end-of-run loud retry on short names the "
                        "curated pass couldn't resolve (otherwise you're asked "
                        "at the end, when attached to a terminal)")
    g.add_argument("--no-last-chance", action="store_true",
                   help="never run the loud retry and never prompt for it "
                        "(just list the unresolved short names)")
    g.add_argument("--custom-wordlists", nargs="+", default=[],
                   help="extra file(s) of full real names (web.config, "
                        "Default.aspx.cs) fired at unresolved short names before "
                        "the loud retry; merged with the built-in CUSTOM_NAMES")
    g.add_argument("--no-custom", action="store_true",
                   help="skip the custom full-name pass before the loud retry")
    g.add_argument("--no-unservable-check", action="store_true",
                   help="don't probe for server-blocked extensions (.config, "
                        ".cs, .master, ...). Without this flag, short names whose "
                        "extension IIS/ASP.NET refuses to serve are detected with "
                        "one control request each and reported separately as "
                        "'unservable' (they exist per shortscan but can't be "
                        "fetched), instead of being fuzzed and loud-retried in "
                        "vain")
    g.add_argument("--compound-stems", action="store_true",
                   help="also append the curated common-suffix words to the "
                        "dictionary stem matches (not just the bare 6-char "
                        "prefix), reaching compounds like contract+management "
                        "or export+data; higher volume, off by default")
    g.add_argument("--compound-joiners", nargs="+", metavar="JOINER",
                   default=list(COMPOUND_JOINERS),
                   help="joiner(s) placed between a dictionary stem match and a "
                        "curated suffix word under --compound-stems (contract + "
                        "management -> contractmanagement / contract_management / "
                        "contract-management). Default: '' '_' '-'. Pass the "
                        "token 'empty' for direct concatenation and 'space' for "
                        "%%20 (a real spaced name like 'contract management' "
                        "collapses to the same 8.3 short name and is reachable "
                        "only as 'contract%%20management'), e.g. "
                        "--compound-joiners empty _ space. Only applies with "
                        "--compound-stems")
    g.add_argument("--resolve-assets", action="store_true",
                   help="also try to recover CSS/image full names; by default "
                        "short names with a css/png/jpg/gif/ico/svg/... "
                        "extension are skipped as low-value static assets")
    g.add_argument("--probe-dirs", action="store_true",
                   help="for an extension-less short name, also fire the explicit "
                        "'name/' directory probe. Off by default: a real "
                        "directory 301-redirects name -> name/ (which classify() "
                        "keys on), so the slash probe is usually redundant and "
                        "doubles the request count for the commonest short-name "
                        "shape. Enable it for a server where 'name' 404s but "
                        "'name/' answers")
    g.add_argument("--suffix-wordlists", nargs="+", default=[
        f"{SECLISTS}/raft-small-words-lowercase.txt",
    ], help="full word list appended after the 6-char prefix when --loud is set "
            "(streem + alert = streemalert); ignored otherwise -- the default "
            "uses the small curated COMMON_SUFFIXES list instead")
    g.add_argument("--stem-wordlists", nargs="+", default=[
        f"{SECLISTS}/raft-medium-words-lowercase.txt",
        f"{SECLISTS}/raft-medium-directories-lowercase.txt",
    ], help="whole dictionary names, matched by prefix (streaming from stream)")
    g.add_argument("--file-wordlists", nargs="+", default=[
        f"{SECLISTS}/raft-medium-files-lowercase.txt",
    ], help="lists of name.ext files (extension is stripped to add the stem)")
    g.add_argument("--ext-wordlists", nargs="+", default=[
        f"{SECLISTS}/raft-medium-extensions-lowercase.txt",
    ], help="lists of extensions (leading dot optional)")

    g = p.add_argument_group("insertion point (manual targeted fuzzing)")
    g.add_argument("--insertion-point", metavar="TEMPLATE",
                   help="manual fuzz mode: skip shortscan and the candidate "
                        "generator entirely and fire a wordlist at a single "
                        "insertion point under the base URL, where the literal "
                        "keyword FUZZ marks the spot (e.g. 'requireFUZZ.zip', "
                        "'backupFUZZ', 'FUZZ.bak'). Each --insertion-wordlist "
                        "entry is substituted for FUZZ and the result is "
                        "confirmed / file-vs-dir classified / recorded / recursed "
                        "exactly like any other hit. Use --max-depth 0 for a "
                        "one-shot with no recursion into discovered directories")
    g.add_argument("--insertion-wordlist", nargs="+", metavar="FILE", default=[
        f"{SECLISTS}/raft-small-words-lowercase.txt",
    ], help="wordlist(s) substituted into the --insertion-point FUZZ keyword "
            "(default raft-small-words); only used in insertion-point mode")

    g = p.add_argument_group("claude (optional LLM reasoning via the claude CLI)")
    g.add_argument("--claude", action="store_true",
                   help="before the ffuf fan-out, ask Claude non-interactively "
                        "(via 'claude -p') to reason over each directory's short "
                        "names and propose a small, targeted guess list that's "
                        "tried first; only short names it can't resolve fall "
                        "through to brute forcing. Uses your existing claude CLI "
                        "auth -- no API key needed. Off by default")
    g.add_argument("--claude-bin", default="claude",
                   help="path to the claude CLI binary")
    g.add_argument("--claude-model", default="",
                   help="model for the reasoning pass, passed to 'claude "
                        "--model' (an alias like 'opus'/'sonnet'/'haiku' or a "
                        "full model id); empty uses the claude CLI's configured "
                        "default")
    g.add_argument("--claude-max-guesses", type=int, default=150,
                   help="cap on candidate names Claude may propose per "
                        "directory (bounds the pre-ffuf request volume)")
    g.add_argument("--claude-timeout", type=int, default=120,
                   help="max seconds for a single 'claude -p' invocation")

    g = p.add_argument_group("numbers")
    g.add_argument("--no-numbers", action="store_true",
                   help="disable numeric candidate generation entirely")
    g.add_argument("--max-number", type=int, default=99,
                   help="append 0..N (and zero-padded 2-digit forms) to prefixes")
    g.add_argument("--year-start", type=int, default=2015)
    g.add_argument("--year-end", type=int, default=2026)
    g.add_argument("--number-matches", action="store_true", default=False,
                   help="also append a light number set to every dictionary "
                        "match, not just the bare prefix. Off by default: it "
                        "multiplies by the match count and is a large, low-hit "
                        "volume driver (a prefix with 50 matches adds ~1100 "
                        "candidates)")
    g.add_argument("--no-number-matches", dest="number_matches",
                   action="store_false",
                   help="(default) only put numbers on the bare prefix")

    g = p.add_argument_group("http")
    g.add_argument("-H", "--header", action="append", default=[],
                   help="extra header, repeatable (e.g. -H 'Host: x')")
    g.add_argument("-x", "--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    g.add_argument("-t", "--threads", type=int, default=40)
    g.add_argument("--rate", type=int, default=0,
                   help="ffuf requests/second cap (0 = unlimited)")
    g.add_argument("--timeout", type=int, default=10,
                   help="per-request timeout (seconds)")
    g.add_argument("--tool-timeout", type=int, default=900,
                   help="max seconds for a single shortscan/ffuf invocation")
    g.add_argument("--match-codes", default="200,204,301,302,307,308,401,403,405,500",
                   help="ffuf -mc match codes")

    g = p.add_argument_group("binaries")
    g.add_argument("--shortscan-bin", default="shortscan")
    g.add_argument("--ffuf-bin", default="ffuf")

    args = p.parse_args()
    args.compound_joiners = normalize_joiners(args.compound_joiners)
    return args


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(red("\ninterrupted"))
