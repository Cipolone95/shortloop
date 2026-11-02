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

@dataclass
class ShortName:
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

# Joiners used when gluing a common-suffix word onto a dictionary stem match
# under --compound-stems (contract+management -> contractmanagement,
# contract_management). "" and "_" are by far the most common on Windows/IIS.
COMPOUND_JOINERS = ("", "_")

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
        log(dim(f"compound-stems on: suffixing {len(COMMON_SUFFIXES)} curated "
                f"words onto each dictionary match (joiners {COMPOUND_JOINERS})"))
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


def candidate_stems(sn, stems, suffixes, args):
    """
    Return the set of lowercase stem candidates for one short name.

    - complete stem (shortfile < 6 chars) -> the stem is already known exactly.
    - truncated stem (shortfile == 6 chars) -> the first 6 chars are known and
      the rest is unknown, so we build:
        (1) prefix + every suffix word   (streem + alert = streemalert)  <-- core
        (2) whole dictionary words that start with the prefix (streaming), which
            (1) would miss because "ing" is not a standalone word
        (3) the bare prefix (real name may be exactly 6 chars)
        (4) numeric completions (prefix+digits/years, and optionally the same on
            prefix-matched words)
    """
    if sn.stem_complete:
        return {sn.stem_prefix}

    pref = sn.stem_prefix
    out = {pref}  # the real name might be exactly the 6-char prefix

    # (1) the core IIS short-name technique: complete the known prefix with each
    #     word from the suffix list  ->  streem + alert -> streemalert
    #     (skip absurdly long compounds -- real names rarely run this long)
    out.update(pref + w for w in suffixes
               if len(pref) + len(w) <= MAX_COMPOUND_NAME)

    # (2) real dictionary names that begin with the prefix (streaming from stream)
    matched = [w for w in stems if w.startswith(pref) and len(w) > len(pref)]
    out.update(matched)

    # (2b) compound completion ON the dictionary matches (opt-in): glue the
    #      curated common-suffix words onto each matched word, so we can reach
    #      app-style compounds like contract+management -> contractmanagement /
    #      contract_management, or export+data. Branch (1) only ever suffixes the
    #      bare 6-char prefix, so these are otherwise unreachable. Deliberately
    #      uses the small COMMON_SUFFIXES (never the loud union) to keep volume
    #      bounded -- it already multiplies by the number of matches.
    if args.compound_stems:
        for m in matched:
            for w in COMMON_SUFFIXES:
                for j in COMPOUND_JOINERS:
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


def candidate_exts(sn, exts):
    """
    Return extension candidates for one short name.

    Special sentinels:
      ""      -> test the bare stem (ext-less file)
      "/"     -> test the stem as a directory  (stem + "/")
    Otherwise a real extension including the leading dot, e.g. ".aspx".
    """
    if sn.is_dir_like:
        return {"", "/"}                 # could be a directory or an ext-less file
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


def build_candidates(sn, suffixes, stems, exts, args):
    """Cartesian product stem x ext -> relative candidate names for ffuf."""
    # if shortscan already resolved the full name, trust it and skip the whole
    # wordlist fan-out -- there's nothing left to guess, just verify the one name.
    # Probe it as a directory too ONLY when it has no file extension; a resolved
    # page like "default.aspx" is a file, and firing "default.aspx/" just invites
    # the IIS PathInfo quirk that makes it look like a directory.
    if sn.fullname:
        fn = sn.fullname.lower()
        cands = {fn}
        if not _looks_like_file(fn):
            cands.add(fn + "/")
        return sorted(cands)

    names = set()
    cst = candidate_stems(sn, stems, suffixes, args)
    cex = candidate_exts(sn, exts)
    for st in cst:
        for ex in cex:
            if ex == "/":
                names.add(st + "/")      # directory probe
            else:
                names.add(st + ex)       # file probe ("" ext -> bare stem)
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
    # .well-known validation dirs (extension-less -> only match dir-like short
    # names). pki-validation is the standard ACME/SSL domain-validation folder
    # (short name PKI-VA~1); acme-challenge is its HTTP-01 sibling.
    "pki-validation", "acme-challenge",
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
    = the final extension including the dot (or "" when there is none)."""
    name = name.strip().lower()
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


def run_ffuf(baseurl, candidates, args, depth):
    """Fuzz candidate names under baseurl; return list of confirmed ffuf hits."""
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
            "-mc", args.match_codes,
            "-ac",                       # auto-calibrate to drop wildcard noise
            "-t", str(args.threads),
            "-s",                        # silent; we render our own output
            "-o", out.name, "-of", "json",
        ]
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
    "vbhtml", "config", "cs", "vb", "dll", "pdb", "resx", "svc",
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
            log(f"{green('FILE')} [{status}] {full}", depth)
        for name, status in sorted(dirs.items()):
            full = url + name + "/"
            record(full)
            log(f"{green('DIR ')} [{status}] {full}", depth)
            if depth + 1 <= args.max_depth and full not in visited:
                queue.append((full, depth + 1))

    def candset(cands):
        return {c.rstrip("/").lower() for c in cands}

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
        hits = run_ffuf(url, sorted(cand_pool), args, depth)
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
        all_candidates = set()
        sn_candsets = []         # [(ShortName, candidate-basename set)] non-seed

        if seeds is not None:
            # known default directory: test its curated contents directly and
            # skip the broad wordlist fan-out (the names here can't be rebuilt
            # from dictionary words anyway).
            all_candidates.update(seeds)
            log(f"{green('known dir')} -> seeding {len(seeds)} expected name(s), "
                f"{dim('skipping wordlist fan-out')}", depth)
            # still keep anything shortscan fully resolved on its own
            for sn in shortnames:
                if sn.fullname:
                    fn = sn.fullname.lower()
                    all_candidates.add(fn)
                    all_candidates.add(fn + "/")
                    log(f"{yellow(sn.label())} {dim('(shortscan: ' + sn.fullname + ')')}",
                        depth)
        else:
            if not shortnames:
                if vulnerable:
                    log(dim("vulnerable but no short names recovered"), depth)
                return

            # Claude first (when enabled): a small, reasoned guess list tried
            # before the brute-force fan-out. Whatever it confirms is already
            # recorded; only the leftovers fall through to the wordlists below.
            pending = shortnames
            if claude is not None:
                pending = claude_first_pass(url, shortnames, depth)
                if not pending:
                    return                      # Claude resolved everything here

            # gather all candidates for this directory, remembering which short
            # name produced each (for the console, and for unconfirmed tracking)
            for sn in pending:
                cands = build_candidates(sn, suffixes, stems, exts, args)
                all_candidates.update(cands)
                sn_candsets.append((sn, candset(cands)))
                log(f"{yellow(sn.label())} -> {len(cands)} candidates"
                    + (f"  {dim('(shortscan: ' + sn.fullname + ')')}" if sn.fullname else ""),
                    depth)

        if not all_candidates:
            return

        hits = run_ffuf(url, sorted(all_candidates), args, depth)
        files, dirs = classify(hits, url)
        emit(files, dirs, depth, url)

        # short names that produced no confirmed hit (seeded dirs are trusted,
        # so they're exempt). Collected for the end-of-run last-chance pass.
        if sn_candsets:
            for sn in unconfirmed_shortnames(sn_candsets, set(files) | set(dirs)):
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

    # ---- phase 1: normal (curated) recursive scan -------------------------- #
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
            hits = run_ffuf(u, sorted(retry_cands), args, d)
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
                hits = run_ffuf(u, sorted(retry_cands), args, d)
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
    g.add_argument("--compound-stems", action="store_true",
                   help="also append the curated common-suffix words to the "
                        "dictionary stem matches (not just the bare 6-char "
                        "prefix), reaching compounds like contract+management "
                        "or export+data; higher volume, off by default")
    g.add_argument("--resolve-assets", action="store_true",
                   help="also try to recover CSS/image full names; by default "
                        "short names with a css/png/jpg/gif/ico/svg/... "
                        "extension are skipped as low-value static assets")
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
    g.add_argument("--number-matches", action="store_true", default=True,
                   help="also append a light number set to wordlist matches, "
                        "not just the bare prefix")
    g.add_argument("--no-number-matches", dest="number_matches",
                   action="store_false",
                   help="only put numbers on the bare prefix (lower volume)")

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

    return p.parse_args()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(red("\ninterrupted"))
