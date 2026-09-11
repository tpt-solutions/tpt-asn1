#!/usr/bin/env python3
"""Generate `tests/pkits_suite.rs.in` from the PKITS.pdf text dump.

Parses the NIST PKITS v1.0 test-description document (exported to text with
`pypdf`/`pdftotext -layout`) into a machine-readable Rust table that drives the
`pkits_harness` integration test.

Invocation:
    python tools/gen_pkits_cases.py PATH_TO_PKITS.txt > crates/tpt-asn1-x509/tests/pkits_suite.rs.in
"""

import re
import sys


CASE_HEADER = re.compile(r"^(\d\.\d+\.\d+)\s+(.+)$")


def split_cases(text):
    """Split the document into (header, body) tuples for every 4.x section."""
    lines = text.splitlines()
    cases = []
    current = None
    for ln in lines:
        m = CASE_HEADER.match(ln.strip())
        if m and m.group(1).startswith("4."):
            if current:
                cases.append(current)
            current = (m.group(1), m.group(2).strip(), [ln])
        elif current is not None:
            current[2].append(ln)
    if current:
        cases.append(current)
    return cases


def section(body, name):
    """Return the contiguous text block belonging to `name:[...]` (until the
    next field header on its own line)."""
    joined = "\n".join(body)
    idx = joined.find(name)
    if idx == -1:
        return None
    rest = joined[idx + len(name):]
    for nxt in ("Expected Result:", "Procedure:", "Certification Path:"):
        j = rest.find("\n" + nxt)
        if j != -1:
            rest = rest[:j]
    return rest.strip()


def extract_paths(body):
    """Parse the bulleted Certification Path list into a list of items.

    The PDF text dump may reorder the "Procedure:/Expected Result:/Certification
    Path:" blocks, so we simply collect every '•' bullet line anywhere in the case
    body. Continuation lines that directly follow a bullet line are appended."""
    items = []
    active = False
    for ln in body:
        stripped = ln.strip()
        if stripped.startswith("\u2022"):
            active = True
            for part in stripped.lstrip("\u2022").split(","):
                part = part.strip()
                if part:
                    items.append(part)
        elif active and stripped:
            # continuation of the previous bullet, unless it is page furniture
            if "=====" in stripped or re.match(r"^\d+$", stripped):
                continue
            if re.match(r"^\d\.\d", stripped) or stripped.isupper():
                active = False
                continue
            items[-1] += " " + stripped
        else:
            # blank line ends a bullet block; later blocks may follow.
            active = False
    return items


def extract_ee_from_prose(body):
    """Match `Validate <name> EE` (greedy so mid-name 'EE' doesn't split)."""
    joined = "\n".join(body)
    m = re.search(r"Validate\s+(.+)\bEE\b", joined, re.DOTALL)
    if not m:
        return None
    return m.group(1).strip()


def resolve_item(item):
    """Return (dir, filename) based on the fixture layout, or None."""
    stem = item.replace(" ", "")
    # deltaCRL/CRL suffixes resolve to the crls directory first.
    if stem.endswith("CRL") or "deltaCRL" in stem:
        return ("crls", stem + ".crl")
    return ("certs", stem + ".crt")


def parse_policy_set(text):
    """Extract an initial-policy-set from an inputs item."""
    m = re.search(r"initial-policy-set\s*=\s*\{([^}]+)\}", text)
    if not m:
        return None
    items = [x.strip() for x in m.group(1).split(",") if x.strip()]
    if not items:
        return None
    if len(items) == 1 and items[0].lower() in ("anypolicy", "any-policy", "any policy"):
        return None  # any-policy is the default; represent as None
    return items


def policy_flags(text):
    explicit = "initial-explicit-policy" in text
    mapping = "initial-policy-mapping-inhibit" in text
    anyp = "initial-inhibit-any-policy" in text
    return explicit, mapping, anyp


def find_inputs(body):
    """Return the 'following inputs' numbered list items, or None."""
    joined = "\n".join(body)
    idx = joined.find("following inputs")
    if idx == -1:
        return None
    rest = joined[idx:]
    proc = rest.find("Procedure:")
    if proc != -1:
        rest = rest[:proc]
    # Numbered items "1. ... 2. ..." possibly wrapped.
    items = []
    cur = None
    for ln in rest.splitlines():
        ln = ln.strip()
        m = re.match(r"^(\d+)[.)]\s*(.*)$", ln)
        if m:
            if cur:
                items.append(cur)
            cur = m.group(2)
        elif cur is not None and ln:
            cur += " " + ln
    if cur:
        items.append(cur)
    return items


def expected_valid(text):
    return not ("not validate successfully" in text)


def build_subcases(cid, body, ee, paths):
    """Build one or more subcases from a test-case body."""
    inputs = find_inputs(body)
    if inputs:
        out = []
        for it in inputs:
            explicit, mapping, anyp = policy_flags(it)
            set_ = parse_policy_set(it)
            ok = expected_valid(it)
            out.append(
                _case(cid, ok, ee, paths, explicit, mapping, anyp, set_)
            )
        return out
    # No explicit input list: derive from Expected Result.
    expected = section(body, "Expected Result:") or "validate successfully"
    ok = expected_valid(expected)
    return [_case(cid, ok, ee, paths, False, False, False, None)]


def _case(cid, ok, ee, paths, explicit, mapping, anyp, set_):
    policy = {
        "explicit": explicit,
        "inhibit_mapping": mapping,
        "inhibit_any": anyp,
        "policy_set": set_,
    }
    vec = ["  {"]
    vec.append(f'    id: "{cid}",')
    vec.append(f'    ee: "{ee}",')
    vec.append(f"    expect_valid: {str(ok).lower()},")
    vec.append(f"    explicit: {str(explicit).lower()},")
    vec.append(f"    inhibit_mapping: {str(mapping).lower()},")
    vec.append(f"    inhibit_any: {str(anyp).lower()},")
    if set_:
        quoted = ", ".join(f'"{p}"' for p in set_)
        vec.append(f"    policy_set: &[{quoted}],")
    else:
        vec.append("    policy_set: &[],")
    if paths:
        quoted = ", ".join(f'"{p}"' for p in paths)
        vec.append(f"    path: &[{quoted}],")
    else:
        vec.append("    path: &[],")
    vec.append("  },")
    return "\n".join(vec)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: gen_pkits_cases.py PATH_TO_PKITS.txt")
    text = open(sys.argv[1], encoding="utf-8").read()
    cases = split_cases(text)

    certs_dir = sys.argv[2] if len(sys.argv) > 2 else None
    crls_dir = sys.argv[3] if len(sys.argv) > 3 else None
    known = {}
    if certs_dir:
        import pathlib
        known["certs"] = {p.stem for p in pathlib.Path(certs_dir).glob("*.crt")}
        known["crls"] = {p.stem for p in pathlib.Path(crls_dir).glob("*.crl")}

    unresolved = []
    rows = []
    for cid, title, body in cases:
        items = extract_paths(body)
        resolved = []
        for it in items:
            r = resolve_item(it)
            if r is None:
                unresolved.append((cid, it))
                continue
            dirn, basename = r
            stem = basename[:-4] if basename.endswith((".crt", ".crl")) else basename
            resolved.append((dirn, stem))
            if known and stem not in known.get(dirn, set()):
                unresolved.append((cid, f"MISSING:{dirn}/{stem}"))
        # The end entity is the last cert listed in the path.
        cers = [s for d, s in resolved if d == "certs"]
        ee = cers[-1] if cers else None
        if ee is None:
            prose_ee = extract_ee_from_prose(body)
            if prose_ee:
                ee = prose_ee
            else:
                unresolved.append((cid, "NO_EE_PARSED"))
        paths = [f"{d}/{s}" for d, s in resolved]
        subs = build_subcases(cid, body, ee, paths)
        rows.extend(subs)

    out = []
    out.append("// @generated by tools/gen_pkits_cases.py - do not edit.\n")
    out.append("pub const CASES: &[Case] = &[")
    out.append("\n".join(rows))
    out.append("];")

    report = sys.stderr
    print(f"# generated {len(rows)} subcases from {len(cases)} cases", file=report)
    print(f"#{'':-<60}", file=report)
    for cid, item in sorted(unresolved):
        print(f"# {cid}: {item}", file=report)

    sys.stdout.write("\n".join(out) + "\n")