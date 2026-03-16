#!/usr/bin/env python3
"""maskdata - Mask sensitive data in text/files (emails, phones, IPs, cards, SSNs). Zero deps."""
import sys, re, os

PATTERNS = {
    "email": (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', lambda m: m[0][0] + "***@" + m[0].split("@")[1][0] + "***"),
    "phone": (r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', lambda m: m[0][:3] + "***" + m[0][-2:]),
    "ssn": (r'\b\d{3}-\d{2}-\d{4}\b', lambda m: "***-**-" + m[0][-4:]),
    "credit_card": (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', lambda m: "****-****-****-" + m[0][-4:]),
    "ipv4": (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', lambda m: ".".join(m[0].split(".")[:2]) + ".*.* "),
    "jwt": (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', lambda m: "eyJ***.[REDACTED]"),
    "api_key": (r'(?:api[_-]?key|token|secret|password|bearer)\s*[:=]\s*["\']?([A-Za-z0-9_\-./+=]{16,})["\']?',
                lambda m: m[0][:m.start(1)-m.start()] + "[REDACTED]"),
    "aws_key": (r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}', lambda m: m[0][:4] + "***REDACTED***"),
}

def mask_text(text, types=None):
    if types is None: types = list(PATTERNS.keys())
    for t in types:
        if t not in PATTERNS: continue
        pattern, replacer = PATTERNS[t]
        text = re.sub(pattern, replacer, text, flags=re.IGNORECASE if t == "api_key" else 0)
    return text

def cmd_mask(args):
    types = None
    only = [a.replace("--only=","") for a in args if a.startswith("--only=")]
    if only: types = only[0].split(",")
    
    files = [a for a in args if not a.startswith("-") and os.path.isfile(a)]
    
    if files:
        for f in files:
            with open(f) as fh: text = fh.read()
            masked = mask_text(text, types)
            if "--in-place" in args:
                with open(f, "w") as fh: fh.write(masked)
                print(f"✅ Masked {f} in place")
            else:
                print(masked)
    else:
        # stdin
        text = sys.stdin.read()
        print(mask_text(text, types))

def cmd_scan(args):
    """Scan for sensitive data without masking."""
    files = [a for a in args if not a.startswith("-") and os.path.isfile(a)]
    if not files:
        print("Usage: maskdata scan <file> [file2...]"); sys.exit(1)
    
    total = 0
    for f in files:
        with open(f) as fh: text = fh.read()
        print(f"\n📄 {f}:")
        for name, (pattern, _) in PATTERNS.items():
            matches = re.findall(pattern, text, flags=re.IGNORECASE if name == "api_key" else 0)
            if matches:
                print(f"  ⚠️  {name}: {len(matches)} found")
                total += len(matches)
    print(f"\n{'⚠️' if total else '✅'} {total} sensitive item(s) found")
    sys.exit(1 if total else 0)

def cmd_types(args):
    print("Available mask types:")
    for t in PATTERNS: print(f"  • {t}")

CMDS = {"mask": cmd_mask, "scan": cmd_scan, "types": cmd_types}

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("-h","--help"):
        print("maskdata - Mask sensitive data in text/files")
        print("Commands: mask, scan, types")
        print("  mask [file] [--in-place] [--only=email,phone]")
        print("  scan <file>  — detect without masking")
        print("  echo 'text' | maskdata mask  — pipe mode")
        sys.exit(0)
    cmd = args[0]
    if cmd not in CMDS: print(f"Unknown: {cmd}"); sys.exit(1)
    CMDS[cmd](args[1:])
