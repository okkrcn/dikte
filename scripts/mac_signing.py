"""Keep a source installation's macOS signing identity across updates.

Only public certificate metadata is read. Private keys stay in Keychain and
codesign uses them there. A signed installation must never fall back to ad-hoc
signing or silently move to another developer/team.
"""

import json
import os
import pathlib
import re
import subprocess
import sys


BUNDLE_ID = "io.github.yusufipk.dikte"


class SigningError(RuntimeError):
    pass


def designated_requirement(details):
    if "Signature=adhoc" in details or "cdhash H" in details:
        return None
    match = re.search(r"^designated => (.+)$", details, re.MULTILINE)
    return match.group(1) if match else None


def select_identity(identities, previous="", requested=""):
    requirement = designated_requirement(previous)
    candidates = identities
    if requirement:
        team = re.search(r"^TeamIdentifier=(.+)$", previous, re.MULTILINE)
        authority = re.search(r"^Authority=([^:]+):", previous, re.MULTILINE)
        if not team or not authority:
            raise SigningError("Cannot identify the installed signing identity; nothing was changed.")
        candidates = [(digest, name) for digest, name in candidates
                      if name.startswith(authority.group(1) + ":")
                      and name.endswith("(" + team.group(1) + ")")]
    if requested:
        candidates = [(digest, name) for digest, name in candidates
                      if requested.upper() == digest or requested == name]
        if len(candidates) != 1:
            raise SigningError("DIKTE_SIGN_IDENTITY does not match a usable, compatible identity.")
    else:
        for kind in ("Developer ID Application:", "Apple Development:"):
            preferred = [(digest, name) for digest, name in candidates
                         if name.startswith(kind)]
            if preferred:
                candidates = preferred
                break
        else:
            candidates = []
    if not candidates:
        if requirement or requested:
            raise SigningError("The installed signing identity is unavailable; nothing was changed.")
        return "-"
    if len(candidates) != 1:
        raise SigningError("Multiple signing identities match. Set DIKTE_SIGN_IDENTITY explicitly.")
    return candidates[0][0]


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise SigningError(f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout + result.stderr


def prepare(app):
    details = ""
    if app.exists():
        # Do not overwrite a broken or externally modified signed bundle.
        run("codesign", "--verify", "--strict", str(app))
        details = run("codesign", "-d", "--verbose=4", "-r-", str(app))
    available = run("security", "find-identity", "-v", "-p", "codesigning")
    identities = re.findall(r'\b([A-F0-9]{40}) "([^"]+)"', available)
    identity = select_identity(identities, details,
                               os.environ.get("DIKTE_SIGN_IDENTITY", ""))
    return {"identity": identity, "requirement": designated_requirement(details)}


def sign(app, plan):
    args = ["codesign", "--force", "--sign", plan["identity"],
            "--identifier", BUNDLE_ID]
    if plan["identity"] != "-":
        args.append("--timestamp")
    run(*args, str(app))
    run("codesign", "--verify", "--strict", str(app))
    if plan["identity"] != "-":
        details = run("codesign", "-d", "--verbose=4", "-r-", str(app))
        if not designated_requirement(details):
            raise SigningError("The new bundle has no stable designated requirement.")
    if plan["requirement"]:
        # Includes Apple's certificate chain and team checks. An identifier by
        # itself is not a secure substitute for the previous requirement.
        run("codesign", "--verify", "--strict", "-R", "=" + plan["requirement"], str(app))


def publish(staged, app):
    previous = staged.parent / "previous.app"
    if app.exists():
        os.replace(app, previous)
    try:
        os.replace(staged, app)
    except OSError:
        if previous.exists():
            os.replace(previous, app)
        raise


def main(args):
    action, app_path, plan_path = args
    app, plan_file = pathlib.Path(app_path), pathlib.Path(plan_path)
    if action == "prepare":
        plan = prepare(app)
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        if plan["identity"] == "-":
            print("Warning: no signing certificate; ad-hoc updates can require permissions again.")
        else:
            print("Stable developer signing identity selected.")
    elif action == "sign":
        sign(app, json.loads(plan_file.read_text(encoding="utf-8")))
    elif action == "publish":
        publish(app, plan_file)
    else:
        raise SigningError("Unknown signing action")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (SigningError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Dikte signing: {exc}", file=sys.stderr)
        sys.exit(1)
