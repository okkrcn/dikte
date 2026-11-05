# Dikte maintenance

## 2026-11-05 — macOS update permissions

- Accessibility failed although the switch was enabled; removing Dikte from the
  list and adding `~/Applications/Dikte.app` again restored pasting (user confirmed).
- Source installer now selects a Keychain signing certificate, preferring
  Developer ID Application, and preserves the installed team and certificate type.
  `DIKTE_SIGN_IDENTITY` resolves ambiguity without committing a personal identity.
- Build/sign in a staging directory; verify the previous designated requirement
  before replacing the app. No certificate fallback is allowed for a previously
  certificate-signed app. A certificate-free install still warns about ad-hoc limits.
- Quit an idle app before replacement and relaunch through LaunchServices.
  Active recording/transcription blocks installation.
- The initial ad-hoc → certificate transition can need a final permission grant.
  TCC databases and permission entries are never changed programmatically.
- Existing uncommitted UI, paste, worker, and native launcher edits predate this
  change; retain them.
- Validation: 1611 tests completed successfully (45 environment/opt-in skips);
  the 13 signing tests also passed with the native Keychain-backed test enabled.
  Two compiled binaries had different CDHashes and the same certificate-backed
  designated requirement; the second satisfied the first's requirement.
- Installed certificate-signed bundle verified with `codesign --verify --strict`
  and started successfully. Awaiting the one-time user permission refresh before
  checking permission retention through another installation.
