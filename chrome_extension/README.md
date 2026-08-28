# OpenAdapt Browser Observer

This extension adds passive DOM structure to an OpenAdapt Flow browser
recording. Flow's Playwright path still records the demonstration, retains each
frame, performs governed actions, and verifies the result. The extension has no
click, type, compiler, or replay command.

## Release files

An admitted Capture GitHub Release contains these browser observer assets:

- `openadapt-capture-browser-observer-<version>.zip`
- `openadapt-capture-browser-observer-<version>.spdx.json`

The ZIP contains `browser-observer.inventory.json`. That file binds the exact
source commit, extension ID, protocol, version, member size, and member SHA-256.
The SPDX file binds the ZIP digest. The Capture release admission binds both
assets beside the exact wheel and source archive. A ZIP outside that four-file
release set isn't an admitted observer.

The manifest public key fixes the unpacked extension ID at
`nalmeopboaacfhieiblejbabajicjmkb`. The native host accepts only that Chrome
origin.

## Session setup

Install the exact admitted `openadapt-capture` wheel. Then run
`capture browser-observer-provision` with the release version, source commit,
ZIP digest, SBOM digest, install root, and Chrome native-host manifest path.
The command verifies both assets, checks every extension member, extracts the
ZIP into a digest-addressed owner-only directory, and writes the exact native
host manifest. Flow verifies the installation again before a launched browser
loads it. An attached browser uses the same release identity.

The package does not register a Chrome Web Store item. A managed installer can
place the verified directory and native-host manifest through the same APIs.

Start a Flow launch or attach recording with the browser observer enabled. Flow
creates one owner-only, expiring session descriptor. Click the extension icon
in each target tab. Chrome then asks for access only to the origin that the Flow
session declared. An SSO origin needs a separate declared grant.

The badge shows `ON` after the admitted extension, native host, loopback
session, tab, and top document are bound. A red `!` means the observer session
failed. Flow must not finalize that recording as observer-backed.

## Data boundary

The content script keeps a bounded source-redacted structural candidate at the
browser event boundary. The candidate has no action command, typed value, or
replay instruction. It stays inside extension session storage until Flow claims
it by the exact document clock, action sequence, retained frame, tab, document,
navigation epoch, and viewport epoch. Only that claimed observation crosses the
native bridge. It contains:

- the session, installation, tab, frame, and document bindings;
- the navigation and viewport epochs;
- frame-local CSS geometry and a positional DOM path; and
- a session-salted identity digest when the field is safe.

It doesn't send keys, field values, raw URLs, selectors, HTML, DOM text, or
accessible names. Password, payment, declared-secret, and
autocomplete-sensitive fields withhold the identity digest. Once a sensitive
field contains a value, the document stays identity-withheld for the rest of
the session. Geometry and lifecycle evidence remain available.

The extension keeps at most 128 unacknowledged messages and one MiB in session
storage. It never drops the oldest message to make space. A full queue fails the
session. A reconnect resumes after the exact acknowledged sequence. A gap,
conflicting duplicate, wrong extension ID, unapproved origin, stale document,
stale viewport epoch, or reconnect timeout also fails it.

## Browser lifecycle

A settled tab resize creates a new viewport epoch. Recording can continue. Flow
associates an observation only when its frame token, document, action sequence,
and viewport epoch match the Playwright action. A resize or monitor-scale
change during an action makes that association invalid. When the observer is
required, Flow leaves the recording incomplete instead of accepting ambiguous
evidence.

Top-level navigation creates a new document binding. Child frames keep their
own Chrome document ID and frame-local viewport. A new tab needs an explicit
operator grant or a bound opener. Chrome internal pages and another extension's
pages cannot be observed.

## Development checks

Run the JavaScript protocol and redaction tests:

```bash
node --test chrome_extension/tests/*.test.mjs
```

Build the two deterministic release assets from an exact commit:

```bash
python scripts/build_browser_observer_extension.py \
  --out-dir dist/browser-observer \
  --source-commit "$(git rev-parse HEAD)" \
  --version 1.3.0
```

The release workflow supplies the reviewed version. Do not publish the ZIP or
SBOM outside the signed Capture release admission.
