# Soundcore Unified

A unified repository merging two open-source Soundcore device management projects:

- **[soundcore-manager/](./soundcore-manager/)** — A full-featured Tauri (Rust + TypeScript/React) desktop app for managing Anker Soundcore BLE headphones.  
  *Originally from [gmallios/SoundcoreManager](https://github.com/gmallios/SoundcoreManager).*

- **[soundcore-desktop/](./soundcore-desktop/)** — A lightweight Python/Tkinter desktop app providing a Bluetooth RFCOMM API and GUI for Anker Soundcore headphones.  
  *Originally from [DamienStaebler/SoundcoreDesktop](https://github.com/DamienStaebler/SoundcoreDesktop).*

---

## soundcore-manager (Rust/Tauri)

A cross-platform desktop companion app built with [Tauri](https://tauri.app/), [React](https://react.dev/), and [TypeScript](https://www.typescriptlang.org/).

### Features
- See charging status and battery level
- Set ANC (Active Noise Cancellation) modes
- Adjust EQ (Equalizer)

### Requirements
- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js](https://nodejs.org/) and [Yarn](https://yarnpkg.com/)

### Getting Started

```bash
cd soundcore-manager
yarn
yarn tauri dev       # Run in development mode
yarn tauri build     # Build production installer
```

See [soundcore-manager/README.md](./soundcore-manager/README.md) for full details.

---

## soundcore-desktop (Python/Tkinter)

A Python-based desktop app and standalone Bluetooth API for Anker Soundcore Life headphones.

### Features
- Premade EQ presets
- ANC modes (Transport, Indoor, Outdoor, Transparency, Normal)

### Requirements
- Python 3
- `PyBluez` (`pip install pybluez`)
- `tkinter` (usually bundled with Python)

### Getting Started

```bash
cd soundcore-desktop
python SoundcoreDesktop.py
```

Or use the API directly:

```python
from SoundcoreAPI import Soundcore

headphone = Soundcore("XX:XX:XX:XX:XX:XX")
headphone.connect()
headphone.ANC("ANC Transport")
headphone.preEQ("Bass Booster")
headphone.close()
```

See [soundcore-desktop/README.md](./soundcore-desktop/README.md) for full details.

---

## Security Fixes Applied

The following security issues from the original repositories were fixed during the merge:

### soundcore-desktop (Python)
- **Unbounded recursion** (`SoundcoreAPI.py`): `__ParseReceiveData` used tail recursion which could exhaust the call stack for long-lived connections. Replaced with an iterative `while` loop.
- **Boolean logic bug** (`SoundcoreAPI.py`): Exception check `if 'timed out' or "[WinError 10054]" in list(str(e))` was always `True` because the string literal `'timed out'` is truthy. Fixed to `if 'timed out' in str(e) or "[WinError 10054]" in str(e)`.
- **Undefined variable** (`SoundcoreDesktop.py`): `macaddress` was referenced without being assigned when no Soundcore device was discovered during Bluetooth scan. Added an explicit check and a descriptive `RuntimeError`.
- **Unvalidated user input** (`SoundcoreDesktop.py`): MAC address entered by the user was passed directly to a socket connection without format validation. Added a `is_valid_mac_address()` helper that enforces the `XX:XX:XX:XX:XX:XX` format before connecting.
- **Fragile JSON read** (`SoundcoreDesktop.py`): `lastConnect.readlines()[0]` assumed the config file was a single line. Replaced with `lastConnect.read()` for robustness.

### soundcore-manager (Tauri/Rust)
- **Overly broad Tauri allowlist** (`manager-app/tauri.conf.json`): `"allowlist": { "all": true }` exposed every Tauri JavaScript API to the webview. Replaced with a minimal allowlist granting only the event, window (show/hide/close), and app APIs that the frontend actually uses.
- **Missing Content Security Policy** (`manager-app/tauri.conf.json`): `"csp": null` disabled CSP entirely. Added a strict policy restricting script sources to `'self'`, allowing inline styles (needed by the UI framework), and permitting only the Tauri IPC endpoint for `connect-src`.
