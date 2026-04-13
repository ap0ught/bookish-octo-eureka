# IoTFlow Research: Soundcore API Surface Analysis

## Source

**Paper:** *IoTFlow: Inferring IoT Device Behavior at Scale through Static Mobile Companion App Analysis*  
**Venue:** ACM CCS 2023 (30th ACM Conference on Computer and Communications Security)  
**Authors:** David Schmidt, Carlotta Tagliaro, Kevin Borgolte, Martina Lindorfer  
**DOI:** [10.1145/3576915.3623211](https://doi.org/10.1145/3576915.3623211)  
**Artifact:** [SecPriv/iotflow on GitHub](https://github.com/SecPriv/iotflow)  
**Data file:** [`soundcore-iotflow.csv`](./soundcore-iotflow.csv) (reproduced from [`dynamic_analysis/paths/soundcore.csv`](https://github.com/SecPriv/iotflow/blob/b00136a20bd75132ee05ec4beeb58521f9fb37d6/dynamic_analysis/paths/soundcore.csv))

---

## Why This Research Matters for This Project

IoTFlow is a security analysis system that reverse-engineers **Android companion apps** for IoT/audio devices to discover **all network API endpoints** those apps communicate with — without any app source code, without a user account, and without a physical device. The Soundcore app was one of the subjects studied.

The result for Soundcore is a complete inventory of every HTTP path the official Soundcore Android app calls at runtime. This is directly relevant to this project for four reasons:

### 1. It Documents the Complete Official Cloud API

The open-source tools in this repo (`soundcore-manager`, `soundcore-desktop`) re-implement the Soundcore protocol by reverse-engineering it. IoTFlow provides an independent, academically-rigorous enumeration of every known cloud endpoint. The CSV columns mean:

| Column | Meaning |
|--------|---------|
| `IOTFLOW` | Path discovered by static analysis of the APK |
| `DYNAMIC` | Path observed during dynamic (live) execution |
| `MATCH` | `exact` = static matched dynamic exactly; `manual` = researcher had to adjust a placeholder |
| `REASON` | Why it was a manual match (e.g., `placeholder` — a variable was substituted in) |
| `IoT-RELATED` / `IoT-RELATED 2` | Whether the endpoint is device-related: `b` = both static+dynamic, `d` = dynamic only, `i` = static only |
| `IoT-RELATED REASON` | Special case (e.g., `crashlytics` for crash reporting SDKs) |

### 2. It Reveals Privacy and Data-Collection Concerns

Several endpoints show the Soundcore app is doing more than controlling headphones:

| Endpoint | Concern |
|----------|---------|
| `v1/user/push_token` | Registers a push notification token — ties device identity to the cloud account |
| `v1/user/aaid/{uuid}` | Sends the Android Advertising ID (AAID) to Soundcore servers — a persistent cross-app tracking identifier |
| `push_log_hdfs` | Pushes logs to a Hadoop Distributed File System endpoint — bulk telemetry collection |
| `track` | Generic event tracking (likely analytics) |
| `v1/user/hearid` | Uploads HearID hearing-test data — potentially sensitive biometric/health data |
| `ads/ga-audiences`, `gtag/js`, `g/collect`, `j/collect`, `collect` | Google Ads and Google Analytics telemetry embedded in the app |
| `pagead/gen_204`, `pagead/conversion/app/deeplink` | Google advertising conversion tracking |
| `discourse-rainbow/*` | Community forum API (third-party Discourse instance) |
| `message-bus/*/poll` | Long-polling for real-time messages — continuous background connection |
| `v1/white_noise/*` | White noise playlist management — content streamed from Soundcore servers |

### 3. It Exposes the Firmware Update Attack Surface

```
[productCode]/firmware/update  →  v1/speaker/sound_core/A3027/firmware/update
[version]/firmware/update
upgrade/prod/1630568634710456_A3027_BT_FW_V01.21_20210818_b56343a_release.bin.converted.bin
```

The firmware update path is product-code and version parameterized and the actual binary is fetched over HTTP from a CDN path (`upgrade/prod/...`). Key questions for this project:
- Is the firmware binary verified (signature check) before being flashed over BLE?
- Is the CDN endpoint using HTTPS with certificate pinning?
- The `.converted.bin` extension suggests the firmware is post-processed — is the conversion deterministic and auditable?

The `soundcore-manager` codebase currently implements firmware version checking (`v1/speaker/up_firmware_version`) but does not yet handle firmware download or verification.

### 4. It Reveals Internal Object Leakage in API Paths (Potential Vulnerability)

Several endpoints discovered by static analysis contain **serialized Java ViewModel objects in the URL path**:

```
v1/user/activate_user/com.oceanwing.soundcore.account.viewmodel.LoginVM(false,false,false,0)
v1/user/check_register_email/com.oceanwing.soundcore.account.viewmodel.SignUpVM(false,false,false,false,false,false,false,0)
v1/user/forget_password/com.oceanwing.soundcore.account.viewmodel.LoginForgotVM(false,0,0,androidx.databinding.ObservableBoolean(false))
```

This means the app was calling `toString()` on a ViewModel and appending the result directly to the URL, rather than extracting the actual value (email, token, etc.). These paths have `i` (static-only) labels, meaning they were found in the APK but **did not match observed live traffic** — the actual live endpoint likely uses a real value (email address, etc.) in the path. This kind of bug:
- Leaks internal class names and structure to the server
- Can expose uninitialized/null state to the server if the object isn't ready
- Could allow server-side fingerprinting of the specific app version

---

## Endpoint Categories Summary

### Confirmed Live (both static + dynamic, `b`)
These are the core device-management APIs this project should be most interested in:

```
v1/user/push_token          — account device registration
v1/pop_up/is_need           — in-app popup/notification check
v1/product/all_online_products  — product catalog fetch
v1/user/user_menu           — UI menu configuration from server
v1/help/data_policy         — privacy policy endpoint
v1/speaker/up_firmware_version  — firmware version check
v1/speaker/bind             — bind a speaker to user account
v1/playlist/lum/status      — luminance/playlist status
v1/banner/get_banner/{type} — promotional banner
v1/speaker/sound_core/{productCode}/firmware/update  — firmware update trigger
v1/survey/{productCode}/info/{serial}  — device survey
v1/user/aaid/{uuid}         — advertising ID upload
```

### Dynamic-Only (`d`) — Observed at runtime, not in static paths
```
push_log_hdfs               — telemetry log upload (Hadoop)
soundcoremall/prod/*.zip    — product image/asset downloads
upgrade/prod/*.bin          — firmware binary download
v1/ar/source/{region}/ALL   — augmented reality content
v1/white_noise/diy/list     — custom white noise list
v1/white_noise/recommend    — recommended white noise
```

### Static-Only (`i`) — In APK code, not observed live
The full account management and device control API (login, register, EQ, sound mode, unbind, etc.) — these require authentication and a live device to exercise.

---

## Implications for This Project

1. **The `soundcore-manager` and `soundcore-desktop` tools currently operate entirely over Bluetooth (BLE/RFCOMM) and do not call these cloud endpoints.** That is a privacy advantage: users can control their device without any data reaching Soundcore servers.

2. **Firmware updates** are the most significant gap. The official app fetches firmware from `upgrade/prod/` CDN paths. This project should document whether it intends to support firmware updates and, if so, implement signature verification before flashing anything over BLE.

3. **The AAID endpoint** (`v1/user/aaid/{uuid}`) is notable because it means the official app tracks users across devices using Android's advertising identifier. Users of this project's tools avoid that tracking entirely.

4. **The Crashlytics endpoints** (`spi/v1/platforms/android/apps/...`) confirm the official app embeds Firebase Crashlytics. This collects crash reports (which can include stack traces with user data) and sends them to Google. Again, this project's tools do not include this SDK.

---

## Citation

```bibtex
@inproceedings{iotflow:ccs2023,
  title     = {{IoTFlow: Inferring IoT Device Behavior at Scale through Static Mobile Companion App Analysis}},
  author    = {Schmidt, David and Tagliaro, Carlotta and Borgolte, Kevin and Lindorfer, Martina},
  booktitle = {Proceedings of the 30th ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  date      = {2023-11},
  doi       = {10.1145/3576915.3623211},
  location  = {Copenhagen, Denmark},
  publisher = {Association for Computing Machinery (ACM)},
}
```
