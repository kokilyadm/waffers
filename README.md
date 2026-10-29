# Waffers — The layer that protects you

**Waffers** is an advanced defense-in-depth Web Application Firewall (WAF) and server-level protection plugin built specifically to shield WordPress installations against recent critical PHP engine vulnerabilities.

> *"The layer that protects you."*

Unlike typical WordPress security plugins that only look for CMS-level SQL injections or XSS, **Waffers** operates at the PHP execution boundary. It intercepts low-level exploit primitives that exploit PHP's request parser, character conversions, and stream filters before they can compromise your web server.

---

## 🛡️ Critical PHP Vulnerabilities Mitigated

### 1. PHP2Shell (CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560)
* **Severity:** **CVSS 9.2 (Critical)**
* **Vulnerability Type:** Memory corruption & use-after-free in PHP core's multipart parser and `session.upload_progress`.
* **The Risk:** Unauthenticated Remote Code Execution (RCE).
* **How Waffers Mitigates It:**
  * **Input Disarming:** Inspects and strips malicious `PHP_SESSION_UPLOAD_PROGRESS` parameters from unauthenticated multipart POST requests (WordPress uses plupload and the REST API for media uploads and does not require PHP's native upload progress).
  * **Memory Sanitization:** Purges upload progress keys from session storage upon request completion.
  * **1-Click Engine Hardening:** Generates and injects `session.upload_progress.enabled = 0` and `expose_php = 0` into `.user.ini` and `.htaccess`.

### 2. PHP-CGI Argument Injection (CVE-2024-4577)
* **Severity:** **CVSS 9.8 (Critical)**
* **Vulnerability Type:** Windows Best-Fit character mapping argument injection (bypassing CVE-2012-1823).
* **The Risk:** Remote Code Execution on Windows servers running PHP via Apache CGI or XAMPP.
* **How Waffers Mitigates It:**
  * Detects soft-hyphens (`%ad`, `%AD`, `\xad`, `\xc2\xad`, `\xef\xbc\x8d`) in query strings and request URIs.
  * Blocks command line arguments (`-d`, `-s`, `-b`, `-c`, `-w`, `-z`, `--`) and dangerous directives (`auto_prepend_file`, `allow_url_include`, `disable_functions`, etc.).
  * Provides 1-click Apache `.htaccess` rewrite rules to drop attacks at the web server layer before PHP is even invoked.

### 3. iconv Heap Buffer Overflow & Stream Filter Chains (CVE-2024-2961)
* **Severity:** **CVSS 8.4 (High)**
* **Vulnerability Type:** Glibc `iconv()` buffer overflow chained through PHP stream wrappers (`php://filter/convert.iconv...`).
* **The Risk:** Heap overflow leading to RCE when vulnerable plugins pass user parameters to file operations (`file_get_contents`, `include`).
* **How Waffers Mitigates It:**
  * Filters and drops `php://filter` requests containing vulnerable character sets (`ISO-2022-CN-EXT`, `IBM273`, etc.).
  * Detects and blocks recursive or deeply chained filter pipes (`convert.iconv.*` > 3 chain depth).
  * Blocks unauthorized execution wrappers (`php://input`, `phar://`, `data://`, `expect://`).

### 4. PHP Object Deserialization Injection (CWE-502)
* **Severity:** **High**
* **The Risk:** Object injection leading to arbitrary gadget chain execution when third-party plugins invoke `unserialize()` on untrusted input.
* **How Waffers Mitigates It:**
  * Deep recursive inspection of `GET` and `POST` variables for serialized object signatures (`O:[0-9]+:"..."`, `C:[0-9]+:"..."`).

### 5. Malformed Multipart Boundary DOS (CVE-2024-8926 / CVE-2024-8927 / CVE-2024-8929)
* **Severity:** **Medium**
* **The Risk:** Header injection, null byte truncation, or worker crash through malformed boundaries.
* **How Waffers Mitigates It:**
  * Validates `Content-Type: multipart/form-data` boundaries against RFC specifications, dropping control characters and oversized boundary headers.

---

## ⚡ Multi-Tier Defense Architecture

Waffers operates in three synergistic layers:

```
                      [ Incoming HTTP Request ]
                                  │
                                  ▼
[ Layer 1: Web Server Tier ] ────► Apache (.htaccess) / Nginx config
                                  Blocks %ad soft hyphens & CGI arguments before PHP starts
                                  │
                                  ▼
[ Layer 2: PHP Pre-Boot Tier ] ──► early-waf.php (via auto_prepend_file or mu-plugins)
                                  Executes before WordPress core and third-party plugins load
                                  │
                                  ▼
[ Layer 3: WordPress WAF Tier ] ─► Waffers Core Engine (plugins_loaded @ priority -9999)
                                  Deep payload inspection, attack logging, and dashboard UI
```

---

## 🚀 Installation & Setup

### Method 1: Standard WordPress Plugin Install
1. In your WordPress admin dashboard, go to **Plugins > Add New Plugin > Upload Plugin**.
2. Upload `waffers.zip` and click **Install Now**, then **Activate**.

### Method 2: Must-Use (MU-Plugin) Mode (Recommended for Pre-Boot Security)
1. In your WordPress admin, go to **Waffers > Server Hardening**.
2. Under **Must-Use Early Loader**, click **Install MU-Plugin Early Loader**.
3. Waffers will automatically install `wp-content/mu-plugins/php-armor-early-loader.php`, ensuring the firewall runs before any standard plugin loads.

### Method 3: 1-Click Server Hardening
1. Go to **Waffers > Server Hardening**.
2. Click **1-Click Install .user.ini Hardening** to turn off `session.upload_progress.enabled` and `expose_php`.
3. If on Apache, click **1-Click Install .htaccess Rules** to block CVE-2024-4577 at the web server level.

---

## 🎛️ Plugin Dashboard Features

| Feature | Description |
| :--- | :--- |
| **Security Dashboard & Audit** | Real-time health audit scanning your PHP version, SAPI, INI settings, and computing a vulnerability posture score. |
| **Firewall Rules** | Granular toggle switches for every CVE shield, Active Block vs Simulation (log-only) mode, and IP/Path whitelisting. |
| **Server Hardening** | 1-click installers for `.user.ini`, `.htaccess`, MU-Plugin loader, and copyable Nginx directives. |
| **Live Attack Logs** | High-performance database log table recording incident IDs, client IPs, CVE references, payload samples, with CSV export. |
| **Exploit Simulator** | Safe testing console allowing administrators to launch harmless mock exploit probes to verify firewall interception. |

---

## 🧪 Testing & Verification

A test suite is included in `tests/`:

```bash
python3 tests/test_suite.py
```
Validates all attack vectors for CVE-2024-4577, PHP2Shell, CVE-2024-2961, object injection, and ensures zero false positives on legitimate WordPress queries.

---

## 📜 License
Licensed under GPL-2.0+. Free to use and distribute.
