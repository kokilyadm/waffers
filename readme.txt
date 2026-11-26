=== Waffers — The layer that protects you ===
Contributors: kokilyadm, rakeshkumar, waffers
Tags: security, firewall, waf, cve-2024-4577, vulnerability
Requires at least: 5.4
Tested up to: 7.1
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

The layer that protects you. Mitigates critical PHP engine vulnerabilities (PHP2Shell, CVE-2024-4577, iconv filter chains) at the execution boundary.

== Description ==

Waffers is the layer that protects you — an advanced defense-in-depth Web Application Firewall (WAF) and server-level protection plugin built specifically to shield WordPress installations against recent critical PHP engine vulnerabilities.

Unlike typical WordPress security plugins that only inspect application-layer requests (SQLi/XSS), Waffers operates at the PHP execution boundary. It intercepts low-level exploit primitives that abuse PHP's request parser, character conversions, and stream filters before they can compromise your web server.

= Key Vulnerabilities Mitigated =

* **PHP2Shell (CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560 - CVSS 9.2 Critical)**: Mitigates memory corruption and use-after-free flaws in PHP's multipart parser and `session.upload_progress` tracking mechanism. Sanitizes upload progress keys and deploys 1-click `.user.ini` directives (`session.upload_progress.enabled = 0`).
* **PHP-CGI Argument Injection (CVE-2024-4577 - CVSS 9.8 Critical)**: Detects and blocks Windows Best-Fit character mapping soft hyphens (`%ad`, `\xc2\xad`, `0xAD`) and command-line arguments (`-d auto_prepend_file`, `-d allow_url_include`) targeting `php-cgi`. Injects Apache `.htaccess` rewrite rules to drop attacks at the web server layer before PHP is invoked.
* **iconv glibc Buffer Overflow & Filter Chains (CVE-2024-2961 - CVSS 8.4 High)**: Blocks malicious `php://filter` chains containing vulnerable charsets (`ISO-2022-CN-EXT`, `IBM273`) and excessive recursive filter sequences. Also blocks unauthorized execution stream wrappers (`php://input`, `phar://`, `data://`, `expect://`).
* **PHP Object Deserialization Injection (CWE-502)**: Scans incoming requests for serialized PHP object patterns (`O:[0-9]+:`) targeting vulnerable third-party plugins.
* **Malformed Multipart Boundary DOS (CVE-2024-8926 / CVE-2024-8927 / CVE-2024-8929)**: Validates `Content-Type: multipart/form-data` boundaries against RFC specifications to prevent parser memory crashes.

= Features =

* **Security Posture & Health Audit**: Real-time diagnostic scanning of PHP version, SAPI, INI directives, and threat posture score.
* **Multi-Tier Protection**: Supports Web Server rules (.htaccess), Must-Use early loader (`mu-plugins`), and standard plugin WAF execution.
* **1-Click Server Hardening**: Automates deployment of `.user.ini` directives and `.htaccess` rewrite blocks.
* **Live Attack & Threat Logs**: High-performance database logger capturing incident IDs, client IPs, rule triggers, and payload samples with CSV export.
* **Exploit Verification Simulator**: Safe testing console allowing administrators to launch harmless mock exploit probes to verify firewall interception.

== Installation ==

= From your WordPress Dashboard =
1. Go to **Plugins > Add New > Upload Plugin**.
2. Upload the `waffers.zip` file.
3. Click **Install Now** and then **Activate**.

= Manual Installation via SFTP/SSH =
1. Unzip the `waffers.zip` archive.
2. Upload the `waffers` folder to your `/wp-content/plugins/` directory.
3. Activate the plugin through the **Plugins** menu in WordPress.

= Recommended Post-Installation Hardening =
1. In your WordPress admin, navigate to **Waffers > Server Hardening**.
2. Click **1-Click Install .user.ini Hardening** to turn off `session.upload_progress.enabled` and `expose_php`.
3. If running Apache or LiteSpeed, click **1-Click Install .htaccess Rules** to block CVE-2024-4577 at the web server tier.
4. Click **Install MU-Plugin Early Loader** to enable pre-boot protection before standard plugins load.

== Frequently Asked Questions ==

= Does Waffers replace the need to update PHP? =
No. Updating your PHP binary and server packages remains the definitive fix for core vulnerabilities. However, in environments where hosting providers have not yet patched PHP or where immediate upgrades are constrained, Waffers provides critical defense-in-depth mitigation by filtering exploit vectors before they reach vulnerable routines.

= Will Waffers slow down my WordPress site? =
No. The firewall inspection algorithms are optimized for ultra-low latency (<0.1ms per request), executing targeted regex checks and bypassing static asset requests.

= Does WordPress need session.upload_progress for file uploads? =
No. WordPress media uploads use its own plupload and REST API mechanisms. PHP's native `session.upload_progress` feature is not used by WordPress core and can be safely disabled to eliminate the PHP2Shell attack vector.

= Does Waffers interfere with WooCommerce or search queries? =
No. Waffers is strictly targeted at exploit strings (such as soft-hyphen switches `%ad-d`, iconv filter chains, and serialized object payloads). Normal WordPress search queries, pagination, WooCommerce cart operations, and REST API calls are fully tested to pass without false positives.

== Screenshots ==

1. Security Dashboard & Vulnerability Health Audit scanner with real-time threat score.
2. Granular Firewall Protection Rules with Active Block vs Simulation modes.
3. 1-Click Server Hardening for .user.ini, .htaccess, and Must-Use early loader.
4. Live Attack Logs table with search, CVE filters, and payload inspection modal.
5. Exploit Simulator console verifying active interception of CVE probes.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Rebranded to Waffers — "the layer that protects you".
* Added mitigation shield for PHP2Shell (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560).
* Added mitigation shield for PHP-CGI Argument Injection (CVE-2024-4577).
* Added mitigation shield for iconv buffer overflow and filter chains (CVE-2024-2961).
* Added PHP Object Injection and multipart boundary DOS inspection.
* Added 1-Click Server Hardening (.user.ini, .htaccess, MU-plugin early loader).
* Added Security Health Scanner and Exploit Simulator console.

== Upgrade Notice ==

= 1.0.0 =
Initial release providing critical defense against recent PHP engine vulnerabilities.
