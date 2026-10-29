<?php
/**
 * Firewall Protection Rules View
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap php-armor-wrap">
	<div class="php-armor-header">
		<div class="php-armor-header-title">
			<span class="dashicons dashicons-shield-alt shield-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Firewall Protection Shields', 'waffers' ); ?></h1>
				<p class="subtitle"><?php esc_html_e( 'Waffers — The layer that protects you', 'waffers' ); ?></p>
			</div>
		</div>
	</div>

	<form id="waffers-settings-form" class="php-armor-form">
		<!-- Master Firewall Switch & Mode -->
		<div class="php-armor-card">
			<h2><?php esc_html_e( 'Master Firewall Controls', 'waffers' ); ?></h2>
			<div class="control-row">
				<label class="switch-container">
					<input type="checkbox" name="enabled" value="1" <?php checked( $options['enabled'], 1 ); ?>>
					<span class="slider round"></span>
					<span class="switch-label"><strong><?php esc_html_e( 'Enable Waffers Firewall Protection', 'waffers' ); ?></strong></span>
				</label>
				<p class="field-desc"><?php esc_html_e( 'Master switch. When enabled, incoming HTTP requests are inspected for exploit payloads targeting PHP.', 'waffers' ); ?></p>
			</div>

			<div class="control-row" style="margin-top: 18px;">
				<label><strong><?php esc_html_e( 'Firewall Enforcement Mode', 'waffers' ); ?></strong></label>
				<div class="radio-group">
					<label class="radio-option">
						<input type="radio" name="block_mode" value="block" <?php checked( $options['block_mode'], 'block' ); ?>>
						<div>
							<strong><?php esc_html_e( 'Active Block Mode (Recommended)', 'waffers' ); ?></strong>
							<p><?php esc_html_e( 'Immediately terminates malicious requests with HTTP 403 Forbidden and records the incident in attack logs.', 'waffers' ); ?></p>
						</div>
					</label>
					<label class="radio-option">
						<input type="radio" name="block_mode" value="simulate" <?php checked( $options['block_mode'], 'simulate' ); ?>>
						<div>
							<strong><?php esc_html_e( 'Simulation Mode (Audit / Log Only)', 'waffers' ); ?></strong>
							<p><?php esc_html_e( 'Inspects and logs attack payloads without dropping requests. Useful for staging environments or initial baseline testing.', 'waffers' ); ?></p>
						</div>
					</label>
				</div>
			</div>
		</div>

		<!-- Specific Vulnerability Shields -->
		<div class="php-armor-card" style="margin-top: 24px;">
			<h2><?php esc_html_e( 'Vulnerability Mitigation Shields', 'waffers' ); ?></h2>
			<p class="section-desc"><?php esc_html_e( 'Each shield inspects specific attack vectors for known PHP engine and core vulnerabilities.', 'waffers' ); ?></p>

			<div class="shields-list">
				<!-- Shield 1: PHP2Shell -->
				<div class="shield-item">
					<label class="switch-container">
						<input type="checkbox" name="php2shell_shield" value="1" <?php checked( $options['php2shell_shield'], 1 ); ?>>
						<span class="slider round"></span>
						<span class="switch-label">
							<strong><?php esc_html_e( 'PHP2Shell Mitigation Shield (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560)', 'waffers' ); ?></strong>
							<span class="badge-cve">CVSS 9.2 CRITICAL</span>
						</span>
					</label>
					<p class="field-desc">
						<?php esc_html_e( 'Inspects multipart/form-data POST requests for malicious manipulation of PHP’s native session.upload_progress. Neutralizes unauthenticated upload progress session allocation probes and memory-safety corruption attempts.', 'waffers' ); ?>
					</p>
				</div>

				<!-- Shield 2: CVE-2024-4577 -->
				<div class="shield-item">
					<label class="switch-container">
						<input type="checkbox" name="cve_2024_4577_shield" value="1" <?php checked( $options['cve_2024_4577_shield'], 1 ); ?>>
						<span class="slider round"></span>
						<span class="switch-label">
							<strong><?php esc_html_e( 'PHP-CGI Argument Injection Shield (CVE-2024-4577)', 'waffers' ); ?></strong>
							<span class="badge-cve">CVSS 9.8 CRITICAL</span>
						</span>
					</label>
					<p class="field-desc">
						<?php esc_html_e( 'Inspects request URIs and query strings for Windows Best-Fit soft-hyphens (%ad, \xc2\xad, \xef\xbc\x8d) and command line argument injection (-d auto_prepend_file, -d allow_url_include, etc.) targeting PHP-CGI and Windows Apache setups.', 'waffers' ); ?>
					</p>
				</div>

				<!-- Shield 3: CVE-2024-2961 -->
				<div class="shield-item">
					<label class="switch-container">
						<input type="checkbox" name="cve_2024_2961_shield" value="1" <?php checked( $options['cve_2024_2961_shield'], 1 ); ?>>
						<span class="slider round"></span>
						<span class="switch-label">
							<strong><?php esc_html_e( 'iconv Buffer Overflow & Stream Wrapper Shield (CVE-2024-2961)', 'waffers' ); ?></strong>
							<span class="badge-cve">CVSS 8.4 HIGH</span>
						</span>
					</label>
					<p class="field-desc">
						<?php esc_html_e( 'Monitors input variables for malicious php://filter chains, specifically blocking the ISO-2022-CN-EXT glibc heap overflow vector and deeply nested filter chains. Also blocks unauthorized execution wrappers (php://input, phar://, data://, expect://).', 'waffers' ); ?>
					</p>
				</div>

				<!-- Shield 4: Object Injection -->
				<div class="shield-item">
					<label class="switch-container">
						<input type="checkbox" name="object_injection_shield" value="1" <?php checked( $options['object_injection_shield'], 1 ); ?>>
						<span class="slider round"></span>
						<span class="switch-label">
							<strong><?php esc_html_e( 'PHP Object Deserialization Injection Shield (CWE-502)', 'waffers' ); ?></strong>
							<span class="badge-cve">HIGH</span>
						</span>
					</label>
					<p class="field-desc">
						<?php esc_html_e( 'Scans incoming URL parameters and request bodies for serialized PHP object patterns (O:length:"class") targeting vulnerable third-party plugins that invoke unserialize() on untrusted input.', 'waffers' ); ?>
					</p>
				</div>

				<!-- Shield 5: Multipart Boundary DOS -->
				<div class="shield-item">
					<label class="switch-container">
						<input type="checkbox" name="multipart_dos_shield" value="1" <?php checked( $options['multipart_dos_shield'], 1 ); ?>>
						<span class="slider round"></span>
						<span class="switch-label">
							<strong><?php esc_html_e( 'Malformed Multipart & Boundary DOS Shield (CVE-2024-8926 / 8927 / 8929)', 'waffers' ); ?></strong>
							<span class="badge-cve">MEDIUM</span>
						</span>
					</label>
					<p class="field-desc">
						<?php esc_html_e( 'Validates Content-Type headers for control characters, null bytes, and anomalous boundary lengths designed to exhaust PHP worker memory or bypass multipart parsing logic.', 'waffers' ); ?>
					</p>
				</div>
			</div>
		</div>

		<!-- Whitelisting & Exclusions -->
		<div class="php-armor-card" style="margin-top: 24px;">
			<h2><?php esc_html_e( 'Whitelists & Customizations', 'waffers' ); ?></h2>

			<div class="form-group">
				<label for="ip_whitelist"><strong><?php esc_html_e( 'Trusted IP Whitelist', 'waffers' ); ?></strong></label>
				<p class="field-desc"><?php esc_html_e( 'Requests originating from these IP addresses will bypass all firewall checks. Enter one IP or CIDR per line (e.g. 192.168.1.1 or 10.0.0.0/24).', 'waffers' ); ?></p>
				<textarea id="ip_whitelist" name="ip_whitelist" rows="3" class="large-text code"><?php echo esc_textarea( $options['ip_whitelist'] ); ?></textarea>
			</div>

			<div class="form-group" style="margin-top: 18px;">
				<label for="path_exclusions"><strong><?php esc_html_e( 'URI Path Exclusions', 'waffers' ); ?></strong></label>
				<p class="field-desc"><?php esc_html_e( 'Paths matching these prefixes will bypass firewall inspection (useful for specific custom webhooks or APIs). One prefix per line (e.g. /custom-webhook/).', 'waffers' ); ?></p>
				<textarea id="path_exclusions" name="path_exclusions" rows="3" class="large-text code"><?php echo esc_textarea( $options['path_exclusions'] ); ?></textarea>
			</div>

			<div class="form-group" style="margin-top: 18px;">
				<label for="custom_block_message"><strong><?php esc_html_e( 'Custom 403 Block Notice', 'waffers' ); ?></strong></label>
				<p class="field-desc"><?php esc_html_e( 'Optional message displayed to users on the 403 Forbidden page (e.g. contact email or support instructions).', 'waffers' ); ?></p>
				<input type="text" id="custom_block_message" name="custom_block_message" value="<?php echo esc_attr( $options['custom_block_message'] ); ?>" class="large-text" placeholder="<?php esc_attr_e( 'If you believe this was an error, please contact security@yourdomain.com.', 'waffers' ); ?>">
			</div>
		</div>

		<div class="form-submit-row" style="margin-top: 24px;">
			<button type="submit" class="button button-primary button-hero" id="save-rules-btn">
				<span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Save Firewall Protection Rules', 'waffers' ); ?>
			</button>
			<span class="spinner" id="save-rules-spinner"></span>
			<span class="save-status-msg" id="save-rules-msg"></span>
		</div>
	</form>
</div>
