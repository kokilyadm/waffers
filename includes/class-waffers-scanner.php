<?php
/**
 * Waffers Security Scanner & Health Auditor
 *
 * Checks PHP version, SAPI, configuration directives, and server environment
 * against known vulnerability profiles (PHP2Shell, CVE-2024-4577, CVE-2024-2961).
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Waffers_Scanner {

	/**
	 * Run comprehensive environment security scan.
	 *
	 * @return array Scan report with threat level, findings, and recommendations.
	 */
	public static function run_scan() {
		$php_version = PHP_VERSION;
		$sapi        = php_sapi_name();
		$is_windows  = ( strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN' );
		$server_soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : 'Unknown';

		$results = array(
			'php_version' => $php_version,
			'sapi'        => $sapi,
			'os'          => PHP_OS,
			'is_windows'  => $is_windows,
			'server_soft' => $server_soft,
			'score'       => 100, // Starts at 100, points deducted for risks
			'items'       => array(),
		);

		// 1. Audit PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
		$php2shell_status = self::check_php2shell_vulnerability( $php_version );
		$results['items']['php2shell'] = $php2shell_status;
		$results['score'] -= $php2shell_status['penalty'];

		// 2. Audit session.upload_progress.enabled
		$upload_prog_status = self::check_upload_progress_directive();
		$results['items']['upload_progress'] = $upload_prog_status;
		$results['score'] -= $upload_prog_status['penalty'];

		// 3. Audit CVE-2024-4577 (PHP-CGI Argument Injection)
		$cgi_status = self::check_cve_2024_4577_vulnerability( $php_version, $is_windows, $sapi );
		$results['items']['cve_2024_4577'] = $cgi_status;
		$results['score'] -= $cgi_status['penalty'];

		// 4. Audit CVE-2024-2961 (iconv / Stream Filter Chains)
		$iconv_status = self::check_iconv_vulnerability();
		$results['items']['iconv_chains'] = $iconv_status;
		$results['score'] -= $iconv_status['penalty'];

		// 5. Audit allow_url_include
		$url_inc_status = self::check_allow_url_include();
		$results['items']['allow_url_include'] = $url_inc_status;
		$results['score'] -= $url_inc_status['penalty'];

		// 6. Audit Early WAF Status
		$early_waf_status = self::check_early_waf_status();
		$results['items']['early_waf'] = $early_waf_status;
		$results['score'] -= $early_waf_status['penalty'];

		// 7. Audit Information Disclosure (expose_php / display_errors)
		$info_leak_status = self::check_info_leaks();
		$results['items']['info_leaks'] = $info_leak_status;
		$results['score'] -= $info_leak_status['penalty'];

		// Ensure score stays within 0..100
		$results['score'] = max( 0, min( 100, $results['score'] ) );

		if ( $results['score'] >= 85 ) {
			$results['threat_level'] = __( 'Low Risk (Well Hardened)', 'waffers' );
			$results['badge_class']  = 'status-good';
		} elseif ( $results['score'] >= 60 ) {
			$results['threat_level'] = __( 'Moderate Risk', 'waffers' );
			$results['badge_class']  = 'status-warn';
		} else {
			$results['threat_level'] = __( 'High Vulnerability Exposure', 'waffers' );
			$results['badge_class']  = 'status-danger';
		}

		return $results;
	}

	/**
	 * Check PHP version against PHP2Shell patched releases.
	 *
	 * Patched in: 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+
	 */
	protected static function check_php2shell_vulnerability( $version ) {
		$is_vuln = true;

		if ( version_compare( $version, '8.5.12', '>=' ) ) {
			$is_vuln = false;
		} elseif ( version_compare( $version, '8.5.0', '>=' ) ) {
			$is_vuln = true;
		} elseif ( version_compare( $version, '8.4.27', '>=' ) ) {
			$is_vuln = false;
		} elseif ( version_compare( $version, '8.4.0', '>=' ) ) {
			$is_vuln = true;
		} elseif ( version_compare( $version, '8.3.36', '>=' ) ) {
			$is_vuln = false;
		} elseif ( version_compare( $version, '8.3.0', '>=' ) ) {
			$is_vuln = true;
		} elseif ( version_compare( $version, '8.2.35', '>=' ) ) {
			$is_vuln = false;
		}

		if ( $is_vuln ) {
			return array(
				'title'          => __( 'PHP2Shell (CVE-2026-109618 / CVE-2026-109619)', 'waffers' ),
				'status'         => __( 'VULNERABLE', 'waffers' ),
				'severity'       => __( 'Critical (CVSS 9.2)', 'waffers' ),
				'penalty'        => 35,
				'description'    => sprintf(
					/* translators: %s: PHP version */
					__( 'Running PHP %s, which is vulnerable to memory corruption and RCE via multipart/form-data and session.upload_progress. Patched in 8.2.35, 8.3.36, 8.4.27, 8.5.12.', 'waffers' ),
					esc_html( $version )
				),
				'recommendation' => __( 'Upgrade server PHP package to a patched release. Ensure Waffers PHP2Shell shield and .user.ini hardening are active.', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'PHP2Shell (CVE-2026-109618 / CVE-2026-109619)', 'waffers' ),
			'status'         => __( 'PATCHED', 'waffers' ),
			'severity'       => __( 'Secure', 'waffers' ),
			'penalty'        => 0,
			'description'    => sprintf(
				/* translators: %s: PHP version */
				__( 'Running PHP %s which contains official patches against PHP2Shell.', 'waffers' ),
				esc_html( $version )
			),
			'recommendation' => __( 'Maintain current PHP version updates and keep defense-in-depth WAF rules active.', 'waffers' ),
		);
	}

	/**
	 * Check session.upload_progress.enabled directive.
	 */
	protected static function check_upload_progress_directive() {
		$enabled = (bool) ini_get( 'session.upload_progress.enabled' );

		if ( $enabled ) {
			return array(
				'title'          => __( 'Session Upload Progress Directive', 'waffers' ),
				'status'         => __( 'ACTIVE (Exposed)', 'waffers' ),
				'severity'       => __( 'High', 'waffers' ),
				'penalty'        => 20,
				'description'    => __( 'session.upload_progress.enabled is currently set to ON (1). This exposes the PHP session upload parser to exploitation vectors.', 'waffers' ),
				'recommendation' => __( 'Disable session upload progress globally via php.ini, or click "Hardening Tools" to set session.upload_progress.enabled = 0 in .user.ini.', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'Session Upload Progress Directive', 'waffers' ),
			'status'         => __( 'DISABLED (Protected)', 'waffers' ),
			'severity'       => __( 'Secure', 'waffers' ),
			'penalty'        => 0,
			'description'    => __( 'session.upload_progress.enabled is set to OFF (0). The session upload progress exploit vector is neutralized at the engine level.', 'waffers' ),
			'recommendation' => __( 'No action required.', 'waffers' ),
		);
	}

	/**
	 * Check CVE-2024-4577 (PHP-CGI Argument Injection).
	 *
	 * Patched in: 8.1.29+, 8.2.20+, 8.3.8+
	 */
	protected static function check_cve_2024_4577_vulnerability( $version, $is_windows, $sapi ) {
		$is_vuln_version = false;

		if ( version_compare( $version, '8.3.8', '<' ) && version_compare( $version, '8.3.0', '>=' ) ) {
			$is_vuln_version = true;
		} elseif ( version_compare( $version, '8.2.20', '<' ) && version_compare( $version, '8.2.0', '>=' ) ) {
			$is_vuln_version = true;
		} elseif ( version_compare( $version, '8.1.29', '<' ) ) {
			$is_vuln_version = true;
		}

		$is_cgi = ( stripos( $sapi, 'cgi' ) !== false );

		if ( $is_vuln_version ) {
			if ( $is_windows || $is_cgi ) {
				return array(
					'title'          => __( 'PHP-CGI Argument Injection (CVE-2024-4577)', 'waffers' ),
					'status'         => __( 'CRITICAL RISK', 'waffers' ),
					'severity'       => __( 'Critical (CVSS 9.8)', 'waffers' ),
					'penalty'        => 30,
					'description'    => sprintf(
						/* translators: 1: PHP version, 2: OS, 3: SAPI */
						__( 'Server is running PHP %1$s on %2$s (%3$s). This environment is susceptible to character Best-Fit mapping argument injection (%ad to -d auto_prepend_file).', 'waffers' ),
						esc_html( $version ),
						esc_html( PHP_OS ),
						esc_html( $sapi )
					),
					'recommendation' => __( 'Upgrade PHP immediately (>= 8.1.29, 8.2.20, 8.3.8). Waffers WAF is actively filtering soft-hyphen (%ad) and CGI argument flags.', 'waffers' ),
				);
			}

			return array(
				'title'          => __( 'PHP-CGI Argument Injection (CVE-2024-4577)', 'waffers' ),
				'status'         => __( 'MONITORED', 'waffers' ),
				'severity'       => __( 'Medium', 'waffers' ),
				'penalty'        => 10,
				'description'    => sprintf(
					/* translators: 1: PHP version, 2: SAPI */
					__( 'PHP %1$s is unpatched for CVE-2024-4577, but server is running on non-Windows OS with SAPI (%2$s). Vulnerability is usually latent unless CGI mapping is enabled.', 'waffers' ),
					esc_html( $version ),
					esc_html( $sapi )
				),
				'recommendation' => __( 'Upgrade PHP to patched version for full compliance. Waffers CGI Argument Shield is actively filtering exploit probes.', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'PHP-CGI Argument Injection (CVE-2024-4577)', 'waffers' ),
			'status'         => __( 'PATCHED', 'waffers' ),
			'severity'       => __( 'Secure', 'waffers' ),
			'penalty'        => 0,
			'description'    => sprintf(
				/* translators: %s: PHP version */
				__( 'PHP %s has official patches for CVE-2024-4577.', 'waffers' ),
				esc_html( $version )
			),
			'recommendation' => __( 'Keep PHP updated and keep CGI query filters active.', 'waffers' ),
		);
	}

	/**
	 * Check iconv and PHP filter chain vulnerability (CVE-2024-2961).
	 */
	protected static function check_iconv_vulnerability() {
		$iconv_loaded = extension_loaded( 'iconv' );

		if ( $iconv_loaded ) {
			return array(
				'title'          => __( 'iconv / PHP Stream Filter Chains (CVE-2024-2961)', 'waffers' ),
				'status'         => __( 'ACTIVE FILTERING (Protected)', 'waffers' ),
				'severity'       => __( 'Protected by WAF (Dependent on glibc for OS)', 'waffers' ),
				'penalty'        => 0,
				'description'    => __( 'PHP iconv extension is loaded. Waffers WAF is actively filtering and dropping all ISO-2022-CN-EXT and recursive filter chain exploit requests.', 'waffers' ),
				'recommendation' => __( 'Your site is protected at the WAF tier. If you manage the Linux VPS/server, ensure system glibc is also updated (sudo apt update && sudo apt upgrade libc6).', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'iconv / PHP Stream Filter Chains (CVE-2024-2961)', 'waffers' ),
			'status'         => __( 'NOT LOADED', 'waffers' ),
			'severity'       => __( 'Secure', 'waffers' ),
			'penalty'        => 0,
			'description'    => __( 'iconv extension is not loaded in this PHP environment.', 'waffers' ),
			'recommendation' => __( 'No action required.', 'waffers' ),
		);
	}

	/**
	 * Check allow_url_include directive.
	 */
	protected static function check_allow_url_include() {
		$enabled = (bool) ini_get( 'allow_url_include' );

		if ( $enabled ) {
			return array(
				'title'          => __( 'allow_url_include Directive', 'waffers' ),
				'status'         => __( 'CRITICAL RISK', 'waffers' ),
				'severity'       => __( 'Critical', 'waffers' ),
				'penalty'        => 25,
				'description'    => __( 'allow_url_include is ON! This allows attackers who discover file inclusion vulnerabilities to execute arbitrary remote code instantly via php://input or data://.', 'waffers' ),
				'recommendation' => __( 'Disable allow_url_include immediately in php.ini or via Waffers Server Hardening.', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'allow_url_include Directive', 'waffers' ),
			'status'         => __( 'DISABLED (Protected)', 'waffers' ),
			'severity'       => __( 'Secure', 'waffers' ),
			'penalty'        => 0,
			'description'    => __( 'allow_url_include is safely turned OFF.', 'waffers' ),
			'recommendation' => __( 'No action required.', 'waffers' ),
		);
	}

	/**
	 * Check Early WAF Bootstrap status.
	 */
	protected static function check_early_waf_status() {
		$is_early_loaded = defined( 'WAFFERS_EARLY_LOADED' ) || defined( 'PHP_ARMOR_EARLY_LOADED' );
		$mu_dir          = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$mu_installed    = file_exists( $mu_dir . '/waffers-early-loader.php' ) || file_exists( $mu_dir . '/php-armor-early-loader.php' );

		if ( $is_early_loaded ) {
			return array(
				'title'          => __( 'Early WAF Bootstrap', 'waffers' ),
				'status'         => __( 'ACTIVE (Early Defense Mode)', 'waffers' ),
				'severity'       => __( 'Optimal', 'waffers' ),
				'penalty'        => 0,
				'description'    => __( 'Waffers is executing at pre-boot stage before WordPress core, blocking engine-level exploits before application code loads.', 'waffers' ),
				'recommendation' => __( 'Early defense is fully engaged.', 'waffers' ),
			);
		} elseif ( $mu_installed ) {
			return array(
				'title'          => __( 'Early WAF Bootstrap', 'waffers' ),
				'status'         => __( 'MU-PLUGIN ACTIVE', 'waffers' ),
				'severity'       => __( 'Good', 'waffers' ),
				'penalty'        => 0,
				'description'    => __( 'Waffers is installed as a Must-Use plugin and loads ahead of standard plugins.', 'waffers' ),
				'recommendation' => __( 'For pre-WordPress bootstrap, you may optionally configure auto_prepend_file in .user.ini.', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'Early WAF Bootstrap', 'waffers' ),
			'status'         => __( 'STANDARD PLUGIN MODE', 'waffers' ),
			'severity'       => __( 'Notice', 'waffers' ),
			'penalty'        => 5,
			'description'    => __( 'Firewall is running in standard plugin mode (hooked at plugins_loaded). Install the 1-click Must-Use loader for earlier interception.', 'waffers' ),
			'recommendation' => __( 'Visit Server Hardening tab to install the 1-click Must-Use (MU) early loader.', 'waffers' ),
		);
	}

	/**
	 * Check info leak directives (expose_php, display_errors).
	 */
	protected static function check_info_leaks() {
		$expose_php     = (bool) ini_get( 'expose_php' );
		$display_errors = (bool) ini_get( 'display_errors' );

		$leaks = array();
		if ( $expose_php ) {
			$leaks[] = 'expose_php=On (broadcasts PHP version in HTTP headers)';
		}
		if ( $display_errors ) {
			$leaks[] = 'display_errors=On (exposes internal paths and database errors)';
		}

		if ( ! empty( $leaks ) ) {
			return array(
				'title'          => __( 'PHP Information Leakage', 'waffers' ),
				'status'         => __( 'EXPOSURE DETECTED', 'waffers' ),
				'severity'       => __( 'Warning', 'waffers' ),
				'penalty'        => 5,
				'description'    => implode( ', ', $leaks ),
				'recommendation' => __( 'Click "Hardening Tools" to apply .user.ini hardening (sets expose_php = 0), or set expose_php = Off in php.ini. (Waffers runtime filter is also actively suppressing X-Powered-By).', 'waffers' ),
			);
		}

		return array(
			'title'          => __( 'PHP Information Leakage', 'waffers' ),
			'status'         => __( 'SECURE', 'waffers' ),
			'severity'       => __( 'Secure', 'waffers' ),
			'penalty'        => 0,
			'description'    => __( 'Sensitive PHP server directives are not leaking environment details to public visitors.', 'waffers' ),
			'recommendation' => __( 'No action required.', 'waffers' ),
		);
	}
}

// Backwards-compatibility alias
if ( ! class_exists( 'PHP_Armor_Scanner' ) ) {
	class_alias( 'Waffers_Scanner', 'PHP_Armor_Scanner' );
}

