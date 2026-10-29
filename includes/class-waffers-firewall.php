<?php
/**
 * Waffers Firewall Engine
 *
 * Core inspection and blocking engine for recent PHP vulnerabilities.
 * Can run within WordPress or standalone in early-bootstrap mode (auto_prepend_file or mu-plugins).
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'WAFFERS_STANDALONE' ) && ! defined( 'PHP_ARMOR_STANDALONE' ) ) {
	exit;
}

class Waffers_Firewall {

	/**
	 * Default settings.
	 *
	 * @var array
	 */
	protected static $default_options = array(
		'enabled'                  => 1,
		'block_mode'               => 'block', // 'block' or 'simulate' (log-only)
		'cve_2024_4577_shield'     => 1, // PHP-CGI Argument Injection (Windows/%ad)
		'php2shell_shield'         => 1, // PHP2Shell (Session Upload Progress / Multipart)
		'cve_2024_2961_shield'     => 1, // iconv / php://filter Chain / Stream Wrappers
		'object_injection_shield'  => 1, // Serialized PHP Object Injection
		'multipart_dos_shield'     => 1, // Malformed multipart headers / boundaries
		'early_waf_active'         => 0, // Whether early bootstrap is active
		'ip_whitelist'             => '',
		'path_exclusions'          => '',
		'notify_email'             => '',
		'custom_block_message'     => '',
	);

	/**
	 * Cached plugin options.
	 *
	 * @var array|null
	 */
	protected static $options = null;

	/**
	 * Last blocked reason if any.
	 *
	 * @var array|null
	 */
	public static $last_block = null;

	/**
	 * Retrieve plugin settings safely (works both in WP and standalone).
	 *
	 * @return array
	 */
	public static function get_options() {
		if ( null !== self::$options ) {
			return self::$options;
		}

		if ( function_exists( 'get_option' ) ) {
			$saved = get_option( 'waffers_options' );
			if ( false === $saved ) {
				$saved = get_option( 'php_armor_options', array() );
			}
			// Use array_merge to avoid fatal error if wp_parse_args / formatting.php is not yet loaded in MU-plugin stage
			self::$options = array_merge( self::$default_options, is_array( $saved ) ? $saved : array() );
		} else {
			// Standalone mode: check config file or fallback to defaults
			$config_file = dirname( __DIR__ ) . '/waffers-config.json';
			if ( ! file_exists( $config_file ) ) {
				$config_file = dirname( __DIR__ ) . '/php-armor-config.json';
			}
			if ( file_exists( $config_file ) ) {
				$json = json_decode( file_get_contents( $config_file ), true );
				self::$options = array_merge( self::$default_options, is_array( $json ) ? $json : array() );
			} else {
				self::$options = self::$default_options;
			}
		}

		return self::$options;
	}

	/**
	 * Main entry point: Inspect incoming request.
	 *
	 * @return bool True if safe, false if blocked.
	 */
	public static function inspect() {
		// Proactively strip X-Powered-By header early to mitigate PHP information leakage
		if ( function_exists( 'header_remove' ) && ! headers_sent() ) {
			header_remove( 'X-Powered-By' );
		}

		$options = self::get_options();

		// If firewall is disabled, pass through immediately
		if ( empty( $options['enabled'] ) ) {
			return true;
		}

		$client_ip = self::get_client_ip();

		// Check IP Whitelist
		if ( ! empty( $options['ip_whitelist'] ) && self::is_ip_whitelisted( $client_ip, $options['ip_whitelist'] ) ) {
			return true;
		}

		// Check Path Exclusions
		if ( ! empty( $options['path_exclusions'] ) && self::is_path_excluded( $options['path_exclusions'] ) ) {
			return true;
		}

		// 1. Check CVE-2024-4577: PHP-CGI Argument Injection (Windows/%ad soft hyphen)
		if ( ! empty( $options['cve_2024_4577_shield'] ) ) {
			$threat = self::detect_cve_2024_4577();
			if ( $threat ) {
				return self::handle_violation( 'CVE-2024-4577', 'PHP-CGI Argument Injection Attempt', $threat );
			}
		}

		// 2. Check PHP2Shell (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560): Session Upload Progress & Multipart abuse
		if ( ! empty( $options['php2shell_shield'] ) ) {
			$threat = self::detect_php2shell();
			if ( $threat ) {
				return self::handle_violation( 'CVE-2026-109619', 'PHP2Shell Session Upload Progress Abuse', $threat );
			}
		}

		// 3. Check CVE-2024-2961 & PHP Stream Wrappers: iconv buffer overflow and filter chains
		if ( ! empty( $options['cve_2024_2961_shield'] ) ) {
			$threat = self::detect_stream_wrapper_exploits();
			if ( $threat ) {
				return self::handle_violation( 'CVE-2024-2961', 'Malicious PHP Filter Chain / Stream Wrapper Abuse', $threat );
			}
		}

		// 4. Check Multipart DOS & Header Anomaly (CVE-2024-8926 / 8927 / 8929)
		if ( ! empty( $options['multipart_dos_shield'] ) ) {
			$threat = self::detect_multipart_anomaly();
			if ( $threat ) {
				return self::handle_violation( 'CVE-2024-8927', 'Malformed Multipart Request / Boundary Anomaly', $threat );
			}
		}

		// 5. Check PHP Object Injection (unserialize gadget chain injection)
		if ( ! empty( $options['object_injection_shield'] ) ) {
			$threat = self::detect_object_injection();
			if ( $threat ) {
				return self::handle_violation( 'CWE-502', 'PHP Serialized Object Injection Attempt', $threat );
			}
		}

		return true;
	}

	/**
	 * Detect CVE-2024-4577: PHP-CGI Argument Injection
	 *
	 * Detects attempts to bypass CVE-2012-1823 via Windows Best-Fit mapping (0xAD -> 0x2D '-')
	 * and command line argument injection into php-cgi.
	 *
	 * @return array|false Threat details or false.
	 */
	public static function detect_cve_2024_4577() {
		$raw_query = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';
		$raw_uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';

		// Also collect raw command line arguments if running in CGI mode
		$argv = isset( $_SERVER['argv'] ) && is_array( $_SERVER['argv'] ) ? implode( ' ', $_SERVER['argv'] ) : '';

		$targets = array(
			'QUERY_STRING' => $raw_query,
			'REQUEST_URI'  => $raw_uri,
			'ARGV'         => $argv,
		);

		// High-risk INI directives and switches frequently targeted in CVE-2024-4577 exploits
		$sensitive_directives = '(auto_prepend_file|auto_append_file|allow_url_include|disable_functions|open_basedir|cgi\.force_redirect|cgi\.redirect_status_env|output_handler)';

		foreach ( $targets as $source => $value ) {
			if ( empty( $value ) ) {
				continue;
			}

			// 1. Direct byte inspection for soft hyphens (%ad, %AD, 0xad, \xc2\xad, fullwidth \xef\xbc\x8d)
			if ( preg_match( '/(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d)/i', $value ) ) {
				// Check if followed by CGI switches (-d, -s, -b, -c, -w, -z, --) or sensitive directive
				if ( preg_match( '/(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d)[\s+]*(-|%ad)?[\s+]*(d|s|b|c|w|z|-)/i', $value ) ||
					 preg_match( '/(%ad|%80|%a0|\xad|\xc2\xad|\xef\xbc\x8d).*?' . $sensitive_directives . '/i', $value ) ) {
					return array(
						'source'  => $source,
						'payload' => self::sanitize_payload_sample( $value ),
						'rule'    => 'Best-Fit Soft-Hyphen CGI Switch Injection',
					);
				}

				// Soft hyphen alone at start of query string is virtually always malicious in web contexts
				if ( 'QUERY_STRING' === $source && preg_match( '/^(%ad|%80|%a0|\xad|\xc2\xad)/i', $value ) ) {
					return array(
						'source'  => $source,
						'payload' => self::sanitize_payload_sample( $value ),
						'rule'    => 'Soft-Hyphen Query Prefix',
					);
				}
			}

			// 2. Direct CGI argument injection (e.g. ?+-d+allow_url_include=1 or ?-d+auto_prepend_file=...)
			// Look for leading arguments or switches
			if ( preg_match( '/(^|[&+\s])-(d|s|b|c|w|z|-)[+=\s]/i', $value ) ) {
				if ( preg_match( '/' . $sensitive_directives . '/i', $value ) ||
					 preg_match( '/(^|[&+\s])-(d|s|b|c|w|z|-)[+=\s].*?(php:\/\/|data:\/\/|http:\/\/|https:\/\/)/i', $value ) ) {
					return array(
						'source'  => $source,
						'payload' => self::sanitize_payload_sample( $value ),
						'rule'    => 'Direct PHP-CGI Argument / Directive Override',
					);
				}
			}

			// 3. Normalized / Decoded check
			$decoded = rawurldecode( $value );
			if ( $decoded !== $value ) {
				if ( preg_match( '/(^|[&+\s])-(d|s|b|c|w|z|-)[+=\s]/i', $decoded ) &&
					 preg_match( '/' . $sensitive_directives . '/i', $decoded ) ) {
					return array(
						'source'  => $source . ' (Decoded)',
						'payload' => self::sanitize_payload_sample( $decoded ),
						'rule'    => 'Decoded PHP-CGI Argument Injection',
					);
				}
			}
		}

		return false;
	}

	/**
	 * Detect PHP2Shell (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560)
	 *
	 * Detects Session Upload Progress abuse & multipart memory-safety exploits.
	 *
	 * @return array|false Threat details or false.
	 */
	public static function detect_php2shell() {
		// Only relevant on POST requests
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || strtoupper( $_SERVER['REQUEST_METHOD'] ) !== 'POST' ) {
			return false;
		}

		$progress_name = ini_get( 'session.upload_progress.name' );
		if ( empty( $progress_name ) ) {
			$progress_name = 'PHP_SESSION_UPLOAD_PROGRESS';
		}

		// Check if request provides the session upload progress parameter
		$has_progress = false;
		$progress_val = '';

		if ( isset( $_POST[ $progress_name ] ) ) {
			$has_progress = true;
			$progress_val = (string) $_POST[ $progress_name ];
		} elseif ( isset( $_POST['PHP_SESSION_UPLOAD_PROGRESS'] ) ) {
			$has_progress = true;
			$progress_val = (string) $_POST['PHP_SESSION_UPLOAD_PROGRESS'];
		}

		if ( $has_progress ) {
			// WordPress core NEVER uses PHP's native session.upload_progress.
			// It uses plupload / REST API chunked uploads.
			// Check if this is an exploit payload (e.g. PHP code injection, excessive length, null bytes, or session poisoning)
			if ( strlen( $progress_val ) > 128 ||
				 preg_match( '/(<\?php|<\?=|base64_decode|system|passthru|exec|shell_exec|eval|\0)/i', $progress_val ) ||
				 preg_match( '/(\.\.\/|\.\.\\\\)/', $progress_val ) ) {
				return array(
					'source'  => 'POST[' . $progress_name . ']',
					'payload' => self::sanitize_payload_sample( $progress_val ),
					'rule'    => 'Malicious Session Upload Progress Key Payload',
				);
			}

			// If unauthenticated or no actual files uploaded in $_FILES, this is an anomalous progress probe
			$is_logged_in = function_exists( 'is_user_logged_in' ) && is_user_logged_in();
			if ( ! $is_logged_in && empty( $_FILES ) ) {
				// Disarm parameter: unset it so PHP engine will not initiate session upload tracking structures
				unset( $_POST[ $progress_name ] );
				unset( $_POST['PHP_SESSION_UPLOAD_PROGRESS'] );

				return array(
					'source'  => 'POST[' . $progress_name . ']',
					'payload' => self::sanitize_payload_sample( $progress_val ),
					'rule'    => 'Unauthenticated Session Upload Progress Probe',
				);
			}

			// Clean up upload progress data from $_SESSION if active
			if ( isset( $_SESSION ) && is_array( $_SESSION ) ) {
				$prefix = ini_get( 'session.upload_progress.prefix' );
				if ( ! empty( $prefix ) ) {
					foreach ( array_keys( $_SESSION ) as $key ) {
						if ( 0 === strpos( $key, $prefix ) ) {
							unset( $_SESSION[ $key ] );
						}
					}
				}
			}
		}

		return false;
	}

	/**
	 * Detect CVE-2024-2961, PHP Filter Chains & Stream Wrapper Exploits
	 *
	 * Mitigates iconv heap overflow via ISO-2022-CN-EXT and arbitrary file read/code execution
	 * via php://filter, phar:// deserialization, data://, and php://input.
	 *
	 * @return array|false Threat details or false.
	 */
	public static function detect_stream_wrapper_exploits() {
		$inputs = array();

		if ( ! empty( $_GET ) ) {
			$inputs['GET'] = $_GET;
		}
		if ( ! empty( $_POST ) ) {
			$inputs['POST'] = $_POST;
		}
		if ( ! empty( $_COOKIE ) ) {
			$inputs['COOKIE'] = $_COOKIE;
		}
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$inputs['URI'] = $_SERVER['REQUEST_URI'];
		}

		// Vulnerable charsets for CVE-2024-2961 and iconv heap corruption
		$vuln_charsets = '(ISO-2022-CN-EXT|IBM273|CP-AR|CSISO2022CN|ISO-2022-JP|EUC-TW)';

		foreach ( $inputs as $type => $data ) {
			$found = self::scan_data_recursively( $data, function( $val ) use ( $vuln_charsets ) {
				if ( ! is_string( $val ) || strlen( $val ) < 5 ) {
					return false;
				}

				// Normalize value for inspection
				$val_normalized = rawurldecode( $val );

				// 1. CVE-2024-2961 iconv filter chain exploit
				if ( stripos( $val_normalized, 'convert.iconv' ) !== false ) {
					if ( preg_match( '/' . $vuln_charsets . '/i', $val_normalized ) ) {
						return array(
							'rule'    => 'CVE-2024-2961 iconv Vulnerable Charset Filter',
							'payload' => $val,
						);
					}

					// Excessive iconv conversions chained together (typical in PHP filter chain RCE generators)
					if ( substr_count( strtolower( $val_normalized ), 'convert.iconv.' ) > 3 ) {
						return array(
							'rule'    => 'Deep iconv Filter Chain Sequence',
							'payload' => $val,
						);
					}
				}

				// 2. Chained php://filter abuse
				if ( stripos( $val_normalized, 'php://filter' ) !== false ) {
					// Check for chained filters trying to read wp-config.php or sensitive files
					if ( preg_match( '/(wp-config\.php|etc\/passwd|\/proc\/self)/i', $val_normalized ) ) {
						return array(
							'rule'    => 'php://filter Sensitive File Target',
							'payload' => $val,
						);
					}

					// Excessive filter pipe operations (e.g. read=convert.base64-encode|convert.base64-decode...)
					if ( substr_count( $val_normalized, '|' ) >= 3 ) {
						return array(
							'rule'    => 'Excessive php://filter Pipe Chaining',
							'payload' => $val,
						);
					}
				}

				// 3. phar:// stream wrapper (PHAR Object Injection)
				if ( preg_match( '/phar:\/\//i', $val_normalized ) ) {
					return array(
						'rule'    => 'phar:// Deserialization Stream Wrapper',
						'payload' => $val,
					);
				}

				// 4. php://input or expect:// in parameters
				if ( preg_match( '/(php:\/\/input|expect:\/\/)/i', $val_normalized ) ) {
					return array(
						'rule'    => 'php://input or expect:// Execution Wrapper',
						'payload' => $val,
					);
				}

				// 5. data:// wrapper with base64 or executable code
				if ( preg_match( '/data:(text\/plain|application).*?base64/i', $val_normalized ) ) {
					return array(
						'rule'    => 'data:// Stream Wrapper Payload',
						'payload' => $val,
					);
				}

				return false;
			} );

			if ( $found ) {
				return array(
					'source'  => $type,
					'payload' => self::sanitize_payload_sample( $found['payload'] ),
					'rule'    => $found['rule'],
				);
			}
		}

		return false;
	}

	/**
	 * Detect Multipart DOS & Header Anomaly (CVE-2024-8926 / CVE-2024-8927 / CVE-2024-8929)
	 *
	 * @return array|false Threat details or false.
	 */
	public static function detect_multipart_anomaly() {
		if ( empty( $_SERVER['CONTENT_TYPE'] ) ) {
			return false;
		}

		$content_type = (string) $_SERVER['CONTENT_TYPE'];

		if ( stripos( $content_type, 'multipart/form-data' ) !== false ) {
			// Check for control characters or null bytes in Content-Type
			if ( preg_match( '/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $content_type ) ) {
				return array(
					'source'  => 'Header: Content-Type',
					'payload' => self::sanitize_payload_sample( $content_type ),
					'rule'    => 'Control Characters in Multipart Content-Type Header',
				);
			}

			// Check boundary length (standard boundaries are <= 70 chars per RFC 2046)
			if ( preg_match( '/boundary=(["\']?)([^;"\']+)\1?/i', $content_type, $matches ) ) {
				$boundary = $matches[2];
				if ( strlen( $boundary ) > 128 ) {
					return array(
						'source'  => 'Header: Boundary',
						'payload' => self::sanitize_payload_sample( $boundary ),
						'rule'    => 'Excessive Multipart Boundary Length (Buffer Abuse)',
					);
				}
			}
		}

		return false;
	}

	/**
	 * Detect PHP Object Injection (CWE-502)
	 *
	 * @param bool $ignore_admin_check Whether to ignore the admin bypass check (e.g. during simulations or explicit scans).
	 * @return array|false Threat details or false.
	 */
	public static function detect_object_injection( $ignore_admin_check = false ) {
		// In WP admin, allow legitimate POST actions from trusted administrators (e.g. tools, import/export)
		// But always scan GET requests, and always scan when forced (such as in simulations).
		if ( ! $ignore_admin_check && empty( $_GET ) && function_exists( 'is_admin' ) && is_admin() && function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return false;
		}

		$inputs = array();
		if ( ! empty( $_GET ) ) {
			$inputs['GET'] = $_GET;
		}
		if ( ! empty( $_POST ) ) {
			$inputs['POST'] = $_POST;
		}

		foreach ( $inputs as $type => $data ) {
			$found = self::scan_data_recursively( $data, function( $val ) {
				if ( ! is_string( $val ) || strlen( $val ) < 10 ) {
					return false;
				}

				$val_normalized = rawurldecode( $val );

				// Check for serialized objects: O:[+-]number:"class_name":number:{...} or C:[+-]number:...
				if ( preg_match( '/(^|[;{}])[OC]:[+\-]?[0-9]+:"[^"]+":[0-9]+:\{/i', $val ) ||
				     preg_match( '/(^|[;{}])[OC]:[+\-]?[0-9]+:"[^"]+":[0-9]+:\{/i', $val_normalized ) ) {
					return array(
						'rule'    => 'Serialized Object Injection (O: / C:)',
						'payload' => $val,
					);
				}

				// Check for nested serialized object inside serialized array: a:...{...O:...}
				if ( preg_match( '/^a:[0-9]+:\{.*[OC]:[+\-]?[0-9]+:"/is', $val ) ||
				     preg_match( '/^a:[0-9]+:\{.*[OC]:[+\-]?[0-9]+:"/is', $val_normalized ) ) {
					return array(
						'rule'    => 'Serialized Array with Nested Object',
						'payload' => $val,
					);
				}

				return false;
			} );

			if ( $found ) {
				return array(
					'source'  => $type,
					'payload' => self::sanitize_payload_sample( $found['payload'] ),
					'rule'    => $found['rule'],
				);
			}
		}

		return false;
	}

	/**
	 * Recursively scan arrays or strings.
	 *
	 * @param mixed    $data     Array or scalar data.
	 * @param callable $callback Inspection callback.
	 * @param int      $depth    Max recursion depth.
	 * @return mixed
	 */
	protected static function scan_data_recursively( $data, $callback, $depth = 0 ) {
		if ( $depth > 8 ) {
			return false;
		}

		if ( is_array( $data ) ) {
			foreach ( $data as $val ) {
				$result = self::scan_data_recursively( $val, $callback, $depth + 1 );
				if ( $result ) {
					return $result;
				}
			}
		} elseif ( is_string( $data ) ) {
			return call_user_func( $callback, $data );
		}

		return false;
	}

	/**
	 * Handle threat violation: log and block or simulate.
	 *
	 * @param string $cve     CVE or CWE identifier.
	 * @param string $title   Human-readable attack title.
	 * @param array  $details Threat details.
	 * @return bool
	 */
	public static function handle_violation( $cve, $title, $details ) {
		$options = self::get_options();
		$mode    = isset( $options['block_mode'] ) ? $options['block_mode'] : 'block';

		$incident_id = strtoupper( substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 10 ) );
		$client_ip   = self::get_client_ip();
		$method      = isset( $_SERVER['REQUEST_METHOD'] ) ? self::safe_clean( $_SERVER['REQUEST_METHOD'] ) : 'GET';
		$uri         = isset( $_SERVER['REQUEST_URI'] ) ? self::safe_clean( $_SERVER['REQUEST_URI'] ) : '';
		$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? self::safe_clean( $_SERVER['HTTP_USER_AGENT'] ) : '';

		self::$last_block = array(
			'incident_id' => $incident_id,
			'cve'         => $cve,
			'title'       => $title,
			'details'     => $details,
			'client_ip'   => $client_ip,
			'timestamp'   => time(),
			'mode'        => $mode,
		);

		// Record attack log
		if ( class_exists( 'Waffers_Logger' ) ) {
			Waffers_Logger::log( array(
				'incident_id'    => $incident_id,
				'ip_address'     => $client_ip,
				'attack_type'    => $title,
				'cve_reference'  => $cve,
				'rule_triggered' => isset( $details['rule'] ) ? $details['rule'] : '',
				'request_method' => $method,
				'request_uri'    => $uri,
				'payload_sample' => isset( $details['payload'] ) ? $details['payload'] : '',
				'user_agent'     => $user_agent,
				'action_taken'   => ( 'simulate' === $mode ) ? 'simulated' : 'blocked',
			) );
		} elseif ( class_exists( 'PHP_Armor_Logger' ) ) {
			PHP_Armor_Logger::log( array(
				'incident_id'    => $incident_id,
				'ip_address'     => $client_ip,
				'attack_type'    => $title,
				'cve_reference'  => $cve,
				'rule_triggered' => isset( $details['rule'] ) ? $details['rule'] : '',
				'request_method' => $method,
				'request_uri'    => $uri,
				'payload_sample' => isset( $details['payload'] ) ? $details['payload'] : '',
				'user_agent'     => $user_agent,
				'action_taken'   => ( 'simulate' === $mode ) ? 'simulated' : 'blocked',
			) );
		}

		// If simulation mode, do not block, allow request to continue
		if ( 'simulate' === $mode ) {
			return true;
		}

		// Enforce block response
		self::send_block_response( $incident_id, $cve, $title );
		exit;
	}

	/**
	 * Send clean, hardened HTTP 403 response.
	 *
	 * @param string $incident_id Unique Incident ID.
	 * @param string $cve         CVE reference.
	 * @param string $title       Attack title.
	 */
	public static function send_block_response( $incident_id, $cve, $title ) {
		if ( ! headers_sent() ) {
			http_response_code( 403 );
			header( 'Content-Type: text/html; charset=UTF-8' );
			header( 'X-Content-Type-Options: nosniff' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'Cache-Control: no-cache, no-store, must-revalidate' );
			header( 'Pragma: no-cache' );
			header( 'Expires: 0' );
		}

		$options = self::get_options();
		$custom_msg = ! empty( $options['custom_block_message'] ) ? self::safe_esc( $options['custom_block_message'] ) : '';
		$client_ip  = self::safe_esc( self::get_client_ip() );
		$time_str   = gmdate( 'Y-m-d H:i:s' ) . ' UTC';

		?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="robots" content="noindex, nofollow, noarchive">
	<title>403 Forbidden - Request Blocked by Waffers</title>
	<style>
		:root {
			--bg: #0f172a;
			--card: #1e293b;
			--border: #334155;
			--danger: #ef4444;
			--text: #f8fafc;
			--muted: #94a3b8;
		}
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			background-color: var(--bg);
			color: var(--text);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.card {
			background: var(--card);
			border: 1px solid var(--border);
			border-radius: 12px;
			max-width: 620px;
			width: 100%;
			padding: 36px;
			box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
		}
		.badge {
			display: inline-flex;
			align-items: center;
			background: rgba(239, 68, 68, 0.15);
			color: var(--danger);
			font-size: 13px;
			font-weight: 600;
			padding: 4px 12px;
			border-radius: 9999px;
			border: 1px solid rgba(239, 68, 68, 0.3);
			margin-bottom: 20px;
		}
		h1 {
			font-size: 24px;
			font-weight: 700;
			margin-bottom: 12px;
			letter-spacing: -0.02em;
		}
		p {
			color: var(--muted);
			font-size: 15px;
			line-height: 1.6;
			margin-bottom: 20px;
		}
		.details {
			background: #090d16;
			border: 1px solid var(--border);
			border-radius: 8px;
			padding: 16px;
			font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
			font-size: 13px;
			margin-bottom: 24px;
		}
		.detail-row {
			display: flex;
			justify-content: space-between;
			padding: 6px 0;
			border-bottom: 1px solid rgba(255, 255, 255, 0.05);
		}
		.detail-row:last-child { border-bottom: none; }
		.label { color: var(--muted); }
		.value { color: #38bdf8; font-weight: 500; }
		.footer {
			border-top: 1px solid var(--border);
			padding-top: 18px;
			font-size: 12px;
			color: var(--muted);
			display: flex;
			justify-content: space-between;
			align-items: center;
		}
		.brand { font-weight: 600; color: #e2e8f0; }
	</style>
</head>
<body>
	<div class="card">
		<div class="badge">SECURITY INTERVENTION</div>
		<h1>403 Forbidden: Request Blocked</h1>
		<p>Your request was identified as matching an exploit pattern targeting known PHP vulnerabilities and has been rejected by <strong>Waffers Web Application Firewall</strong>.</p>
		<?php if ( ! empty( $custom_msg ) ) : ?>
			<p><?php echo $custom_msg; ?></p>
		<?php endif; ?>
		<div class="details">
			<div class="detail-row">
				<span class="label">Incident ID:</span>
				<span class="value"><?php echo self::safe_esc( $incident_id ); ?></span>
			</div>
			<div class="detail-row">
				<span class="label">Detection Rule:</span>
				<span class="value"><?php echo self::safe_esc( $title ); ?> (<?php echo self::safe_esc( $cve ); ?>)</span>
			</div>
			<div class="detail-row">
				<span class="label">Client IP:</span>
				<span class="value"><?php echo $client_ip; ?></span>
			</div>
			<div class="detail-row">
				<span class="label">Timestamp:</span>
				<span class="value"><?php echo self::safe_esc( $time_str ); ?></span>
			</div>
		</div>
		<div class="footer">
			<span class="brand">Waffers — The layer that protects you</span>
			<span>Secured by Waffers</span>
		</div>
	</div>
</body>
</html>
		<?php
	}

	/**
	 * Safe string cleaner without requiring WordPress formatting.php.
	 *
	 * @param string $str Raw string.
	 * @return string
	 */
	public static function safe_clean( $str ) {
		if ( ! is_string( $str ) ) {
			return '';
		}
		if ( function_exists( 'sanitize_text_field' ) ) {
			return sanitize_text_field( $str );
		}
		return strip_tags( $str );
	}

	/**
	 * Safe HTML escaper without requiring WordPress formatting.php.
	 *
	 * @param string $str Raw string.
	 * @return string
	 */
	public static function safe_esc( $str ) {
		if ( function_exists( 'esc_html' ) ) {
			return esc_html( (string) $str );
		}
		return htmlspecialchars( (string) $str, ENT_QUOTES, 'UTF-8' );
	}

	/**
	 * Sanitize payload for logging and display without breaking.
	 *
	 * @param string $payload Raw payload.
	 * @return string
	 */
	public static function sanitize_payload_sample( $payload ) {
		if ( ! is_string( $payload ) ) {
			return '';
		}
		// Truncate to 500 characters
		$sample = substr( $payload, 0, 500 );
		// Replace non-printable characters
		return preg_replace( '/[^\x20-\x7E\t\r\n]/', '.', $sample );
	}

	/**
	 * Get accurate client IP address with proxy header validation.
	 *
	 * @return string
	 */
	public static function get_client_ip() {
		$headers = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip_list = explode( ',', (string) $_SERVER[ $header ] );
				$ip      = trim( $ip_list[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
	}

	/**
	 * Check if IP is in whitelist (supports single IP, comma separated, or CIDR).
	 *
	 * @param string $ip        Client IP.
	 * @param string $whitelist Configured whitelist.
	 * @return bool
	 */
	protected static function is_ip_whitelisted( $ip, $whitelist ) {
		$lines = array_filter( array_map( 'trim', explode( "\n", str_replace( ',', "\n", $whitelist ) ) ) );
		foreach ( $lines as $allowed ) {
			if ( $ip === $allowed ) {
				return true;
			}
			// Simple CIDR check
			if ( strpos( $allowed, '/' ) !== false ) {
				list( $subnet, $bits ) = explode( '/', $allowed, 2 );
				$ip_long     = ip2long( $ip );
				$subnet_long = ip2long( $subnet );
				if ( false !== $ip_long && false !== $subnet_long ) {
					$mask = -1 << ( 32 - (int) $bits );
					if ( ( $ip_long & $mask ) === ( $subnet_long & $mask ) ) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Check if current URI is in path exclusions list.
	 *
	 * @param string $exclusions Configured exclusion lines.
	 * @return bool
	 */
	protected static function is_path_excluded( $exclusions ) {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( empty( $uri ) ) {
			return false;
		}

		$lines = array_filter( array_map( 'trim', explode( "\n", $exclusions ) ) );
		foreach ( $lines as $pattern ) {
			if ( 0 === strpos( $uri, $pattern ) || fnmatch( $pattern, $uri ) ) {
				return true;
			}
		}
		return false;
	}
}

// Backwards-compatibility alias
if ( ! class_exists( 'PHP_Armor_Firewall' ) ) {
	class_alias( 'Waffers_Firewall', 'PHP_Armor_Firewall' );
}

