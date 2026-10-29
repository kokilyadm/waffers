<?php
/**
 * Waffers Core Orchestrator
 *
 * Singleton orchestrator coordinating lifecycle, hooks, and firewall execution.
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Waffers_Core {

	/**
	 * Singleton instance.
	 *
	 * @var Waffers_Core|null
	 */
	private static $instance = null;

	/**
	 * Admin controller instance.
	 *
	 * @var Waffers_Admin|null
	 */
	public $admin = null;

	/**
	 * Get singleton instance.
	 *
	 * @return Waffers_Core
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->load_dependencies();
		$this->init_hooks();
	}

	/**
	 * Load class files.
	 */
	private function load_dependencies() {
		require_once WAFFERS_PATH . 'includes/class-waffers-firewall.php';
		require_once WAFFERS_PATH . 'includes/class-waffers-logger.php';
		require_once WAFFERS_PATH . 'includes/class-waffers-scanner.php';
		require_once WAFFERS_PATH . 'includes/class-waffers-server-config.php';

		if ( is_admin() ) {
			require_once WAFFERS_PATH . 'admin/class-waffers-admin.php';
		}
	}

	/**
	 * Initialize WordPress action & filter hooks.
	 */
	private function init_hooks() {
		// Load textdomain for i18n
		add_action( 'init', array( $this, 'load_textdomain' ) );

		// Run firewall early if not already executed by early-waf.php
		if ( ! defined( 'WAFFERS_EARLY_LOADED' ) && ! defined( 'PHP_ARMOR_EARLY_LOADED' ) ) {
			add_action( 'plugins_loaded', array( $this, 'run_firewall' ), -9999 );
		}

		// Proactively strip X-Powered-By to prevent PHP version leakage
		add_action( 'send_headers', array( $this, 'strip_powered_by_header' ), 999 );
		add_action( 'init', array( $this, 'strip_powered_by_header' ), -9999 );

		if ( is_admin() ) {
			$this->admin = new Waffers_Admin();
			add_action( 'admin_init', array( $this, 'register_privacy_policy_content' ) );
		}

		// Handle CSV export actions (both current and legacy hooks)
		add_action( 'admin_post_waffers_export_csv', array( 'Waffers_Logger', 'export_csv' ) );
		add_action( 'admin_post_php_armor_export_csv', array( 'Waffers_Logger', 'export_csv' ) );
	}

	/**
	 * Load plugin translation files.
	 */
	public function load_textdomain() {
		load_plugin_textdomain(
			'waffers-the-layer-that-protects-you',
			false,
			dirname( plugin_basename( WAFFERS_FILE ) ) . '/languages'
		);
	}

	/**
	 * Strip X-Powered-By header from HTTP response.
	 */
	public function strip_powered_by_header() {
		if ( function_exists( 'header_remove' ) && ! headers_sent() ) {
			header_remove( 'X-Powered-By' );
		}
	}

	/**
	 * Run firewall inspection.
	 */
	public function run_firewall() {
		Waffers_Firewall::inspect();
	}

	/**
	 * Register Suggested Privacy Policy Content (GDPR & Privacy Compliance).
	 */
	public function register_privacy_policy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		$content = sprintf(
			'<h2>%s</h2>' .
			'<p>%s</p>' .
			'<h3>%s</h3>' .
			'<p>%s</p>' .
			'<h3>%s</h3>' .
			'<p>%s</p>' .
			'<h3>%s</h3>' .
			'<p>%s</p>',
			esc_html__( 'Waffers Web Application Firewall', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'Waffers operates locally on this web server to protect this website against PHP engine vulnerabilities, malicious requests, and remote exploit attempts.', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'What Personal Data is Collected and Why', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'When an HTTP request triggers a security defense rule, Waffers records the visitor’s IP address, User-Agent, request timestamp, target URI, and a sample of the intercepted attack payload in the local site database. This information is processed strictly under legitimate interest to prevent unauthorized system access, block exploits, and maintain site security.', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'Data Retention & Deletion', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'Recorded security logs are automatically pruned after 30 days or retained up to a maximum of 10,000 entries. Administrators may also clear all logged events at any time via the Waffers Attack Logs dashboard.', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'Third-Party Sharing', 'waffers-the-layer-that-protects-you' ),
			esc_html__( 'Waffers is a 100% self-hosted, standalone security firewall. No visitor data, IP addresses, or security telemetry are ever transmitted to external servers or third-party organizations.', 'waffers-the-layer-that-protects-you' )
		);

		wp_add_privacy_policy_content(
			__( 'Waffers — The layer that protects you', 'waffers-the-layer-that-protects-you' ),
			wp_kses_post( wpautop( $content, false ) )
		);
	}

	/**
	 * Plugin activation routine.
	 */
	public static function activate() {
		// Create logs database table
		Waffers_Logger::create_table();

		// Check options and migrate legacy options if present
		$options = get_option( 'waffers_options' );
		if ( false === $options ) {
			$legacy = get_option( 'php_armor_options' );
			if ( is_array( $legacy ) && ! empty( $legacy ) ) {
				$options = $legacy;
			} else {
				$options = array(
					'enabled'                 => 1,
					'block_mode'              => 'block',
					'cve_2024_4577_shield'    => 1,
					'php2shell_shield'        => 1,
					'cve_2024_2961_shield'    => 1,
					'object_injection_shield' => 1,
					'multipart_dos_shield'    => 1,
					'early_waf_active'        => 0,
					'ip_whitelist'            => '',
					'path_exclusions'         => '',
					'notify_email'            => get_option( 'admin_email', '' ),
					'custom_block_message'    => '',
				);
			}
			update_option( 'waffers_options', $options );
			self::sync_standalone_config( $options );
		}
	}

	/**
	 * Plugin deactivation routine.
	 */
	public static function deactivate() {
		if ( function_exists( 'wp_upload_dir' ) ) {
			$upload = wp_upload_dir();
			if ( ! empty( $upload['basedir'] ) && file_exists( $upload['basedir'] . '/waffers-config.json' ) ) {
				@unlink( $upload['basedir'] . '/waffers-config.json' );
			}
		}
	}

	/**
	 * Sync WordPress settings to a local JSON file in uploads directory for standalone reading.
	 *
	 * @param array $options Options array.
	 */
	public static function sync_standalone_config( $options ) {
		if ( function_exists( 'wp_upload_dir' ) ) {
			$upload = wp_upload_dir();
			if ( ! empty( $upload['basedir'] ) && is_writable( $upload['basedir'] ) ) {
				@file_put_contents( $upload['basedir'] . '/waffers-config.json', wp_json_encode( $options ), LOCK_EX );
			}
		}
	}
}

// Backwards-compatibility alias
if ( ! class_exists( 'PHP_Armor_Core' ) ) {
	class_alias( 'Waffers_Core', 'PHP_Armor_Core' );
}

