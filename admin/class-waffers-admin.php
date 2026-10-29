<?php
/**
 * Waffers Admin Controller
 *
 * Manages WordPress admin menu, setting pages, AJAX handlers, and assets.
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Waffers_Admin {

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );

		// AJAX endpoints (primary Waffers actions)
		add_action( 'wp_ajax_waffers_save_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_waffers_apply_hardening', array( $this, 'ajax_apply_hardening' ) );
		add_action( 'wp_ajax_waffers_clear_logs', array( $this, 'ajax_clear_logs' ) );
		add_action( 'wp_ajax_waffers_run_simulation', array( $this, 'ajax_run_simulation' ) );

		// AJAX endpoints (backwards-compatibility aliases)
		add_action( 'wp_ajax_php_armor_save_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_php_armor_apply_hardening', array( $this, 'ajax_apply_hardening' ) );
		add_action( 'wp_ajax_php_armor_clear_logs', array( $this, 'ajax_clear_logs' ) );
		add_action( 'wp_ajax_php_armor_run_simulation', array( $this, 'ajax_run_simulation' ) );
	}

	/**
	 * Register Admin Menu Pages.
	 */
	public function register_admin_menu() {
		$main_slug = 'waffers';

		add_menu_page(
			__( 'Waffers — The layer that protects you', 'waffers' ),
			__( 'Waffers', 'waffers' ),
			'manage_options',
			$main_slug,
			array( $this, 'render_dashboard_page' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			$main_slug,
			__( 'Waffers — Security Dashboard & Health Scan', 'waffers' ),
			__( 'Dashboard & Audit', 'waffers' ),
			'manage_options',
			$main_slug,
			array( $this, 'render_dashboard_page' )
		);

		add_submenu_page(
			$main_slug,
			__( 'Waffers — Firewall Protection Rules', 'waffers' ),
			__( 'Firewall Rules', 'waffers' ),
			'manage_options',
			'waffers-rules',
			array( $this, 'render_rules_page' )
		);

		add_submenu_page(
			$main_slug,
			__( 'Waffers — Server-Level Hardening (.user.ini / .htaccess)', 'waffers' ),
			__( 'Server Hardening', 'waffers' ),
			'manage_options',
			'waffers-hardening',
			array( $this, 'render_hardening_page' )
		);

		add_submenu_page(
			$main_slug,
			__( 'Waffers — Live Attack & Threat Logs', 'waffers' ),
			__( 'Attack Logs', 'waffers' ),
			'manage_options',
			'waffers-logs',
			array( $this, 'render_logs_page' )
		);

		add_submenu_page(
			$main_slug,
			__( 'Waffers — Exploit Simulation Console', 'waffers' ),
			__( 'Exploit Simulator', 'waffers' ),
			'manage_options',
			'waffers-simulator',
			array( $this, 'render_simulator_page' )
		);

		// Backwards-compatible aliases for legacy URLs
		$legacy_slugs = array(
			'php-armor'           => 'render_dashboard_page',
			'php-armor-rules'     => 'render_rules_page',
			'php-armor-hardening' => 'render_hardening_page',
			'php-armor-logs'      => 'render_logs_page',
			'php-armor-simulator' => 'render_simulator_page',
		);
		foreach ( $legacy_slugs as $slug => $callback ) {
			add_submenu_page(
				null,
				'Waffers',
				'Waffers',
				'manage_options',
				$slug,
				array( $this, $callback )
			);
		}
	}

	/**
	 * Enqueue admin scripts & styles on Waffers pages.
	 *
	 * @param string $hook Admin page hook.
	 */
	public function enqueue_assets( $hook ) {
		if ( strpos( $hook, 'waffers' ) === false && strpos( $hook, 'php-armor' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'waffers-admin-css',
			WAFFERS_URL . 'admin/css/admin.css',
			array(),
			WAFFERS_VERSION
		);

		wp_enqueue_script(
			'waffers-admin-js',
			WAFFERS_URL . 'admin/js/admin.js',
			array( 'jquery' ),
			WAFFERS_VERSION,
			true
		);

		$data = array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'waffers_admin_nonce' ),
		);

		wp_localize_script( 'waffers-admin-js', 'waffersData', $data );
		wp_localize_script( 'waffers-admin-js', 'phpArmorData', $data );
	}

	/**
	 * Render Dashboard & Audit Page.
	 */
	public function render_dashboard_page() {
		$scan_results = Waffers_Scanner::run_scan();
		$stats        = Waffers_Logger::get_stats_24h();
		$options      = Waffers_Firewall::get_options();

		include WAFFERS_PATH . 'admin/views/dashboard.php';
	}

	/**
	 * Render Firewall Rules Page.
	 */
	public function render_rules_page() {
		$options = Waffers_Firewall::get_options();
		include WAFFERS_PATH . 'admin/views/firewall-rules.php';
	}

	/**
	 * Render Server Hardening Page.
	 */
	public function render_hardening_page() {
		$is_htaccess_active = Waffers_Server_Config::is_htaccess_installed();
		$is_user_ini_active = Waffers_Server_Config::is_user_ini_installed();
		$is_mu_active       = Waffers_Server_Config::is_mu_loader_installed();
		$nginx_snippet      = Waffers_Server_Config::generate_nginx_config();

		include WAFFERS_PATH . 'admin/views/server-hardening.php';
	}

	/**
	 * Render Attack Logs Page.
	 */
	public function render_logs_page() {
		$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		$cve    = isset( $_GET['cve'] ) ? sanitize_text_field( wp_unslash( $_GET['cve'] ) ) : '';
		$page   = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;

		$log_data = Waffers_Logger::get_logs( array(
			'page'   => $page,
			'search' => $search,
			'cve'    => $cve,
		) );

		include WAFFERS_PATH . 'admin/views/attack-logs.php';
	}

	/**
	 * Render Exploit Simulator Page.
	 */
	public function render_simulator_page() {
		include WAFFERS_PATH . 'admin/views/simulator.php';
	}

	/**
	 * Verify admin AJAX security check.
	 */
	protected function verify_ajax_request() {
		$nonce = isset( $_REQUEST['nonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['nonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'waffers_admin_nonce' ) && ! wp_verify_nonce( $nonce, 'php_armor_admin_nonce' ) ) {
			wp_send_json_error( array( 'message' => __( 'Security verification failed.', 'waffers' ) ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized user access.', 'waffers' ) ) );
		}
	}

	/**
	 * AJAX: Save Settings.
	 */
	public function ajax_save_settings() {
		$this->verify_ajax_request();

		$updated = array(
			'enabled'                 => isset( $_POST['enabled'] ) ? 1 : 0,
			'block_mode'              => ( isset( $_POST['block_mode'] ) && 'simulate' === $_POST['block_mode'] ) ? 'simulate' : 'block',
			'cve_2024_4577_shield'    => isset( $_POST['cve_2024_4577_shield'] ) ? 1 : 0,
			'php2shell_shield'        => isset( $_POST['php2shell_shield'] ) ? 1 : 0,
			'cve_2024_2961_shield'    => isset( $_POST['cve_2024_2961_shield'] ) ? 1 : 0,
			'object_injection_shield' => isset( $_POST['object_injection_shield'] ) ? 1 : 0,
			'multipart_dos_shield'    => isset( $_POST['multipart_dos_shield'] ) ? 1 : 0,
			'early_waf_active'        => isset( $_POST['early_waf_active'] ) ? 1 : 0,
			'ip_whitelist'            => isset( $_POST['ip_whitelist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ip_whitelist'] ) ) : '',
			'path_exclusions'         => isset( $_POST['path_exclusions'] ) ? sanitize_textarea_field( wp_unslash( $_POST['path_exclusions'] ) ) : '',
			'notify_email'            => isset( $_POST['notify_email'] ) ? sanitize_email( wp_unslash( $_POST['notify_email'] ) ) : '',
			'custom_block_message'    => isset( $_POST['custom_block_message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['custom_block_message'] ) ) : '',
		);

		update_option( 'waffers_options', $updated );
		update_option( 'php_armor_options', $updated );
		Waffers_Core::sync_standalone_config( $updated );

		wp_send_json_success( array( 'message' => __( 'Waffers settings saved successfully.', 'waffers' ) ) );
	}

	/**
	 * AJAX: Apply or Remove Server Hardening.
	 */
	public function ajax_apply_hardening() {
		$this->verify_ajax_request();

		$target = isset( $_POST['target'] ) ? sanitize_text_field( wp_unslash( $_POST['target'] ) ) : '';
		$action = isset( $_POST['hardening_action'] ) ? sanitize_text_field( wp_unslash( $_POST['hardening_action'] ) ) : 'apply';

		$result = array( 'success' => false, 'message' => __( 'Unknown hardening target requested.', 'waffers' ) );

		if ( 'htaccess' === $target ) {
			$result = ( 'apply' === $action ) ? Waffers_Server_Config::apply_htaccess() : Waffers_Server_Config::remove_htaccess();
		} elseif ( 'user_ini' === $target ) {
			$result = ( 'apply' === $action ) ? Waffers_Server_Config::apply_user_ini( true ) : Waffers_Server_Config::remove_user_ini();
		} elseif ( 'mu_loader' === $target ) {
			$result = ( 'apply' === $action ) ? Waffers_Server_Config::install_mu_loader() : Waffers_Server_Config::remove_mu_loader();
		}

		if ( ! empty( $result['success'] ) ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: Clear Attack Logs.
	 */
	public function ajax_clear_logs() {
		$this->verify_ajax_request();

		Waffers_Logger::clear_logs();
		wp_send_json_success( array( 'message' => __( 'All recorded attack logs have been truncated.', 'waffers' ) ) );
	}

	/**
	 * AJAX: Run Safe Exploit Simulation.
	 */
	public function ajax_run_simulation() {
		$this->verify_ajax_request();

		$test_type = isset( $_POST['test_type'] ) ? sanitize_text_field( wp_unslash( $_POST['test_type'] ) ) : '';
		$options   = Waffers_Firewall::get_options();

		// Backup current superglobals
		$backup_server = $_SERVER;
		$backup_post   = $_POST;
		$backup_get    = $_GET;

		$intercepted = false;
		$threat_data = null;
		$test_name   = '';

		switch ( $test_type ) {
			case 'cve_2024_4577':
				$test_name = __( 'CVE-2024-4577 (Windows PHP-CGI Argument Injection probe with %ad soft-hyphen)', 'waffers' );
				if ( empty( $options['cve_2024_4577_shield'] ) ) {
					wp_send_json_error( array(
						'intercepted' => false,
						'test'        => $test_name,
						'message'     => __( 'The PHP-CGI Argument Injection shield is currently disabled in Firewall Rules. Please enable it and save settings before testing.', 'waffers' ),
					) );
					return;
				}
				$_SERVER['QUERY_STRING'] = '%ad-d+auto_prepend_file=php://input';
				$_SERVER['REQUEST_URI']  = '/index.php?' . $_SERVER['QUERY_STRING'];
				$threat = Waffers_Firewall::detect_cve_2024_4577();
				if ( $threat ) {
					$intercepted = true;
					$threat_data = $threat;
				}
				break;

			case 'php2shell':
				$test_name = __( 'PHP2Shell (CVE-2026-109619 Multipart Session Upload Progress attack probe)', 'waffers' );
				if ( empty( $options['php2shell_shield'] ) ) {
					wp_send_json_error( array(
						'intercepted' => false,
						'test'        => $test_name,
						'message'     => __( 'The PHP2Shell shield is currently disabled in Firewall Rules. Please enable it and save settings before testing.', 'waffers' ),
					) );
					return;
				}
				$_SERVER['REQUEST_METHOD'] = 'POST';
				$prog_key = ini_get( 'session.upload_progress.name' );
				if ( empty( $prog_key ) ) {
					$prog_key = 'PHP_SESSION_UPLOAD_PROGRESS';
				}
				$_POST[ $prog_key ] = '<?php phpinfo(); ?>_malicious_session_struct';
				$threat = Waffers_Firewall::detect_php2shell();
				if ( $threat ) {
					$intercepted = true;
					$threat_data = $threat;
				}
				break;

			case 'cve_2024_2961':
				$test_name = __( 'CVE-2024-2961 (iconv ISO-2022-CN-EXT heap overflow filter chain probe)', 'waffers' );
				if ( empty( $options['cve_2024_2961_shield'] ) ) {
					wp_send_json_error( array(
						'intercepted' => false,
						'test'        => $test_name,
						'message'     => __( 'The iconv / Stream Wrapper shield is currently disabled in Firewall Rules. Please enable it and save settings before testing.', 'waffers' ),
					) );
					return;
				}
				$_GET['filter_test'] = 'php://filter/convert.iconv.ISO-2022-CN-EXT.UTF-8/resource=data:text/plain,test';
				$threat = Waffers_Firewall::detect_stream_wrapper_exploits();
				if ( $threat ) {
					$intercepted = true;
					$threat_data = $threat;
				}
				break;

			case 'object_injection':
				$test_name = __( 'PHP Object Injection (CWE-502 Serialized Gadget Chain probe)', 'waffers' );
				if ( empty( $options['object_injection_shield'] ) ) {
					wp_send_json_error( array(
						'intercepted' => false,
						'test'        => $test_name,
						'message'     => __( 'The PHP Object Injection shield is currently disabled in Firewall Rules. Please enable it and save settings before testing.', 'waffers' ),
					) );
					return;
				}
				$_GET['payload'] = 'O:14:"App\\Vulnerable":1:{s:4:"cmd";s:7:"whoami";}';
				$threat = Waffers_Firewall::detect_object_injection( true );
				if ( $threat ) {
					$intercepted = true;
					$threat_data = $threat;
				}
				break;

			default:
				wp_send_json_error( array( 'message' => __( 'Invalid simulation type requested.', 'waffers' ) ) );
				return;
		}

		// Restore superglobals
		$_SERVER = $backup_server;
		$_POST   = $backup_post;
		$_GET    = $backup_get;

		if ( $intercepted ) {
			wp_send_json_success( array(
				'intercepted' => true,
				'test'        => $test_name,
				'rule'        => isset( $threat_data['rule'] ) ? $threat_data['rule'] : 'Matched',
				'payload'     => isset( $threat_data['payload'] ) ? $threat_data['payload'] : '',
				'source'      => isset( $threat_data['source'] ) ? $threat_data['source'] : '',
				'message'     => __( 'Firewall successfully detected and neutralized the exploit payload!', 'waffers' ),
			) );
		} else {
			wp_send_json_error( array(
				'intercepted' => false,
				'test'        => $test_name,
				'message'     => __( 'Payload was not intercepted. Verify that this specific shield is enabled in Firewall Rules.', 'waffers' ),
			) );
		}
	}
}

// Backwards-compatibility alias
if ( ! class_exists( 'PHP_Armor_Admin' ) ) {
	class_alias( 'Waffers_Admin', 'PHP_Armor_Admin' );
}

