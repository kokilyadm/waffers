<?php
/**
 * Plugin Name:       Waffers
 * Plugin URI:        https://github.com/kokilyadm/waffers
 * Description:       The layer that protects you. Proactive defense-in-depth Web Application Firewall mitigating recent critical PHP engine vulnerabilities including PHP2Shell (CVE-2026-109618/9), PHP-CGI Argument Injection (CVE-2024-4577), iconv Filter Chains (CVE-2024-2961), and stream wrapper abuse.
 * Version:           1.0.0
 * Requires at least: 5.4
 * Requires PHP:      7.2
 * Author:            Waffers Security
 * License:           GPL-2.0+
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       waffers
 * Domain Path:       /languages
 *
 * @package           Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define Plugin Constants
define( 'WAFFERS_VERSION', '1.0.0' );
define( 'WAFFERS_FILE', __FILE__ );
define( 'WAFFERS_PATH', plugin_dir_path( __FILE__ ) );
define( 'WAFFERS_URL', plugin_dir_url( __FILE__ ) );

// Legacy aliases for backwards compatibility
if ( ! defined( 'PHP_ARMOR_VERSION' ) ) {
	define( 'PHP_ARMOR_VERSION', WAFFERS_VERSION );
	define( 'PHP_ARMOR_FILE', WAFFERS_FILE );
	define( 'PHP_ARMOR_PATH', WAFFERS_PATH );
	define( 'PHP_ARMOR_URL', WAFFERS_URL );
}

// Load Core Plugin Orchestrator
require_once WAFFERS_PATH . 'includes/class-waffers-core.php';

// Register Lifecycle Hooks
register_activation_hook( __FILE__, array( 'Waffers_Core', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Waffers_Core', 'deactivate' ) );

// Initialize Plugin
function waffers_init() {
	return Waffers_Core::get_instance();
}
waffers_init();

// Add Settings Link to Plugins Table
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), function( $links ) {
	$settings_link = sprintf(
		'<a href="%s">%s</a>',
		esc_url( admin_url( 'admin.php?page=waffers' ) ),
		esc_html__( 'Security Dashboard', 'waffers' )
	);
	array_unshift( $links, $settings_link );
	return $links;
} );
