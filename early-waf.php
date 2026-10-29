<?php
/**
 * Waffers Early Bootstrap Firewall
 *
 * This file can be loaded via PHP's `auto_prepend_file` directive in `.user.ini`,
 * `.htaccess`, `php.ini`, or as a WordPress Must-Use plugin (`wp-content/mu-plugins/`).
 *
 * It inspects requests before WordPress standard plugins or themes load,
 * stopping attacks at the earliest possible stage.
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( defined( 'WAFFERS_EARLY_LOADED' ) || defined( 'PHP_ARMOR_EARLY_LOADED' ) ) {
	return;
}
define( 'WAFFERS_EARLY_LOADED', true );
define( 'PHP_ARMOR_EARLY_LOADED', true );

$waffers_plugin_dir = __DIR__;

// Load real logger first
if ( file_exists( $waffers_plugin_dir . '/includes/class-waffers-logger.php' ) ) {
	require_once $waffers_plugin_dir . '/includes/class-waffers-logger.php';
} elseif ( file_exists( $waffers_plugin_dir . '/includes/class-php-armor-logger.php' ) ) {
	require_once $waffers_plugin_dir . '/includes/class-php-armor-logger.php';
}

// Load firewall engine
if ( file_exists( $waffers_plugin_dir . '/includes/class-waffers-firewall.php' ) ) {
	require_once $waffers_plugin_dir . '/includes/class-waffers-firewall.php';
} elseif ( file_exists( $waffers_plugin_dir . '/includes/class-php-armor-firewall.php' ) ) {
	require_once $waffers_plugin_dir . '/includes/class-php-armor-firewall.php';
}

if ( class_exists( 'Waffers_Firewall' ) || class_exists( 'PHP_Armor_Firewall' ) ) {
	$waffers_firewall_class = class_exists( 'Waffers_Firewall' ) ? 'Waffers_Firewall' : 'PHP_Armor_Firewall';

	// If WordPress hook system is ready (e.g. in MU-plugin context),
	// hook to plugins_loaded at priority -99999 so that:
	// 1. It executes before ANY standard plugin or theme code.
	// 2. All WordPress core functions (formatting, pluggable, wpdb) are fully loaded.
	if ( function_exists( 'add_action' ) ) {
		add_action( 'plugins_loaded', array( $waffers_firewall_class, 'inspect' ), -99999 );
	} else {
		// Pure pre-boot environment (auto_prepend_file in php.ini / .user.ini)
		call_user_func( array( $waffers_firewall_class, 'inspect' ) );
	}
}
