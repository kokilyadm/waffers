<?php
/**
 * Waffers Uninstall Routine
 *
 * Cleans up options, database tables, and standalone configuration files upon deletion.
 *
 * @package Waffers
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// 1. Drop Custom Database Tables
$waffers_table   = $wpdb->prefix . 'waffers_logs';
$php_armor_table = $wpdb->prefix . 'php_armor_logs';
$wpdb->query( "DROP TABLE IF EXISTS {$waffers_table}" );
$wpdb->query( "DROP TABLE IF EXISTS {$php_armor_table}" );

// 2. Delete Stored Options
delete_option( 'waffers_options' );
delete_option( 'php_armor_options' );

// 3. Remove Standalone Config Files
$config_files = array(
	plugin_dir_path( __FILE__ ) . 'waffers-config.json',
	plugin_dir_path( __FILE__ ) . 'php-armor-config.json',
	defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/waffers-events.log' : '',
	defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/php-armor-events.log' : '',
);
foreach ( $config_files as $file ) {
	if ( ! empty( $file ) && file_exists( $file ) ) {
		@unlink( $file );
	}
}

// 4. Remove Early Loaders from mu-plugins if present
$mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/mu-plugins' : '' );
if ( ! empty( $mu_dir ) ) {
	$mu_loaders = array(
		$mu_dir . '/waffers-early-loader.php',
		$mu_dir . '/php-armor-early-loader.php',
	);
	foreach ( $mu_loaders as $loader ) {
		if ( file_exists( $loader ) ) {
			@unlink( $loader );
		}
	}
}

// 5. Clean up .htaccess and .user.ini blocks
$root_dir = defined( 'ABSPATH' ) ? ABSPATH : dirname( dirname( __DIR__ ) ) . '/';

$htaccess = $root_dir . '.htaccess';
if ( file_exists( $htaccess ) && is_writable( $htaccess ) ) {
	$content = file_get_contents( $htaccess );
	$patterns = array(
		'/# BEGIN Waffers Security Rules.*?# END Waffers Security Rules\s*/s',
		'/# BEGIN PHP Armor Security Rules.*?# END PHP Armor Security Rules\s*/s',
	);
	foreach ( $patterns as $p ) {
		$content = preg_replace( $p, '', $content );
	}
	@file_put_contents( $htaccess, $content, LOCK_EX );
}

$user_ini = $root_dir . '.user.ini';
if ( file_exists( $user_ini ) && is_writable( $user_ini ) ) {
	$content = file_get_contents( $user_ini );
	$patterns = array(
		'/; BEGIN Waffers Security Directives.*?; END Waffers Security Directives\s*/s',
		'/; BEGIN PHP Armor Security Directives.*?; END PHP Armor Security Directives\s*/s',
	);
	foreach ( $patterns as $p ) {
		$content = preg_replace( $p, '', $content );
	}
	$cleaned = trim( $content );
	if ( empty( $cleaned ) ) {
		@unlink( $user_ini );
	} else {
		@file_put_contents( $user_ini, $cleaned, LOCK_EX );
	}
}
