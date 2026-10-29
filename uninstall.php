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
$waffers_table       = $wpdb->prefix . 'waffers_logs';
$waffers_table_armor = $wpdb->prefix . 'php_armor_logs';

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
$wpdb->query( "DROP TABLE IF EXISTS {$waffers_table}" );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
$wpdb->query( "DROP TABLE IF EXISTS {$waffers_table_armor}" );

// 2. Delete Stored Options
delete_option( 'waffers_options' );
delete_option( 'php_armor_options' );

// 3. Remove Standalone Config Files
$waffers_config_files = array(
	plugin_dir_path( __FILE__ ) . 'waffers-config.json',
	plugin_dir_path( __FILE__ ) . 'php-armor-config.json',
);
if ( function_exists( 'wp_upload_dir' ) ) {
	$waffers_upload = wp_upload_dir();
	if ( ! empty( $waffers_upload['basedir'] ) ) {
		$waffers_config_files[] = $waffers_upload['basedir'] . '/waffers-config.json';
	}
}

foreach ( $waffers_config_files as $waffers_file ) {
	if ( ! empty( $waffers_file ) && file_exists( $waffers_file ) ) {
		if ( function_exists( 'wp_delete_file' ) ) {
			wp_delete_file( $waffers_file );
		}
	}
}

// 4. Remove Early Loaders from mu-plugins if present
$waffers_mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/mu-plugins' : '' );
if ( ! empty( $waffers_mu_dir ) ) {
	$waffers_mu_loaders = array(
		$waffers_mu_dir . '/waffers-early-loader.php',
		$waffers_mu_dir . '/php-armor-early-loader.php',
	);
	foreach ( $waffers_mu_loaders as $waffers_loader ) {
		if ( file_exists( $waffers_loader ) ) {
			if ( function_exists( 'wp_delete_file' ) ) {
				wp_delete_file( $waffers_loader );
			}
		}
	}
}

// 5. Clean up .htaccess and .user.ini blocks
$waffers_server_config = plugin_dir_path( __FILE__ ) . 'includes/class-waffers-server-config.php';
if ( file_exists( $waffers_server_config ) ) {
	require_once $waffers_server_config;
	if ( class_exists( 'Waffers_Server_Config' ) ) {
		Waffers_Server_Config::remove_htaccess();
		Waffers_Server_Config::remove_user_ini();
	}
}
