<?php
/**
 * Waffers Server-Level Configuration & Hardening Manager
 *
 * Manages automated installation of .user.ini directives, Apache .htaccess rewrite rules,
 * Nginx configuration directives, and Must-Use (MU) early loader scripts.
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Waffers_Server_Config {

	const HTACCESS_START        = '# BEGIN Waffers Security Rules';
	const HTACCESS_END          = '# END Waffers Security Rules';
	const LEGACY_HTACCESS_START = '# BEGIN PHP Armor Security Rules';
	const LEGACY_HTACCESS_END   = '# END PHP Armor Security Rules';

	const USER_INI_START        = '; BEGIN Waffers Security Directives';
	const USER_INI_END          = '; END Waffers Security Directives';
	const LEGACY_USER_INI_START = '; BEGIN PHP Armor Security Directives';
	const LEGACY_USER_INI_END   = '; END PHP Armor Security Directives';

	/**
	 * Get WordPress root path.
	 *
	 * @return string
	 */
	public static function get_root_path() {
		return defined( 'ABSPATH' ) ? ABSPATH : dirname( dirname( __DIR__ ) ) . '/';
	}

	/**
	 * Get path to .htaccess.
	 *
	 * @return string
	 */
	public static function get_htaccess_path() {
		return self::get_root_path() . '.htaccess';
	}

	/**
	 * Get path to .user.ini.
	 *
	 * @return string
	 */
	public static function get_user_ini_path() {
		return self::get_root_path() . '.user.ini';
	}

	/**
	 * Get path to MU-Plugin loader.
	 *
	 * @return string
	 */
	public static function get_mu_loader_path() {
		$mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		return $mu_dir . '/waffers-early-loader.php';
	}

	/**
	 * Get legacy path to MU-Plugin loader.
	 *
	 * @return string
	 */
	public static function get_legacy_mu_loader_path() {
		$mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		return $mu_dir . '/php-armor-early-loader.php';
	}

	/**
	 * Check if .htaccess has Waffers rules installed.
	 *
	 * @return bool
	 */
	public static function is_htaccess_installed() {
		$path = self::get_htaccess_path();
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		$content = file_get_contents( $path );
		return ( false !== strpos( $content, self::HTACCESS_START ) || false !== strpos( $content, self::LEGACY_HTACCESS_START ) );
	}

	/**
	 * Check if .user.ini has Waffers directives installed.
	 *
	 * @return bool
	 */
	public static function is_user_ini_installed() {
		$path = self::get_user_ini_path();
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		$content = file_get_contents( $path );
		return ( false !== strpos( $content, self::USER_INI_START ) || false !== strpos( $content, self::LEGACY_USER_INI_START ) );
	}

	/**
	 * Check if MU-Plugin early loader is installed.
	 *
	 * @return bool
	 */
	public static function is_mu_loader_installed() {
		return file_exists( self::get_mu_loader_path() ) || file_exists( self::get_legacy_mu_loader_path() );
	}

	/**
	 * Generate .htaccess rules.
	 *
	 * @return string
	 */
	public static function generate_htaccess_rules() {
		$rules  = self::HTACCESS_START . "\n";
		$rules .= "<IfModule mod_rewrite.c>\n";
		$rules .= "RewriteEngine On\n";
		$rules .= "# CVE-2024-4577: Block soft hyphen (%ad) and CGI argument injection\n";
		$rules .= "RewriteCond %{QUERY_STRING} ^(%ad|%80|%a0|-d|-s|-b|-c|-w|-z) [NC,OR]\n";
		$rules .= "RewriteCond %{QUERY_STRING} (%ad|-d\s+auto_prepend_file|-d\s+allow_url_include|-d\s+disable_functions) [NC,OR]\n";
		$rules .= "# CVE-2024-2961: Block iconv vulnerable charset filters and excessive filter chains\n";
		$rules .= "RewriteCond %{QUERY_STRING} (ISO-2022-CN-EXT|IBM273|php:\/\/input|phar:\/\/|data:\/\/text\/plain) [NC]\n";
		$rules .= "RewriteRule .* - [F,L]\n";
		$rules .= "</IfModule>\n\n";
		$rules .= "<IfModule mod_php.c>\n";
		$rules .= "# Neutralize PHP2Shell and unsafe includes\n";
		$rules .= "php_value session.upload_progress.enabled 0\n";
		$rules .= "php_flag allow_url_include Off\n";
		$rules .= "php_flag expose_php Off\n";
		$rules .= "</IfModule>\n";
		$rules .= self::HTACCESS_END;

		return $rules;
	}

	/**
	 * Generate .user.ini directives.
	 *
	 * @param bool $include_auto_prepend Whether to include early-waf auto_prepend_file.
	 * @return string
	 */
	public static function generate_user_ini_directives( $include_auto_prepend = false ) {
		$early_waf_file = dirname( __DIR__ ) . '/early-waf.php';

		$directives  = self::USER_INI_START . "\n";
		$directives .= "; Mitigate PHP2Shell (CVE-2026-109618 / CVE-2026-109619) & CVE-2026-115560\n";
		$directives .= "session.upload_progress.enabled = 0\n\n";
		$directives .= "; Mitigate Remote Code Execution via stream wrappers\n";
		$directives .= "allow_url_include = 0\n\n";
		$directives .= "; Prevent PHP fingerprinting\n";
		$directives .= "expose_php = 0\n";

		if ( $include_auto_prepend && file_exists( $early_waf_file ) ) {
			$directives .= "\n; Waffers Early Pre-Boot WAF\n";
			$directives .= 'auto_prepend_file = "' . addslashes( $early_waf_file ) . "\"\n";
		}

		$directives .= self::USER_INI_END;

		return $directives;
	}

	/**
	 * Generate Nginx configuration directives for manual insertion.
	 *
	 * @return string
	 */
	public static function generate_nginx_config() {
		$config  = "# ================================================================\n";
		$config .= "# Waffers Nginx Protection Rules\n";
		$config .= "# The layer that protects you\n";
		$config .= "# Place these directives inside your server { ... } block in nginx.conf\n";
		$config .= "# ================================================================\n\n";
		$config .= "# 1. Block CVE-2024-4577 (PHP-CGI Argument Injection & Soft-Hyphens)\n";
		$config .= "if (\$query_string ~* \"(%ad|%80|%a0|-d|-s|-b|-c|-w|-z).*(auto_prepend_file|allow_url_include|disable_functions)\") {\n";
		$config .= "    return 403;\n";
		$config .= "}\n";
		$config .= "if (\$query_string ~* \"^(%ad|%80|%a0)\") {\n";
		$config .= "    return 403;\n";
		$config .= "}\n\n";
		$config .= "# 2. Block CVE-2024-2961 (iconv Vulnerable Charsets) & Malicious Stream Wrappers\n";
		$config .= "if (\$query_string ~* \"(ISO-2022-CN-EXT|IBM273|phar:\/\/|php:\/\/input)\") {\n";
		$config .= "    return 403;\n";
		$config .= "}\n\n";
		$config .= "# 3. Set FastCGI parameters for PHP-FPM (Mitigates PHP2Shell)\n";
		$config .= "# In your location ~ \\.php\$ block, append:\n";
		$config .= "# fastcgi_param PHP_VALUE \"session.upload_progress.enabled=0\\nallow_url_include=0\";\n";

		return $config;
	}

	/**
	 * Install or update .htaccess rules.
	 *
	 * @return array Result [success, message].
	 */
	public static function apply_htaccess() {
		$path     = self::get_htaccess_path();
		$existing = file_exists( $path ) ? file_get_contents( $path ) : '';

		// Remove old blocks if present
		$patterns = array(
			'/' . preg_quote( self::HTACCESS_START, '/' ) . '.*?' . preg_quote( self::HTACCESS_END, '/' ) . '\s*/s',
			'/' . preg_quote( self::LEGACY_HTACCESS_START, '/' ) . '.*?' . preg_quote( self::LEGACY_HTACCESS_END, '/' ) . '\s*/s',
		);
		foreach ( $patterns as $p ) {
			$existing = preg_replace( $p, '', $existing );
		}

		$new_rules    = self::generate_htaccess_rules() . "\n\n" . ltrim( $existing );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected
		$write_result = @file_put_contents( $path, $new_rules, LOCK_EX );

		if ( false === $write_result ) {
			return array(
				'success' => false,
				'message' => __( 'Unable to write to .htaccess. Please check file permissions or apply rules manually.', 'waffers' ),
			);
		}

		return array(
			'success' => true,
			'message' => __( 'Successfully installed Waffers hardening rules in .htaccess.', 'waffers' ),
		);
	}

	/**
	 * Remove .htaccess rules.
	 *
	 * @return array Result [success, message].
	 */
	public static function remove_htaccess() {
		$path = self::get_htaccess_path();
		if ( ! file_exists( $path ) ) {
			return array( 'success' => true, 'message' => __( '.htaccess file does not exist.', 'waffers' ) );
		}

		$existing = file_get_contents( $path );
		$patterns = array(
			'/' . preg_quote( self::HTACCESS_START, '/' ) . '.*?' . preg_quote( self::HTACCESS_END, '/' ) . '\s*/s',
			'/' . preg_quote( self::LEGACY_HTACCESS_START, '/' ) . '.*?' . preg_quote( self::LEGACY_HTACCESS_END, '/' ) . '\s*/s',
		);
		foreach ( $patterns as $p ) {
			$existing = preg_replace( $p, '', $existing );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected
		$write_result = @file_put_contents( $path, $existing, LOCK_EX );
		if ( false === $write_result ) {
			return array(
				'success' => false,
				'message' => __( 'Failed to remove Waffers block from .htaccess due to file permissions.', 'waffers' ),
			);
		}

		return array(
			'success' => true,
			'message' => __( 'Waffers rules removed from .htaccess.', 'waffers' ),
		);
	}

	/**
	 * Install or update .user.ini directives.
	 *
	 * @param bool $auto_prepend Whether to include auto_prepend_file directive.
	 * @return array Result [success, message].
	 */
	public static function apply_user_ini( $auto_prepend = false ) {
		$path     = self::get_user_ini_path();
		$existing = file_exists( $path ) ? file_get_contents( $path ) : '';

		// Remove old blocks if present
		$patterns = array(
			'/' . preg_quote( self::USER_INI_START, '/' ) . '.*?' . preg_quote( self::USER_INI_END, '/' ) . '\s*/s',
			'/' . preg_quote( self::LEGACY_USER_INI_START, '/' ) . '.*?' . preg_quote( self::LEGACY_USER_INI_END, '/' ) . '\s*/s',
		);
		foreach ( $patterns as $p ) {
			$existing = preg_replace( $p, '', $existing );
		}

		$new_content  = self::generate_user_ini_directives( $auto_prepend ) . "\n\n" . ltrim( $existing );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected
		$write_result = @file_put_contents( $path, $new_content, LOCK_EX );

		if ( false === $write_result ) {
			return array(
				'success' => false,
				'message' => __( 'Unable to write to .user.ini. Check file permissions or create the file manually.', 'waffers' ),
			);
		}

		return array(
			'success' => true,
			'message' => __( 'Successfully wrote Waffers hardening directives to .user.ini. (Changes typically take 1-5 minutes for PHP-FPM to reload).', 'waffers' ),
		);
	}

	/**
	 * Remove .user.ini directives.
	 *
	 * @return array Result [success, message].
	 */
	public static function remove_user_ini() {
		$path = self::get_user_ini_path();
		if ( ! file_exists( $path ) ) {
			return array( 'success' => true, 'message' => __( '.user.ini does not exist.', 'waffers' ) );
		}

		$existing = file_get_contents( $path );
		$patterns = array(
			'/' . preg_quote( self::USER_INI_START, '/' ) . '.*?' . preg_quote( self::USER_INI_END, '/' ) . '\s*/s',
			'/' . preg_quote( self::LEGACY_USER_INI_START, '/' ) . '.*?' . preg_quote( self::LEGACY_USER_INI_END, '/' ) . '\s*/s',
		);
		foreach ( $patterns as $p ) {
			$existing = preg_replace( $p, '', $existing );
		}
		$cleaned = trim( $existing );

		if ( empty( $cleaned ) ) {
			if ( function_exists( 'wp_delete_file' ) ) {
				wp_delete_file( $path );
			}
		} else {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected
			@file_put_contents( $path, $cleaned, LOCK_EX );
		}

		return array(
			'success' => true,
			'message' => __( 'Waffers directives removed from .user.ini.', 'waffers' ),
		);
	}

	/**
	 * Install Must-Use (MU-Plugin) Early Loader.
	 *
	 * @return array Result [success, message].
	 */
	public static function install_mu_loader() {
		$mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		if ( ! is_dir( $mu_dir ) ) {
			$made = wp_mkdir_p( $mu_dir );
			if ( ! $made ) {
				return array(
					'success' => false,
					'message' => __( 'Could not create wp-content/mu-plugins directory. Check folder permissions.', 'waffers' ),
				);
			}
		}

		$target_file     = self::get_mu_loader_path();
		$plugin_firewall = dirname( __DIR__ ) . '/early-waf.php';

		$code  = "<?php\n";
		$code .= "/**\n";
		$code .= " * Plugin Name: Waffers Early Loader (Must-Use)\n";
		$code .= " * Description: The layer that protects you — Automatically loads Waffers Firewall before all standard plugins and themes.\n";
		$code .= " * Author: Waffers Security\n";
		$code .= " */\n\n";
		$code .= "if ( ! defined( 'ABSPATH' ) ) {\n";
		$code .= "    exit;\n";
		$code .= "}\n\n";
		$code .= "\$early_file = '" . addslashes( $plugin_firewall ) . "';\n";
		$code .= "if ( ! file_exists( \$early_file ) && defined( 'WP_PLUGIN_DIR' ) ) {\n";
		$code .= "    if ( file_exists( WP_PLUGIN_DIR . '/waffers/early-waf.php' ) ) {\n";
		$code .= "        \$early_file = WP_PLUGIN_DIR . '/waffers/early-waf.php';\n";
		$code .= "    } elseif ( file_exists( WP_PLUGIN_DIR . '/php-armor/early-waf.php' ) ) {\n";
		$code .= "        \$early_file = WP_PLUGIN_DIR . '/php-armor/early-waf.php';\n";
		$code .= "    }\n";
		$code .= "}\n\n";
		$code .= "if ( file_exists( \$early_file ) ) {\n";
		$code .= "    require_once \$early_file;\n";
		$code .= "}\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected
		$written = @file_put_contents( $target_file, $code, LOCK_EX );
		if ( false === $written ) {
			return array(
				'success' => false,
				'message' => __( 'Unable to write early loader file to wp-content/mu-plugins/.', 'waffers' ),
			);
		}

		// Also clean up legacy mu loader file if present
		$legacy_file = self::get_legacy_mu_loader_path();
		if ( file_exists( $legacy_file ) && $legacy_file !== $target_file ) {
			if ( function_exists( 'wp_delete_file' ) ) {
				wp_delete_file( $legacy_file );
			}
		}

		return array(
			'success' => true,
			'message' => __( 'Waffers Must-Use Early Loader installed successfully! It will now execute before all standard plugins.', 'waffers' ),
		);
	}

	/**
	 * Remove Must-Use Early Loader.
	 *
	 * @return array Result [success, message].
	 */
	public static function remove_mu_loader() {
		$target_file = self::get_mu_loader_path();
		if ( file_exists( $target_file ) ) {
			if ( function_exists( 'wp_delete_file' ) ) {
				$deleted = wp_delete_file( $target_file );
			} else {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				$deleted = @unlink( $target_file );
			}
			if ( ! $deleted ) {
				return array(
					'success' => false,
					'message' => __( 'Failed to delete early loader from wp-content/mu-plugins/.', 'waffers' ),
				);
			}
		}

		$legacy_file = self::get_legacy_mu_loader_path();
		if ( file_exists( $legacy_file ) ) {
			if ( function_exists( 'wp_delete_file' ) ) {
				wp_delete_file( $legacy_file );
			}
		}

		return array(
			'success' => true,
			'message' => __( 'Waffers Must-Use Early Loader removed.', 'waffers' ),
		);
	}
}

// Backwards-compatibility alias
if ( ! class_exists( 'PHP_Armor_Server_Config' ) ) {
	class_alias( 'Waffers_Server_Config', 'PHP_Armor_Server_Config' );
}

