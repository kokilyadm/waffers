<?php
/**
 * Waffers Attack Event Logger & Database Store
 *
 * Records blocked and simulated security events in WordPress custom table,
 * providing search, aggregation stats, pruning, and CSV export.
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Waffers_Logger' ) ) :

class Waffers_Logger {

	/**
	 * Custom database table name without prefix.
	 */
	const TABLE_NAME = 'waffers_logs';

	/**
	 * Legacy database table name without prefix.
	 */
	const LEGACY_TABLE_NAME = 'php_armor_logs';

	/**
	 * Get full table name with WordPress prefix.
	 *
	 * @return string
	 */
	public static function get_table_name() {
		global $wpdb;
		if ( isset( $wpdb ) && ! empty( $wpdb->prefix ) ) {
			return $wpdb->prefix . self::TABLE_NAME;
		}
		return 'wp_' . self::TABLE_NAME;
	}

	/**
	 * Get legacy table name with WordPress prefix.
	 *
	 * @return string
	 */
	public static function get_legacy_table_name() {
		global $wpdb;
		if ( isset( $wpdb ) && ! empty( $wpdb->prefix ) ) {
			return $wpdb->prefix . self::LEGACY_TABLE_NAME;
		}
		return 'wp_' . self::LEGACY_TABLE_NAME;
	}

	/**
	 * Create or update database table using dbDelta.
	 */
	public static function create_table() {
		global $wpdb;

		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

		$table_name      = self::get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			incident_id varchar(16) NOT NULL,
			timestamp datetime NOT NULL,
			ip_address varchar(45) NOT NULL,
			attack_type varchar(128) NOT NULL,
			cve_reference varchar(32) NOT NULL,
			rule_triggered varchar(128) NOT NULL,
			request_method varchar(10) NOT NULL,
			request_uri text NOT NULL,
			payload_sample text NOT NULL,
			user_agent text NOT NULL,
			action_taken varchar(20) NOT NULL DEFAULT 'blocked',
			PRIMARY KEY  (id),
			KEY incident_id (incident_id),
			KEY ip_address (ip_address),
			KEY cve_reference (cve_reference),
			KEY timestamp (timestamp)
		) {$charset_collate};";

		dbDelta( $sql );

		// Migrate records from legacy table if present
		$legacy_table = self::get_legacy_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy_table ) ) === $legacy_table ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$existing_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
			if ( 0 === $existing_count ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->query( "INSERT INTO {$table_name} SELECT * FROM {$legacy_table}" );
			}
		}
	}

	/**
	 * Record a security attack event.
	 *
	 * @param array $entry Event data.
	 * @return bool
	 */
	public static function log( $entry ) {
		global $wpdb;

		$incident_id    = isset( $entry['incident_id'] ) ? substr( self::safe_clean( $entry['incident_id'] ), 0, 16 ) : '';
		$ip_address     = isset( $entry['ip_address'] ) ? substr( self::safe_clean( $entry['ip_address'] ), 0, 45 ) : '';
		$attack_type    = isset( $entry['attack_type'] ) ? substr( self::safe_clean( $entry['attack_type'] ), 0, 128 ) : '';
		$cve_reference  = isset( $entry['cve_reference'] ) ? substr( self::safe_clean( $entry['cve_reference'] ), 0, 32 ) : '';
		$rule_triggered = isset( $entry['rule_triggered'] ) ? substr( self::safe_clean( $entry['rule_triggered'] ), 0, 128 ) : '';
		$request_method = isset( $entry['request_method'] ) ? substr( self::safe_clean( $entry['request_method'] ), 0, 10 ) : 'GET';
		$request_uri    = isset( $entry['request_uri'] ) ? self::safe_clean( $entry['request_uri'] ) : '';
		$payload_sample = isset( $entry['payload_sample'] ) ? self::safe_clean( $entry['payload_sample'] ) : '';
		$user_agent     = isset( $entry['user_agent'] ) ? self::safe_clean( $entry['user_agent'] ) : '';
		$action_taken   = isset( $entry['action_taken'] ) ? substr( self::safe_clean( $entry['action_taken'] ), 0, 20 ) : 'blocked';
		$now            = function_exists( 'current_time' ) ? current_time( 'mysql', true ) : gmdate( 'Y-m-d H:i:s' );

		// If WPDB is ready, insert directly into database
		if ( isset( $wpdb ) && $wpdb instanceof wpdb && ! empty( $wpdb->prefix ) ) {
			$table_name = self::get_table_name();
			$inserted = $wpdb->insert(
				$table_name,
				array(
					'incident_id'    => $incident_id,
					'timestamp'      => $now,
					'ip_address'     => $ip_address,
					'attack_type'    => $attack_type,
					'cve_reference'  => $cve_reference,
					'rule_triggered' => $rule_triggered,
					'request_method' => $request_method,
					'request_uri'    => $request_uri,
					'payload_sample' => $payload_sample,
					'user_agent'     => $user_agent,
					'action_taken'   => $action_taken,
				),
				array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
			);

			if ( $inserted ) {
				// Periodically prune logs (1 in 100 chance using wp_rand)
				$rand_check = function_exists( 'wp_rand' ) ? wp_rand( 1, 100 ) : 50;
				if ( 50 === $rand_check ) {
					self::prune_old_logs();
				}
				return true;
			}
		}

		return false;
	}

	/**
	 * Retrieve paginated and filtered attack logs.
	 *
	 * @param array $args Filter and pagination parameters.
	 * @return array [logs, total, total_pages, page]
	 */
	public static function get_logs( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'page'     => 1,
			'per_page' => 20,
			'search'   => '',
			'cve'      => '',
			'action'   => '',
			'orderby'  => 'id',
			'order'    => 'DESC',
		);
		$r = wp_parse_args( $args, $defaults );

		$table = self::get_table_name();

		// Verify table exists; if not, check legacy table
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			$legacy = self::get_legacy_table_name();
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy ) ) === $legacy ) {
				$table = $legacy;
			} else {
				return array(
					'logs'        => array(),
					'total'       => 0,
					'total_pages' => 0,
					'page'        => 1,
				);
			}
		}

		$page     = max( 1, (int) $r['page'] );
		$per_page = max( 1, (int) $r['per_page'] );
		$offset   = ( $page - 1 ) * $per_page;
		$order    = ( 'ASC' === strtoupper( $r['order'] ) ) ? 'ASC' : 'DESC';

		$where_clauses = array();
		$params        = array();

		if ( ! empty( $r['search'] ) ) {
			$like            = '%' . $wpdb->esc_like( $r['search'] ) . '%';
			$where_clauses[] = '(ip_address LIKE %s OR request_uri LIKE %s OR payload_sample LIKE %s OR incident_id LIKE %s)';
			$params[]        = $like;
			$params[]        = $like;
			$params[]        = $like;
			$params[]        = $like;
		}

		if ( ! empty( $r['cve'] ) ) {
			$where_clauses[] = 'cve_reference = %s';
			$params[]        = $r['cve'];
		}

		if ( ! empty( $r['action'] ) ) {
			$where_clauses[] = 'action_taken = %s';
			$params[]        = $r['action'];
		}

		if ( empty( $where_clauses ) ) {
			// Fast path without search filters
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

			if ( 'ASC' === $order ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$logs = $wpdb->get_results(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						"SELECT * FROM {$table} ORDER BY id ASC LIMIT %d OFFSET %d",
						$per_page,
						$offset
					),
					ARRAY_A
				);
			} else {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$logs = $wpdb->get_results(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						"SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d",
						$per_page,
						$offset
					),
					ARRAY_A
				);
			}
		} else {
			$where_sql = implode( ' AND ', $where_clauses );

			// Count query with placeholders
			$count_query = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$total = (int) $wpdb->get_var( $wpdb->prepare( $count_query, $params ) );

			// Data query with placeholders
			$data_query   = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id {$order} LIMIT %d OFFSET %d";
			$query_params = array_merge( $params, array( $per_page, $offset ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$logs = $wpdb->get_results( $wpdb->prepare( $data_query, $query_params ), ARRAY_A );
		}

		return array(
			'logs'        => is_array( $logs ) ? $logs : array(),
			'total'       => $total,
			'total_pages' => ceil( $total / $per_page ),
			'page'        => $page,
		);
	}

	/**
	 * Get 24-hour block statistics.
	 *
	 * @return array
	 */
	public static function get_stats_24h() {
		global $wpdb;
		$table = self::get_table_name();

		// Verify table exists; if not, check legacy table
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			$legacy = self::get_legacy_table_name();
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy ) ) === $legacy ) {
				$table = $legacy;
			} else {
				return array(
					'total_24h'      => 0,
					'all_time_total' => 0,
					'by_cve'         => array(),
					'top_ips'        => array(),
				);
			}
		}

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - 86400 );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE timestamp >= %s",
				$cutoff
			)
		);

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$by_cve = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT cve_reference, COUNT(*) as count FROM {$table} WHERE timestamp >= %s GROUP BY cve_reference ORDER BY count DESC",
				$cutoff
			),
			ARRAY_A
		);

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$top_ips = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT ip_address, COUNT(*) as count FROM {$table} WHERE timestamp >= %s GROUP BY ip_address ORDER BY count DESC LIMIT 5",
				$cutoff
			),
			ARRAY_A
		);

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$all_time_total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		return array(
			'total_24h'      => $total,
			'all_time_total' => $all_time_total,
			'by_cve'         => is_array( $by_cve ) ? $by_cve : array(),
			'top_ips'        => is_array( $top_ips ) ? $top_ips : array(),
		);
	}

	/**
	 * Prune old logs (older than 30 days or keep only latest 10,000 entries).
	 */
	public static function prune_old_logs() {
		global $wpdb;
		$table = self::get_table_name();

		// Delete entries older than 30 days
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( 30 * 86400 ) );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE timestamp < %s", $cutoff ) );

		// Cap table at 10,000 rows
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		if ( $total > 10000 ) {
			$excess = $total - 10000;
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} ORDER BY id ASC LIMIT %d", $excess ) );
		}
	}

	/**
	 * Truncate entire logs table.
	 */
	public static function clear_logs() {
		global $wpdb;
		$table = self::get_table_name();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		$legacy = self::get_legacy_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy ) ) === $legacy ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "TRUNCATE TABLE {$legacy}" );
		}
	}

	/**
	 * Escape a single cell for standard CSV output.
	 *
	 * @param mixed $value Cell value.
	 * @return string
	 */
	public static function format_csv_cell( $value ) {
		return '"' . str_replace( '"', '""', (string) $value ) . '"';
	}

	/**
	 * Export logs to CSV output with nonce and capability check.
	 */
	public static function export_csv() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized user action.', 'waffers-the-layer-that-protects-you' ), 403 );
		}

		// Verify nonce for either waffers or legacy action
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'waffers_export_csv' ) && ! wp_verify_nonce( $nonce, 'php_armor_export_csv' ) ) {
			wp_die( esc_html__( 'Security verification failed. Please try again from the dashboard.', 'waffers-the-layer-that-protects-you' ), 403 );
		}

		global $wpdb;
		$table = self::get_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			$legacy = self::get_legacy_table_name();
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy ) ) === $legacy ) {
				$table = $legacy;
			}
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 5000", ARRAY_A );

		$filename = 'waffers-attack-logs-' . gmdate( 'Y-m-d-His' ) . '.csv';

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=' . $filename );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		// Header row
		$header_cells = array( 'ID', 'Incident ID', 'Timestamp (UTC)', 'IP Address', 'Attack Type', 'CVE Reference', 'Rule Triggered', 'Method', 'Request URI', 'Payload Sample', 'User Agent', 'Action' );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo implode( ',', array_map( array( __CLASS__, 'format_csv_cell' ), $header_cells ) ) . "\r\n";

		if ( ! empty( $rows ) ) {
			foreach ( $rows as $row ) {
				$row_cells = array(
					$row['id'],
					$row['incident_id'],
					$row['timestamp'],
					$row['ip_address'],
					$row['attack_type'],
					$row['cve_reference'],
					$row['rule_triggered'],
					$row['request_method'],
					$row['request_uri'],
					$row['payload_sample'],
					$row['user_agent'],
					$row['action_taken'],
				);
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo implode( ',', array_map( array( __CLASS__, 'format_csv_cell' ), $row_cells ) ) . "\r\n";
			}
		}

		exit;
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
		if ( function_exists( 'wp_strip_all_tags' ) ) {
			return wp_strip_all_tags( $str );
		}
		return preg_replace( '@<[\/\!]*?[^<>]*?>@si', '', $str );
	}
}

endif;

// Backwards-compatibility alias
if ( ! class_exists( 'PHP_Armor_Logger' ) ) {
	class_alias( 'Waffers_Logger', 'PHP_Armor_Logger' );
}
