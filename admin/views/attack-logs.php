<?php
/**
 * Attack Logs View
 *
 * @package Waffers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap php-armor-wrap">
	<div class="php-armor-header">
		<div class="php-armor-header-title">
			<span class="dashicons dashicons-shield-alt shield-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Live Attack & Threat Logs', 'waffers' ); ?></h1>
				<p class="subtitle"><?php esc_html_e( 'Waffers — The layer that protects you', 'waffers' ); ?></p>
			</div>
		</div>
		<div class="php-armor-header-actions">
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=waffers_export_csv' ), 'waffers_export_csv' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-download"></span> <?php esc_html_e( 'Export to CSV', 'waffers' ); ?>
			</a>
			<button type="button" class="button button-link-delete" id="clear-logs-btn">
				<span class="dashicons dashicons-trash"></span> <?php esc_html_e( 'Clear All Logs', 'waffers' ); ?>
			</button>
		</div>
	</div>

	<!-- Filter & Search Bar -->
	<div class="php-armor-card" style="margin-bottom: 20px;">
		<form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>" class="logs-filter-form">
			<input type="hidden" name="page" value="waffers-logs">
			<div class="filter-row">
				<div class="filter-item">
					<label for="search-input"><?php esc_html_e( 'Search Logs:', 'waffers' ); ?></label>
					<input type="text" id="search-input" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'IP, URI, Incident ID, payload...', 'waffers' ); ?>">
				</div>
				<div class="filter-item">
					<label for="cve-select"><?php esc_html_e( 'Filter by CVE:', 'waffers' ); ?></label>
					<select id="cve-select" name="cve">
						<option value=""><?php esc_html_e( 'All Vulnerabilities', 'waffers' ); ?></option>
						<option value="CVE-2026-109619" <?php selected( $cve, 'CVE-2026-109619' ); ?>><?php esc_html_e( 'PHP2Shell (CVE-2026-109619)', 'waffers' ); ?></option>
						<option value="CVE-2024-4577" <?php selected( $cve, 'CVE-2024-4577' ); ?>><?php esc_html_e( 'PHP-CGI Injection (CVE-2024-4577)', 'waffers' ); ?></option>
						<option value="CVE-2024-2961" <?php selected( $cve, 'CVE-2024-2961' ); ?>><?php esc_html_e( 'iconv Filter Chain (CVE-2024-2961)', 'waffers' ); ?></option>
						<option value="CVE-2024-8927" <?php selected( $cve, 'CVE-2024-8927' ); ?>><?php esc_html_e( 'Multipart DOS (CVE-2024-8927)', 'waffers' ); ?></option>
						<option value="CWE-502" <?php selected( $cve, 'CWE-502' ); ?>><?php esc_html_e( 'Object Injection (CWE-502)', 'waffers' ); ?></option>
					</select>
				</div>
				<div class="filter-item filter-btn-col">
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Apply Filters', 'waffers' ); ?></button>
					<?php if ( ! empty( $search ) || ! empty( $cve ) ) : ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-logs' ) ); ?>" class="button"><?php esc_html_e( 'Reset', 'waffers' ); ?></a>
					<?php endif; ?>
				</div>
			</div>
		</form>
	</div>

	<!-- Logs Table -->
	<div class="php-armor-card">
		<div class="table-top-meta">
			<span>
				<?php
				/* translators: 1: Number of entries currently displayed, 2: Total number of recorded events */
				printf( esc_html__( 'Showing %1$d of %2$s recorded events', 'waffers' ), count( $log_data['logs'] ), esc_html( number_format_i18n( $log_data['total'] ) ) );
				?>
			</span>
		</div>

		<?php if ( empty( $log_data['logs'] ) ) : ?>
			<div class="empty-state">
				<span class="dashicons dashicons-shield empty-icon"></span>
				<h3><?php esc_html_e( 'No Security Events Recorded', 'waffers' ); ?></h3>
				<p><?php esc_html_e( 'Your site has not intercepted any matching PHP attack payloads yet, or logs were recently cleared.', 'waffers' ); ?></p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-simulator' ) ); ?>" class="button button-secondary">
					<?php esc_html_e( 'Run Exploit Simulator to Test Logs', 'waffers' ); ?>
				</a>
			</div>
		<?php else : ?>
			<div class="log-table-wrap">
				<table class="wp-list-table widefat striped attack-log-table">
					<thead>
						<tr>
							<th style="width: 130px;"><?php esc_html_e( 'Date / Time (UTC)', 'waffers' ); ?></th>
							<th style="width: 90px;"><?php esc_html_e( 'Incident ID', 'waffers' ); ?></th>
							<th style="width: 120px;"><?php esc_html_e( 'Client IP', 'waffers' ); ?></th>
							<th style="width: 140px;"><?php esc_html_e( 'Vulnerability', 'waffers' ); ?></th>
							<th><?php esc_html_e( 'Attack Type / Rule', 'waffers' ); ?></th>
							<th style="width: 80px;"><?php esc_html_e( 'Method', 'waffers' ); ?></th>
							<th><?php esc_html_e( 'Target URI', 'waffers' ); ?></th>
							<th style="width: 90px;"><?php esc_html_e( 'Action', 'waffers' ); ?></th>
							<th style="width: 80px;"><?php esc_html_e( 'Payload', 'waffers' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $log_data['logs'] as $waffers_log ) : ?>
							<tr>
								<td class="code-font"><?php echo esc_html( $waffers_log['timestamp'] ); ?></td>
								<td><span class="incident-badge"><?php echo esc_html( $waffers_log['incident_id'] ); ?></span></td>
								<td class="code-font"><?php echo esc_html( $waffers_log['ip_address'] ); ?></td>
								<td>
									<span class="cve-pill"><?php echo esc_html( $waffers_log['cve_reference'] ); ?></span>
								</td>
								<td>
									<strong><?php echo esc_html( $waffers_log['attack_type'] ); ?></strong>
									<?php if ( ! empty( $waffers_log['rule_triggered'] ) ) : ?>
										<div class="sub-rule-text"><?php echo esc_html( $waffers_log['rule_triggered'] ); ?></div>
									<?php endif; ?>
								</td>
								<td><span class="method-tag"><?php echo esc_html( $waffers_log['request_method'] ); ?></span></td>
								<td class="uri-cell code-font" title="<?php echo esc_attr( $waffers_log['request_uri'] ); ?>">
									<?php echo esc_html( substr( $waffers_log['request_uri'], 0, 45 ) . ( strlen( $waffers_log['request_uri'] ) > 45 ? '...' : '' ) ); ?>
								</td>
								<td>
									<span class="action-tag <?php echo ( 'blocked' === $waffers_log['action_taken'] ) ? 'tag-blocked' : 'tag-simulated'; ?>">
										<?php echo esc_html( strtoupper( $waffers_log['action_taken'] ) ); ?>
									</span>
								</td>
								<td>
									<button type="button" class="button button-small view-payload-btn"
										data-incident="<?php echo esc_attr( $waffers_log['incident_id'] ); ?>"
										data-payload="<?php echo esc_attr( $waffers_log['payload_sample'] ); ?>"
										data-agent="<?php echo esc_attr( $waffers_log['user_agent'] ); ?>">
										<?php esc_html_e( 'View', 'waffers' ); ?>
									</button>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<!-- Pagination -->
			<?php if ( $log_data['total_pages'] > 1 ) : ?>
				<div class="tablenav">
					<div class="tablenav-pages">
						<?php
						echo wp_kses_post(
							paginate_links( array(
								'base'      => add_query_arg( 'paged', '%#%' ),
								'format'    => '',
								'prev_text' => '&laquo;',
								'next_text' => '&raquo;',
								'total'     => $log_data['total_pages'],
								'current'   => $log_data['page'],
							) )
						);
						?>
					</div>
				</div>
			<?php endif; ?>
		<?php endif; ?>
	</div>

	<!-- Payload Details Modal -->
	<div id="payload-modal" class="php-armor-modal" style="display: none;">
		<div class="modal-content">
			<div class="modal-header">
				<h3><?php esc_html_e( 'Attack Payload Details', 'waffers' ); ?> (<span id="modal-incident-id"></span>)</h3>
				<span class="modal-close">&times;</span>
			</div>
			<div class="modal-body">
				<label><strong><?php esc_html_e( 'Captured Payload Sample:', 'waffers' ); ?></strong></label>
				<pre id="modal-payload-text" class="payload-box code-font"></pre>
				<label style="margin-top: 15px; display: block;"><strong><?php esc_html_e( 'User Agent:', 'waffers' ); ?></strong></label>
				<div id="modal-user-agent" class="agent-box code-font"></div>
			</div>
			<div class="modal-footer">
				<button type="button" class="button button-secondary modal-close-btn"><?php esc_html_e( 'Close', 'waffers' ); ?></button>
			</div>
		</div>
	</div>
</div>
