<?php
/**
 * Dashboard & Security Audit View
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
				<h1><?php esc_html_e( 'Waffers', 'waffers-the-layer-that-protects-you' ); ?></h1>
				<p class="subtitle"><?php esc_html_e( 'The layer that protects you — Real-time proactive mitigation against critical PHP vulnerabilities', 'waffers-the-layer-that-protects-you' ); ?></p>
			</div>
		</div>
		<div class="php-armor-header-actions">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-simulator' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-dashboard"></span> <?php esc_html_e( 'Test Exploit Simulator', 'waffers-the-layer-that-protects-you' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-rules' ) ); ?>" class="button button-primary">
				<span class="dashicons dashicons-admin-settings"></span> <?php esc_html_e( 'Configure Shields', 'waffers-the-layer-that-protects-you' ); ?>
			</a>
		</div>
	</div>

	<!-- Threat Score & Quick Metrics -->
	<div class="php-armor-grid-3">
		<!-- Threat Meter Card -->
		<div class="php-armor-card php-armor-score-card">
			<h3><?php esc_html_e( 'PHP Security Posture', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<div class="score-display <?php echo esc_attr( $scan_results['badge_class'] ); ?>">
				<div class="score-circle">
					<span class="score-number"><?php echo esc_html( $scan_results['score'] ); ?></span>
					<span class="score-max">/100</span>
				</div>
				<div class="score-meta">
					<span class="score-label"><?php echo esc_html( $scan_results['threat_level'] ); ?></span>
					<p class="score-desc"><?php esc_html_e( 'Based on PHP version, SAPI, INI settings, and WAF shield status.', 'waffers-the-layer-that-protects-you' ); ?></p>
				</div>
			</div>
		</div>

		<!-- 24h Threat Activity -->
		<div class="php-armor-card">
			<h3><?php esc_html_e( '24h Threat Interceptions', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<div class="stat-number"><?php echo esc_html( number_format_i18n( $stats['total_24h'] ) ); ?></div>
			<p class="stat-sub"><?php esc_html_e( 'Malicious requests blocked in the last 24 hours', 'waffers-the-layer-that-protects-you' ); ?></p>
			<div class="stat-footer">
				<span><?php esc_html_e( 'All-Time Blocked:', 'waffers-the-layer-that-protects-you' ); ?> <strong><?php echo esc_html( number_format_i18n( $stats['all_time_total'] ) ); ?></strong></span>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-logs' ) ); ?>"><?php esc_html_e( 'View Logs &rarr;', 'waffers-the-layer-that-protects-you' ); ?></a>
			</div>
		</div>

		<!-- Server Architecture Info -->
		<div class="php-armor-card">
			<h3><?php esc_html_e( 'Server Environment', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<div class="info-list">
				<div class="info-item">
					<span class="info-label"><?php esc_html_e( 'PHP Engine:', 'waffers-the-layer-that-protects-you' ); ?></span>
					<span class="info-val code-font"><?php echo esc_html( 'PHP ' . $scan_results['php_version'] ); ?></span>
				</div>
				<div class="info-item">
					<span class="info-label"><?php esc_html_e( 'Server SAPI:', 'waffers-the-layer-that-protects-you' ); ?></span>
					<span class="info-val code-font"><?php echo esc_html( $scan_results['sapi'] ); ?></span>
				</div>
				<div class="info-item">
					<span class="info-label"><?php esc_html_e( 'Operating System:', 'waffers-the-layer-that-protects-you' ); ?></span>
					<span class="info-val"><?php echo esc_html( $scan_results['os'] ); ?></span>
				</div>
				<div class="info-item">
					<span class="info-label"><?php esc_html_e( 'WAF Protection:', 'waffers-the-layer-that-protects-you' ); ?></span>
					<span class="badge-status <?php echo ( ! empty( $options['enabled'] ) ) ? 'badge-active' : 'badge-inactive'; ?>">
						<?php echo ( ! empty( $options['enabled'] ) ) ? 'ACTIVE (' . esc_html( strtoupper( $options['block_mode'] ) ) . ')' : 'DISABLED'; ?>
					</span>
				</div>
			</div>
		</div>
	</div>

	<!-- CVE Audit Checklist -->
	<div class="php-armor-card" style="margin-top: 24px;">
		<div class="card-header-flex">
			<div>
				<h2><?php esc_html_e( 'PHP Vulnerability & Hardening Audit', 'waffers-the-layer-that-protects-you' ); ?></h2>
				<p class="section-desc"><?php esc_html_e( 'Automated diagnostic of high-impact PHP core CVEs affecting WordPress environments', 'waffers-the-layer-that-protects-you' ); ?></p>
			</div>
			<button type="button" class="button" onclick="location.reload();">
				<span class="dashicons dashicons-update"></span> <?php esc_html_e( 'Re-Scan Server', 'waffers-the-layer-that-protects-you' ); ?>
			</button>
		</div>

		<div class="audit-table-wrap">
			<table class="wp-list-table widefat striped audit-table">
				<thead>
					<tr>
						<th style="width: 250px;"><?php esc_html_e( 'Target Vulnerability / Component', 'waffers-the-layer-that-protects-you' ); ?></th>
						<th style="width: 140px;"><?php esc_html_e( 'Status', 'waffers-the-layer-that-protects-you' ); ?></th>
						<th style="width: 130px;"><?php esc_html_e( 'Threat Impact', 'waffers-the-layer-that-protects-you' ); ?></th>
						<th><?php esc_html_e( 'Audit Findings & Diagnostics', 'waffers-the-layer-that-protects-you' ); ?></th>
						<th style="width: 180px;"><?php esc_html_e( 'Action / Mitigation', 'waffers-the-layer-that-protects-you' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $scan_results['items'] as $waffers_key => $waffers_item ) : ?>
						<?php
						$waffers_row_class   = ( 0 === $waffers_item['penalty'] ) ? 'row-pass' : ( $waffers_item['penalty'] > 15 ? 'row-fail' : 'row-warn' );
						$waffers_badge_class = ( 0 === $waffers_item['penalty'] ) ? 'status-pill-good' : ( $waffers_item['penalty'] > 15 ? 'status-pill-danger' : 'status-pill-warn' );
						?>
						<tr class="<?php echo esc_attr( $waffers_row_class ); ?>">
							<td>
								<strong><?php echo esc_html( $waffers_item['title'] ); ?></strong>
							</td>
							<td>
								<span class="status-pill <?php echo esc_attr( $waffers_badge_class ); ?>">
									<?php echo esc_html( $waffers_item['status'] ); ?>
								</span>
							</td>
							<td>
								<span class="severity-tag"><?php echo esc_html( $waffers_item['severity'] ); ?></span>
							</td>
							<td>
								<p class="audit-desc"><?php echo esc_html( $waffers_item['description'] ); ?></p>
								<div class="audit-remedy">
									<strong><?php esc_html_e( 'Recommendation:', 'waffers-the-layer-that-protects-you' ); ?></strong> <?php echo esc_html( $waffers_item['recommendation'] ); ?>
								</div>
							</td>
							<td>
								<?php if ( in_array( $waffers_key, array( 'upload_progress', 'early_waf', 'info_leaks', 'allow_url_include' ), true ) ) : ?>
									<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-hardening' ) ); ?>" class="button button-small button-primary">
										<?php esc_html_e( 'Hardening Tools', 'waffers-the-layer-that-protects-you' ); ?>
									</a>
								<?php else : ?>
									<a href="<?php echo esc_url( admin_url( 'admin.php?page=waffers-rules' ) ); ?>" class="button button-small">
										<?php esc_html_e( 'Shield Options', 'waffers-the-layer-that-protects-you' ); ?>
									</a>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>

	<!-- Recent Attack Activity Log Preview -->
	<?php if ( ! empty( $stats['by_cve'] ) ) : ?>
		<div class="php-armor-grid-2" style="margin-top: 24px;">
			<div class="php-armor-card">
				<h3><?php esc_html_e( 'Blocks by Vulnerability Type (Last 24h)', 'waffers-the-layer-that-protects-you' ); ?></h3>
				<ul class="threat-breakdown">
					<?php foreach ( $stats['by_cve'] as $waffers_stat ) : ?>
						<li>
							<span class="threat-name"><?php echo esc_html( $waffers_stat['cve_reference'] ); ?></span>
							<span class="threat-count badge-pill"><?php echo esc_html( $waffers_stat['count'] ); ?> attacks</span>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>

			<div class="php-armor-card">
				<h3><?php esc_html_e( 'Top Attacker IPs (Last 24h)', 'waffers-the-layer-that-protects-you' ); ?></h3>
				<ul class="threat-breakdown">
					<?php foreach ( $stats['top_ips'] as $waffers_ip_stat ) : ?>
						<li>
							<span class="threat-name code-font"><?php echo esc_html( $waffers_ip_stat['ip_address'] ); ?></span>
							<span class="threat-count badge-pill"><?php echo esc_html( $waffers_ip_stat['count'] ); ?> hits</span>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
		</div>
	<?php endif; ?>
</div>
