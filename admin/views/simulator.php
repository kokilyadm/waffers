<?php
/**
 * Exploit Simulator & Verification Console View
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
				<h1><?php esc_html_e( 'Exploit Simulation & Verification Console', 'waffers' ); ?></h1>
				<p class="subtitle"><?php esc_html_e( 'Waffers — The layer that protects you', 'waffers' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Info Notice -->
	<div class="hardening-intro-banner">
		<span class="dashicons dashicons-info banner-icon"></span>
		<div>
			<strong><?php esc_html_e( 'Safe Diagnostic Simulator:', 'waffers' ); ?></strong>
			<p>
				<?php esc_html_e( 'These simulated probes execute harmless synthetic payloads in memory against Waffers\' detection regexes and parsers. They do not execute external code or disrupt your live website.', 'waffers' ); ?>
			</p>
		</div>
	</div>

	<div class="php-armor-grid-2" style="margin-top: 24px;">
		<!-- Simulator 1: CVE-2024-4577 -->
		<div class="php-armor-card sim-card">
			<div class="card-top-status">
				<span class="badge-cve">CVSS 9.8</span>
				<span class="tech-label"><?php esc_html_e( 'PHP-CGI Injection', 'waffers' ); ?></span>
			</div>
			<h3><?php esc_html_e( 'CVE-2024-4577: PHP-CGI Argument Injection', 'waffers' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Simulates an exploit attempting to use the Windows Best-Fit soft-hyphen character (%ad) to inject command line switches (-d auto_prepend_file=php://input) into php-cgi.', 'waffers' ); ?>
			</p>
			<div class="sim-payload-box code-font">
				GET /index.php?%ad-d+auto_prepend_file=php://input
			</div>
			<div class="sim-action-row">
				<button type="button" class="button button-primary run-sim-btn" data-type="cve_2024_4577">
					<span class="dashicons dashicons-controls-play"></span> <?php esc_html_e( 'Run Safe Probe', 'waffers' ); ?>
				</button>
				<span class="spinner sim-spinner"></span>
			</div>
			<div class="sim-result-box" style="display: none;"></div>
		</div>

		<!-- Simulator 2: PHP2Shell -->
		<div class="php-armor-card sim-card">
			<div class="card-top-status">
				<span class="badge-cve">CVSS 9.2</span>
				<span class="tech-label"><?php esc_html_e( 'Memory Corruption', 'waffers' ); ?></span>
			</div>
			<h3><?php esc_html_e( 'PHP2Shell (CVE-2026-109618 / CVE-2026-109619)', 'waffers' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Simulates an unauthenticated multipart POST probe attempting to abuse PHP’s session.upload_progress parameter with code fragments and boundary manipulation.', 'waffers' ); ?>
			</p>
			<div class="sim-payload-box code-font">
				POST / HTTP/1.1<br>
				PHP_SESSION_UPLOAD_PROGRESS: &lt;?php phpinfo(); ?&gt;_session_probe
			</div>
			<div class="sim-action-row">
				<button type="button" class="button button-primary run-sim-btn" data-type="php2shell">
					<span class="dashicons dashicons-controls-play"></span> <?php esc_html_e( 'Run Safe Probe', 'waffers' ); ?>
				</button>
				<span class="spinner sim-spinner"></span>
			</div>
			<div class="sim-result-box" style="display: none;"></div>
		</div>

		<!-- Simulator 3: CVE-2024-2961 -->
		<div class="php-armor-card sim-card">
			<div class="card-top-status">
				<span class="badge-cve">CVSS 8.4</span>
				<span class="tech-label"><?php esc_html_e( 'glibc iconv Overflow', 'waffers' ); ?></span>
			</div>
			<h3><?php esc_html_e( 'CVE-2024-2961: iconv Filter Chain', 'waffers' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Simulates a PHP filter chain attack injecting the vulnerable ISO-2022-CN-EXT character set conversion into request parameters to trigger heap buffer overflow.', 'waffers' ); ?>
			</p>
			<div class="sim-payload-box code-font">
				GET /?filter=php://filter/convert.iconv.ISO-2022-CN-EXT.UTF-8/resource=...
			</div>
			<div class="sim-action-row">
				<button type="button" class="button button-primary run-sim-btn" data-type="cve_2024_2961">
					<span class="dashicons dashicons-controls-play"></span> <?php esc_html_e( 'Run Safe Probe', 'waffers' ); ?>
				</button>
				<span class="spinner sim-spinner"></span>
			</div>
			<div class="sim-result-box" style="display: none;"></div>
		</div>

		<!-- Simulator 4: Object Injection -->
		<div class="php-armor-card sim-card">
			<div class="card-top-status">
				<span class="badge-cve">CWE-502</span>
				<span class="tech-label"><?php esc_html_e( 'Deserialization', 'waffers' ); ?></span>
			</div>
			<h3><?php esc_html_e( 'PHP Object Injection (Gadget Chain)', 'waffers' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Simulates an attack string injecting serialized PHP object metadata (O:14:"App\Vulnerable") targeting vulnerable third-party plugins.', 'waffers' ); ?>
			</p>
			<div class="sim-payload-box code-font">
				GET /?payload=O:14:"App\Vulnerable":1:{s:4:"cmd";s:7:"whoami";}
			</div>
			<div class="sim-action-row">
				<button type="button" class="button button-primary run-sim-btn" data-type="object_injection">
					<span class="dashicons dashicons-controls-play"></span> <?php esc_html_e( 'Run Safe Probe', 'waffers' ); ?>
				</button>
				<span class="spinner sim-spinner"></span>
			</div>
			<div class="sim-result-box" style="display: none;"></div>
		</div>
	</div>
</div>
