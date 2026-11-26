<?php
/**
 * Server-Level Hardening View (.user.ini / .htaccess / Nginx)
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
				<h1><?php esc_html_e( 'Server-Level Hardening & Early Defense', 'waffers-the-layer-that-protects-you' ); ?></h1>
				<p class="subtitle"><?php esc_html_e( 'Waffers — The layer that protects you', 'waffers-the-layer-that-protects-you' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Notice Banner -->
	<div class="hardening-intro-banner">
		<span class="dashicons dashicons-info banner-icon"></span>
		<div>
			<strong><?php esc_html_e( 'Why Server-Level Hardening is Crucial for PHP CVEs:', 'waffers-the-layer-that-protects-you' ); ?></strong>
			<p>
				<?php esc_html_e( 'Vulnerabilities like PHP2Shell (CVE-2026-109618/9) and CVE-2024-4577 target the PHP binary or its request parser before standard WordPress plugins load. Configuring .user.ini and .htaccess stops malicious payloads at the web server and PHP engine boundary.', 'waffers-the-layer-that-protects-you' ); ?>
			</p>
		</div>
	</div>

	<div class="php-armor-grid-2" style="margin-top: 24px;">
		<!-- Card 1: .user.ini Hardening -->
		<div class="php-armor-card hardening-card">
			<div class="card-top-status">
				<span class="status-pill <?php echo $is_user_ini_active ? 'status-pill-good' : 'status-pill-warn'; ?>">
					<?php echo $is_user_ini_active ? esc_html__( 'ACTIVE & HARDENED', 'waffers-the-layer-that-protects-you' ) : esc_html__( 'NOT INSTALLED', 'waffers-the-layer-that-protects-you' ); ?>
				</span>
				<span class="tech-label"><?php esc_html_e( 'PHP-FPM / CGI Directives', 'waffers-the-layer-that-protects-you' ); ?></span>
			</div>
			<h3><?php esc_html_e( '1. PHP INI Directives (.user.ini)', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Deploys directives into the WordPress root directory .user.ini. This turns off session.upload_progress.enabled, disables allow_url_include, and hides PHP version headers without editing the global php.ini.', 'waffers-the-layer-that-protects-you' ); ?>
			</p>
			<div class="code-preview">
; Waffers Hardening
session.upload_progress.enabled = 0
allow_url_include = 0
expose_php = 0
auto_prepend_file = "early-waf.php"
			</div>
			<div class="card-action-bar">
				<?php if ( $is_user_ini_active ) : ?>
					<button type="button" class="button button-secondary hardening-action-btn" data-target="user_ini" data-action="remove">
						<?php esc_html_e( 'Remove Directives', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
					<button type="button" class="button button-primary hardening-action-btn" data-target="user_ini" data-action="apply">
						<?php esc_html_e( 'Re-Apply / Update', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
				<?php else : ?>
					<button type="button" class="button button-primary hardening-action-btn" data-target="user_ini" data-action="apply">
						<span class="dashicons dashicons-yes"></span> <?php esc_html_e( '1-Click Install .user.ini Hardening', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
				<?php endif; ?>
			</div>
		</div>

		<!-- Card 2: Apache .htaccess Hardening -->
		<div class="php-armor-card hardening-card">
			<div class="card-top-status">
				<span class="status-pill <?php echo $is_htaccess_active ? 'status-pill-good' : 'status-pill-warn'; ?>">
					<?php echo $is_htaccess_active ? esc_html__( 'ACTIVE & HARDENED', 'waffers-the-layer-that-protects-you' ) : esc_html__( 'NOT INSTALLED', 'waffers-the-layer-that-protects-you' ); ?>
				</span>
				<span class="tech-label"><?php esc_html_e( 'Apache / LiteSpeed', 'waffers-the-layer-that-protects-you' ); ?></span>
			</div>
			<h3><?php esc_html_e( '2. Apache Web Server Rules (.htaccess)', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Injects Apache mod_rewrite rules directly into your root .htaccess file to drop requests carrying the soft-hyphen character (%ad) and command line arguments (CVE-2024-4577) before PHP is invoked.', 'waffers-the-layer-that-protects-you' ); ?>
			</p>
			<div class="code-preview">
# BEGIN Waffers Security Rules
RewriteEngine On
RewriteCond %{QUERY_STRING} ^(%ad|%80|%a0|-d|-s|-b|-c|-w|-z) [NC,OR]
RewriteCond %{QUERY_STRING} (%ad|-d\s+auto_prepend_file) [NC]
RewriteRule .* - [F,L]
# END Waffers Security Rules
			</div>
			<div class="card-action-bar">
				<?php if ( $is_htaccess_active ) : ?>
					<button type="button" class="button button-secondary hardening-action-btn" data-target="htaccess" data-action="remove">
						<?php esc_html_e( 'Remove .htaccess Rules', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
					<button type="button" class="button button-primary hardening-action-btn" data-target="htaccess" data-action="apply">
						<?php esc_html_e( 'Re-Apply / Update', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
				<?php else : ?>
					<button type="button" class="button button-primary hardening-action-btn" data-target="htaccess" data-action="apply">
						<span class="dashicons dashicons-yes"></span> <?php esc_html_e( '1-Click Install .htaccess Rules', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
				<?php endif; ?>
			</div>
		</div>
	</div>

	<div class="php-armor-grid-2" style="margin-top: 24px;">
		<!-- Card 3: Must-Use Plugin Loader -->
		<div class="php-armor-card hardening-card">
			<div class="card-top-status">
				<span class="status-pill <?php echo $is_mu_active ? 'status-pill-good' : 'status-pill-warn'; ?>">
					<?php echo $is_mu_active ? esc_html__( 'MU-PLUGIN ACTIVE', 'waffers-the-layer-that-protects-you' ) : esc_html__( 'NOT INSTALLED', 'waffers-the-layer-that-protects-you' ); ?>
				</span>
				<span class="tech-label"><?php esc_html_e( 'WordPress Bootstrap', 'waffers-the-layer-that-protects-you' ); ?></span>
			</div>
			<h3><?php esc_html_e( '3. Must-Use (MU-Plugin) Early Loader', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Creates wp-content/mu-plugins/waffers-early-loader.php. Must-Use plugins execute automatically before standard plugins and themes, ensuring your firewall evaluates requests ahead of any vulnerable third-party code.', 'waffers-the-layer-that-protects-you' ); ?>
			</p>
			<div class="card-action-bar" style="margin-top: 40px;">
				<?php if ( $is_mu_active ) : ?>
					<button type="button" class="button button-secondary hardening-action-btn" data-target="mu_loader" data-action="remove">
						<?php esc_html_e( 'Remove MU-Plugin Loader', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
				<?php else : ?>
					<button type="button" class="button button-primary hardening-action-btn" data-target="mu_loader" data-action="apply">
						<span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Install MU-Plugin Early Loader', 'waffers-the-layer-that-protects-you' ); ?>
					</button>
				<?php endif; ?>
			</div>
		</div>

		<!-- Card 4: Nginx Configuration -->
		<div class="php-armor-card hardening-card">
			<div class="card-top-status">
				<span class="status-pill status-pill-info"><?php esc_html_e( 'MANUAL DEPLOYMENT', 'waffers-the-layer-that-protects-you' ); ?></span>
				<span class="tech-label"><?php esc_html_e( 'Nginx Engine', 'waffers-the-layer-that-protects-you' ); ?></span>
			</div>
			<h3><?php esc_html_e( '4. Nginx Server Configuration', 'waffers-the-layer-that-protects-you' ); ?></h3>
			<p class="card-desc">
				<?php esc_html_e( 'Because Nginx does not allow runtime directory file modifications (like .htaccess), add these directives inside your Nginx server block to drop CVE-2024-4577 and CVE-2024-2961 at the web server tier.', 'waffers-the-layer-that-protects-you' ); ?>
			</p>
			<div class="code-preview" style="max-height: 140px; overflow-y: auto;">
				<pre class="code-font" id="nginx-config-text"><?php echo esc_html( $nginx_snippet ); ?></pre>
			</div>
			<div class="card-action-bar">
				<button type="button" class="button button-secondary" id="copy-nginx-btn">
					<span class="dashicons dashicons-clipboard"></span> <?php esc_html_e( 'Copy Nginx Directives', 'waffers-the-layer-that-protects-you' ); ?>
				</button>
			</div>
		</div>
	</div>
</div>
