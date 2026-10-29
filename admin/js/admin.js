/**
 * Waffers Admin JavaScript
 *
 * @package Waffers
 */

/* global jQuery, waffersData, phpArmorData */
jQuery(document).ready(function($) {
	'use strict';

	var cfg = (typeof waffersData !== 'undefined') ? waffersData : (typeof phpArmorData !== 'undefined' ? phpArmorData : {});

	// 1. Save Settings Form
	$('#waffers-settings-form, #php-armor-settings-form').on('submit', function(e) {
		e.preventDefault();

		var $form = $(this);
		var $btn = $('#save-rules-btn');
		var $spinner = $('#save-rules-spinner');
		var $msg = $('#save-rules-msg');

		$btn.prop('disabled', true);
		$spinner.addClass('is-active');
		$msg.text('').removeClass('status-good status-danger');

		var formData = $form.serializeArray();
		formData.push({ name: 'action', value: 'waffers_save_settings' });
		formData.push({ name: 'nonce', value: cfg.nonce });

		$.post(cfg.ajaxUrl, formData, function(response) {
			$btn.prop('disabled', false);
			$spinner.removeClass('is-active');

			if (response.success) {
				$msg.text(response.data.message).css('color', '#059669');
				setTimeout(function() {
					$msg.fadeOut(function() {
						$(this).text('').show();
					});
				}, 4000);
			} else {
				$msg.text(response.data.message || 'Error saving settings.').css('color', '#dc2626');
			}
		}).fail(function() {
			$btn.prop('disabled', false);
			$spinner.removeClass('is-active');
			$msg.text('Network communication error.').css('color', '#dc2626');
		});
	});

	// 2. Server Hardening Action Buttons
	$('.hardening-action-btn').on('click', function(e) {
		e.preventDefault();

		var $btn = $(this);
		var target = $btn.data('target');
		var action = $btn.data('action');
		var origText = $btn.html();

		$btn.prop('disabled', true).text('Working...');

		$.post(cfg.ajaxUrl, {
			action: 'waffers_apply_hardening',
			nonce: cfg.nonce,
			target: target,
			hardening_action: action
		}, function(response) {
			if (response.success) {
				alert(response.data.message);
				location.reload();
			} else {
				alert('Error: ' + (response.data.message || 'Action failed'));
				$btn.prop('disabled', false).html(origText);
			}
		}).fail(function() {
			alert('Network request failed.');
			$btn.prop('disabled', false).html(origText);
		});
	});

	// 3. Copy Nginx Directives
	$('#copy-nginx-btn').on('click', function(e) {
		e.preventDefault();
		var text = $('#nginx-config-text').text();
		var $btn = $(this);

		if (navigator.clipboard) {
			navigator.clipboard.writeText(text).then(function() {
				var orig = $btn.html();
				$btn.html('<span class="dashicons dashicons-yes"></span> Copied to Clipboard!');
				setTimeout(function() { $btn.html(orig); }, 3000);
			});
		} else {
			// Fallback
			var $temp = $('<textarea>');
			$('body').append($temp);
			$temp.val(text).select();
			document.execCommand('copy');
			$temp.remove();
			alert('Nginx configuration copied to clipboard.');
		}
	});

	// 4. Clear Attack Logs
	$('#clear-logs-btn').on('click', function(e) {
		e.preventDefault();
		if (!confirm('Are you sure you want to delete all recorded attack logs? This action cannot be undone.')) {
			return;
		}

		var $btn = $(this);
		$btn.prop('disabled', true);

		$.post(cfg.ajaxUrl, {
			action: 'waffers_clear_logs',
			nonce: cfg.nonce
		}, function(response) {
			if (response.success) {
				location.reload();
			} else {
				alert(response.data.message || 'Failed to clear logs.');
				$btn.prop('disabled', false);
			}
		}).fail(function() {
			alert('Network error.');
			$btn.prop('disabled', false);
		});
	});

	// 5. Payload Modal Viewer
	$('.view-payload-btn').on('click', function(e) {
		e.preventDefault();
		var $btn = $(this);
		var incident = $btn.data('incident');
		var payload = $btn.data('payload');
		var agent = $btn.data('agent');

		$('#modal-incident-id').text(incident);
		$('#modal-payload-text').text(payload || '[Empty or unavailable]');
		$('#modal-user-agent').text(agent || '[No User-Agent header]');
		$('#payload-modal').fadeIn(150);
	});

	$('.modal-close, .modal-close-btn').on('click', function() {
		$('#payload-modal').fadeOut(150);
	});

	$(window).on('click', function(e) {
		if ($(e.target).is('#payload-modal')) {
			$('#payload-modal').fadeOut(150);
		}
	});

	// 6. Exploit Simulator Probes
	$('.run-sim-btn').on('click', function(e) {
		e.preventDefault();
		var $btn = $(this);
		var type = $btn.data('type');
		var $card = $btn.closest('.sim-card');
		var $spinner = $card.find('.sim-spinner');
		var $result = $card.find('.sim-result-box');

		$btn.prop('disabled', true);
		$spinner.addClass('is-active');
		$result.hide().empty().removeClass('sim-result-success sim-result-fail');

		$.post(cfg.ajaxUrl, {
			action: 'waffers_run_simulation',
			nonce: cfg.nonce,
			test_type: type
		}, function(response) {
			$btn.prop('disabled', false);
			$spinner.removeClass('is-active');

			if (response.success && response.data.intercepted) {
				$result.addClass('sim-result-success');
				$result.html(
					'<strong>PROBE INTERCEPTED & NEUTRALIZED</strong><br>' +
					'<span><strong>Detection Rule:</strong> ' + response.data.rule + '</span><br>' +
					'<span><strong>Source:</strong> ' + response.data.source + '</span><br>' +
					'<span><strong>Matched Payload:</strong> <code class="code-font">' + $('<div>').text(response.data.payload).html() + '</code></span><br>' +
					'<span style="font-size:11px; color:#047857; margin-top:4px; display:inline-block;">Firewall rule is active and functioning correctly.</span>'
				).fadeIn();
			} else {
				$result.addClass('sim-result-fail');
				$result.html(
					'<strong>NOT INTERCEPTED</strong><br>' +
					(response.data.message || 'Payload bypassed inspection. Check that this shield is turned ON in Firewall Rules.')
				).fadeIn();
			}
		}).fail(function() {
			$btn.prop('disabled', false);
			$spinner.removeClass('is-active');
			$result.addClass('sim-result-fail').html('Network error occurred while testing.').fadeIn();
		});
	});
});
