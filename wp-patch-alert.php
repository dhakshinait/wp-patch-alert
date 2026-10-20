<?php
/**
 * Plugin Name: WP Patch Alert
 * Description: Checks active plugins and the active theme against the WPScan or Wordfence vulnerability database, lists affected components, and emails selected administrators.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Tested up to: 7.1
 * Requires PHP: 7.4
 * Author: Dhakshina
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-patch-alert
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WP_PATCH_ALERT_VERSION', '1.0.0' );
define( 'WP_PATCH_ALERT_FILE', __FILE__ );
define( 'WP_PATCH_ALERT_DIR', plugin_dir_path( __FILE__ ) );

define( 'WP_PATCH_ALERT_OPTION_SETTINGS', 'wp_patch_alert_settings' );
define( 'WP_PATCH_ALERT_OPTION_RESULTS', 'wp_patch_alert_results' );
define( 'WP_PATCH_ALERT_OPTION_QUEUE', 'wp_patch_alert_queue' );
define( 'WP_PATCH_ALERT_OPTION_CACHE_KEYS', 'wp_patch_alert_cache_keys' );
define( 'WP_PATCH_ALERT_CRON_HOOK', 'wp_patch_alert_daily_scan' );

require_once WP_PATCH_ALERT_DIR . 'includes/class-api-client.php';
require_once WP_PATCH_ALERT_DIR . 'includes/class-wordfence-client.php';
require_once WP_PATCH_ALERT_DIR . 'includes/class-notifier.php';
require_once WP_PATCH_ALERT_DIR . 'includes/class-scanner.php';
require_once WP_PATCH_ALERT_DIR . 'includes/class-admin.php';

/**
 * Default settings stored in wp_options.
 *
 * @return array<string, mixed>
 */
function wp_patch_alert_default_settings() {
	return array(
		'token'                => '',
		'provider'             => 'wpscan',
		'recipients'           => array(),
		'scan_inactive'        => false,
		'plan'                 => '',
		'requests_remaining'   => null,
		'status_checked_at'    => 0,
		'status_error'         => '',
	);
}

/**
 * Saved settings merged with defaults.
 *
 * @return array<string, mixed>
 */
function wp_patch_alert_get_settings() {
	$saved = get_option( WP_PATCH_ALERT_OPTION_SETTINGS, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}

	return wp_parse_args( $saved, wp_patch_alert_default_settings() );
}

/**
 * Default scan results.
 *
 * @return array<string, mixed>
 */
function wp_patch_alert_default_results() {
	return array(
		'last_scan'    => 0,
		'findings'     => array(),
		'pending'      => array(),
		'checked'      => array(),
		'notified'     => array(),
		'email_status' => '',
		'email_error'  => '',
		'error'        => '',
		'provider'     => '',
		'copyrights'   => array(),
		'feed_notice'  => '',
		'feed_downloaded_at' => 0,
	);
}

/**
 * Saved scan results merged with defaults.
 *
 * @return array<string, mixed>
 */
function wp_patch_alert_get_results() {
	$saved = get_option( WP_PATCH_ALERT_OPTION_RESULTS, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}

	return wp_parse_args( $saved, wp_patch_alert_default_results() );
}

/**
 * Schedule the daily scan.
 */
function wp_patch_alert_activate() {
	if ( ! wp_next_scheduled( WP_PATCH_ALERT_CRON_HOOK ) ) {
		wp_schedule_event( time(), 'daily', WP_PATCH_ALERT_CRON_HOOK );
	}
}

/**
 * Remove the scheduled scan.
 */
function wp_patch_alert_deactivate() {
	wp_clear_scheduled_hook( WP_PATCH_ALERT_CRON_HOOK );
}

/**
 * Run one scan. Used by cron and the manual scan action.
 *
 * @return array<string, mixed>|WP_Error
 */
function wp_patch_alert_run_scan() {
	$scanner = new WP_Patch_Alert_Scanner();
	return $scanner->scan();
}

/**
 * Load translations and admin screens.
 */
function wp_patch_alert_init() {
	load_plugin_textdomain( 'wp-patch-alert', false, dirname( plugin_basename( WP_PATCH_ALERT_FILE ) ) . '/languages' );

	if ( is_admin() ) {
		$admin = new WP_Patch_Alert_Admin();
		$admin->hooks();
	}
}

register_activation_hook( WP_PATCH_ALERT_FILE, 'wp_patch_alert_activate' );
register_deactivation_hook( WP_PATCH_ALERT_FILE, 'wp_patch_alert_deactivate' );
add_action( WP_PATCH_ALERT_CRON_HOOK, 'wp_patch_alert_run_scan' );
add_action( 'plugins_loaded', 'wp_patch_alert_init' );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once WP_PATCH_ALERT_DIR . 'includes/class-cli.php';
	WP_CLI::add_command( 'patch-alert', 'WP_Patch_Alert_CLI' );
}
