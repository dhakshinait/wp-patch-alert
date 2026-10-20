<?php
/**
 * Remove plugin data on uninstall.
 *
 * Option names match the constants in wp-patch-alert.php.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$cache_keys = get_option( 'wp_patch_alert_cache_keys', array() );
if ( is_array( $cache_keys ) ) {
	foreach ( $cache_keys as $cache_key ) {
		if ( is_string( $cache_key ) && '' !== $cache_key ) {
			delete_transient( $cache_key );
		}
	}
}

delete_option( 'wp_patch_alert_settings' );
delete_option( 'wp_patch_alert_results' );
delete_option( 'wp_patch_alert_queue' );
delete_option( 'wp_patch_alert_cache_keys' );
delete_transient( 'wp_patch_alert_scanning' );
wp_clear_scheduled_hook( 'wp_patch_alert_daily_scan' );

/**
 * Delete the cached Wordfence feed directory.
 *
 * @param string $dir Directory path.
 */
function wp_patch_alert_uninstall_delete_dir( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}

	$items = scandir( $dir );
	if ( ! is_array( $items ) ) {
		return;
	}

	foreach ( $items as $item ) {
		if ( '.' === $item || '..' === $item ) {
			continue;
		}
		$path = $dir . '/' . $item;
		if ( is_dir( $path ) ) {
			wp_patch_alert_uninstall_delete_dir( $path );
		} else {
			unlink( $path );
		}
	}

	rmdir( $dir );
}

$uploads = wp_upload_dir();
if ( empty( $uploads['error'] ) ) {
	wp_patch_alert_uninstall_delete_dir( trailingslashit( $uploads['basedir'] ) . 'wp-patch-alert' );
}
