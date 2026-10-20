<?php
/**
 * WP-CLI command for a single plugin scan.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs only this plugin's scan. Other scheduled site events are not touched.
 */
class WP_Patch_Alert_CLI {

	/**
	 * Scan plugins and the active theme with the saved settings.
	 *
	 * Uses the same job as the daily cron hook `wp_patch_alert_daily_scan`.
	 *
	 * ## EXAMPLES
	 *
	 *     wp patch-alert scan
	 *     wp patch-alert scan --path=/path/to/wordpress
	 *
	 * @param array<int, string>    $args Positional arguments.
	 * @param array<string, string> $assoc_args Associative arguments.
	 * @return void
	 */
	public function scan( $args, $assoc_args ) {
		unset( $args, $assoc_args );

		$result = wp_patch_alert_run_scan();
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}

		if ( ! empty( $result['error'] ) ) {
			WP_CLI::error( (string) $result['error'] );
		}

		if ( ! empty( $result['feed_notice'] ) ) {
			WP_CLI::warning( (string) $result['feed_notice'] );
		}

		$findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? count( $result['findings'] ) : 0;
		$pending  = isset( $result['pending'] ) && is_array( $result['pending'] ) ? count( $result['pending'] ) : 0;

		WP_CLI::success(
			sprintf(
				'Scan finished. %1$d vulnerabilities. %2$d components still waiting.',
				$findings,
				$pending
			)
		);
	}
}
