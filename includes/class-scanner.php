<?php
/**
 * Inventory, version matching, and quota-aware scanning.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Checks active plugins and the active theme against cached or live WPScan data.
 */
class WP_Patch_Alert_Scanner {

	/**
	 * Run one scan, persisting the queue when the daily quota runs out.
	 *
	 * @return array<string, mixed>|WP_Error
	 */
	public function scan() {
		if ( get_transient( 'wp_patch_alert_scanning' ) ) {
			return new WP_Error(
				'wp_patch_alert_locked',
				__( 'A scan is already running.', 'wp-patch-alert' )
			);
		}

		set_transient( 'wp_patch_alert_scanning', 1, 15 * MINUTE_IN_SECONDS );

		try {
			return $this->run_scan();
		} finally {
			delete_transient( 'wp_patch_alert_scanning' );
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private function run_scan() {
		$results  = wp_patch_alert_get_results();
		$settings = wp_patch_alert_get_settings();

		$provider = ( isset( $settings['provider'] ) && 'wordfence' === $settings['provider'] ) ? 'wordfence' : 'wpscan';

		if ( '' === $settings['token'] ) {
			$results['error']        = ( 'wordfence' === $provider )
				? __( 'Add a Wordfence API key before scanning.', 'wp-patch-alert' )
				: __( 'Add a WPScan API token before scanning.', 'wp-patch-alert' );
			$results['last_scan']    = time();
			$results['email_status'] = 'suppressed';
			$results['email_error']  = '';
			$results['provider']     = $provider;
			update_option( WP_PATCH_ALERT_OPTION_RESULTS, $results, false );
			return $results;
		}

		$previous_provider = ( isset( $results['provider'] ) && 'wordfence' === $results['provider'] ) ? 'wordfence' : 'wpscan';
		if ( $previous_provider !== $provider ) {
			$results['checked']  = array();
			$results['notified'] = array();
			$results['findings'] = array();
			update_option( WP_PATCH_ALERT_OPTION_QUEUE, array(), false );
		}

		if ( 'wordfence' === $provider ) {
			return $this->run_wordfence_scan( $results, $settings );
		}

		$inventory = $this->get_inventory();
		$checked   = isset( $results['checked'] ) && is_array( $results['checked'] ) ? $results['checked'] : array();
		$notified  = isset( $results['notified'] ) && is_array( $results['notified'] ) ? $results['notified'] : array();
		$queue     = get_option( WP_PATCH_ALERT_OPTION_QUEUE, array() );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}

		$inventory_keys = array();
		foreach ( $inventory as $item ) {
			$inventory_keys[ $this->component_key( $item ) ] = $item['version'];
		}

		foreach ( array_keys( $checked ) as $key ) {
			$checked_version = ( is_array( $checked[ $key ] ) && isset( $checked[ $key ]['version'] ) ) ? $checked[ $key ]['version'] : null;
			if ( ! isset( $inventory_keys[ $key ] ) || $checked_version !== $inventory_keys[ $key ] ) {
				unset( $checked[ $key ] );
			}
		}

		$queue = array_values(
			array_filter(
				$queue,
				function ( $item ) use ( $inventory_keys ) {
					if ( ! is_array( $item ) || ! isset( $item['type'], $item['slug'], $item['version'] ) ) {
						return false;
					}
					$key = $this->component_key( $item );
					return isset( $inventory_keys[ $key ] ) && $inventory_keys[ $key ] === $item['version'];
				}
			)
		);

		$queued_keys = array();
		foreach ( $queue as $item ) {
			$queued_keys[ $this->component_key( $item ) ] = true;
		}

		$client          = new WP_Patch_Alert_API_Client( $settings['token'] );
		$completed_keys  = array();
		$allow_email     = true;
		$error           = '';

		foreach ( $inventory as $item ) {
			$key          = $this->component_key( $item );
			$cached_vulns = $client->get_cached_vulnerabilities( $item['type'], $item['slug'], $item['version'] );
			if ( null !== $cached_vulns ) {
				$checked[ $key ]  = $this->checked_record( $item, $cached_vulns );
				$completed_keys[] = $key;
				$queue            = $this->remove_from_queue( $queue, $key );
				unset( $queued_keys[ $key ] );
				continue;
			}

			if ( ! isset( $queued_keys[ $key ] ) ) {
				$queue[]             = $item;
				$queued_keys[ $key ] = true;
			}
		}

		$status = $client->get_status();
		$this->store_status( $settings, $status );

		if ( empty( $status['ok'] ) ) {
			$allow_email = false;
			$error       = '' !== $status['error'] ? $status['error'] : __( 'The WPScan API status request failed.', 'wp-patch-alert' );
		} else {
			// Leave at least two requests so a later scan can still read account status.
			$budget = max( 0, (int) $status['requests_remaining'] - 2 );
			while ( $budget > 0 && ! empty( $queue ) ) {
				$item = array_shift( $queue );
				$key  = $this->component_key( $item );
				unset( $queued_keys[ $key ] );

				$lookup = $client->get_vulnerabilities( $item['type'], $item['slug'], $item['version'] );
				if ( ! empty( $lookup['requested'] ) ) {
					--$budget;
				}

				if ( empty( $lookup['ok'] ) ) {
					if ( empty( $lookup['stop'] ) ) {
						$checked[ $key ]  = $this->checked_record( $item, array() );
						$completed_keys[] = $key;
						continue;
					}

					array_unshift( $queue, $item );
					$allow_email = false;
					$error       = '' !== $lookup['error'] ? $lookup['error'] : __( 'The WPScan API request failed.', 'wp-patch-alert' );
					break;
				}

				$checked[ $key ]  = $this->checked_record( $item, $lookup['vulnerabilities'] );
				$completed_keys[] = $key;
			}
		}

		update_option( WP_PATCH_ALERT_OPTION_QUEUE, array_values( $queue ), false );

		$pending = array();
		foreach ( $queue as $item ) {
			$key = $this->component_key( $item );
			if ( isset( $checked[ $key ] ) && $checked[ $key ]['version'] === $item['version'] ) {
				continue;
			}
			$pending[] = array(
				'type'    => $item['type'],
				'name'    => $item['name'],
				'slug'    => $item['slug'],
				'version' => $item['version'],
			);
		}

		$results['checked']      = $checked;
		$results['notified']     = $notified;
		$results['pending']      = $pending;
		$results['findings']     = $this->flatten_findings( $checked, $notified );
		$results['last_scan']    = time();
		$results['error']        = $error;
		$results['email_status'] = $allow_email ? '' : 'suppressed';
		$results['email_error']  = '';
		$results['provider']     = 'wpscan';
		$results['copyrights']   = array();
		$results['feed_notice']  = '';

		if ( $allow_email ) {
			$notifier = new WP_Patch_Alert_Notifier();
			$results  = $notifier->maybe_notify( $results, $completed_keys, $inventory_keys );
		}

		update_option( WP_PATCH_ALERT_OPTION_RESULTS, $results, false );

		return $results;
	}

	/**
	 * Match the inventory against one Wordfence feed download.
	 *
	 * @param array<string, mixed> $results Saved results, already cleared when the provider changed.
	 * @param array<string, mixed> $settings Plugin settings.
	 * @return array<string, mixed>
	 */
	private function run_wordfence_scan( $results, $settings ) {
		$inventory      = $this->get_inventory();
		$inventory_keys = array();
		foreach ( $inventory as $item ) {
			$inventory_keys[ $this->component_key( $item ) ] = $item['version'];
		}

		$client = new WP_Patch_Alert_Wordfence_Client( $settings['token'] );
		$match  = $client->match( $inventory );

		$results['provider']    = 'wordfence';
		$results['pending']     = array();
		$results['feed_notice'] = '';
		$results['last_scan']   = time();
		$results['email_error'] = '';
		update_option( WP_PATCH_ALERT_OPTION_QUEUE, array(), false );

		if ( empty( $match['ok'] ) ) {
			$results['error']        = $match['error'];
			$results['email_status'] = 'suppressed';
			update_option( WP_PATCH_ALERT_OPTION_RESULTS, $results, false );
			return $results;
		}

		$checked        = $match['checked'];
		$notified       = isset( $results['notified'] ) && is_array( $results['notified'] ) ? $results['notified'] : array();
		$completed_keys = array_keys( $checked );

		$results['checked']            = $checked;
		$results['notified']           = $notified;
		$results['findings']           = $this->flatten_findings( $checked, $notified );
		$results['copyrights']         = $match['copyrights'];
		$results['feed_downloaded_at'] = $match['downloaded_at'];
		$results['error']              = '';
		$results['email_status']       = '';
		if ( ! empty( $match['stale'] ) ) {
			$results['feed_notice'] = __( 'The Wordfence feed could not be refreshed. This scan used the saved copy.', 'wp-patch-alert' );
		}

		$notifier = new WP_Patch_Alert_Notifier();
		$results  = $notifier->maybe_notify( $results, $completed_keys, $inventory_keys );
		update_option( WP_PATCH_ALERT_OPTION_RESULTS, $results, false );

		return $results;
	}

	/**
	 * Active plugins, the active theme, and its parent theme.
	 * Inactive plugins are included only when that setting is enabled.
	 *
	 * @return array<int, array{type: string, slug: string, version: string, name: string}>
	 */
	public function get_inventory() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$settings       = wp_patch_alert_get_settings();
		$scan_inactive  = ! empty( $settings['scan_inactive'] );
		$items          = array();

		foreach ( get_plugins() as $plugin_file => $plugin ) {
			if ( ! $scan_inactive && ! is_plugin_active( $plugin_file ) ) {
				continue;
			}
			$directory = dirname( $plugin_file );
			$slug      = ( '.' === $directory ) ? basename( $plugin_file, '.php' ) : $directory;
			$items[]   = array(
				'type'    => 'plugin',
				'slug'    => $slug,
				'version' => isset( $plugin['Version'] ) ? (string) $plugin['Version'] : '',
				'name'    => isset( $plugin['Name'] ) ? (string) $plugin['Name'] : $slug,
			);
		}

		$theme = wp_get_theme();
		if ( $theme->exists() ) {
			$items[] = $this->theme_item( $theme );
			$parent  = $theme->parent();
			if ( $parent && $parent->exists() && $parent->get_stylesheet() !== $theme->get_stylesheet() ) {
				$items[] = $this->theme_item( $parent );
			}
		}

		return $items;
	}

	/**
	 * Whether a WPScan vulnerability record affects an installed version.
	 *
	 * Affected when the installed version is at or after introduced_in (if set)
	 * and fixed_in is empty or newer than the installed version.
	 *
	 * @param string               $installed_version Installed version.
	 * @param array<string, mixed> $vulnerability     API vulnerability object.
	 * @return bool
	 */
	public static function vulnerability_affects( $installed_version, $vulnerability ) {
		$introduced = isset( $vulnerability['introduced_in'] ) ? trim( (string) $vulnerability['introduced_in'] ) : '';
		$fixed      = isset( $vulnerability['fixed_in'] ) ? trim( (string) $vulnerability['fixed_in'] ) : '';

		if ( '' !== $introduced && version_compare( $installed_version, $introduced, '<' ) ) {
			return false;
		}

		if ( '' === $fixed ) {
			return true;
		}

		return version_compare( $installed_version, $fixed, '<' );
	}

	/**
	 * @param WP_Theme $theme Theme object.
	 * @return array{type: string, slug: string, version: string, name: string}
	 */
	private function theme_item( $theme ) {
		return array(
			'type'    => 'theme',
			'slug'    => (string) $theme->get_stylesheet(),
			'version' => (string) $theme->get( 'Version' ),
			'name'    => (string) $theme->get( 'Name' ),
		);
	}

	/**
	 * @param array{type: string, slug: string, version: string, name: string} $item Inventory item.
	 * @return string
	 */
	private function component_key( $item ) {
		return $item['type'] . ':' . $item['slug'];
	}

	/**
	 * @param array{type: string, slug: string, version: string, name: string} $item Inventory item.
	 * @param array<int, mixed>                                                 $vulnerabilities Raw API vulnerabilities.
	 * @return array{type: string, slug: string, version: string, name: string, findings: array<int, array<string, mixed>>}
	 */
	private function checked_record( $item, $vulnerabilities ) {
		$findings = array();
		foreach ( $vulnerabilities as $vulnerability ) {
			if ( ! is_array( $vulnerability ) || ! self::vulnerability_affects( $item['version'], $vulnerability ) ) {
				continue;
			}
			$findings[] = $this->format_finding( $item, $vulnerability );
		}

		return array(
			'type'     => $item['type'],
			'slug'     => $item['slug'],
			'version'  => $item['version'],
			'name'     => $item['name'],
			'findings' => $findings,
		);
	}

	/**
	 * @param array{type: string, slug: string, version: string, name: string} $item Inventory item.
	 * @param array<string, mixed>                                             $vulnerability API vulnerability.
	 * @return array<string, mixed>
	 */
	private function format_finding( $item, $vulnerability ) {
		$cve = '';
		if ( isset( $vulnerability['references']['cve'] ) && is_array( $vulnerability['references']['cve'] ) ) {
			$cve = implode( ', ', array_map( 'strval', $vulnerability['references']['cve'] ) );
		}

		$severity = '';
		if ( isset( $vulnerability['cvss'] ) && is_array( $vulnerability['cvss'] ) ) {
			if ( ! empty( $vulnerability['cvss']['severity'] ) ) {
				$severity = (string) $vulnerability['cvss']['severity'];
			} elseif ( isset( $vulnerability['cvss']['score'] ) && '' !== (string) $vulnerability['cvss']['score'] ) {
				$severity = (string) $vulnerability['cvss']['score'];
			}
		}

		$vuln_id = isset( $vulnerability['id'] ) ? (string) $vulnerability['id'] : md5( ( $vulnerability['title'] ?? '' ) . '|' . ( $vulnerability['fixed_in'] ?? '' ) );

		return array(
			'type'     => $item['type'],
			'name'     => $item['name'],
			'slug'     => $item['slug'],
			'version'  => $item['version'],
			'vuln_id'  => $vuln_id,
			'title'    => isset( $vulnerability['title'] ) ? (string) $vulnerability['title'] : '',
			'severity' => $severity,
			'cve'      => $cve,
			'fixed_in' => isset( $vulnerability['fixed_in'] ) ? trim( (string) $vulnerability['fixed_in'] ) : '',
			'notified' => false,
		);
	}

	/**
	 * @param array<string, array<string, mixed>> $checked Checked components.
	 * @param array<string, array<int, string>>   $notified Notified vulnerability IDs by component.
	 * @return array<int, array<string, mixed>>
	 */
	private function flatten_findings( $checked, $notified ) {
		$findings = array();
		foreach ( $checked as $key => $record ) {
			$sent = isset( $notified[ $key ] ) && is_array( $notified[ $key ] ) ? array_map( 'strval', $notified[ $key ] ) : array();
			if ( empty( $record['findings'] ) || ! is_array( $record['findings'] ) ) {
				continue;
			}
			foreach ( $record['findings'] as $finding ) {
				$finding['notified'] = in_array( (string) $finding['vuln_id'], $sent, true );
				$findings[]          = $finding;
			}
		}

		usort(
			$findings,
			function ( $a, $b ) {
				return array( $a['type'], $a['name'], $a['title'] ) <=> array( $b['type'], $b['name'], $b['title'] );
			}
		);

		return $findings;
	}

	/**
	 * @param array<int, array<string, string>> $queue Queue items.
	 * @param string                             $key Component key.
	 * @return array<int, array<string, string>>
	 */
	private function remove_from_queue( $queue, $key ) {
		return array_values(
			array_filter(
				$queue,
				function ( $item ) use ( $key ) {
					return $this->component_key( $item ) !== $key;
				}
			)
		);
	}

	/**
	 * @param array<string, mixed>                                           $settings Saved settings.
	 * @param array{ok: bool, plan: string, requests_remaining: int|null, error: string} $status Status payload.
	 */
	private function store_status( $settings, $status ) {
		$settings['status_checked_at'] = time();
		if ( ! empty( $status['ok'] ) ) {
			$settings['plan']               = $status['plan'];
			$settings['requests_remaining'] = $status['requests_remaining'];
			$settings['status_error']       = '';
		} else {
			$settings['status_error'] = $status['error'];
		}
		update_option( WP_PATCH_ALERT_OPTION_SETTINGS, $settings );
	}
}
