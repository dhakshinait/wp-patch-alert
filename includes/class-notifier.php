<?php
/**
 * Email selected administrators when affecting vulnerabilities change.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Diffs vulnerability IDs and sends plain-text mail to chosen administrators.
 */
class WP_Patch_Alert_Notifier {

	/**
	 * Email when the affecting vulnerability set changed for components checked in this scan.
	 *
	 * Pending components are left out of the comparison. Recipient IDs that no longer
	 * belong to an administrator are dropped. An empty recipient list skips mail and
	 * leaves the notified set unchanged so a later selection can still send.
	 *
	 * @param array<string, mixed>    $results Scan results, including checked and notified maps.
	 * @param array<int, string>      $completed_keys Component keys finished in this scan.
	 * @param array<string, string>   $inventory_keys Current component key to version map.
	 * @return array<string, mixed>
	 */
	public function maybe_notify( $results, $completed_keys, $inventory_keys ) {
		$notified = isset( $results['notified'] ) && is_array( $results['notified'] ) ? $results['notified'] : array();
		$checked  = isset( $results['checked'] ) && is_array( $results['checked'] ) ? $results['checked'] : array();

		$current_ids = array();
		foreach ( $checked as $key => $record ) {
			$current_ids[ $key ] = $this->ids_from_record( $record );
		}

		$keys = array_unique( array_merge( array_values( $completed_keys ), array_keys( $notified ) ) );
		$changed = false;

		foreach ( $keys as $key ) {
			if ( ! in_array( $key, $completed_keys, true ) && isset( $inventory_keys[ $key ] ) ) {
				continue;
			}

			$before = isset( $notified[ $key ] ) && is_array( $notified[ $key ] ) ? $this->normalize_ids( $notified[ $key ] ) : array();
			$after  = isset( $current_ids[ $key ] ) ? $current_ids[ $key ] : array();
			if ( $before !== $after ) {
				$changed = true;
				break;
			}
		}

		if ( ! $changed ) {
			$results['email_status'] = 'unchanged';
			$results['email_error']  = '';
			$results['findings']     = $this->apply_notified_flags( $results['findings'], $notified );
			return $results;
		}

		$recipients = $this->recipient_emails();
		if ( empty( $recipients ) ) {
			$results['email_status'] = 'skipped_no_recipients';
			$results['email_error']  = '';
			$results['notified']     = $notified;
			$results['findings']     = $this->apply_notified_flags( $results['findings'], $notified );
			return $results;
		}

		$findings = isset( $results['findings'] ) && is_array( $results['findings'] ) ? $results['findings'] : array();
		$sent     = wp_mail( $recipients, $this->subject( $findings ), $this->body( $findings ) );

		if ( ! $sent ) {
			$results['email_status'] = 'failed';
			$results['email_error']  = __( 'The vulnerability email could not be sent.', 'wp-patch-alert' );
			$results['notified']     = $notified;
			$results['findings']     = $this->apply_notified_flags( $results['findings'], $notified );
			return $results;
		}

		foreach ( $keys as $key ) {
			if ( ! in_array( $key, $completed_keys, true ) && isset( $inventory_keys[ $key ] ) ) {
				continue;
			}
			if ( empty( $current_ids[ $key ] ) ) {
				unset( $notified[ $key ] );
				continue;
			}
			$notified[ $key ] = $current_ids[ $key ];
		}

		$results['notified']     = $notified;
		$results['email_status'] = 'sent';
		$results['email_error']  = '';
		$results['findings']     = $this->apply_notified_flags( $findings, $notified );

		return $results;
	}

	/**
	 * Email addresses for selected users who are still administrators.
	 *
	 * @return array<int, string>
	 */
	private function recipient_emails() {
		$settings = wp_patch_alert_get_settings();
		$ids      = isset( $settings['recipients'] ) && is_array( $settings['recipients'] ) ? $settings['recipients'] : array();
		$emails   = array();

		foreach ( $ids as $user_id ) {
			$user = get_userdata( (int) $user_id );
			if ( ! $user instanceof WP_User ) {
				continue;
			}
			if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
				continue;
			}
			if ( ! is_email( $user->user_email ) ) {
				continue;
			}
			$emails[] = $user->user_email;
		}

		return array_values( array_unique( $emails ) );
	}

	/**
	 * @param array<string, mixed> $record Checked component record.
	 * @return array<int, string>
	 */
	private function ids_from_record( $record ) {
		if ( empty( $record['findings'] ) || ! is_array( $record['findings'] ) ) {
			return array();
		}

		$ids = array();
		foreach ( $record['findings'] as $finding ) {
			if ( isset( $finding['vuln_id'] ) ) {
				$ids[] = (string) $finding['vuln_id'];
			}
		}

		return $this->normalize_ids( $ids );
	}

	/**
	 * @param array<int, mixed> $ids Vulnerability IDs.
	 * @return array<int, string>
	 */
	private function normalize_ids( $ids ) {
		$ids = array_map( 'strval', $ids );
		$ids = array_values( array_unique( $ids ) );
		sort( $ids, SORT_STRING );
		return $ids;
	}

	/**
	 * @param array<int, array<string, mixed>> $findings Findings list.
	 * @param array<string, array<int, string>> $notified Notified IDs by component key.
	 * @return array<int, array<string, mixed>>
	 */
	private function apply_notified_flags( $findings, $notified ) {
		if ( ! is_array( $findings ) ) {
			return array();
		}

		foreach ( $findings as $index => $finding ) {
			$key                     = $finding['type'] . ':' . $finding['slug'];
			$sent                    = isset( $notified[ $key ] ) && is_array( $notified[ $key ] ) ? array_map( 'strval', $notified[ $key ] ) : array();
			$findings[ $index ]['notified'] = in_array( (string) $finding['vuln_id'], $sent, true );
		}

		return $findings;
	}

	/**
	 * @param array<int, array<string, mixed>> $findings Current findings.
	 * @return string
	 */
	private function subject( $findings ) {
		$name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( empty( $findings ) ) {
			return sprintf(
				/* translators: %s: site name. */
				__( '[%s] Plugin and theme vulnerabilities cleared', 'wp-patch-alert' ),
				$name
			);
		}

		return sprintf(
			/* translators: %s: site name. */
			__( '[%s] Vulnerabilities found in plugins or themes', 'wp-patch-alert' ),
			$name
		);
	}

	/**
	 * @param array<int, array<string, mixed>> $findings Current findings.
	 * @return string
	 */
	private function body( $findings ) {
		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: site name. */
			__( 'Site: %s', 'wp-patch-alert' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);
		$lines[] = sprintf(
			/* translators: %s: site URL. */
			__( 'URL: %s', 'wp-patch-alert' ),
			home_url( '/' )
		);
		$lines[] = '';

		if ( empty( $findings ) ) {
			$lines[] = __( 'No checked plugins or the active theme are currently affected by a known vulnerability.', 'wp-patch-alert' );
			return implode( "\n", $lines );
		}

		$lines[] = __( 'The following plugins and themes are affected:', 'wp-patch-alert' );
		$lines[] = '';

		foreach ( $findings as $finding ) {
			$type = ( 'theme' === $finding['type'] ) ? __( 'Theme', 'wp-patch-alert' ) : __( 'Plugin', 'wp-patch-alert' );
			$lines[] = sprintf(
				'%s: %s %s',
				$type,
				wp_strip_all_tags( (string) $finding['name'] ),
				(string) $finding['version']
			);
			$lines[] = sprintf(
				/* translators: %s: vulnerability title. */
				__( 'Vulnerability: %s', 'wp-patch-alert' ),
				wp_strip_all_tags( (string) $finding['title'] )
			);
			$lines[] = sprintf(
				/* translators: %s: severity label or score. */
				__( 'Severity: %s', 'wp-patch-alert' ),
				'' !== (string) $finding['severity'] ? (string) $finding['severity'] : __( 'Unknown', 'wp-patch-alert' )
			);
			$lines[] = sprintf(
				/* translators: %s: CVE identifiers. */
				__( 'CVE: %s', 'wp-patch-alert' ),
				'' !== (string) $finding['cve'] ? (string) $finding['cve'] : __( 'None', 'wp-patch-alert' )
			);
			$lines[] = sprintf(
				/* translators: %s: fixed version. */
				__( 'Fixed in: %s', 'wp-patch-alert' ),
				'' !== (string) $finding['fixed_in'] ? (string) $finding['fixed_in'] : __( 'No fix published', 'wp-patch-alert' )
			);
			$lines[] = '';
		}

		return implode( "\n", $lines );
	}
}
