<?php
/**
 * Settings, vulnerabilities list, and admin notice.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WordPress admin UI for WP Patch Alert.
 */
class WP_Patch_Alert_Admin {

	/**
	 * Register admin hooks.
	 */
	public function hooks() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_notices', array( $this, 'admin_notice' ) );
		add_action( 'admin_post_wp_patch_alert_scan', array( $this, 'handle_scan' ) );
	}

	/**
	 * Add the vulnerabilities screen and the settings screen.
	 */
	public function register_menu() {
		add_menu_page(
			__( 'Vulnerabilities', 'wp-patch-alert' ),
			__( 'Vulnerabilities', 'wp-patch-alert' ),
			'manage_options',
			'wp-patch-alert',
			array( $this, 'render_vulnerabilities' ),
			'dashicons-shield',
			80
		);

		add_options_page(
			__( 'WP Patch Alert', 'wp-patch-alert' ),
			__( 'WP Patch Alert', 'wp-patch-alert' ),
			'manage_options',
			'wp-patch-alert-settings',
			array( $this, 'render_settings' )
		);
	}

	/**
	 * Register the settings option.
	 */
	public function register_settings() {
		register_setting(
			'wp_patch_alert',
			WP_PATCH_ALERT_OPTION_SETTINGS,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
				'default'           => wp_patch_alert_default_settings(),
			)
		);
	}

	/**
	 * Save the token and the selected administrator IDs.
	 *
	 * An empty token field keeps the stored token. Only users with the
	 * administrator role can be stored as recipients.
	 *
	 * @param mixed $input Posted settings.
	 * @return array<string, mixed>
	 */
	public function sanitize_settings( $input ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return wp_patch_alert_get_settings();
		}

		$existing = wp_patch_alert_get_settings();
		$clean    = $existing;
		$clean['provider'] = ( is_array( $input ) && isset( $input['provider'] ) && 'wordfence' === $input['provider'] ) ? 'wordfence' : 'wpscan';

		$posted_token = '';
		if ( is_array( $input ) && isset( $input['token'] ) ) {
			$posted_token = trim( (string) $input['token'] );
		}

		if ( '' !== $posted_token ) {
			if ( preg_match( '/^[A-Za-z0-9._~+\/=-]+$/', $posted_token ) ) {
				$clean['token'] = $posted_token;
			} else {
				$clean['status_error'] = __( 'The API token contains unsupported characters and was not saved.', 'wp-patch-alert' );
			}
		}

		$clean['recipients'] = array();
		$posted_recipients   = ( is_array( $input ) && isset( $input['recipients'] ) && is_array( $input['recipients'] ) ) ? $input['recipients'] : array();
		foreach ( $posted_recipients as $user_id ) {
			$user_id = absint( $user_id );
			$user    = get_userdata( $user_id );
			if ( $user instanceof WP_User && in_array( 'administrator', (array) $user->roles, true ) ) {
				$clean['recipients'][] = $user_id;
			}
		}
		$clean['recipients']    = array_values( array_unique( $clean['recipients'] ) );
		$clean['scan_inactive'] = is_array( $input ) && ! empty( $input['scan_inactive'] );

		if ( '' === $clean['token'] ) {
			$clean['plan']               = '';
			$clean['requests_remaining'] = null;
			$clean['status_checked_at']  = time();
			$clean['status_error']       = ( 'wordfence' === $clean['provider'] )
				? __( 'Add a Wordfence API key before scanning.', 'wp-patch-alert' )
				: __( 'Add a WPScan API token to run scans.', 'wp-patch-alert' );
			return $clean;
		}

		if ( '' !== $posted_token && ! preg_match( '/^[A-Za-z0-9._~+\/=-]+$/', $posted_token ) ) {
			return $clean;
		}

		if ( 'wordfence' === $clean['provider'] ) {
			$clean['plan']               = '';
			$clean['requests_remaining'] = null;
			$clean['status_checked_at']  = 0;
			$clean['status_error']       = '';
			return $clean;
		}

		$client = new WP_Patch_Alert_API_Client( $clean['token'] );
		$status = $client->get_status();
		$clean['status_checked_at'] = time();
		if ( ! empty( $status['ok'] ) ) {
			$clean['plan']               = $status['plan'];
			$clean['requests_remaining'] = $status['requests_remaining'];
			$clean['status_error']       = '';
		} else {
			$clean['status_error'] = $status['error'];
		}

		return $clean;
	}

	/**
	 * Settings screen.
	 */
	public function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings = wp_patch_alert_get_settings();
		$admins   = get_users(
			array(
				'role'    => 'administrator',
				'orderby' => 'display_name',
				'order'   => 'ASC',
			)
		);
		$selected = array_map( 'intval', (array) $settings['recipients'] );
		$provider = ( isset( $settings['provider'] ) && 'wordfence' === $settings['provider'] ) ? 'wordfence' : 'wpscan';
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'WP Patch Alert', 'wp-patch-alert' ); ?></h1>
			<?php $this->render_status_message( $settings ); ?>
			<form action="options.php" method="post">
				<?php settings_fields( 'wp_patch_alert' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php echo esc_html__( 'Vulnerability source', 'wp-patch-alert' ); ?></th>
						<td>
							<fieldset>
								<legend class="screen-reader-text"><?php echo esc_html__( 'Vulnerability source', 'wp-patch-alert' ); ?></legend>
								<label style="display:block;margin-bottom:6px;">
									<input type="radio" name="<?php echo esc_attr( WP_PATCH_ALERT_OPTION_SETTINGS ); ?>[provider]" value="wpscan" <?php checked( 'wpscan', $provider ); ?> />
									<?php echo esc_html__( 'WPScan', 'wp-patch-alert' ); ?>
								</label>
								<label style="display:block;">
									<input type="radio" name="<?php echo esc_attr( WP_PATCH_ALERT_OPTION_SETTINGS ); ?>[provider]" value="wordfence" <?php checked( 'wordfence', $provider ); ?> />
									<?php echo esc_html__( 'Wordfence Intelligence', 'wp-patch-alert' ); ?>
								</label>
							</fieldset>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label id="wp-patch-alert-token-label" for="wp-patch-alert-token">
								<?php echo esc_html( 'wordfence' === $provider ? __( 'Wordfence API key', 'wp-patch-alert' ) : __( 'WPScan API token', 'wp-patch-alert' ) ); ?>
							</label>
						</th>
						<td>
							<input
								type="password"
								class="regular-text"
								id="wp-patch-alert-token"
								name="<?php echo esc_attr( WP_PATCH_ALERT_OPTION_SETTINGS ); ?>[token]"
								value=""
								autocomplete="new-password"
							/>
							<?php if ( '' !== $settings['token'] ) : ?>
								<p class="description"><?php echo esc_html__( 'A token is saved. Leave this blank to keep it.', 'wp-patch-alert' ); ?></p>
							<?php endif; ?>
							<p class="description" id="wp-patch-alert-token-help-wpscan" <?php echo 'wordfence' === $provider ? 'hidden' : ''; ?>>
								<?php
								echo wp_kses(
									sprintf(
										/* translators: %s: WPScan API documentation URL. */
										__( 'Create a token at <a href="%s">wpscan.com</a>. The free plan allows 25 requests per day. Each uncached plugin or theme uses one request.', 'wp-patch-alert' ),
										esc_url( 'https://wpscan.com/api/' )
									),
									array(
										'a' => array(
											'href' => array(),
										),
									)
								);
								?>
							</p>
							<p class="description" id="wp-patch-alert-token-help-wordfence" <?php echo 'wordfence' === $provider ? '' : 'hidden'; ?>>
								<?php
								echo wp_kses(
									sprintf(
										/* translators: %s: Wordfence integrations URL. */
										__( 'Create a key under Integrations at <a href="%s">wordfence.com</a>. The feed downloads on the next scan and is reused for 12 hours. Saving this screen does not download it.', 'wp-patch-alert' ),
										esc_url( 'https://www.wordfence.com/account/' )
									),
									array(
										'a' => array(
											'href' => array(),
										),
									)
								);
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Inactive plugins', 'wp-patch-alert' ); ?></th>
						<td>
							<label for="wp-patch-alert-scan-inactive">
								<input
									type="checkbox"
									id="wp-patch-alert-scan-inactive"
									name="<?php echo esc_attr( WP_PATCH_ALERT_OPTION_SETTINGS ); ?>[scan_inactive]"
									value="1"
									<?php checked( ! empty( $settings['scan_inactive'] ) ); ?>
								/>
								<?php echo esc_html__( 'Also scan inactive plugins', 'wp-patch-alert' ); ?>
							</label>
							<p class="description"><?php echo esc_html__( 'Leave this unchecked to check active plugins only.', 'wp-patch-alert' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Notify these administrators', 'wp-patch-alert' ); ?></th>
						<td>
							<?php if ( empty( $admins ) ) : ?>
								<p><?php echo esc_html__( 'No administrator accounts were found.', 'wp-patch-alert' ); ?></p>
							<?php else : ?>
								<fieldset>
									<legend class="screen-reader-text"><?php echo esc_html__( 'Notify these administrators', 'wp-patch-alert' ); ?></legend>
									<?php foreach ( $admins as $admin ) : ?>
										<label style="display:block;margin-bottom:6px;">
											<input
												type="checkbox"
												name="<?php echo esc_attr( WP_PATCH_ALERT_OPTION_SETTINGS ); ?>[recipients][]"
												value="<?php echo esc_attr( (string) $admin->ID ); ?>"
												<?php checked( in_array( (int) $admin->ID, $selected, true ) ); ?>
											/>
											<?php
											echo esc_html(
												sprintf(
													'%s (%s)',
													$admin->display_name,
													$admin->user_email
												)
											);
											?>
										</label>
									<?php endforeach; ?>
									<p class="description"><?php echo esc_html__( 'Only administrator accounts are listed. Other roles are never emailed.', 'wp-patch-alert' ); ?></p>
								</fieldset>
							<?php endif; ?>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save settings', 'wp-patch-alert' ) ); ?>
			</form>
			<hr />
			<h2><?php echo esc_html__( 'Scan now', 'wp-patch-alert' ); ?></h2>
			<p id="wp-patch-alert-scan-note" <?php echo 'wordfence' === $provider ? 'hidden' : ''; ?>><?php echo esc_html__( 'Check active plugins and the active theme. Inactive plugins are included only when that option is checked. A large site may take more than one day on the free API plan.', 'wp-patch-alert' ); ?></p>
			<p id="wp-patch-alert-scan-note-wordfence" <?php echo 'wordfence' === $provider ? '' : 'hidden'; ?>><?php echo esc_html__( 'Check active plugins and the active theme with the saved Wordfence feed. Inactive plugins are included only when that option is checked. The first scan downloads the feed.', 'wp-patch-alert' ); ?></p>
			<script>
				( function () {
					var radios = document.querySelectorAll( 'input[name="<?php echo esc_js( WP_PATCH_ALERT_OPTION_SETTINGS ); ?>[provider]"]' );
					var label = document.getElementById( 'wp-patch-alert-token-label' );
					var wpscanHelp = document.getElementById( 'wp-patch-alert-token-help-wpscan' );
					var wordfenceHelp = document.getElementById( 'wp-patch-alert-token-help-wordfence' );
					var scanNote = document.getElementById( 'wp-patch-alert-scan-note' );
					var wordfenceNote = document.getElementById( 'wp-patch-alert-scan-note-wordfence' );
					function sync() {
						var provider = 'wpscan';
						radios.forEach( function ( radio ) {
							if ( radio.checked ) {
								provider = radio.value;
							}
						} );
						var wordfence = provider === 'wordfence';
						if ( label ) {
							label.textContent = wordfence ? '<?php echo esc_js( __( 'Wordfence API key', 'wp-patch-alert' ) ); ?>' : '<?php echo esc_js( __( 'WPScan API token', 'wp-patch-alert' ) ); ?>';
						}
						if ( wpscanHelp ) {
							wpscanHelp.hidden = wordfence;
						}
						if ( wordfenceHelp ) {
							wordfenceHelp.hidden = ! wordfence;
						}
						if ( scanNote ) {
							scanNote.hidden = wordfence;
						}
						if ( wordfenceNote ) {
							wordfenceNote.hidden = ! wordfence;
						}
					}
					radios.forEach( function ( radio ) {
						radio.addEventListener( 'change', sync );
					} );
				} )();
			</script>
			<?php $this->render_scan_form( '' === $settings['token'] ); ?>
		</div>
		<?php
	}

	/**
	 * Vulnerabilities list.
	 */
	public function render_vulnerabilities() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$results  = wp_patch_alert_get_results();
		$findings = isset( $results['findings'] ) && is_array( $results['findings'] ) ? $results['findings'] : array();
		$pending  = isset( $results['pending'] ) && is_array( $results['pending'] ) ? $results['pending'] : array();
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Vulnerabilities', 'wp-patch-alert' ); ?></h1>
			<?php $this->render_scan_notices( $results ); ?>

			<?php if ( ! empty( $findings ) ) : ?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th scope="col"><?php echo esc_html__( 'Type', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Name', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Installed version', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Vulnerability', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Severity', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'CVE', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Fixed in', 'wp-patch-alert' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $findings as $finding ) : ?>
							<tr>
								<td><?php echo esc_html( 'theme' === $finding['type'] ? __( 'Theme', 'wp-patch-alert' ) : __( 'Plugin', 'wp-patch-alert' ) ); ?></td>
								<td><?php echo esc_html( (string) $finding['name'] ); ?></td>
								<td><?php echo esc_html( (string) $finding['version'] ); ?></td>
								<td><?php echo esc_html( (string) $finding['title'] ); ?></td>
								<td><?php echo esc_html( '' !== (string) $finding['severity'] ? (string) $finding['severity'] : __( 'Unknown', 'wp-patch-alert' ) ); ?></td>
								<td><?php echo esc_html( '' !== (string) $finding['cve'] ? (string) $finding['cve'] : '—' ); ?></td>
								<td><?php echo esc_html( '' !== (string) $finding['fixed_in'] ? (string) $finding['fixed_in'] : __( 'None', 'wp-patch-alert' ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php $this->render_copyrights( $results ); ?>
			<?php elseif ( ! empty( $results['last_scan'] ) && empty( $results['error'] ) && empty( $pending ) ) : ?>
				<p><?php echo esc_html__( 'No vulnerabilities were found in the last scan.', 'wp-patch-alert' ); ?></p>
			<?php elseif ( empty( $results['last_scan'] ) ) : ?>
				<p><?php echo esc_html__( 'No scan has run yet.', 'wp-patch-alert' ); ?></p>
			<?php endif; ?>

			<?php if ( ! empty( $pending ) ) : ?>
				<h2><?php echo esc_html__( 'Waiting for API quota', 'wp-patch-alert' ); ?></h2>
				<p><?php echo esc_html__( 'These components were not checked because the daily WPScan request limit was reached. They stay queued for the next scan.', 'wp-patch-alert' ); ?></p>
				<table class="widefat striped">
					<thead>
						<tr>
							<th scope="col"><?php echo esc_html__( 'Type', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Name', 'wp-patch-alert' ); ?></th>
							<th scope="col"><?php echo esc_html__( 'Installed version', 'wp-patch-alert' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $pending as $item ) : ?>
							<tr>
								<td><?php echo esc_html( 'theme' === $item['type'] ? __( 'Theme', 'wp-patch-alert' ) : __( 'Plugin', 'wp-patch-alert' ) ); ?></td>
								<td><?php echo esc_html( (string) $item['name'] ); ?></td>
								<td><?php echo esc_html( (string) $item['version'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Persistent notice while findings exist.
	 */
	public function admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && 'toplevel_page_wp-patch-alert' === $screen->id ) {
			return;
		}

		$results  = wp_patch_alert_get_results();
		$findings = isset( $results['findings'] ) && is_array( $results['findings'] ) ? $results['findings'] : array();
		$count    = count( $findings );
		if ( 0 === $count ) {
			return;
		}

		echo '<div class="notice notice-error"><p>';
		echo esc_html(
			sprintf(
				/* translators: %d: number of vulnerabilities. */
				_n(
					'%d vulnerability affects this site.',
					'%d vulnerabilities affect this site.',
					$count,
					'wp-patch-alert'
				),
				$count
			)
		);
		echo ' <a href="' . esc_url( admin_url( 'admin.php?page=wp-patch-alert' ) ) . '">';
		echo esc_html__( 'View details', 'wp-patch-alert' );
		echo '</a></p></div>';
	}

	/**
	 * @param array<string, mixed> $results Scan results.
	 */
	private function render_copyrights( $results ) {
		if ( 'wordfence' !== ( isset( $results['provider'] ) ? $results['provider'] : '' ) ) {
			return;
		}

		$copyrights = isset( $results['copyrights'] ) && is_array( $results['copyrights'] ) ? $results['copyrights'] : array();
		if ( empty( $copyrights ) ) {
			return;
		}

		echo '<div class="notice notice-info" style="margin-top:16px;"><p>';
		echo esc_html__( 'Vulnerability data from Wordfence Intelligence.', 'wp-patch-alert' );
		echo '</p>';
		foreach ( $copyrights as $notice ) {
			if ( ! is_string( $notice ) || '' === $notice ) {
				continue;
			}
			echo '<p>' . esc_html( $notice ) . '</p>';
		}
		echo '</div>';
	}

	/**
	 * Manual scan handler.
	 */
	public function handle_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to scan.', 'wp-patch-alert' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'wp_patch_alert_scan' );

		$result = wp_patch_alert_run_scan();
		$url    = admin_url( 'admin.php?page=wp-patch-alert' );
		if ( is_wp_error( $result ) ) {
			$url = add_query_arg( 'locked', '1', $url );
		}

		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * @param array<string, mixed> $settings Plugin settings.
	 */
	private function render_status_message( $settings ) {
		$provider = ( isset( $settings['provider'] ) && 'wordfence' === $settings['provider'] ) ? 'wordfence' : 'wpscan';

		if ( 'wordfence' === $provider ) {
			if ( ! empty( $settings['status_error'] ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html( (string) $settings['status_error'] ) . '</p></div>';
			}

			$feed = WP_Patch_Alert_Wordfence_Client::feed_status();
			echo '<div class="notice notice-info"><p>';
			if ( null === $feed ) {
				echo esc_html__( 'The Wordfence feed downloads on the next scan. Saving these settings does not download it.', 'wp-patch-alert' );
			} else {
				echo esc_html(
					sprintf(
						/* translators: 1: download date, 2: expiry date. */
						__( 'Wordfence feed downloaded %1$s. It is reused until %2$s.', 'wp-patch-alert' ),
						wp_date( 'Y-m-d H:i', (int) $feed['downloaded_at'] ),
						wp_date( 'Y-m-d H:i', (int) $feed['expires_at'] )
					)
				);
			}
			echo '</p></div>';
			return;
		}

		if ( ! empty( $settings['status_error'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( (string) $settings['status_error'] ) . '</p></div>';
		}

		if ( empty( $settings['status_checked_at'] ) || ! empty( $settings['status_error'] ) ) {
			return;
		}

		$plan = '' !== (string) $settings['plan'] ? (string) $settings['plan'] : __( 'Unknown', 'wp-patch-alert' );
		echo '<div class="notice notice-info"><p>';
		echo esc_html(
			sprintf(
				/* translators: 1: plan name, 2: remaining requests, 3: date and time. */
				__( 'WPScan plan: %1$s. Requests remaining: %2$s. Checked %3$s.', 'wp-patch-alert' ),
				$plan,
				null === $settings['requests_remaining'] ? __( 'Unknown', 'wp-patch-alert' ) : (string) (int) $settings['requests_remaining'],
				wp_date( 'Y-m-d H:i', (int) $settings['status_checked_at'] )
			)
		);
		echo '</p></div>';
	}

	/**
	 * @param array<string, mixed> $results Scan results.
	 */
	private function render_scan_notices( $results ) {
		if ( isset( $_GET['locked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'A scan is already running.', 'wp-patch-alert' ) . '</p></div>';
		}

		if ( ! empty( $results['feed_notice'] ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html( (string) $results['feed_notice'] ) . '</p></div>';
		}

		if ( ! empty( $results['error'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( (string) $results['error'] ) . '</p></div>';
		}

		if ( 'skipped_no_recipients' === $results['email_status'] ) {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html__( 'No email was sent because no administrator is selected.', 'wp-patch-alert' );
			echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=wp-patch-alert-settings' ) ) . '">';
			echo esc_html__( 'Choose recipients', 'wp-patch-alert' );
			echo '</a></p></div>';
		} elseif ( 'failed' === $results['email_status'] && ! empty( $results['email_error'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( (string) $results['email_error'] ) . '</p></div>';
		}

		if ( ! empty( $results['last_scan'] ) ) {
			echo '<p>';
			echo esc_html(
				sprintf(
					/* translators: %s: date and time of the last scan. */
					__( 'Last scan: %s', 'wp-patch-alert' ),
					wp_date( 'Y-m-d H:i', (int) $results['last_scan'] )
				)
			);
			if ( 'wordfence' === ( isset( $results['provider'] ) ? $results['provider'] : '' ) && ! empty( $results['feed_downloaded_at'] ) ) {
				echo ' ';
				echo esc_html(
					sprintf(
						/* translators: %s: date and time the Wordfence feed was downloaded. */
						__( 'Wordfence feed downloaded: %s', 'wp-patch-alert' ),
						wp_date( 'Y-m-d H:i', (int) $results['feed_downloaded_at'] )
					)
				);
			}
			echo '</p>';
		}
	}

	/**
	 * @param bool $disabled Whether the scan button is disabled.
	 */
	private function render_scan_form( $disabled ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_patch_alert_scan' ); ?>
			<input type="hidden" name="action" value="wp_patch_alert_scan" />
			<?php
			submit_button(
				__( 'Scan now', 'wp-patch-alert' ),
				'secondary',
				'submit',
				false,
				$disabled ? array( 'disabled' => 'disabled' ) : array()
			);
			?>
		</form>
		<?php
	}
}
