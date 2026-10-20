<?php
/**
 * WPScan Vulnerability Database API client.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Calls the public WPScan API v3 and caches plugin and theme payloads.
 */
class WP_Patch_Alert_API_Client {

	const BASE_URL  = 'https://wpscan.com/api/v3/';
	const CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * API token.
	 *
	 * @var string
	 */
	private $token;

	/**
	 * @param string $token WPScan API token.
	 */
	public function __construct( $token ) {
		$this->token = $token;
	}

	/**
	 * Read the account plan and remaining daily requests.
	 *
	 * @return array{ok: bool, plan: string, requests_remaining: int|null, error: string}
	 */
	public function get_status() {
		$result = array(
			'ok'                 => false,
			'plan'               => '',
			'requests_remaining' => null,
			'error'              => '',
		);

		$response = $this->request( 'status' );
		if ( is_wp_error( $response ) ) {
			$result['error'] = $response->get_error_message();
			return $result;
		}

		$code = (int) $response['code'];
		if ( 401 === $code || 403 === $code ) {
			$result['error'] = __( 'The WPScan API token was rejected.', 'wp-patch-alert' );
			return $result;
		}

		if ( 429 === $code ) {
			$result['error'] = __( 'The WPScan API rate limit was reached.', 'wp-patch-alert' );
			return $result;
		}

		if ( 200 !== $code || ! is_array( $response['body'] ) ) {
			$result['error'] = __( 'The WPScan API status request failed.', 'wp-patch-alert' );
			return $result;
		}

		if ( ! isset( $response['body']['requests_remaining'] ) ) {
			$result['error'] = __( 'The WPScan API did not report how many requests remain.', 'wp-patch-alert' );
			return $result;
		}

		$result['ok']                 = true;
		$result['plan']               = isset( $response['body']['plan'] ) ? (string) $response['body']['plan'] : '';
		$result['requests_remaining'] = (int) $response['body']['requests_remaining'];

		return $result;
	}

	/**
	 * Vulnerabilities for one plugin or theme.
	 *
	 * A 404 means the slug is not in the database and is treated as clean.
	 * Cached payloads are reused for 12 hours for the same slug and version.
	 *
	 * @param string $type    Either plugin or theme.
	 * @param string $slug    Component slug.
	 * @param string $version Installed version. Included in the cache key only.
	 * @return array{ok: bool, cached: bool, requested: bool, vulnerabilities: array<int, array<string, mixed>>, error: string, stop: bool}
	 */
	public function get_vulnerabilities( $type, $slug, $version ) {
		$result = array(
			'ok'              => false,
			'cached'          => false,
			'requested'       => false,
			'vulnerabilities' => array(),
			'error'           => '',
			'stop'            => false,
		);

		$slug = (string) $slug;
		if ( ! preg_match( '/^[A-Za-z0-9_.-]+$/', $slug ) ) {
			$result['error'] = __( 'A component slug could not be sent to the WPScan API.', 'wp-patch-alert' );
			return $result;
		}

		$cached = $this->get_cached_vulnerabilities( $type, $slug, $version );
		if ( null !== $cached ) {
			$result['ok']              = true;
			$result['cached']          = true;
			$result['vulnerabilities'] = $cached;
			return $result;
		}

		$cache_key           = $this->cache_key( $type, $slug, $version );
		$path                = ( 'theme' === $type ) ? 'themes/' . rawurlencode( $slug ) : 'plugins/' . rawurlencode( $slug );
		$result['requested'] = true;
		$response            = $this->request( $path );
		if ( is_wp_error( $response ) ) {
			$result['error'] = $response->get_error_message();
			$result['stop']  = true;
			return $result;
		}

		$code = (int) $response['code'];
		if ( 404 === $code ) {
			$this->store_cache( $cache_key, array() );
			$result['ok'] = true;
			return $result;
		}

		if ( 401 === $code || 403 === $code ) {
			$result['error'] = __( 'The WPScan API token was rejected.', 'wp-patch-alert' );
			$result['stop']  = true;
			return $result;
		}

		if ( 429 === $code ) {
			$result['error'] = __( 'The WPScan API rate limit was reached.', 'wp-patch-alert' );
			$result['stop']  = true;
			return $result;
		}

		if ( 200 !== $code || ! is_array( $response['body'] ) ) {
			$result['error'] = __( 'The WPScan API request failed.', 'wp-patch-alert' );
			$result['stop']  = true;
			return $result;
		}

		$vulnerabilities = array();
		$payload         = $response['body'];
		if ( isset( $payload[ $slug ] ) && is_array( $payload[ $slug ] ) ) {
			$component = $payload[ $slug ];
		} else {
			$component = reset( $payload );
		}

		if ( is_array( $component ) && isset( $component['vulnerabilities'] ) && is_array( $component['vulnerabilities'] ) ) {
			$vulnerabilities = $component['vulnerabilities'];
		}

		$this->store_cache( $cache_key, $vulnerabilities );
		$result['ok']              = true;
		$result['vulnerabilities'] = $vulnerabilities;

		return $result;
	}

	/**
	 * Return a cached vulnerability list, or null when this version is not cached.
	 *
	 * @param string $type Component type, plugin or theme.
	 * @param string $slug Component slug.
	 * @param string $version Installed version.
	 * @return array<int, mixed>|null
	 */
	public function get_cached_vulnerabilities( $type, $slug, $version ) {
		$slug = (string) $slug;
		if ( ! preg_match( '/^[A-Za-z0-9_.-]+$/', $slug ) ) {
			return null;
		}

		$cached = get_transient( $this->cache_key( $type, $slug, $version ) );
		if ( ! is_array( $cached ) || ! isset( $cached['vulnerabilities'] ) || ! is_array( $cached['vulnerabilities'] ) ) {
			return null;
		}

		return $cached['vulnerabilities'];
	}

	/**
	 * @param string $path Path relative to the v3 API root.
	 * @return array{code: int, body: mixed}|WP_Error
	 */
	private function request( $path ) {
		$url      = self::BASE_URL . ltrim( $path, '/' );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 15,
				'redirection' => 2,
				'headers'     => array(
					'Authorization' => 'Token token=' . $this->token,
					'Accept'        => 'application/json',
				),
				'user-agent'  => 'WP Patch Alert/' . WP_PATCH_ALERT_VERSION . '; ' . home_url( '/' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'wp_patch_alert_http',
				__( 'The WPScan API could not be reached.', 'wp-patch-alert' )
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		return array(
			'code' => (int) wp_remote_retrieve_response_code( $response ),
			'body' => $body,
		);
	}

	/**
	 * @param string $type Component type.
	 * @param string $slug Component slug.
	 * @param string $version Installed version.
	 * @return string
	 */
	private function cache_key( $type, $slug, $version ) {
		return 'wppa_' . md5( $type . '|' . $slug . '|' . $version );
	}

	/**
	 * @param string               $cache_key Transient name.
	 * @param array<int, mixed>    $vulnerabilities Raw vulnerability list.
	 */
	private function store_cache( $cache_key, $vulnerabilities ) {
		set_transient(
			$cache_key,
			array(
				'vulnerabilities' => $vulnerabilities,
			),
			self::CACHE_TTL
		);

		$keys = get_option( WP_PATCH_ALERT_OPTION_CACHE_KEYS, array() );
		if ( ! is_array( $keys ) ) {
			$keys = array();
		}
		if ( ! in_array( $cache_key, $keys, true ) ) {
			$keys[] = $cache_key;
			update_option( WP_PATCH_ALERT_OPTION_CACHE_KEYS, $keys, false );
		}
	}
}
