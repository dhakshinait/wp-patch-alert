<?php
/**
 * Wordfence Intelligence scanner feed client.
 *
 * @package WP_Patch_Alert
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Downloads the Wordfence scanner feed and matches it to the local inventory.
 */
class WP_Patch_Alert_Wordfence_Client {

	const FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner';
	const CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * Largest JSON value or NDJSON line kept in memory.
	 * One feed record is a few kilobytes. Anything larger is rejected
	 * before PHP hits its memory limit.
	 */
	const MAX_VALUE_BYTES = 2097152;

	/**
	 * Largest sliding read buffer. Already-consumed bytes are discarded
	 * as the parser moves forward.
	 */
	const MAX_BUFFER_BYTES = 8388608;

	/**
	 * API key.
	 *
	 * @var string
	 */
	private $token;

	/**
	 * @param string $token Wordfence API key.
	 */
	public function __construct( $token ) {
		$this->token = $token;
	}

	/**
	 * Match the inventory against the scanner feed.
	 *
	 * @param array<int, array{type: string, slug: string, version: string, name: string}> $inventory Inventory rows.
	 * @return array{ok: bool, error: string, stale: bool, checked: array<string, array<string, mixed>>, copyrights: array<int, string>, downloaded_at: int}
	 */
	public function match( $inventory ) {
		$result = array(
			'ok'             => false,
			'error'          => '',
			'stale'          => false,
			'checked'        => array(),
			'copyrights'     => array(),
			'downloaded_at'  => 0,
		);

		$feed = $this->ensure_feed();
		if ( empty( $feed['ok'] ) ) {
			$result['error'] = $feed['error'];
			return $result;
		}

		$parsed = $this->parse_feed( $feed['path'], $inventory );
		if ( empty( $parsed['ok'] ) ) {
			$result['error'] = $parsed['error'];
			return $result;
		}

		$result['ok']            = true;
		$result['stale']         = ! empty( $feed['stale'] );
		$result['checked']       = $parsed['checked'];
		$result['copyrights']    = $parsed['copyrights'];
		$result['downloaded_at'] = (int) filemtime( $feed['path'] );

		return $result;
	}

	/**
	 * Saved feed age, when a feed file exists.
	 *
	 * @return array{downloaded_at: int, expires_at: int, fresh: bool}|null
	 */
	public static function feed_status() {
		$path = self::feed_path();
		if ( '' === $path || ! is_readable( $path ) ) {
			return null;
		}

		$downloaded = (int) filemtime( $path );

		return array(
			'downloaded_at' => $downloaded,
			'expires_at'    => $downloaded + self::CACHE_TTL,
			'fresh'         => ( time() - $downloaded ) < self::CACHE_TTL,
		);
	}

	/**
	 * Whether one software record affects an installed version.
	 *
	 * @param string               $installed_version Installed version.
	 * @param array<string, mixed> $software          Feed software object.
	 * @return bool
	 */
	public static function version_affected( $installed_version, $software ) {
		$patched = isset( $software['patched_versions'] ) && is_array( $software['patched_versions'] ) ? $software['patched_versions'] : array();
		foreach ( $patched as $version ) {
			if ( is_string( $version ) && '' !== $version && version_compare( $installed_version, $version, '==' ) ) {
				return false;
			}
		}

		foreach ( self::version_ranges( isset( $software['affected_versions'] ) ? $software['affected_versions'] : array() ) as $range ) {
			if ( self::version_in_range( $installed_version, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Lowest patched version newer than the installed version.
	 *
	 * @param string            $installed_version Installed version.
	 * @param array<int, mixed> $patched_versions  Patched versions from the feed.
	 * @return string
	 */
	public static function fixed_version( $installed_version, $patched_versions ) {
		$candidates = array();
		foreach ( $patched_versions as $version ) {
			if ( is_string( $version ) && '' !== $version && version_compare( $installed_version, $version, '<' ) ) {
				$candidates[] = $version;
			}
		}

		if ( empty( $candidates ) ) {
			return '';
		}

		usort( $candidates, 'version_compare' );

		return $candidates[0];
	}

	/**
	 * @param mixed $affected Feed affected_versions value.
	 * @return array<int, array<string, mixed>>
	 */
	private static function version_ranges( $affected ) {
		if ( ! is_array( $affected ) ) {
			return array();
		}

		if ( isset( $affected['from_version'] ) || isset( $affected['to_version'] ) ) {
			return array( $affected );
		}

		$ranges = array();
		foreach ( $affected as $range ) {
			if ( is_array( $range ) && ( isset( $range['from_version'] ) || isset( $range['to_version'] ) ) ) {
				$ranges[] = $range;
			}
		}

		return $ranges;
	}

	/**
	 * @param string               $installed_version Installed version.
	 * @param array<string, mixed> $range             One affected range.
	 * @return bool
	 */
	private static function version_in_range( $installed_version, $range ) {
		$from = isset( $range['from_version'] ) ? trim( (string) $range['from_version'] ) : '*';
		$to   = isset( $range['to_version'] ) ? trim( (string) $range['to_version'] ) : '*';

		if ( '*' !== $from && '' !== $from ) {
			$operator = self::is_inclusive( $range, 'from_inclusive' ) ? '>=' : '>';
			if ( ! version_compare( $installed_version, $from, $operator ) ) {
				return false;
			}
		}

		if ( '*' !== $to && '' !== $to ) {
			$operator = self::is_inclusive( $range, 'to_inclusive' ) ? '<=' : '<';
			if ( ! version_compare( $installed_version, $to, $operator ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param array<string, mixed> $range Feed range.
	 * @param string               $key   Inclusive flag name.
	 * @return bool
	 */
	private static function is_inclusive( $range, $key ) {
		if ( ! array_key_exists( $key, $range ) ) {
			return true;
		}

		$value = $range[ $key ];
		if ( is_bool( $value ) || is_int( $value ) ) {
			return (bool) $value;
		}

		if ( is_string( $value ) ) {
			return ! in_array( strtolower( $value ), array( '0', 'false', 'no' ), true );
		}

		return true;
	}

	/**
	 * @return array{ok: bool, error: string, stale: bool, path: string}
	 */
	private function ensure_feed() {
		$result = array(
			'ok'    => false,
			'error' => '',
			'stale' => false,
			'path'  => '',
		);

		$path = self::feed_path();
		if ( '' === $path ) {
			$result['error'] = __( 'The Wordfence feed could not be stored on this site.', 'wp-patch-alert' );
			return $result;
		}

		if ( is_readable( $path ) && ( time() - (int) filemtime( $path ) ) < self::CACHE_TTL ) {
			$result['ok']   = true;
			$result['path'] = $path;
			return $result;
		}

		$download = $this->download_feed( $path );
		if ( ! empty( $download['ok'] ) ) {
			$result['ok']   = true;
			$result['path'] = $path;
			return $result;
		}

		if ( ! empty( $download['use_existing'] ) && is_readable( $path ) ) {
			$result['ok']    = true;
			$result['stale'] = true;
			$result['path']  = $path;
			$result['error'] = $download['error'];
			return $result;
		}

		$result['error'] = '' !== $download['error'] ? $download['error'] : __( 'The Wordfence feed could not be downloaded.', 'wp-patch-alert' );
		return $result;
	}

	/**
	 * @param string $path Final feed path.
	 * @return array{ok: bool, error: string, use_existing: bool}
	 */
	private function download_feed( $path ) {
		$result = array(
			'ok'           => false,
			'error'        => '',
			'use_existing' => false,
		);

		$dir  = dirname( $path );
		$part = $dir . '/feed.part';
		$next = $dir . '/feed.json.new';

		$response = wp_remote_get(
			self::FEED_URL,
			array(
				'timeout'     => 120,
				'redirection' => 2,
				'headers'     => array(
					'Authorization' => 'Bearer ' . $this->token,
					'Accept'        => 'application/json',
				),
				'stream'      => true,
				'filename'    => $part,
				'user-agent'  => 'WP Patch Alert/' . WP_PATCH_ALERT_VERSION . '; ' . home_url( '/' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->delete_file( $part );
			$result['error']        = __( 'The Wordfence feed could not be reached.', 'wp-patch-alert' );
			$result['use_existing'] = true;
			return $result;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 401 === $code || 403 === $code ) {
			$this->delete_file( $part );
			$result['error'] = __( 'The Wordfence API key was rejected.', 'wp-patch-alert' );
			return $result;
		}

		if ( 429 === $code ) {
			$this->delete_file( $part );
			$result['error']        = __( 'The Wordfence feed was requested too recently. The previous feed will be used when one is saved.', 'wp-patch-alert' );
			$result['use_existing'] = true;
			return $result;
		}

		if ( 200 !== $code || ! is_readable( $part ) || 0 === (int) filesize( $part ) ) {
			$this->delete_file( $part );
			$result['error']        = __( 'The Wordfence feed could not be downloaded.', 'wp-patch-alert' );
			$result['use_existing'] = true;
			return $result;
		}

		$ready = $part;
		if ( $this->is_gzip( $part ) ) {
			if ( ! $this->decompress_gzip( $part, $next ) ) {
				$this->delete_file( $part );
				$this->delete_file( $next );
				$result['error']        = __( 'The Wordfence feed could not be read.', 'wp-patch-alert' );
				$result['use_existing'] = true;
				return $result;
			}
			$this->delete_file( $part );
			$ready = $next;
		} elseif ( ! rename( $part, $next ) ) {
			$this->delete_file( $part );
			$result['error']        = __( 'The Wordfence feed could not be stored on this site.', 'wp-patch-alert' );
			$result['use_existing'] = true;
			return $result;
		} else {
			$ready = $next;
		}

		if ( ! $this->looks_like_feed( $ready ) || ! rename( $ready, $path ) ) {
			$this->delete_file( $ready );
			$result['error']        = __( 'The Wordfence feed could not be read.', 'wp-patch-alert' );
			$result['use_existing'] = true;
			return $result;
		}

		$result['ok'] = true;
		return $result;
	}

	/**
	 * @param string                                                                        $path Feed file.
	 * @param array<int, array{type: string, slug: string, version: string, name: string}> $inventory Inventory rows.
	 * @return array{ok: bool, error: string, checked: array<string, array<string, mixed>>, copyrights: array<int, string>}
	 */
	private function parse_feed( $path, $inventory ) {
		$result = array(
			'ok'         => false,
			'error'      => '',
			'checked'    => array(),
			'copyrights' => array(),
		);

		$by_key  = array();
		$lookup  = array();
		$buckets = array();

		foreach ( $inventory as $item ) {
			$key                        = $item['type'] . ':' . $item['slug'];
			$by_key[ $key ]             = $item;
			$lookup_key                 = strtolower( $key );
			$lookup[ $lookup_key ]      = $key;
			$buckets[ $key ]            = array();
		}

		$copyrights = array();
		$parsed     = $this->each_record(
			$path,
			function ( $record ) use ( $lookup, $by_key, &$buckets, &$copyrights ) {
				$this->collect_record( $record, $lookup, $by_key, $buckets, $copyrights );
			}
		);

		if ( ! $parsed ) {
			$result['error'] = __( 'The Wordfence feed could not be read without using too much memory. The scan stopped before PHP ran out of memory.', 'wp-patch-alert' );
			return $result;
		}

		$checked = array();
		foreach ( $by_key as $key => $item ) {
			$checked[ $key ] = array(
				'type'     => $item['type'],
				'slug'     => $item['slug'],
				'version'  => $item['version'],
				'name'     => $item['name'],
				'findings' => $buckets[ $key ],
			);
		}

		$result['ok']         = true;
		$result['checked']    = $checked;
		$result['copyrights'] = array_values( array_unique( $copyrights ) );

		return $result;
	}

	/**
	 * @param array<string, mixed>                                      $record Feed record.
	 * @param array<string, string>                                     $lookup Lowercase component key to stored key.
	 * @param array<string, array{type: string, slug: string, version: string, name: string}> $by_key Inventory by stored key.
	 * @param array<string, array<int, array<string, mixed>>>           $buckets Findings being collected.
	 * @param array<int, string>                                        $copyrights Copyright lines.
	 */
	private function collect_record( $record, $lookup, $by_key, &$buckets, &$copyrights ) {
		if ( empty( $record['software'] ) || ! is_array( $record['software'] ) ) {
			return;
		}

		$record_id = isset( $record['id'] ) ? (string) $record['id'] : md5( (string) ( $record['title'] ?? '' ) );
		$matched   = false;

		foreach ( $record['software'] as $software ) {
			if ( ! is_array( $software ) ) {
				continue;
			}

			$type = isset( $software['type'] ) ? strtolower( (string) $software['type'] ) : '';
			$slug = isset( $software['slug'] ) ? strtolower( (string) $software['slug'] ) : '';
			if ( 'plugin' !== $type && 'theme' !== $type ) {
				continue;
			}

			$stored_key = isset( $lookup[ $type . ':' . $slug ] ) ? $lookup[ $type . ':' . $slug ] : '';
			if ( '' === $stored_key || ! isset( $by_key[ $stored_key ] ) ) {
				continue;
			}

			$item = $by_key[ $stored_key ];
			if ( ! self::version_affected( $item['version'], $software ) ) {
				continue;
			}

			$patched = isset( $software['patched_versions'] ) && is_array( $software['patched_versions'] ) ? $software['patched_versions'] : array();
			$buckets[ $stored_key ][] = array(
				'type'     => $item['type'],
				'name'     => $item['name'],
				'slug'     => $item['slug'],
				'version'  => $item['version'],
				'vuln_id'  => $record_id,
				'title'    => isset( $record['title'] ) ? (string) $record['title'] : '',
				'severity' => $this->severity( $record ),
				'cve'      => $this->cve( $record ),
				'fixed_in' => self::fixed_version( $item['version'], $patched ),
				'notified' => false,
			);
			$matched = true;
		}

		if ( $matched ) {
			$notice = $this->copyright_text( $record );
			if ( '' !== $notice ) {
				$copyrights[] = $notice;
			}
		}
	}

	/**
	 * Walk feed records without loading the whole document.
	 *
	 * The scanner feed is a large JSON object or array. Decoding it in one
	 * step uses several times the file size and exhausts a 256 MB memory limit.
	 *
	 * @param string   $path Feed file.
	 * @param callable $callback Called with each record array.
	 * @return bool
	 */
	private function each_record( $path, $callback ) {
		if ( $this->is_ndjson( $path ) ) {
			$handle = fopen( $path, 'rb' );
			if ( ! $handle ) {
				return false;
			}

			while ( true ) {
				$line = $this->read_capped_line( $handle, self::MAX_VALUE_BYTES );
				if ( null === $line ) {
					fclose( $handle );
					return false;
				}
				if ( false === $line ) {
					break;
				}
				$line = trim( $line );
				if ( '' === $line ) {
					continue;
				}
				$record = json_decode( $line, true );
				if ( is_array( $record ) ) {
					$callback( $record );
				}
				unset( $record );
			}

			fclose( $handle );
			return true;
		}

		$handle = fopen( $path, 'rb' );
		if ( ! $handle ) {
			return false;
		}

		$buffer = '';
		$offset = 0;
		$this->skip_whitespace( $handle, $buffer, $offset );
		$start = $this->peek_char( $handle, $buffer, $offset );
		if ( '{' !== $start && '[' !== $start ) {
			fclose( $handle );
			return false;
		}
		$this->consume_char( $buffer, $offset );

		$saw_record = false;
		while ( true ) {
			$this->skip_whitespace( $handle, $buffer, $offset );
			$next = $this->peek_char( $handle, $buffer, $offset );
			if ( null === $next || '}' === $next || ']' === $next ) {
				fclose( $handle );
				return $saw_record || ( null !== $next );
			}

			$id = '';
			if ( '{' === $start ) {
				$id = $this->read_json_string( $handle, $buffer, $offset );
				if ( ! is_string( $id ) ) {
					fclose( $handle );
					return false;
				}
				$this->skip_whitespace( $handle, $buffer, $offset );
				if ( ':' !== $this->peek_char( $handle, $buffer, $offset ) ) {
					fclose( $handle );
					return false;
				}
				$this->consume_char( $buffer, $offset );
				$this->skip_whitespace( $handle, $buffer, $offset );
			}

			$json = $this->read_json_value( $handle, $buffer, $offset );
			if ( ! is_string( $json ) ) {
				fclose( $handle );
				return false;
			}

			$record = json_decode( $json, true );
			unset( $json );
			if ( is_array( $record ) ) {
				if ( '' !== $id && empty( $record['id'] ) ) {
					$record['id'] = $id;
				}
				$callback( $record );
				$saw_record = true;
			}
			unset( $record );

			$this->skip_whitespace( $handle, $buffer, $offset );
			if ( ',' === $this->peek_char( $handle, $buffer, $offset ) ) {
				$this->consume_char( $buffer, $offset );
			}
			$this->compact_buffer( $buffer, $offset );
		}
	}

	/**
	 * @param resource $handle File handle.
	 * @param string   $buffer Read buffer.
	 * @param int      $offset Offset into the buffer.
	 */
	private function skip_whitespace( $handle, &$buffer, &$offset ) {
		while ( true ) {
			$this->ensure_buffer( $handle, $buffer, $offset, 1 );
			if ( $offset >= strlen( $buffer ) ) {
				return;
			}
			$char = $buffer[ $offset ];
			if ( ' ' !== $char && "\n" !== $char && "\r" !== $char && "\t" !== $char ) {
				return;
			}
			++$offset;
		}
	}

	/**
	 * @param resource $handle File handle.
	 * @param string   $buffer Read buffer.
	 * @param int      $offset Offset into the buffer.
	 * @return string|null
	 */
	private function peek_char( $handle, &$buffer, $offset ) {
		$this->ensure_buffer( $handle, $buffer, $offset, 1 );
		if ( $offset >= strlen( $buffer ) ) {
			return null;
		}

		return $buffer[ $offset ];
	}

	/**
	 * @param string $buffer Read buffer.
	 * @param int    $offset Offset into the buffer.
	 */
	private function consume_char( &$buffer, &$offset ) {
		++$offset;
	}

	/**
	 * @param resource $handle File handle.
	 * @param string   $buffer Read buffer.
	 * @param int      $offset Offset into the buffer.
	 * @return string|null Decoded JSON string.
	 */
	private function read_json_string( $handle, &$buffer, &$offset ) {
		$this->ensure_buffer( $handle, $buffer, $offset, 1 );
		if ( $offset >= strlen( $buffer ) || '"' !== $buffer[ $offset ] ) {
			return null;
		}

		$begin = $offset;
		++$offset;
		$escape = false;
		while ( true ) {
			$this->ensure_buffer( $handle, $buffer, $offset, 1 );
			if ( $offset >= strlen( $buffer ) ) {
				return null;
			}
			$char = $buffer[ $offset ];
			++$offset;
			if ( ( $offset - $begin ) > self::MAX_VALUE_BYTES ) {
				return null;
			}
			if ( $escape ) {
				$escape = false;
				continue;
			}
			if ( '\\' === $char ) {
				$escape = true;
				continue;
			}
			if ( '"' === $char ) {
				$decoded = json_decode( substr( $buffer, $begin, $offset - $begin ), true );
				return is_string( $decoded ) ? $decoded : null;
			}
		}
	}

	/**
	 * @param resource $handle File handle.
	 * @param string   $buffer Read buffer.
	 * @param int      $offset Offset into the buffer.
	 * @return string|null Raw JSON value.
	 */
	private function read_json_value( $handle, &$buffer, &$offset ) {
		$this->ensure_buffer( $handle, $buffer, $offset, 1 );
		if ( $offset >= strlen( $buffer ) ) {
			return null;
		}

		$begin = $offset;
		$char  = $buffer[ $offset ];
		if ( '"' === $char ) {
			$decoded_start = $offset;
			if ( null === $this->read_json_string( $handle, $buffer, $offset ) ) {
				return null;
			}
			return substr( $buffer, $decoded_start, $offset - $decoded_start );
		}

		if ( '{' !== $char && '[' !== $char ) {
			while ( true ) {
				$this->ensure_buffer( $handle, $buffer, $offset, 1 );
				if ( $offset >= strlen( $buffer ) ) {
					break;
				}
				$current = $buffer[ $offset ];
				if ( false !== strpos( ",}] \t\r\n", $current ) ) {
					break;
				}
				++$offset;
				if ( ( $offset - $begin ) > self::MAX_VALUE_BYTES ) {
					return null;
				}
			}
			if ( $offset === $begin ) {
				return null;
			}
			return substr( $buffer, $begin, $offset - $begin );
		}

		$depth     = 0;
		$in_string = false;
		$escape    = false;
		while ( true ) {
			$this->ensure_buffer( $handle, $buffer, $offset, 1 );
			if ( $offset >= strlen( $buffer ) ) {
				return null;
			}
			$current = $buffer[ $offset ];
			++$offset;
			if ( ( $offset - $begin ) > self::MAX_VALUE_BYTES ) {
				return null;
			}
			if ( $in_string ) {
				if ( $escape ) {
					$escape = false;
				} elseif ( '\\' === $current ) {
					$escape = true;
				} elseif ( '"' === $current ) {
					$in_string = false;
				}
				continue;
			}
			if ( '"' === $current ) {
				$in_string = true;
			} elseif ( '{' === $current || '[' === $current ) {
				++$depth;
			} elseif ( '}' === $current || ']' === $current ) {
				--$depth;
				if ( 0 === $depth ) {
					return substr( $buffer, $begin, $offset - $begin );
				}
			}
		}
	}

	/**
	 * @param resource $handle File handle.
	 * @param string   $buffer Read buffer.
	 * @param int      $offset Offset into the buffer.
	 * @param int      $minimum Bytes required beyond the offset.
	 */
	private function ensure_buffer( $handle, &$buffer, $offset, $minimum ) {
		while ( ( strlen( $buffer ) - $offset ) < $minimum && ! feof( $handle ) ) {
			if ( strlen( $buffer ) >= self::MAX_BUFFER_BYTES ) {
				return;
			}
			$chunk = fread( $handle, 65536 );
			if ( ! is_string( $chunk ) || '' === $chunk ) {
				break;
			}
			$buffer .= $chunk;
		}
	}

	/**
	 * @param string $buffer Read buffer.
	 * @param int    $offset Offset into the buffer.
	 */
	private function compact_buffer( &$buffer, &$offset ) {
		if ( $offset > 131072 ) {
			$buffer = substr( $buffer, $offset );
			$offset = 0;
		}
	}

	/**
	 * Read one line, stopping if it exceeds the memory cap.
	 *
	 * fgets() would load a minified multi-megabyte line in one allocation.
	 *
	 * @param resource $handle File handle.
	 * @param int      $maximum Maximum line length in bytes.
	 * @return string|false|null Line text, false at end of file, null when the line is too long.
	 */
	private function read_capped_line( $handle, $maximum ) {
		$line = '';
		$any  = false;

		while ( ! feof( $handle ) ) {
			$char = fgetc( $handle );
			if ( false === $char ) {
				break;
			}
			$any = true;
			if ( "\n" === $char ) {
				return rtrim( $line, "\r" );
			}
			if ( strlen( $line ) >= $maximum ) {
				return null;
			}
			$line .= $char;
		}

		if ( ! $any ) {
			return false;
		}

		return rtrim( $line, "\r" );
	}

	/**
	 * @param string $path Feed file.
	 * @return bool
	 */
	private function is_ndjson( $path ) {
		$handle = fopen( $path, 'rb' );
		if ( ! $handle ) {
			return false;
		}

		$lines = array();
		while ( count( $lines ) < 2 ) {
			$line = $this->read_capped_line( $handle, self::MAX_VALUE_BYTES );
			if ( null === $line || false === $line ) {
				break;
			}
			$line = trim( $line );
			if ( '' !== $line ) {
				$lines[] = $line;
			}
		}
		fclose( $handle );

		if ( count( $lines ) < 2 ) {
			return false;
		}

		$first  = json_decode( $lines[0], true );
		$second = json_decode( $lines[1], true );

		return is_array( $first ) && is_array( $second );
	}

	/**
	 * @param string $path File path.
	 * @return bool
	 */
	private function looks_like_feed( $path ) {
		$handle = fopen( $path, 'rb' );
		if ( ! $handle ) {
			return false;
		}

		$sample = '';
		while ( strlen( $sample ) < 64 && false !== ( $line = fgets( $handle ) ) ) {
			$sample .= $line;
		}
		fclose( $handle );

		$sample = ltrim( $sample );

		return isset( $sample[0] ) && ( '{' === $sample[0] || '[' === $sample[0] );
	}

	/**
	 * @param array<string, mixed> $record Feed record.
	 * @return string
	 */
	private function severity( $record ) {
		if ( isset( $record['cvss'] ) && is_array( $record['cvss'] ) ) {
			if ( ! empty( $record['cvss']['rating'] ) ) {
				return (string) $record['cvss']['rating'];
			}
			if ( isset( $record['cvss']['score'] ) && '' !== (string) $record['cvss']['score'] ) {
				return (string) $record['cvss']['score'];
			}
		}

		return '';
	}

	/**
	 * @param array<string, mixed> $record Feed record.
	 * @return string
	 */
	private function cve( $record ) {
		if ( ! empty( $record['cve'] ) ) {
			return is_array( $record['cve'] ) ? implode( ', ', array_map( 'strval', $record['cve'] ) ) : (string) $record['cve'];
		}

		if ( ! empty( $record['cves'] ) && is_array( $record['cves'] ) ) {
			return implode( ', ', array_map( 'strval', $record['cves'] ) );
		}

		return '';
	}

	/**
	 * @param array<string, mixed> $record Feed record.
	 * @return string
	 */
	private function copyright_text( $record ) {
		if ( ! empty( $record['copyright'] ) && is_string( $record['copyright'] ) ) {
			return trim( $record['copyright'] );
		}

		if ( empty( $record['copyrights'] ) || ! is_array( $record['copyrights'] ) ) {
			return '';
		}

		if ( ! empty( $record['copyrights']['message'] ) && is_string( $record['copyrights']['message'] ) ) {
			return trim( $record['copyrights']['message'] );
		}

		$parts = array();
		foreach ( $record['copyrights'] as $item ) {
			if ( is_string( $item ) && '' !== trim( $item ) ) {
				$parts[] = trim( $item );
			} elseif ( is_array( $item ) && ! empty( $item['message'] ) && is_string( $item['message'] ) ) {
				$parts[] = trim( $item['message'] );
			} elseif ( is_array( $item ) && ! empty( $item['notice'] ) && is_string( $item['notice'] ) ) {
				$parts[] = trim( $item['notice'] );
			}
		}

		return implode( ' ', $parts );
	}

	/**
	 * @return string
	 */
	private static function feed_path() {
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['error'] ) ) {
			return '';
		}

		$dir = trailingslashit( $uploads['basedir'] ) . 'wp-patch-alert';
		if ( ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		$index = $dir . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php\n// Silence is golden.\n" );
		}

		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Deny from all\n" );
		}

		return $dir . '/feed.json';
	}

	/**
	 * @param string $path File path.
	 * @return bool
	 */
	private function is_gzip( $path ) {
		$handle = fopen( $path, 'rb' );
		if ( ! $handle ) {
			return false;
		}
		$magic = fread( $handle, 2 );
		fclose( $handle );

		return "\x1f\x8b" === $magic;
	}

	/**
	 * @param string $source Gzip file.
	 * @param string $dest Plain file.
	 * @return bool
	 */
	private function decompress_gzip( $source, $dest ) {
		$in = gzopen( $source, 'rb' );
		if ( ! $in ) {
			return false;
		}

		$out = fopen( $dest, 'wb' );
		if ( ! $out ) {
			gzclose( $in );
			return false;
		}

		$ok = true;
		while ( ! gzeof( $in ) ) {
			$chunk = gzread( $in, 1048576 );
			if ( false === $chunk ) {
				$ok = false;
				break;
			}
			if ( '' !== $chunk && false === fwrite( $out, $chunk ) ) {
				$ok = false;
				break;
			}
		}

		fclose( $out );
		gzclose( $in );

		return $ok;
	}

	/**
	 * @param string $path File path.
	 */
	private function delete_file( $path ) {
		if ( is_file( $path ) ) {
			unlink( $path );
		}
	}
}
