=== WP Patch Alert ===
Contributors: dhakshinait
Tags: security, vulnerability, plugins, email, wpscan
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Checks active plugins and the active theme for known vulnerabilities and emails the administrators you choose.

== Description ==

WP Patch Alert compares the plugins that are active on your site, and the theme that is actually running, with a vulnerability database. Choose WPScan or Wordfence Intelligence in the settings. When a known issue affects an installed version, it is listed in wp-admin and can be emailed to selected administrator accounts.

The plugin does not update plugins or themes for you. It reports what is affected, the severity, the CVE when one is listed, and the version that fixes it.

= What is checked =

* Every active plugin.
* Inactive plugins, when "Also scan inactive plugins" is checked in the settings. That option is off by default.
* The active theme.
* The parent theme, when the active theme is a child theme.

Inactive themes and WordPress core are not checked.

A vulnerability is treated as affecting the site when the installed version is inside the published range. For WPScan, the installed version is the same as or newer than `introduced_in`, when that value is set, and it is older than `fixed_in`. For Wordfence, the installed version falls inside an affected range and is not one of the patched versions. If no fix has been published, the installed version is still reported.

= Email =

Choose which administrator accounts receive mail on the settings screen. Editors and every other role are not listed and are never emailed. A message is sent only when the set of affecting vulnerabilities changes. If no administrator is selected, the scan still runs and the Vulnerabilities page says that no email was sent.

= API token and quota =

Choose the source under Settings, then WP Patch Alert.

WPScan needs a token from [wpscan.com](https://wpscan.com/api/). The free plan allows 25 requests per day. Each uncached plugin or theme uses one request, so a large plugin list may take more than one scan to finish. Components that were not checked stay queued, and the Vulnerabilities page lists them under "Waiting for API quota." Successful responses are cached for 12 hours.

Wordfence Intelligence needs an API key from the Integrations page in your Wordfence account. One scan downloads the scanner feed and matches plugins and themes on your site. The feed is saved for 12 hours. A free key can download the feed about once every 30 minutes. Saving the settings does not download the feed.

= External service =

With WPScan selected, each scan sends plugin slugs, theme slugs, and your API token to `https://wpscan.com/api/v3/`. The token is sent in the Authorization header. The plugin does not send site content or user accounts.

With Wordfence selected, the scan downloads `https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner` and sends your API key in the Authorization header. It does not send the list of installed plugins or themes. Matching happens on your site. CVE lines from that feed include the copyright notice supplied in the feed. Use of the data is covered by the Wordfence Intelligence terms.

== Installation ==

1. Upload the `wp-patch-alert` folder to `/wp-content/plugins/`, or install the zip from the Plugins screen.
2. Activate WP Patch Alert.
3. Open Settings, then WP Patch Alert.
4. Choose WPScan or Wordfence Intelligence, then paste the token or API key for that source.
5. Check the administrator accounts that should receive alerts. Check "Also scan inactive plugins" if those plugins should be included, then save.
6. Choose Scan now, wait for the daily scheduled scan, or run `wp patch-alert scan`.
7. Open the Vulnerabilities menu to review the results.

== Frequently Asked Questions ==

= Where do I get an API token? =

For WPScan, create an account at [wpscan.com](https://wpscan.com/api/) and copy the token from your profile. For Wordfence, create a key under Integrations in your Wordfence account. Paste it into Settings, then WP Patch Alert. Leave the field blank on later saves to keep the key that is already stored.

= Why was a plugin not checked? =

With WPScan, the free plan allows 25 requests per day. The scanner stops before that quota is exhausted and continues on the next run. Anything still waiting is listed on the Vulnerabilities page.

With Wordfence, one feed download covers every plugin and theme in that feed. A plugin is missing from the results only when the feed has no affecting record for the installed version.

= Who receives the email? =

Only the administrator accounts you check in the settings. If a selected user is no longer an administrator, that address is skipped. Other roles are never emailed.

= Does this plugin update anything? =

No. It reports vulnerabilities. Update the affected plugin or theme from the normal WordPress screens.

= Can a script run only this scan? =

Yes. See the WP-CLI section below. `wp patch-alert scan` runs this plugin only and does not run the site's other cron events.

== WP-CLI ==

Run one scan from the WordPress directory:

`wp patch-alert scan`

From another directory, pass the WordPress path:

`wp patch-alert scan --path=/path/to/wordpress`

The command uses the saved source, token, inactive-plugin option, and recipient list. It is the same job as Scan now and the daily schedule. On success it prints the number of vulnerabilities and how many components are still waiting. It exits with an error when the scan fails, including a missing token or an API failure, so Jenkins can mark the job failed.

The daily event hook is `wp_patch_alert_daily_scan`. To run that hook by itself, without other due events:

`wp cron event run wp_patch_alert_daily_scan`

= Are inactive themes checked? =

Inactive themes are not checked. Inactive plugins are checked only when "Also scan inactive plugins" is enabled. The scan always covers active plugins, the active theme, and that theme's parent when there is one.

== Changelog ==

= 1.0.0 =
* First release.
* Daily and manual scans of active plugins and the active theme.
* Optional scan of inactive plugins.
* Vulnerabilities list, admin notice, and email to selected administrators.
* Optional Wordfence Intelligence scanner feed.
* WP-CLI command `wp patch-alert scan` for a single scan without running other site cron events.
