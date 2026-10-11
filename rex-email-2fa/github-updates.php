<?php
/** Updates from public GitHub releases. */
if (!defined('ABSPATH')) { exit; }
final class Dares_2FA_GitHub_Updates {
    const REPO = 'spikerm/wordpress-2fa';
    const CACHE = 'dares2fa_github_release';
    public function __construct() {
        add_filter('pre_set_site_transient_update_plugins', [$this, 'updates']);
        add_filter('plugins_api', [$this, 'information'], 20, 3);
    }
    public function release() {
        $cached = get_site_transient(self::CACHE);
        if ($cached !== false) { return $cached ?: false; }
        $response = wp_remote_get('https://api.github.com/repos/' . self::REPO . '/releases/latest', ['timeout' => 10, 'headers' => ['Accept' => 'application/vnd.github+json']]);
        $result = false;
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (is_array($data) && empty($data['draft']) && empty($data['prerelease']) && preg_match('/^v?(\d+\.\d+\.\d+)$/', $data['tag_name'] ?? '', $match)) {
                $version = $match[1];
                $expected = 'https://github.com/' . self::REPO . '/releases/download/' . ($data['tag_name'] ?? '') . '/Dares-Email-2FA-v' . $version . '.zip';
                foreach (($data['assets'] ?? []) as $asset) {
                    if (($asset['browser_download_url'] ?? '') === $expected) {
                        $result = ['version' => $version, 'package' => $expected];
                        break;
                    }
                }
            }
        }
        set_site_transient(self::CACHE, $result ?: [], $result ? 6 * HOUR_IN_SECONDS : 15 * MINUTE_IN_SECONDS);
        return $result;
    }
    public function updates($transient) {
        $file = plugin_basename(__DIR__ . '/rex-email-2fa.php');
        if (!is_object($transient) || empty($transient->checked[$file])) { return $transient; }
        $release = $this->release();
        if ($release && version_compare($release['version'], $transient->checked[$file], '>')) {
            $transient->response[$file] = (object) ['slug' => 'rex-email-2fa', 'plugin' => $file, 'new_version' => $release['version'], 'url' => 'https://github.com/' . self::REPO, 'package' => $release['package'], 'requires' => '6.2', 'requires_php' => '7.4'];
        }
        return $transient;
    }
    public function information($result, $action, $args) {
        if ($action !== 'plugin_information' || ($args->slug ?? '') !== 'rex-email-2fa') { return $result; }
        $release = $this->release();
        if (!$release) { return $result; }
        return (object) ['name' => 'Dares E-mail 2FA', 'slug' => 'rex-email-2fa', 'version' => $release['version'], 'homepage' => 'https://github.com/' . self::REPO, 'download_link' => $release['package'], 'requires' => '6.2', 'requires_php' => '7.4', 'sections' => ['description' => 'E-mailverificatie, uitnodigingen en accountgoedkeuring voor WordPress. Bekijk de release op GitHub voor wijzigingen.']];
    }
}
new Dares_2FA_GitHub_Updates();
