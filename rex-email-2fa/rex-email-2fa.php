<?php
/**
 * Plugin Name: Dares E-mail 2FA
 * Description: Nederlandse inlogpagina, e-mailcodes, uitnodigingen en accountgoedkeuring voor WordPress.
 * Plugin URI: https://github.com/spikerm/wordpress-2fa
 * Update URI: https://github.com/spikerm/wordpress-2fa
 * Version: 1.2.2
 * Author: Rex Markesteijn
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * Text Domain: rex-email-2fa
 */
if (!defined('ABSPATH')) { exit; }
final class Rex_Email_2FA {
    private static $instance;
    private $interactive = false;
    private $verified = 0;
    private $challenge = false;
    private $message = '';
    public static function instance() { return self::$instance ?: (self::$instance = new self()); }
    private function __construct() {
        add_filter('authenticate', [$this, 'authenticate'], PHP_INT_MAX, 3);
        add_filter('send_auth_cookies', [$this, 'cookies_allowed'], PHP_INT_MAX, 6);
        add_filter('wp_is_application_passwords_available_for_user', [$this, 'application_passwords'], PHP_INT_MAX, 2);
        add_action('login_init', [$this, 'native_gate']);
        add_action('template_redirect', [$this, 'front_gate'], 0);
        add_shortcode('rex_login', [$this, 'shortcode']);
        add_filter('wp_nav_menu_objects', [$this, 'menu_items'], 20, 2);
        add_filter('render_block_data', [$this, 'navigation_block'], 20, 3);
        add_action('show_user_profile', [$this, 'profile_status'], 20);
        add_action('edit_user_profile', [$this, 'profile_status'], 20);
        add_filter('manage_users_columns', [$this, 'user_columns']);
        add_filter('manage_users_custom_column', [$this, 'user_status_column'], 10, 3);
        add_action('admin_menu', function() { add_options_page('Dares E-mail 2FA', 'Dares E-mail 2FA', 'manage_options', 'rex-email-2fa', [$this, 'settings_page']); });
        add_action('admin_post_rex2fa_settings', [$this, 'save_settings']);
        add_action('admin_post_rex2fa_test', [$this, 'test_email']);
        add_action('admin_post_rex2fa_page', [$this, 'create_page']);
        add_action('rex2fa_cleanup', [$this, 'cleanup']);
    }
    public static function activate($network_wide = false) {
        if ($network_wide) { wp_die('Dares E-mail 2FA ondersteunt geen netwerkactivatie. Activeer de plugin per site.'); }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE {$wpdb->prefix}rex2fa_challenges (
            token_hash varchar(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            code_hash varchar(64) NOT NULL,
            csrf varchar(64) NOT NULL,
            fingerprint varchar(64) NOT NULL,
            expires bigint(20) unsigned NOT NULL,
            attempts int unsigned NOT NULL DEFAULT 0,
            sends int unsigned NOT NULL DEFAULT 1,
            sent_at bigint(20) unsigned NOT NULL,
            remember_flag tinyint NOT NULL DEFAULT 0,
            redirect_url text NOT NULL,
            PRIMARY KEY  (token_hash),
            KEY expires (expires)
        ) $charset;");
        dbDelta("CREATE TABLE {$wpdb->prefix}rex2fa_limits (
            bucket varchar(64) NOT NULL,
            hits int unsigned NOT NULL DEFAULT 0,
            expires bigint(20) unsigned NOT NULL,
            PRIMARY KEY  (bucket),
            KEY expires (expires)
        ) $charset;");
        add_option('rex2fa_options', ['enabled'=>0, 'roles'=>array_keys(wp_roles()->roles), 'redirect'=>home_url('/'), 'subject'=>'Je inlogcode voor {site}', 'body'=>"Hallo {name},\n\nJe inlogcode voor {site} is: {code}\n\nDe code is 5 minuten geldig en kan één keer worden gebruikt.\nHeb je niet geprobeerd in te loggen? Wijzig dan je wachtwoord.\n\n{site}"]);
        if (!wp_next_scheduled('rex2fa_cleanup')) { wp_schedule_event(time()+3600, 'hourly', 'rex2fa_cleanup'); }
    }
    public static function deactivate() { wp_clear_scheduled_hook('rex2fa_cleanup'); }
    private function opts() { return (array)get_option('rex2fa_options', []); }
    private function enabled() {
        if (defined('REX_EMAIL_2FA_DISABLE') && REX_EMAIL_2FA_DISABLE) { return false; }
        return !empty($this->opts()['enabled']);
    }
    private function protected_user($user) {
        if (!$user instanceof WP_User || !$this->enabled()) { return false; }
        return (bool)apply_filters('dares2fa_user_required', (bool)array_intersect($user->roles, $this->opts()['roles'] ?? []), $user);
    }
    public function application_passwords($allowed, $user) { return $this->protected_user($user) ? false : $allowed; }
    public function cookies_allowed($send, $expire, $expiration, $uid, $scheme, $token) {
        return $this->protected_user(get_user_by('id', $uid)) && $this->verified !== (int)$uid ? false : $send;
    }
    private function post($key) { return isset($_POST[$key]) && is_string($_POST[$key]) ? wp_unslash($_POST[$key]) : ''; }
    private function query($key) { return isset($_GET[$key]) && is_string($_GET[$key]) ? wp_unslash($_GET[$key]) : ''; }
    private function cookie_name() { return 'rex2fa_' . substr(hash('sha256', home_url('/')), 0, 12); }
    private function token() {
        $value = $_COOKIE[$this->cookie_name()] ?? '';
        return is_string($value) && preg_match('/^[a-f0-9]{64}$/D', $value) ? $value : '';
    }
    private function cookie($value) {
        setcookie($this->cookie_name(), $value, ['expires'=>$value ? time()+300 : time()-3600, 'path'=>'/', 'secure'=>is_ssl(), 'httponly'=>true, 'samesite'=>'Lax']);
        if ($value) { $_COOKIE[$this->cookie_name()] = $value; } else { unset($_COOKIE[$this->cookie_name()]); }
    }
    private function digest($value) { return hash_hmac('sha256', $value, wp_salt('auth')); }
    private function fingerprint($user) { return $this->digest($user->ID . '|' . $user->user_email . '|' . $user->user_pass); }
    private function table() { global $wpdb; return $wpdb->prefix . 'rex2fa_challenges'; }
    private function rate($bucket, $max, $window) {
        global $wpdb;
        $table = $wpdb->prefix . 'rex2fa_limits'; $key = $this->digest($bucket); $now = time();
        $ok = $wpdb->query($wpdb->prepare("INSERT INTO $table (bucket,hits,expires) VALUES (%s,1,%d) ON DUPLICATE KEY UPDATE hits=IF(expires<=%d,1,hits+1), expires=IF(expires<=%d,%d,expires)", $key, $now+$window, $now, $now, $now+$window));
        return $ok !== false && (int)$wpdb->get_var($wpdb->prepare("SELECT hits FROM $table WHERE bucket=%s", $key)) <= $max;
    }
    private function login_limit($name) {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : 'unknown';
        $a = $this->rate('login-ip:' . $ip, 30, 900);
        $b = $this->rate('login-name:' . strtolower(trim($name)), 10, 900);
        return $a && $b;
    }
    public function authenticate($user, $username, $password) {
        if (!$this->protected_user($user)) { return $user; }
        global $pagenow;
        $native = $pagenow === 'wp-login.php' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && !wp_doing_ajax();
        if (!$this->interactive && !$native) { return new WP_Error('rex2fa_required', 'E-mailverificatie vereist. Log in via de inlogpagina.'); }
        if (!is_ssl()) { return new WP_Error('rex2fa_https', 'Voor veilig inloggen met e-mailcodes is HTTPS vereist.'); }
        if ($native && !$this->login_limit($username)) { return new WP_Error('rex2fa_limit', 'Te veel pogingen. Probeer het over 15 minuten opnieuw.'); }
        $result = $this->start($user);
        if (is_wp_error($result)) { return $result; }
        if ($native) { wp_safe_redirect($this->gate_url()); exit; }
        return new WP_Error('rex2fa_pending', 'Vul de code uit je e-mail in.');
    }
    private function start($user) {
        global $wpdb;
        if (!$this->rate('mail-user:' . $user->ID, 10, 3600)) { return new WP_Error('rex2fa_mail_limit', 'Te veel codes aangevraagd. Probeer het later opnieuw.'); }
        $old = $this->token();
        if ($old) { $wpdb->delete($this->table(), ['token_hash'=>$this->digest($old)]); }
        $token = bin2hex(random_bytes(32)); $code = (string)random_int(100000, 999999); $csrf = bin2hex(random_bytes(32));
        $options = $this->opts();
        $redirect = wp_validate_redirect($this->post('redirect_to'), $options['redirect'] ?? home_url('/'));
        $insert = $wpdb->insert($this->table(), ['token_hash'=>$this->digest($token), 'user_id'=>$user->ID, 'code_hash'=>$this->digest($token . ':' . $code), 'csrf'=>$csrf, 'fingerprint'=>$this->fingerprint($user), 'expires'=>time()+300, 'attempts'=>0, 'sends'=>1, 'sent_at'=>time(), 'remember_flag'=>!empty($_POST['rememberme']) ? 1 : 0, 'redirect_url'=>$redirect]);
        if (!$insert) { return new WP_Error('rex2fa_storage', 'Verificatie kon niet worden gestart. Neem contact op met de beheerder.'); }
        if (!$this->mail($user, $code)) { $wpdb->delete($this->table(), ['token_hash'=>$this->digest($token)]); return new WP_Error('rex2fa_mail', 'De e-mail kon niet worden verstuurd. Neem contact op met de beheerder.'); }
        $this->cookie($token); $this->challenge = true; do_action('dares2fa_audit', 'code_sent', $user->ID, 'Inlogcode verstuurd');
        return true;
    }
    private function mail($user, $code) {
        $opts = $this->opts();
        $values = ['{site}'=>wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES), '{name}'=>$user->display_name, '{code}'=>$code];
        $subject = str_replace(["\r", "\n"], '', strtr($opts['subject'], $values));
        return $GLOBALS['dares2fa_management']->deliver($user->user_email, $subject, strtr($opts['body'], $values));
    }
    private function current_challenge() {
        global $wpdb;
        $token = $this->token(); if (!$token) { return null; }
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $this->table() . ' WHERE token_hash=%s', $this->digest($token)));
        if (!$row) { return null; }
        $user = get_user_by('id', $row->user_id);
        if ((int)$row->expires <= time() || (int)$row->attempts >= 5 || !$this->protected_user($user) || !hash_equals($row->fingerprint, $this->fingerprint($user))) {
            $wpdb->delete($this->table(), ['token_hash'=>$row->token_hash]); return null;
        }
        return $row;
    }
    private function gate_url() { return add_query_arg('action', 'rex_email_2fa', site_url('wp-login.php', 'login')); }
    private function secure_headers() { nocache_headers(); header('Referrer-Policy: no-referrer'); header('X-Robots-Tag: noindex, nofollow'); }
    public function native_gate() {
        if ($this->query('action') !== 'rex_email_2fa') { return; }
        $this->secure_headers(); $this->handle_code();
        login_header('E-mailverificatie'); echo $this->form(); login_footer(); exit;
    }
    public function front_gate() {
        global $post;
        $is_page = $post instanceof WP_Post && has_shortcode($post->post_content, 'rex_login');
        if ($is_page) { $this->secure_headers(); }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { return; }
        if ($this->post('rex2fa_action') === '') { return; }
        $this->secure_headers();
        if ($this->post('rex2fa_action') !== 'login') { $this->handle_code(); return; }
        if (!$this->enabled()) { $this->message = 'Deze inlogpagina is nog niet ingeschakeld door de beheerder.'; return; }
        if (!wp_verify_nonce($this->post('_wpnonce'), 'rex2fa_login')) { $this->message = 'De pagina is verlopen. Vernieuw de pagina en probeer opnieuw.'; return; }
        if (!is_ssl()) { $this->message = 'Voor veilig inloggen is HTTPS vereist.'; return; }
        $username = trim($this->post('log'));
        if (!$this->login_limit($username)) { $this->message = 'Te veel pogingen. Probeer het over 15 minuten opnieuw.'; return; }
        $this->interactive = true;
        $user = wp_signon(['user_login'=>$username, 'user_password'=>$this->post('pwd'), 'remember'=>!empty($_POST['rememberme'])], is_ssl());
        $this->interactive = false;
        if (is_wp_error($user)) {
            if ($user->get_error_code() !== 'rex2fa_pending') { $this->message = in_array($user->get_error_code(), ['rex2fa_mail', 'rex2fa_storage', 'rex2fa_mail_limit', 'rex2fa_approval_required'], true) ? $user->get_error_message() : 'Inloggen niet gelukt. Controleer je gegevens en eventuele Wordfence-instellingen.'; }
            return;
        }
        wp_safe_redirect(wp_validate_redirect($this->post('redirect_to'), $this->opts()['redirect'] ?? home_url('/'))); exit;
    }
    private function handle_code() {
        global $wpdb;
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { return; }
        $row = $this->current_challenge();
        if (!$row) { $this->message = 'De code is verlopen of geblokkeerd. Log opnieuw in.'; $this->cookie(''); return; }
        if (!hash_equals($row->csrf, $this->post('rex2fa_csrf'))) { $this->message = 'Ongeldige aanvraag. Vernieuw de pagina.'; return; }
        $table = $this->table(); $now = time(); $action = $this->post('rex2fa_action');
        if ($action === 'cancel') { $wpdb->delete($table, ['token_hash'=>$row->token_hash]); $this->cookie(''); wp_safe_redirect(wp_login_url()); exit; }
        if ($action === 'resend') {
            $user = get_user_by('id', $row->user_id);
            $code = (string)random_int(100000, 999999);
            if (!$this->rate('mail-user:' . $user->ID, 10, 3600)) { $this->message = 'Te veel codes aangevraagd. Probeer het later opnieuw.'; return; }
            $changed = $wpdb->query($wpdb->prepare("UPDATE $table SET code_hash=%s,sends=sends+1,sent_at=%d WHERE token_hash=%s AND sends<3 AND sent_at<=%d AND expires>%d AND attempts<5", $this->digest($this->token().':'.$code), $now, $row->token_hash, $now-60, $now));
            if ($changed !== 1) { $this->message = 'Wacht 60 seconden tussen e-mails. Je kunt maximaal 3 codes per inlogpoging aanvragen.'; return; }
            if (!$this->mail($user, $code)) { $wpdb->delete($table, ['token_hash'=>$row->token_hash]); $this->cookie(''); $this->message = 'E-mail versturen mislukt. Log opnieuw in of neem contact op met de beheerder.'; return; }
            $this->message = 'Een nieuwe code is verstuurd. Alleen de nieuwste code werkt; de oorspronkelijke vervaltijd blijft gelden.'; return;
        }
        if ($action !== 'verify') { return; }
        $changed = $wpdb->query($wpdb->prepare("UPDATE $table SET attempts=attempts+1 WHERE token_hash=%s AND attempts<5 AND expires>%d", $row->token_hash, $now));
        if ($changed !== 1) { $this->message = 'De code is verlopen of geblokkeerd.'; return; }
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE token_hash=%s", $row->token_hash));
        $code = trim($this->post('code'));
        if (!$row || !preg_match('/^[0-9]{6}$/D', $code) || !hash_equals($row->code_hash, $this->digest($this->token().':'.$code))) {
            do_action('dares2fa_audit', 'code_failed', (int)($row->user_id ?? 0), 'Onjuiste inlogcode');
            $this->message = 'Onjuiste code. ' . max(0, 5-(int)($row->attempts ?? 5)) . ' pogingen over.'; return;
        }
        $user = get_user_by('id', $row->user_id);
        if (!$this->protected_user($user) || !hash_equals($row->fingerprint, $this->fingerprint($user))) { $this->message = 'Je account is gewijzigd. Log opnieuw in.'; return; }
        $consumed = $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE token_hash=%s AND code_hash=%s AND attempts=%d AND expires>%d", $row->token_hash, $row->code_hash, $row->attempts, time()));
        if ($consumed !== 1) { $this->message = 'Deze code is al gebruikt of verlopen. Log opnieuw in.'; return; }
        do_action('dares2fa_audit', 'code_verified', $user->ID, 'E-mailcode gecontroleerd');
        $this->verified = (int)$user->ID;
        $this->cookie(''); wp_set_current_user($user->ID); wp_set_auth_cookie($user->ID, (bool)$row->remember_flag, is_ssl()); do_action('wp_login', $user->user_login, $user);
        wp_safe_redirect(wp_validate_redirect($row->redirect_url, home_url('/'))); exit;
    }
    public function shortcode() {
        if (is_user_logged_in()) { return '<div class="rex2fa-card">Je bent ingelogd als <strong>' . esc_html(wp_get_current_user()->display_name) . '</strong>. <a href="'.esc_url(wp_logout_url(get_permalink())).'">Uitloggen</a></div>'; }
        return $this->form();
    }
    private function form() {
        $row = $this->current_challenge();
        ob_start(); ?>
        <style>.rex2fa-card{box-sizing:border-box;max-width:440px;margin:30px auto;padding:30px;background:#111c2e;color:#e8eef8;border:1px solid #2d405d;border-radius:18px;font:16px/1.55 system-ui,sans-serif;box-shadow:0 16px 40px #0002}.rex2fa-card h2{color:#fff;font-size:26px;margin:0 0 8px}.rex2fa-card p{color:#b5c6dd}.rex2fa-card label{display:block;margin:18px 0 6px}.rex2fa-card input:not([type=checkbox]){box-sizing:border-box;width:100%;background:#081321;color:#fff;border:1px solid #50637e;padding:13px;border-radius:9px;font:inherit}.rex2fa-card input:focus{outline:2px solid #38bdf8;outline-offset:2px}.rex2fa-card button{cursor:pointer;background:#38bdf8;color:#062133;border:0;border-radius:9px;padding:12px 16px;font:600 16px system-ui;margin-top:20px;width:100%}.rex2fa-card button.secondary{background:#20334b;color:#e8eef8;margin-top:10px}.rex2fa-card a{color:#7dd3fc}.rex2fa-card .notice{background:#223751;border-left:3px solid #38bdf8;padding:12px;margin:15px 0}.rex2fa-card .check{display:flex;gap:8px;align-items:center}.rex2fa-card small{color:#b5c6dd}.rex2fa-card .code{letter-spacing:.35em;text-align:center;font-size:25px!important}</style>
        <div class="rex2fa-card">
        <?php echo $GLOBALS['dares2fa_management']->brand_header(); ?>
        <?php if ($this->message): ?><div class="notice" role="alert"><?php echo esc_html($this->message); ?></div><?php endif; ?>
        <?php if ($row): ?>
        <h2>Controleer je e-mail</h2><p>We hebben een code naar het e-mailadres van je account gestuurd. Controleer ook je spammap.</p>
        <form method="post" action="<?php echo esc_url($this->gate_url()); ?>">
            <input type="hidden" name="rex2fa_csrf" value="<?php echo esc_attr($row->csrf); ?>">
            <label for="rex2fa-code">Eenmalige inlogcode</label><input class="code" id="rex2fa-code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required autofocus>
            <small>Geldig tot <?php echo esc_html(wp_date('H:i', $row->expires)); ?> · <?php echo esc_html(5-(int)$row->attempts); ?> pogingen over</small>
            <button type="submit" name="rex2fa_action" value="verify">Code controleren</button>
            <button class="secondary" type="submit" name="rex2fa_action" value="resend" formnovalidate>Nieuwe code versturen</button>
            <button class="secondary" type="submit" name="rex2fa_action" value="cancel" formnovalidate>Opnieuw inloggen</button>
        </form>
        <?php elseif (!$this->enabled()): ?><h2>Inloggen</h2><p>Deze inlogpagina is nog niet ingeschakeld. <a href="<?php echo esc_url(wp_login_url()); ?>">WordPress-login openen</a></p>
        <?php else: ?>
        <h2>Welkom terug</h2><p>Log veilig in op <?php echo esc_html(get_bloginfo('name')); ?>.</p>
        <form method="post" action="<?php echo esc_url(get_permalink() ?: wp_login_url()); ?>">
        <?php wp_nonce_field('rex2fa_login'); ?>
        <input type="hidden" name="rex2fa_action" value="login"><input type="hidden" name="redirect_to" value="<?php echo esc_attr($this->opts()['redirect'] ?? home_url('/')); ?>">
        <label for="rex2fa-log">E-mailadres of gebruikersnaam</label><input id="rex2fa-log" type="text" name="log" autocomplete="username" required>
        <label for="rex2fa-pwd">Wachtwoord</label><input id="rex2fa-pwd" type="password" name="pwd" autocomplete="current-password" required>
        <label class="check"><input type="checkbox" name="rememberme" value="1"> Ingelogd blijven</label><button type="submit">Inloggen</button>
        <p><a href="<?php echo esc_url(wp_lostpassword_url()); ?>">Wachtwoord vergeten?</a></p><?php if (isset($GLOBALS['rex2fa_invitations']) && $GLOBALS['rex2fa_invitations']->enabled()): ?><p><a href="<?php echo esc_url($GLOBALS['rex2fa_invitations']->url()); ?>">Account aanvragen met een uitnodiging</a></p><?php endif; ?>
        </form><?php endif; ?></div>
        <?php return ob_get_clean();
    }
    private function is_login_page($id) {
        $id = (int)$id;
        if (!$id) { return false; }
        $page = get_post($id);
        if (!$page || $page->post_type !== 'page' || $page->post_status !== 'publish') { return false; }
        return has_shortcode($page->post_content, 'rex_login');
    }
    private function is_login_url($url) {
        if (!is_string($url) || $url === '') { return false; }
        // Never convert password-reset, registration or foreign-site links.
        $parts = wp_parse_url($url);
        if (!$parts || !in_array(strtolower($parts['scheme'] ?? 'https'), ['http', 'https'], true)) { return false; }
        $home = wp_parse_url(home_url('/'));
        $site = wp_parse_url(site_url('/'));
        $host = strtolower($parts['host'] ?? $home['host']);
        if (!in_array($host, [strtolower($home['host']), strtolower($site['host'])], true)) { return false; }
        $login = wp_parse_url(wp_login_url());
        if ($host === strtolower($login['host']) && ($parts['path'] ?? '/') === ($login['path'] ?? '')) {
            $query = []; parse_str($parts['query'] ?? '', $query);
            return !isset($query['action']) || $query['action'] === 'login';
        }
        // Make relative links absolute before resolving their WordPress page.
        if (empty($parts['host'])) {
            if (substr($url, 0, 1) === '/') {
                $origin = ($home['scheme'] ?? 'https') . '://' . $home['host'] . (isset($home['port']) ? ':' . $home['port'] : '');
                $url = $origin . $url;
            } else { $url = home_url('/' . ltrim($url, '/')); }
        }
        return $this->is_login_page(url_to_postid($url));
    }
    public function menu_items($items, $args = null) {
        if (is_admin()) { return $items; }
        $logged_in = is_user_logged_in();
        foreach ($items as $index => $item) {
            $marked = in_array('rex-login', (array)($item->classes ?? []), true);
            $page = ($item->object ?? '') === 'page' && $this->is_login_page($item->object_id ?? 0);
            if (!$marked && !$page && !$this->is_login_url($item->url ?? '')) { continue; }
            // Clone: do not mutate objects reused by menu caches or other menus.
            $item = clone $item;
            $item->title = $logged_in ? 'Uitloggen' : 'Inloggen';
            $item->target = ''; $item->xfn = '';
            if ($logged_in) {
                $item->url = wp_logout_url(home_url('/'));
                $item->classes = array_values(array_diff((array)($item->classes ?? []), ['current-menu-item', 'current_page_item', 'current-menu-parent', 'current-menu-ancestor', 'current_page_parent', 'current_page_ancestor']));
                $item->current = false; $item->current_item_parent = false; $item->current_item_ancestor = false;
            }
            $items[$index] = $item;
        }
        return $items;
    }
    public function navigation_block($block, $source = null, $parent = null) {
        if (is_admin() || ($block['blockName'] ?? '') !== 'core/navigation-link') { return $block; }
        $attrs = (array)($block['attrs'] ?? []);
        $classes = preg_split('/\s+/', trim($attrs['className'] ?? ''));
        $marked = in_array('rex-login', $classes, true);
        $page = ($attrs['type'] ?? '') === 'page' && $this->is_login_page($attrs['id'] ?? 0);
        if (!$marked && !$page && !$this->is_login_url($attrs['url'] ?? '')) { return $block; }
        $logged_in = is_user_logged_in();
        $attrs['label'] = $logged_in ? 'Uitloggen' : 'Inloggen';
        $attrs['opensInNewTab'] = false;
        if ($logged_in) {
            $attrs['url'] = wp_logout_url(home_url('/'));
            // A logout action is a custom link, not the current login page.
            unset($attrs['id']); $attrs['kind'] = 'custom'; $attrs['type'] = 'custom';
            unset($attrs['rel']);
        }
        $block['attrs'] = $attrs;
        return $block;
    }
    private function user_2fa_status($user) {
        if (!$user instanceof WP_User) { return ['label'=>'Onbekend', 'detail'=>'Gebruiker niet gevonden.', 'active'=>false]; }
        if (defined('REX_EMAIL_2FA_DISABLE') && REX_EMAIL_2FA_DISABLE) {
            return ['label'=>'Uitgeschakeld via noodherstel', 'detail'=>'De noodinstelling REX_EMAIL_2FA_DISABLE schakelt e-mail-2FA tijdelijk uit.', 'active'=>false];
        }
        if (!$this->enabled()) {
            return ['label'=>'Uitgeschakeld', 'detail'=>'E-mail-2FA is uitgeschakeld in de plugininstellingen.', 'active'=>false];
        }
        if (!$this->protected_user($user)) {
            if (get_user_meta($user->ID, '_dares2fa_policy', true) === 'exempt') { return ['label'=>'Persoonlijke vrijstelling', 'detail'=>'De beheerder heeft deze gebruiker vrijgesteld van e-mail-2FA.', 'active'=>false]; }
            return ['label'=>'Niet verplicht voor deze gebruiker', 'detail'=>'Geen van de huidige gebruikersrollen is geselecteerd voor verplichte e-mail-2FA.', 'active'=>false];
        }
        return ['label'=>'Actief — e-mailcode verplicht', 'detail'=>'Bij een nieuwe wachtwoordlogin is een eenmalige code naar het e-mailadres van dit account verplicht. Er is geen aparte activering per gebruiker nodig.', 'active'=>true];
    }
    private function user_approval_status($user) {
        $status = (string)get_user_meta($user->ID, '_rex2fa_status', true);
        $labels = ['pending_email'=>'Geblokkeerd — wacht op e-mailbevestiging', 'pending'=>'Geblokkeerd — wacht op goedkeuring', 'approving'=>'Geblokkeerd — goedkeuring wordt verwerkt', 'rejected'=>'Geblokkeerd — aanvraag afgewezen', 'cleanup'=>'Geblokkeerd — aanvraag wordt opgeruimd', 'approved'=>'Goedgekeurd'];
        return ['label'=>$labels[$status] ?? 'Bestaand account — geen openstaande aanvraag', 'blocked'=>in_array($status, ['pending_email', 'pending', 'approving', 'rejected', 'cleanup'], true)];
    }
    public function profile_status($user) {
        if (!$user instanceof WP_User || (get_current_user_id() !== (int)$user->ID && !current_user_can('edit_user', $user->ID))) { return; }
        $status = $this->user_2fa_status($user); $approval = $this->user_approval_status($user);
        ?>
        <h2>Dares E-mail 2FA</h2>
        <table class="form-table" role="presentation">
        <tr><th>2FA-status</th><td><strong style="color:<?php echo $status['active'] ? '#16733b' : '#555'; ?>"><?php echo esc_html($status['label']); ?></strong><p class="description"><?php echo esc_html($status['detail']); ?></p>
        <?php if (current_user_can('manage_options')): ?><p><a class="button" href="<?php echo esc_url(admin_url('options-general.php?page=rex-email-2fa')); ?>">2FA-instellingen beheren</a></p><?php else: ?><p class="description">De beheerder bepaalt voor welke gebruikersrollen e-mail-2FA verplicht is.</p><?php endif; ?></td></tr>
        <tr><th>Verificatiemethode</th><td>Eenmalige code via e-mail · 5 minuten geldig</td></tr>
        <tr><th>E-mailadres voor codes</th><td><?php echo esc_html($user->user_email); ?><p class="description">Het opgeslagen e-mailadres van dit WordPress-account wordt gebruikt. Een wijziging hierboven geldt na het opslaan van het profiel.</p></td></tr>
        <tr><th>Accountstatus</th><td><strong><?php echo esc_html($approval['label']); ?></strong><?php if ($approval['blocked']): ?><p class="description">Dit account kan nog niet inloggen, ook als e-mail-2FA is uitgeschakeld.</p><?php endif; ?>
        <?php if (current_user_can('manage_options') && $approval['blocked']): ?><p><a class="button" href="<?php echo esc_url(admin_url('users.php?page=rex2fa-invitations')); ?>">Accountaanvragen bekijken</a></p><?php endif; ?></td></tr>
        </table>
        <?php
    }
    public function user_columns($columns) { $columns['rex_email_2fa'] = 'Dares E-mail 2FA'; return $columns; }
    public function user_status_column($value, $column, $uid) {
        if ($column !== 'rex_email_2fa') { return $value; }
        $user = get_user_by('id', $uid); if (!$user) { return 'Onbekend'; }
        $approval = $this->user_approval_status($user);
        if ($approval['blocked']) { return esc_html($approval['label']); }
        $status = $this->user_2fa_status($user);
        return esc_html($status['label']);
    }
    private function admin_check($nonce) { if (!current_user_can('manage_options')) { wp_die('Geen toegang.'); } check_admin_referer($nonce); }
    private function back($message) { wp_safe_redirect(add_query_arg(['page'=>'rex-email-2fa', 'rex_message'=>$message], admin_url('options-general.php'))); exit; }
    public function save_settings() {
        $this->admin_check('rex2fa_settings'); $roles = [];
        foreach (wp_roles()->roles as $role=>$details) { if (isset($_POST['roles']) && is_array($_POST['roles']) && in_array($role, $_POST['roles'], true)) { $roles[]=$role; } }
        $enabled = !empty($_POST['enabled']);
        if ($enabled && (!is_ssl() || !$roles)) { $this->back('Kies minstens één rol en gebruik HTTPS voordat je verificatie inschakelt.'); }
        $subject = sanitize_text_field($this->post('subject')); $body = sanitize_textarea_field($this->post('body'));
        if (strpos($body, '{code}') === false) { $this->back('De e-mailtekst moet {code} bevatten. Instellingen niet opgeslagen.'); }
        update_option('rex2fa_options', ['enabled'=>$enabled ? 1 : 0, 'roles'=>$roles, 'redirect'=>wp_validate_redirect(esc_url_raw($this->post('redirect')), home_url('/')), 'subject'=>$subject ?: 'Je inlogcode voor {site}', 'body'=>$body]);
        do_action('dares2fa_audit','2fa_settings',0,'Algemene e-mail-2FA-instellingen bijgewerkt');
        $this->back('Instellingen opgeslagen.');
    }
    public function test_email() { $this->admin_check('rex2fa_test'); $this->back($this->mail(wp_get_current_user(), '123456') ? 'Testmail aangeboden aan de mailserver. Controleer je inbox; dit bevestigt nog geen aflevering.' : 'Testmail versturen mislukt. Controleer SMTP.'); }
    public function create_page() {
        $this->admin_check('rex2fa_page');
        $existing = get_post((int)get_option('rex2fa_page_id'));
        if ($existing && $existing->post_status !== 'trash') { $this->back('De inlogpagina bestaat al: ' . get_permalink($existing)); }
        $id = wp_insert_post(['post_type'=>'page', 'post_status'=>'publish', 'post_title'=>'Inloggen', 'post_content'=>'[rex_login]'], true);
        if (is_wp_error($id)) { $this->back('Pagina maken mislukt.'); }
        update_option('rex2fa_page_id', $id); $this->back('Inlogpagina gemaakt: ' . get_permalink($id));
    }
    public function cleanup() { global $wpdb; foreach ([$this->table(), $wpdb->prefix.'rex2fa_limits'] as $table) { $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE expires<=%d", time())); } }
    public function settings_page() {
        if (!current_user_can('manage_options')) { return; } $opts=$this->opts(); ?>
        <div class="wrap"><h1>Dares E-mail 2FA</h1>
        <?php if ($this->query('rex_message')): ?><div class="notice notice-info"><p><?php echo esc_html($this->query('rex_message')); ?></p></div><?php endif; ?>
        <p>Versie 1.2.2 · Eenmalige codes van 6 cijfers · 5 minuten geldig · Maximaal 5 pogingen · HTTPS verplicht</p>
        <div class="notice notice-warning inline"><p><strong>Wordfence:</strong> schakel Wordfence-2FA uit voor gebruikers die deze e-mailverificatie gaan gebruiken en zet verplichte Wordfence-2FA voor die rollen uit. De firewall en scans blijven actief. Test reCAPTCHA apart met de eigen inlogpagina.</p></div>
        <p>Begin met een testmail en een testgebruiker. Houd je huidige beheerderssessie open tijdens de eerste inlogtest. Bestaande sessies worden niet uitgelogd.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('rex2fa_test'); ?><input type="hidden" name="action" value="rex2fa_test"><button class="button">Testmail naar mijn account versturen</button></form>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('rex2fa_settings'); ?><input type="hidden" name="action" value="rex2fa_settings">
        <table class="form-table"><tr><th>Verificatie inschakelen</th><td><label><input type="checkbox" name="enabled" value="1" <?php checked(!empty($opts['enabled'])); ?>> E-mailcodes verplicht voor de gekozen rollen</label></td></tr>
        <tr><th>Gebruikersrollen</th><td><?php foreach (wp_roles()->roles as $role=>$details): ?><label style="display:block"><input type="checkbox" name="roles[]" value="<?php echo esc_attr($role); ?>" <?php checked(in_array($role, $opts['roles'] ?? [], true)); ?>> <?php echo esc_html(translate_user_role($details['name'])); ?></label><?php endforeach; ?></td></tr>
        <tr><th><label for="rex-redirect">Na inloggen</label></th><td><input class="regular-text" id="rex-redirect" type="url" name="redirect" value="<?php echo esc_attr($opts['redirect'] ?? home_url('/')); ?>"><p class="description">Adres op deze website waar gebruikers na inloggen terechtkomen.</p></td></tr>
        <tr><th><label for="rex-subject">E-mailonderwerp</label></th><td><input class="regular-text" id="rex-subject" name="subject" value="<?php echo esc_attr($opts['subject'] ?? ''); ?>"></td></tr>
        <tr><th><label for="rex-body">E-mailtekst</label></th><td><textarea class="large-text" rows="9" id="rex-body" name="body"><?php echo esc_textarea($opts['body'] ?? ''); ?></textarea><p class="description">Gebruik {site}, {name} en {code}. {code} is verplicht.</p></td></tr></table><?php submit_button('Instellingen opslaan'); ?></form>
        <h2>Eigen inlogpagina</h2><p>Plaats <code>[rex_login]</code> op een pagina of gebruik onderstaande knop.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('rex2fa_page'); ?><input type="hidden" name="action" value="rex2fa_page"><button class="button">Inlogpagina aanmaken</button></form>
        <h2>Uitgebreid Dares-beheer</h2><p>Logboek, sessiebeheer, vormgeving, e-mailteksten en automatisch opruimen vind je bij <a href="<?php echo esc_url(admin_url('options-general.php?page=dares2fa-tools')); ?>">Dares 2FA beheer</a>. Persoonlijke 2FA-instellingen staan in het gebruikersprofiel.</p><h2>Registratie op uitnodiging</h2><p>Beheer uitnodigingslinks, codes en accountaanvragen via <a href="<?php echo esc_url(admin_url('users.php?page=rex2fa-invitations')); ?>">Gebruikers → Uitnodigingen en aanvragen</a>. De functie staat standaard uit. E-mailbevestiging en goedkeuring zijn verplicht.</p><h2>Menuknop Inloggen / Uitloggen</h2><p>Voeg de pagina met <code>[rex_login]</code> toe aan je menu. De knop wisselt automatisch tussen Inloggen en Uitloggen, ook in de WordPress Navigatieblokken. Bij een eigen menu-link kun je de CSS-klasse <code>rex-login</code> toevoegen. Na uitloggen keert de bezoeker terug naar de homepage. Wis na de update de website-cache; ingelogde pagina’s mogen niet als publieke pagina worden gecachet.</p><h2>Technische aandachtspunten</h2><p>Sluit de inlogpagina en wp-login.php uit van alle pagina- en CDN-caches. App-wachtwoorden en wachtwoordlogins via XML-RPC/REST zijn geblokkeerd voor beschermde rollen. Deze versie is bedoeld voor één WordPress-site, niet voor netwerkactivatie in Multisite.</p>
        <p>Noodherstel via wp-config.php: <code>define('REX_EMAIL_2FA_DISABLE', true);</code>. Verwijder dit na herstel.</p></div>
        <?php
    }
}
register_activation_hook(__FILE__, ['Rex_Email_2FA', 'activate']);
register_deactivation_hook(__FILE__, ['Rex_Email_2FA', 'deactivate']);
Rex_Email_2FA::instance();

require_once __DIR__ . '/management.php';
require_once __DIR__ . '/invitations.php';

require_once __DIR__ . '/github-updates.php';
