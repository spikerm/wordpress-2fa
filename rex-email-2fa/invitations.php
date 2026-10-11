<?php
if (!defined('ABSPATH')) { exit; }
final class Rex_2FA_Invitations {
    private $message = '';
    private $creating_email = '';
    private $invite_cookie;
    public function __construct() {
        $this->invite_cookie = 'rex2fa_inv_' . substr(hash('sha256', home_url('/')), 0, 12);
        add_action('init', [$this, 'upgrade']);
        add_action('login_init', [$this, 'gate'], 1);
        add_filter('authenticate', [$this, 'pending_auth'], PHP_INT_MAX - 1, 3);
        add_filter('send_auth_cookies', [$this, 'pending_cookies'], PHP_INT_MAX, 6);
        add_filter('determine_current_user', [$this, 'pending_session'], PHP_INT_MAX);
        add_filter('wp_is_application_passwords_available_for_user', [$this, 'pending_api'], PHP_INT_MAX, 2);
        add_filter('pre_option_users_can_register', [$this, 'native_registration']);
        add_shortcode('rex_register', [$this, 'shortcode']);
        add_action('login_form', [$this, 'login_link']);
        add_action('admin_menu', function() { add_users_page('Uitnodigingen en aanvragen', 'Uitnodigingen en aanvragen', 'manage_options', 'rex2fa-invitations', [$this, 'admin_page']); });
        add_action('admin_post_rex2fa_inv_settings', [$this, 'settings']);
        add_action('admin_post_rex2fa_inv_create', [$this, 'create']);
        add_action('admin_post_rex2fa_inv_revoke', [$this, 'revoke']);
        add_action('admin_post_rex2fa_inv_delete', [$this, 'delete_invitation']);
        add_action('admin_post_rex2fa_inv_review', [$this, 'review']);
        add_action('template_redirect', [$this, 'front'], 1);
        add_action('admin_notices', [$this, 'notice']);
    }
    public function upgrade() {
        if (get_option('rex2fa_inv_schema') === '1') { return; }
        global $wpdb; require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE {$wpdb->prefix}rex2fa_invitations (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            token_hash varchar(64) NOT NULL,
            label varchar(190) NOT NULL,
            email varchar(190) NOT NULL DEFAULT '',
            expires bigint(20) unsigned NOT NULL,
            max_uses int unsigned NOT NULL DEFAULT 1,
            uses int unsigned NOT NULL DEFAULT 0,
            revoked tinyint NOT NULL DEFAULT 0,
            created_by bigint(20) unsigned NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY token_hash (token_hash)
        ) $charset;");
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($this->table()))) === $this->table()) {
            add_option('rex2fa_inv_options', ['enabled'=>0, 'role'=>'subscriber']);
            update_option('rex2fa_inv_schema', '1');
        }
    }
    private function table() { global $wpdb; return $wpdb->prefix . 'rex2fa_invitations'; }
    private function opts() { return (array)get_option('rex2fa_inv_options', ['enabled'=>0, 'role'=>'subscriber']); }
    public function enabled() { return !empty($this->opts()['enabled']) && !(defined('REX_EMAIL_2FA_DISABLE') && REX_EMAIL_2FA_DISABLE); }
    private function hash($value) { return hash_hmac('sha256', $value, wp_salt('auth')); }
    private function post($key) { return isset($_POST[$key]) && is_string($_POST[$key]) ? wp_unslash($_POST[$key]) : ''; }
    private function query($key) { return isset($_GET[$key]) && is_string($_GET[$key]) ? wp_unslash($_GET[$key]) : ''; }
    public function login_link() {
        if ($this->enabled()) { echo '<p style="margin:12px 0"><a href="'.esc_url($this->url()).'">Account aanvragen met een uitnodiging</a></p>'; }
    }
    public function url() { return add_query_arg('action', 'rex_register', site_url('wp-login.php', 'login')); }
    private function status($user) { return $user instanceof WP_User ? (string)get_user_meta($user->ID, '_rex2fa_status', true) : ''; }
    private function blocked($user) {
        if (!$user instanceof WP_User) { return false; }
        return in_array($this->status($user), ['pending_email', 'pending', 'approving', 'rejected', 'cleanup'], true) || ($this->creating_email !== '' && strcasecmp($this->creating_email, $user->user_email) === 0);
    }
    public function pending_auth($user, $name, $password) {
        if (!$this->blocked($user)) { return $user; }
        return new WP_Error('rex2fa_approval_required', 'Dit account is nog niet goedgekeurd. Controleer je e-mail of neem contact op met de beheerder.');
    }
    public function pending_cookies($send, $expire, $expiration, $uid, $scheme, $token) { return $this->blocked(get_user_by('id', $uid)) ? false : $send; }
    public function pending_session($uid) { return $uid && $this->blocked(get_user_by('id', $uid)) ? 0 : $uid; }
    public function pending_api($allowed, $user) { return $this->blocked($user) ? false : $allowed; }
    public function native_registration($value) { return $this->enabled() ? 0 : $value; }
    private function headers() { nocache_headers(); header('Referrer-Policy: no-referrer'); header('X-Robots-Tag: noindex, nofollow'); }
    private function cookie($code) {
        setcookie($this->invite_cookie, $code, ['expires'=>$code ? time()+86400 : time()-3600, 'path'=>'/', 'secure'=>is_ssl(), 'httponly'=>true, 'samesite'=>'Lax']);
        $_COOKIE[$this->invite_cookie] = $code;
    }
    private function invitation($code) {
        global $wpdb;
        if (!preg_match('/^[a-f0-9]{32}$/D', $code)) { return null; }
        return $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $this->table() . ' WHERE token_hash=%s AND revoked=0 AND expires>%d AND uses<max_uses', $this->hash($code), time()));
    }
    public function gate() {
        $action = $this->query('action');
        if ($action === 'register' && $this->enabled()) { wp_safe_redirect($this->url()); exit; }
        if (!in_array($action, ['rex_register', 'rex_confirm_email'], true)) { return; }
        $this->headers();
        if ($action === 'rex_confirm_email') { $html = $this->confirmation(); }
        else {
            $code = $this->query('invite');
            if ($code !== '' && $this->enabled() && is_ssl()) {
                if ($this->invitation($code)) { $this->cookie($code); }
                else { $this->cookie(''); }
                wp_safe_redirect($this->url()); exit;
            }
            $this->submit(); $html = $this->form();
        }
        login_header('Aanmelden op uitnodiging'); echo $html; login_footer(); exit;
    }
    public function front() {
        global $post;
        if ($post instanceof WP_Post && has_shortcode($post->post_content, 'rex_register')) { $this->headers(); }
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && $this->post('rex_inv_action') === 'register') { $this->headers(); $this->submit(); }
    }
    public function shortcode() { return $this->form(); }
    private function rate($key, $max, $window) {
        global $wpdb; $table=$wpdb->prefix.'rex2fa_limits'; $key=$this->hash('invitation:'.$key); $now=time();
        $result=$wpdb->query($wpdb->prepare("INSERT INTO $table (bucket,hits,expires) VALUES (%s,1,%d) ON DUPLICATE KEY UPDATE hits=IF(expires<=%d,1,hits+1), expires=IF(expires<=%d,%d,expires)", $key,$now+$window,$now,$now,$now+$window));
        return $result!==false && (int)$wpdb->get_var($wpdb->prepare("SELECT hits FROM $table WHERE bucket=%s",$key)) <= $max;
    }
    private function submit() {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || $this->post('rex_inv_action') !== 'register') { return; }
        if (!$this->enabled() || !is_ssl()) { $this->message='Aanmelden is momenteel niet beschikbaar.'; return; }
        if (!wp_verify_nonce($this->post('_wpnonce'), 'rex2fa_register')) { $this->message='De pagina is verlopen. Vernieuw de pagina.'; return; }
        if (!$this->rate('ip:'.($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 10, 3600)) { $this->message='Te veel aanvragen. Probeer het over een uur opnieuw.'; return; }
        $code=strtolower(preg_replace('/\s+/', '', $this->post('invite_code')));
        if ($code==='') { $code=is_string($_COOKIE[$this->invite_cookie] ?? null) ? $_COOKIE[$this->invite_cookie] : ''; }
        $invite=$this->invitation($code);
        $name=sanitize_text_field($this->post('display_name')); $email=sanitize_email($this->post('email')); $password=$this->post('password');
        if (!$invite || !$name || !is_email($email) || ($invite->email && strcasecmp($invite->email,$email)!==0)) { $this->message='Controleer je naam, e-mailadres en uitnodiging. De uitnodiging kan verlopen, gebruikt of ingetrokken zijn.'; return; }
        if (strlen($password)<12 || strlen($password)>256 || $password!==$this->post('password_again')) { $this->message='Gebruik een wachtwoord van 12 tot 256 tekens en vul het twee keer hetzelfde in.'; return; }
        if (email_exists($email)) { $this->message='Aanmelden is met deze gegevens niet mogelijk. Heb je al een account? Gebruik dan Inloggen of Wachtwoord vergeten.'; return; }
        global $wpdb; $table=$this->table();
        $claimed=$wpdb->query($wpdb->prepare("UPDATE $table SET uses=uses+1 WHERE id=%d AND revoked=0 AND expires>%d AND uses<max_uses", $invite->id,time()));
        if ($claimed!==1) { $this->message='Deze uitnodiging is niet meer beschikbaar.'; return; }
        // No role or access is granted until an administrator approves.
        $username='rex_' . bin2hex(random_bytes(8));
        $this->creating_email=$email;
        $uid=wp_insert_user(['user_login'=>$username,'user_email'=>$email,'user_pass'=>$password,'display_name'=>$name,'role'=>'','meta_input'=>['_rex2fa_status'=>'pending_email','_rex2fa_invite_id'=>(int)$invite->id,'_rex2fa_requested_at'=>time()]]);
        $this->creating_email='';
        if (is_wp_error($uid)) { $wpdb->query($wpdb->prepare("UPDATE $table SET uses=GREATEST(0,uses-1) WHERE id=%d",$invite->id)); $this->message='Aanmelden is niet gelukt. Neem contact op met de beheerder.'; return; }
        WP_Session_Tokens::get_instance($uid)->destroy_all();
        $sent=$this->send_confirmation(get_user_by('id',$uid));
        do_action('dares2fa_audit','application_created',$uid,'Accountaanvraag aangemaakt');
        do_action('dares2fa_audit',$sent?'confirmation_sent':'confirmation_mail_failed',$uid,'Bevestigingsmail '.($sent?'verstuurd':'versturen mislukt'));
        $this->cookie('');
        $this->message=$sent ? 'Je aanvraag is opgeslagen. Bevestig eerst je e-mailadres via de link in je e-mail. Daarna beoordeelt een beheerder je aanvraag. Je kunt nog niet inloggen.' : 'Je aanvraag is opgeslagen, maar de bevestigingsmail kon niet worden verstuurd. Neem contact op met de beheerder; die kan de mail opnieuw versturen.';
    }
    private function send_confirmation($user) {
        $token=bin2hex(random_bytes(32));
        update_user_meta($user->ID,'_rex2fa_email_hash',$this->hash($token));
        update_user_meta($user->ID,'_rex2fa_email_expires',time()+86400);
        update_user_meta($user->ID,'_rex2fa_email_address',$user->user_email);
        $url=add_query_arg(['action'=>'rex_confirm_email','uid'=>$user->ID,'token'=>$token],site_url('wp-login.php','login'));
        return $GLOBALS['dares2fa_management']->send('confirm',$user->user_email,['{name}'=>$user->display_name,'{link}'=>$url]);
    }
    private function confirmation() {
        $uid=absint($this->query('uid') ?: $this->post('uid')); $token=$this->query('token') ?: $this->post('token');
        $valid=$this->can_confirm($uid,$token);
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && $this->post('rex_inv_action')==='confirm') {
            if (!is_ssl() || !$valid || !wp_verify_nonce($this->post('_wpnonce'),'rex2fa_confirm_'.$uid)) { return $this->card('E-mail bevestigen','De link is ongeldig of verlopen. Vraag de beheerder een nieuwe bevestigingsmail.'); }
            if ($this->confirm($uid,$token)) { return $this->card('E-mailadres bevestigd','Je aanvraag wacht nu op goedkeuring door een beheerder. Je ontvangt een e-mail zodra je account is goedgekeurd.'); }
            return $this->card('E-mail bevestigen','Deze link is al gebruikt of verlopen.');
        }
        if (!is_ssl() || !$valid) { return $this->card('E-mail bevestigen','De link is ongeldig, verlopen of al gebruikt. Neem zo nodig contact op met de beheerder.'); }
        $html='<form method="post" action="'.esc_url(add_query_arg('action','rex_confirm_email',site_url('wp-login.php','login'))).'">'.wp_nonce_field('rex2fa_confirm_'.$uid,'_wpnonce',true,false).'<input type="hidden" name="rex_inv_action" value="confirm"><input type="hidden" name="uid" value="'.esc_attr($uid).'"><input type="hidden" name="token" value="'.esc_attr($token).'"><button type="submit">E-mailadres bevestigen</button></form>';
        return $this->card('E-mail bevestigen','Klik hieronder om je aanvraag naar de beheerders te sturen. Een beheerder moet je account daarna nog goedkeuren.',$html);
    }
    private function can_confirm($uid,$token) {
        $user=get_user_by('id',$uid);
        return is_string($token) && preg_match('/^[a-f0-9]{64}$/D',$token) && $user && $this->status($user)==='pending_email' && (int)get_user_meta($uid,'_rex2fa_email_expires',true)>time() && strcasecmp($user->user_email,(string)get_user_meta($uid,'_rex2fa_email_address',true))===0 && hash_equals((string)get_user_meta($uid,'_rex2fa_email_hash',true),$this->hash($token));
    }
    private function confirm($uid,$token) {
        if (!$this->can_confirm($uid,$token) || !update_user_meta($uid,'_rex2fa_status','pending','pending_email')) { return false; }
        delete_user_meta($uid,'_rex2fa_email_hash'); delete_user_meta($uid,'_rex2fa_email_expires');
        update_user_meta($uid,'_rex2fa_email_verified',time());do_action('dares2fa_audit','email_confirmed',$uid,'Aanvraag-e-mailadres bevestigd');
        $user=get_user_by('id',$uid); $url=admin_url('users.php?page=rex2fa-invitations');
        // Notify administrator accounts only after the email has been confirmed.
        $addresses=[];
        foreach (get_users(['role'=>'administrator']) as $admin) { if (user_can($admin,'manage_options') && is_email($admin->user_email)) { $addresses[]=$admin->user_email; } }
        $main=get_option('admin_email'); if (is_email($main)) { $addresses[]=$main; }
        foreach (array_unique($addresses) as $email) { wp_mail($email,'Nieuwe accountaanvraag: '.$user->display_name,"{$user->display_name} ({$user->user_email}) heeft het e-mailadres bevestigd.\n\nBeoordeel de aanvraag hier:\n$url",['Content-Type: text/plain; charset=UTF-8']); }
        return true;
    }
    private function card($title,$text,$html='') {
        // Inline styles also win against theme rules with !important on labels.
        $opts = $GLOBALS['dares2fa_management']->opts();
        $background = sanitize_hex_color($opts['background'] ?? '') ?: '#111c2e';
        $text_color = Dares_2FA_Management::readable_color(sanitize_hex_color($opts['text'] ?? '') ?: '#e8eef8', $background);
        $label_style = 'color:'.$text_color.'!important;-webkit-text-fill-color:'.$text_color.'!important;opacity:1!important;visibility:visible!important;text-shadow:none!important;font-size:16px!important;font-weight:600!important;line-height:1.5!important;';
        $html = str_replace('<label ', '<label style="'.esc_attr($label_style).'" ', $html);
        return '<style>.rex-invite{box-sizing:border-box;max-width:480px;margin:25px auto;padding:28px;border:1px solid #304563;border-radius:16px;background:#111c2e;color:#e8eef8;font:16px/1.5 system-ui}.rex-invite h2{color:#fff}.rex-invite label{display:block;margin:14px 0 5px}.rex-invite input{box-sizing:border-box;width:100%;padding:11px;border-radius:8px;border:1px solid #50637e;background:#081321;color:#fff;font:inherit}.rex-invite button{padding:12px 18px;background:#38bdf8;border:0;border-radius:8px;color:#062133;font-weight:700;cursor:pointer;margin-top:20px}.rex-invite a{color:#7dd3fc}.rex-invite .message{padding:12px;background:#223751;margin:14px 0}</style><div class="rex-invite">'.$GLOBALS['dares2fa_management']->brand_header().'<h2>'.esc_html($title).'</h2><p>'.esc_html($text).'</p>'.$html.'</div>';
    }
    private function form() {
        if (!$this->enabled()) { return $this->card('Aanmelden','Aanmelden op uitnodiging is momenteel uitgeschakeld.'); }
        if (!is_ssl()) { return $this->card('Aanmelden','Voor aanmelden is HTTPS vereist.'); }
        if (is_user_logged_in()) { return $this->card('Aanmelden','Je bent al ingelogd.'); }
        $stored=is_string($_COOKIE[$this->invite_cookie] ?? null) ? $_COOKIE[$this->invite_cookie] : '';
        $has=$this->invitation($stored);
        $html=$this->message ? '<div role="status" class="message">'.esc_html($this->message).'</div>' : '';
        $html.='<form method="post" action="'.esc_url($this->url()).'">'.wp_nonce_field('rex2fa_register','_wpnonce',true,false).'<input type="hidden" name="rex_inv_action" value="register">';
        if (!$has) { $html.='<label for="rex-inv-code">Uitnodigingscode</label><input id="rex-inv-code" name="invite_code" type="text" autocomplete="off" required>'; }
        else { $html.='<p>Je beveiligde uitnodiging is herkend.</p>'; }
        $html.='<label for="rex-inv-name">Naam</label><input id="rex-inv-name" name="display_name" autocomplete="name" maxlength="190" required><label for="rex-inv-email">E-mailadres</label><input id="rex-inv-email" name="email" type="email" autocomplete="email" maxlength="190" required><label for="rex-inv-pass">Wachtwoord (minimaal 12 tekens)</label><input id="rex-inv-pass" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" required><label for="rex-inv-pass-again">Wachtwoord herhalen</label><input id="rex-inv-pass-again" name="password_again" type="password" autocomplete="new-password" minlength="12" maxlength="256" required><button type="submit">Account aanvragen</button></form><p><a href="'.esc_url(wp_login_url()).'">Heb je al een account? Inloggen</a></p>';
        return $this->card('Account aanvragen','Alleen met een uitnodiging. Na e-mailbevestiging moet een beheerder je aanvraag goedkeuren.',$html);
    }
    public function safe_roles() {
        $roles=[];
        foreach (wp_roles()->roles as $key=>$role) {
            $caps=$role['capabilities'];
            if (!empty($caps['manage_options']) || !empty($caps['edit_users']) || !empty($caps['promote_users']) || !empty($caps['activate_plugins'])) { continue; }
            $roles[$key]=$role;
        }
        return $roles;
    }
    private function admin_check($nonce) { if (!current_user_can('manage_options')) { wp_die('Geen toegang.'); } check_admin_referer($nonce); }
    private function back($text) { wp_safe_redirect(add_query_arg(['page'=>'rex2fa-invitations','rex_inv_notice'=>$text],admin_url('users.php'))); exit; }
    public function settings() {
        $this->admin_check('rex2fa_inv_settings'); $role=sanitize_key($this->post('role'));
        if (!isset($this->safe_roles()[$role])) { $this->back('Kies een geldige rol zonder beheerdersrechten.'); }
        if (!empty($_POST['enabled']) && !is_ssl()) { $this->back('HTTPS is vereist.'); }
        update_option('rex2fa_inv_options',['enabled'=>!empty($_POST['enabled'])?1:0,'role'=>$role]);do_action('dares2fa_audit','registration_settings',0,'Uitnodigingsregistratie '.(!empty($_POST['enabled'])?'ingeschakeld':'uitgeschakeld')); $this->back('Instellingen opgeslagen.');
    }
    public function create() {
        $this->admin_check('rex2fa_inv_create');
        if (!$this->enabled() || !is_ssl()) { $this->back('Schakel uitnodigingsregistratie eerst in via HTTPS.'); }
        $label=sanitize_text_field($this->post('label'));$raw_email=trim($this->post('email'));$email=sanitize_email($raw_email);
        if ((!empty($_POST['send_email']) && !is_email($email)) || ($raw_email!=='' && !is_email($email))) { $this->back('Vul een geldig e-mailadres in of laat het veld leeg.'); }
        $days=max(1,min(365,absint($this->post('days'))));$is_link=$this->post('kind')!=='code';$uses=$is_link?1:max(1,min(1000,absint($this->post('max_uses'))));
        $raw=bin2hex(random_bytes(16)); global $wpdb;
        $ok=$wpdb->insert($this->table(),['token_hash'=>$this->hash($raw),'label'=>$label?:'Uitnodiging','email'=>$email,'expires'=>time()+$days*DAY_IN_SECONDS,'max_uses'=>$uses,'uses'=>0,'revoked'=>0,'created_by'=>get_current_user_id()]);
        if (!$ok) { $this->back('Uitnodiging aanmaken mislukt.'); }
        // Show the secret once in this POST response, never in an admin URL or database.
        $url=add_query_arg('invite',$raw,$this->url());$this->headers();
        $id=$wpdb->insert_id;do_action('dares2fa_audit','invite_created',0,'Uitnodiging #'.$id.' aangemaakt');
        $mail_note='';
        if (!empty($_POST['send_email'])) {
            $sent=$GLOBALS['dares2fa_management']->send('invite',$email,['{name}'=>$label?:$email,'{link}'=>$url,'{expires}'=>wp_date('d-m-Y H:i',time()+$days*DAY_IN_SECONDS)]);
            $mail_note=$sent?'Uitnodiging aangeboden aan de mailserver.':'Mail versturen mislukt. Kopieer de link of maak na herstel een nieuwe uitnodiging.';
            do_action('dares2fa_audit',$sent?'invite_mailed':'invite_mail_failed',0,'Uitnodiging #'.$id.' '.($sent?'gemaild':'mailen mislukt'));
        }
        wp_die('<h1>Uitnodiging aangemaakt</h1><p>'.esc_html($mail_note).'</p><p>Kopieer deze gegevens nu. De geheime code wordt niet bewaard en is niet opnieuw op te vragen.</p><p><strong>Code:</strong></p><pre>'.esc_html($raw).'</pre><p><strong>Beveiligde link:</strong></p><p><a href="'.esc_url($url).'">'.esc_html($url).'</a></p><p>Bij een code kan dezelfde link ook worden gebruikt. Een persoonlijke link kan één keer worden gebruikt.</p><p><a href="'.esc_url(admin_url('users.php?page=rex2fa-invitations')).'">Terug naar uitnodigingen</a></p>','Uitnodiging aangemaakt',['response'=>200]);
    }
    public function revoke() { $id=absint($this->post('id'));$this->admin_check('rex2fa_inv_revoke_'.$id);global $wpdb;$wpdb->update($this->table(),['revoked'=>1],['id'=>$id]);do_action('dares2fa_audit','invite_revoked',0,'Uitnodiging #'.$id.' ingetrokken');$this->back('Uitnodiging ingetrokken. Bestaande aanvragen blijven afzonderlijk te beoordelen.'); }
    public function delete_invitation() {
        $id = absint($this->post('id'));
        $this->admin_check('rex2fa_inv_delete_' . $id);
        global $wpdb;
        // Atomic restriction: only revoked invitations can be deleted.
        $deleted = $wpdb->delete($this->table(), ['id'=>$id, 'revoked'=>1], ['%d', '%d']);
        if ($deleted === 1) { do_action('dares2fa_audit','invite_deleted',0,'Ingetrokken uitnodiging #'.$id.' verwijderd'); }
        $this->back($deleted === false ? 'Verwijderen mislukt. Probeer opnieuw.' : ($deleted === 1 ? 'Ingetrokken uitnodiging verwijderd. Accounts en aanvragen blijven behouden.' : 'Deze uitnodiging is niet ingetrokken of is al verwijderd.'));
    }
    public function review() {
        $uid=absint($this->post('uid'));$this->admin_check('rex2fa_inv_review_'.$uid);
        $decision=$this->post('decision');$role=sanitize_key($this->post('role'));
        $result=$this->decide($uid,$decision,$role);
        $this->back(is_wp_error($result)?$result->get_error_message():$result);
    }
    public function decide($uid,$decision,$role) {
        if (!current_user_can('manage_options') || !current_user_can('edit_user',$uid)) { return new WP_Error('forbidden','Geen toegang tot dit account.'); }
        $user=get_user_by('id',$uid);$status=$this->status($user);
        if (!$user || !in_array($status,['pending_email','pending'],true) || $uid===get_current_user_id()) { return new WP_Error('state','Deze aanvraag kan niet worden gewijzigd.'); }
        if ($decision==='resend') {
            if ($status!=='pending_email') { return new WP_Error('state','Dit e-mailadres is al bevestigd.'); }
            if (!$this->rate('resend-user:'.$uid,3,3600)) { return new WP_Error('limit','Maximaal 3 bevestigingsmails per uur.'); }
            $sent=$this->send_confirmation($user);do_action('dares2fa_audit',$sent?'confirmation_resent':'confirmation_mail_failed',$uid,'Bevestigingsmail opnieuw aangevraagd');return $sent?'Bevestigingsmail opnieuw aangeboden aan de mailserver.':new WP_Error('mail','Mail versturen mislukt. Controleer SMTP.');
        }
        if ($decision==='approve') {
            if ($status!=='pending' || !get_user_meta($uid,'_rex2fa_email_verified',true) || strcasecmp($user->user_email,(string)get_user_meta($uid,'_rex2fa_email_address',true))!==0) { return new WP_Error('email','E-mailadres moet eerst bevestigd zijn.'); }
            if (!isset($this->safe_roles()[$role]) || !current_user_can('promote_users')) { return new WP_Error('role','Kies een geldige rol zonder beheerdersrechten.'); }
            // Compare-and-swap prevents two reviewers approving/rejecting simultaneously.
            if (!update_user_meta($uid,'_rex2fa_status','approving','pending')) { return new WP_Error('state','De aanvraag is inmiddels gewijzigd.'); }
            $user->set_role($role); update_user_meta($uid,'_rex2fa_status','approved','approving');
            update_user_meta($uid,'_rex2fa_reviewed_by',get_current_user_id()); update_user_meta($uid,'_rex2fa_reviewed_at',time());
            do_action('dares2fa_audit','application_approved',$uid,'Account goedgekeurd met rol '.$role);
            $sent=$GLOBALS['dares2fa_management']->send('approved',$user->user_email,['{name}'=>$user->display_name,'{link}'=>wp_login_url()]);
            return $sent?'Account goedgekeurd; bericht aangeboden aan de mailserver.':'Account goedgekeurd, maar de melding kon niet worden verstuurd.';
        }
        if ($decision==='reject') {
            if (!update_user_meta($uid,'_rex2fa_status','rejected',$status)) { return new WP_Error('state','De aanvraag is inmiddels gewijzigd.'); }
            $user->set_role('');WP_Session_Tokens::get_instance($uid)->destroy_all();delete_user_meta($uid,'_rex2fa_email_hash');
            update_user_meta($uid,'_rex2fa_reviewed_by',get_current_user_id());update_user_meta($uid,'_rex2fa_reviewed_at',time());
            do_action('dares2fa_audit','application_rejected',$uid,'Accountaanvraag afgewezen');
            $sent=$GLOBALS['dares2fa_management']->send('rejected',$user->user_email,['{name}'=>$user->display_name]);
            return $sent?'Aanvraag afgewezen; bericht aangeboden aan de mailserver.':'Aanvraag afgewezen; melding versturen mislukt.';
        }
        return new WP_Error('action','Ongeldige actie.');
    }
    public function notice() {
        if (!current_user_can('manage_options')) { return; }
        $users=get_users(['meta_key'=>'_rex2fa_status','meta_value'=>'pending','number'=>1,'fields'=>'ID']);
        if ($users) { echo '<div class="notice notice-info"><p>Er staan bevestigde accountaanvragen klaar. <a href="'.esc_url(admin_url('users.php?page=rex2fa-invitations')).'">Aanvragen beoordelen</a></p></div>'; }
    }
    public function admin_page() { $GLOBALS['dares2fa_management']->invitations_page($this); }
}
$GLOBALS['rex2fa_invitations']=new Rex_2FA_Invitations();
