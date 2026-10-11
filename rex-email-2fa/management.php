<?php
if (!defined('ABSPATH')) { exit; }
final class Dares_2FA_Management {
    public function __construct() {
        add_action('init', [$this, 'upgrade']);
        add_action('admin_menu', function() { add_options_page('Dares 2FA beheer', 'Dares 2FA beheer', 'manage_options', 'dares2fa-tools', [$this, 'tools_page']); });
        add_action('admin_post_dares2fa_tools', [$this, 'save_tools']);
        add_action('admin_post_dares2fa_bulk', [$this, 'bulk']);
        add_action('admin_post_dares2fa_sessions', [$this, 'sessions']);
        add_action('admin_post_dares2fa_cleanup', [$this, 'manual_cleanup']);
        add_action('personal_options_update', [$this, 'save_user']);
        add_action('edit_user_profile_update', [$this, 'save_user']);
        add_action('show_user_profile', [$this, 'user_controls'], 25);
        add_action('edit_user_profile', [$this, 'user_controls'], 25);
        add_filter('dares2fa_user_required', [$this, 'user_required'], 10, 2);
        add_action('dares2fa_audit', [$this, 'audit'], 10, 3);
        add_action('wp_login', function($name,$user) { $this->audit('login_success',$user->ID,'Inloggen geslaagd'); }, 10, 2);
        add_action('wp_login_failed', function($name,$error=null) {
            if ($error instanceof WP_Error && $error->get_error_code()==='rex2fa_pending') { return; }
            $this->audit('login_failed',0,'Inloggen geweigerd');
        },10,2);
        add_action('wp_logout', function($uid) { $this->audit('logout',(int)$uid,'Uitgelogd'); });
        add_action('rex2fa_cleanup', [$this, 'scheduled_cleanup']);
        add_action('login_enqueue_scripts', [$this, 'brand_styles']);
        add_action('wp_head', [$this, 'brand_styles']);
    }
    public function opts() { return (array)get_option('dares2fa_management', []); }
    private function post($key) { return isset($_POST[$key]) && is_string($_POST[$key]) ? wp_unslash($_POST[$key]) : ''; }
    private function query($key) { return isset($_GET[$key]) && is_string($_GET[$key]) ? wp_unslash($_GET[$key]) : ''; }
    private function table() { global $wpdb; return $wpdb->prefix.'dares2fa_audit'; }
    public function upgrade() {
        if (get_option('dares2fa_schema')==='1') { return; }
        global $wpdb;require_once ABSPATH.'wp-admin/includes/upgrade.php';$charset=$wpdb->get_charset_collate();
        dbDelta("CREATE TABLE {$wpdb->prefix}dares2fa_audit (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            created bigint(20) unsigned NOT NULL,
            actor bigint(20) unsigned NOT NULL DEFAULT 0,
            subject bigint(20) unsigned NOT NULL DEFAULT 0,
            event varchar(64) NOT NULL,
            detail varchar(500) NOT NULL,
            PRIMARY KEY  (id),
            KEY created (created),
            KEY event (event)
        ) $charset;");
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($this->table())))===$this->table()) { update_option('dares2fa_schema','1'); }
    }
    public function audit($event,$subject=0,$detail='') {
        global $wpdb;
        if (get_option('dares2fa_schema')!=='1') { return; }
        // No passwords, codes, token URLs, email addresses or IP addresses in this log.
        $wpdb->insert($this->table(),['created'=>time(),'actor'=>get_current_user_id(),'subject'=>(int)$subject,'event'=>substr(sanitize_key($event),0,64),'detail'=>dares2fa_substr(sanitize_text_field($detail),0,500)]);
    }
    private function check($nonce) { if (!current_user_can('manage_options')) { wp_die('Geen toegang.'); }check_admin_referer($nonce); }
    private function back($message,$page='dares2fa-tools') { $path=$page==='rex2fa-invitations'?'users.php':'options-general.php';wp_safe_redirect(add_query_arg(['page'=>$page,'dares_notice'=>$message],admin_url($path)));exit; }
    public function user_required($required,$user) {
        $mode=(string)get_user_meta($user->ID,'_dares2fa_policy',true);
        if ($mode==='required') { return true; }
        if ($mode==='exempt') { return false; }
        return $required;
    }
    public function save_user($uid) {
        if (!isset($_POST['dares2fa_policy'])) { return; }
        if (!current_user_can('manage_options') || !current_user_can('edit_user',$uid)) { return; }
        if (!wp_verify_nonce($this->post('_dares2fa_profile_nonce'),'dares2fa_profile_'.$uid)) { return; }
        $mode=$this->post('dares2fa_policy');if (!in_array($mode,['inherit','required','exempt'],true)) { return; }
        if ((string)get_user_meta($uid,'_dares2fa_policy',true)!==$mode) { update_user_meta($uid,'_dares2fa_policy',$mode);$this->audit('user_2fa_policy',$uid,'Persoonlijke 2FA-instelling: '.['inherit'=>'rollen volgen','required'=>'verplicht','exempt'=>'vrijstelling'][$mode]); }
    }
    public function user_controls($user) {
        if (!current_user_can('manage_options') || !current_user_can('edit_user',$user->ID)) { return; }
        $mode=get_user_meta($user->ID,'_dares2fa_policy',true) ?: 'inherit';
        $count=count(WP_Session_Tokens::get_instance($user->ID)->get_all()); ?>
        <h2>Dares 2FA: persoonlijke instelling en sessies</h2><table class="form-table"><tr><th>Persoonlijke 2FA-instelling</th><td>
        <?php wp_nonce_field('dares2fa_profile_'.$user->ID,'_dares2fa_profile_nonce'); ?>
        <select name="dares2fa_policy"><option value="inherit" <?php selected($mode,'inherit'); ?>>Gebruikersrollen volgen</option><option value="required" <?php selected($mode,'required'); ?>>E-mail-2FA verplicht voor deze gebruiker</option><option value="exempt" <?php selected($mode,'exempt'); ?>>Vrijstelling voor deze gebruiker</option></select>
        <p class="description">Opslaan via Profiel bijwerken. De algemene 2FA-schakelaar blijft leidend; accountgoedkeuring blijft verplicht.</p></td></tr>
        <tr><th>Actieve sessies</th><td><?php echo esc_html($count); ?> sessie(s). <a href="<?php echo esc_url(add_query_arg(['page'=>'dares2fa-tools','tab'=>'sessions','uid'=>$user->ID],admin_url('options-general.php'))); ?>">Sessies beheren</a><p class="description">Alle sessies beëindigen vraagt een beveiligd POST-verzoek in het beheerscherm.</p></td></tr></table>
        <?php
    }
    public function terminate($uid) {
        if (!current_user_can('manage_options') || !current_user_can('edit_user',$uid) || !get_user_by('id',$uid)) { return new WP_Error('access','Geen toegang tot dit account.'); }
        WP_Session_Tokens::get_instance($uid)->destroy_all();
        // Also cancel pending email-code challenges, so they cannot restore a session.
        global $wpdb;$wpdb->delete($wpdb->prefix.'rex2fa_challenges',['user_id'=>$uid],['%d']);
        $this->audit('sessions_ended',$uid,'Alle sessies en openstaande inlogcodes beëindigd');return true;
    }
    public function sessions() { $uid=absint($this->post('uid'));$this->check('dares2fa_sessions_'.$uid);$r=$this->terminate($uid);$this->back(is_wp_error($r)?$r->get_error_message():'Alle sessies beëindigd.'); }
    public function defaults() {
        return [
            'invite'=>['subject'=>'Uitnodiging voor {site}','body'=>"Hallo {name},\n\nJe bent uitgenodigd om een account aan te vragen bij {site}.\n\nOpen deze beveiligde link:\n{link}\n\nGeldig tot {expires}. Na e-mailbevestiging moet een beheerder je account nog goedkeuren."],
            'confirm'=>['subject'=>'Bevestig je e-mailadres voor {site}','body'=>"Hallo {name},\n\nBevestig je e-mailadres via deze link:\n{link}\n\nDe link is 24 uur geldig. Een beheerder moet je account daarna nog goedkeuren.\nHeb je dit niet aangevraagd? Je kunt deze e-mail negeren."],
            'approved'=>['subject'=>'Je account is goedgekeurd','body'=>"Hallo {name},\n\nJe account voor {site} is goedgekeurd. Log in met je e-mailadres en je gekozen wachtwoord:\n{link}"],
            'rejected'=>['subject'=>'Je accountaanvraag is afgewezen','body'=>"Hallo {name},\n\nEen beheerder heeft je accountaanvraag voor {site} afgewezen. Neem contact op met de beheerder als je hierover vragen hebt."]
        ];
    }
    public function send($type,$email,$values=[]) {
        $defaults=$this->defaults();if (!isset($defaults[$type]) || !is_email($email)) { return false; }
        $opts=$this->opts();$template=$opts['templates'][$type]??$defaults[$type];
        $values=array_merge(['{site}'=>wp_specialchars_decode(get_bloginfo('name'),ENT_QUOTES),'{name}'=>$email,'{email}'=>$email,'{link}'=>'','{expires}'=>''], $values);
        $subject=str_replace(["\r","\n"],'',strtr($template['subject'],$values));
        return $this->deliver($email,$subject,strtr($template['body'],$values));
    }
    public function deliver($email,$subject,$body) {
        $opts=$this->opts();$headers=['Content-Type: text/plain; charset=UTF-8'];
        if (!empty($opts['sender_email']) && is_email($opts['sender_email'])) {
            $sender=str_replace(['<','>',"\r","\n"],'',$opts['sender_name']??'Dares');$headers[]='From: '.$sender.' <'.$opts['sender_email'].'>';
        }
        return wp_mail($email,$subject,$body,$headers);
    }
    public function brand_header() {
        $opts=$this->opts();$html='';$id=absint($opts['logo_id']??0);
        if ($id && wp_attachment_is_image($id)) { $src=wp_get_attachment_image_url($id,'medium');if($src){$html.='<img src="'.esc_url($src).'" alt="'.esc_attr(get_bloginfo('name')).'" style="display:block;max-width:180px;max-height:90px;height:auto;margin:0 auto 18px">';} }
        if (!empty($opts['brand_title'])) { $html.='<p style="text-align:center;font-weight:700">'.esc_html($opts['brand_title']).'</p>'; }
        return $html;
    }
    public function brand_styles() {
        $opts=$this->opts();$accent=sanitize_hex_color($opts['accent']??'') ?: '#38bdf8';$background=sanitize_hex_color($opts['background']??'') ?: '#111c2e';$text=sanitize_hex_color($opts['text']??'') ?: '#e8eef8';
        echo '<style>.rex2fa-card,.rex-invite{background:'.esc_attr($background).'!important;color:'.esc_attr($text).'!important}.rex2fa-card h2,.rex-invite h2,.rex2fa-card p,.rex-invite p,.rex2fa-card small{color:'.esc_attr($text).'!important}.rex2fa-card button:not(.secondary),.rex-invite button{background:'.esc_attr($accent).'!important}.rex2fa-card a,.rex-invite a{color:'.esc_attr($accent).'!important}</style>';
    }
    public function save_tools() {
        $this->check('dares2fa_tools');$opts=$this->opts();$templates=[];
        foreach($this->defaults() as $type=>$default){$subject=sanitize_text_field($this->post($type.'_subject'));$body=sanitize_textarea_field($this->post($type.'_body'));
            if(in_array($type,['invite','confirm','approved'],true)&&strpos($body,'{link}')===false){$this->back('De e-mailtekst voor '.$type.' moet {link} bevatten.');}
            $templates[$type]=['subject'=>$subject?:$default['subject'],'body'=>$body?:$default['body']];
        }
        $sender=sanitize_email($this->post('sender_email'));if($this->post('sender_email')!==''&&!is_email($sender)){$this->back('Ongeldig afzenderadres.');}
        $logo=absint($this->post('logo_id'));if($logo&&!wp_attachment_is_image($logo)){$this->back('Kies een afbeelding uit de mediabibliotheek.');}
        $opts=array_merge($opts,['templates'=>$templates,'sender_email'=>$sender,'sender_name'=>sanitize_text_field($this->post('sender_name')),'brand_title'=>sanitize_text_field($this->post('brand_title')),'logo_id'=>$logo,'accent'=>sanitize_hex_color($this->post('accent'))?:'#38bdf8','background'=>sanitize_hex_color($this->post('background'))?:'#111c2e','text'=>sanitize_hex_color($this->post('text'))?:'#e8eef8','cleanup_enabled'=>!empty($_POST['cleanup_enabled'])?1:0,'cleanup_days'=>max(1,min(365,absint($this->post('cleanup_days')))),'log_days'=>max(1,min(365,absint($this->post('log_days'))))]);
        update_option('dares2fa_management',$opts);$this->audit('settings_updated',0,'Vormgeving, mail en opruiminstellingen opgeslagen');$this->back('Instellingen opgeslagen.');
    }
    public function cleanup_candidates($offset = 0) {
        $opts=$this->opts();$before=time()-max(1,(int)($opts['cleanup_days']??30))*DAY_IN_SECONDS;
        return get_users(['number'=>100,'offset'=>max(0,(int)$offset),'fields'=>'all','meta_query'=>['relation'=>'AND',['key'=>'_rex2fa_status','value'=>'pending_email'],['key'=>'_rex2fa_requested_at','value'=>$before,'compare'=>'<','type'=>'NUMERIC']]]);
    }
    public function cleanup_accounts() {
        if(empty($this->opts()['cleanup_enabled'])){return 0;}
        require_once ABSPATH.'wp-admin/includes/user.php';$deleted=0;
        $offset=max(0,(int)get_option('dares2fa_cleanup_offset',0));
        $candidates=$this->cleanup_candidates($offset);
        foreach($candidates as $user){
            // Claim only still-unconfirmed applications; confirmed/approved accounts are excluded.
            if($user->roles || user_can($user,'manage_options')){continue;}
            global $wpdb;
            if ($wpdb->get_var($wpdb->prepare("SELECT ID FROM {$wpdb->posts} WHERE post_author=%d LIMIT 1", $user->ID))) { continue; }
            if(!update_user_meta($user->ID,'_rex2fa_status','cleanup','pending_email')){continue;}
            if(wp_delete_user($user->ID)){$deleted++;$this->audit('application_expired',$user->ID,'Oude onbevestigde aanvraag verwijderd');}
            else{update_user_meta($user->ID,'_rex2fa_status','pending_email','cleanup');}
        }
        update_option('dares2fa_cleanup_offset',count($candidates)<100?0:$offset+count($candidates)-$deleted);
        return $deleted;
    }
    public function scheduled_cleanup() {
        $this->cleanup_accounts();global $wpdb;$days=max(1,(int)($this->opts()['log_days']??90));$wpdb->query($wpdb->prepare('DELETE FROM '.$this->table().' WHERE created<%d',time()-$days*DAY_IN_SECONDS));
    }
    public function manual_cleanup() { $this->check('dares2fa_cleanup');$n=$this->cleanup_accounts();$this->back($n.' onbevestigde aanvragen verwijderd.'); }
    public function bulk() {
        $this->check('dares2fa_bulk');$ids=$_POST['ids']??[];if(!is_array($ids)){$this->back('Selecteer aanvragen of uitnodigingen.','rex2fa-invitations');}
        $ids=array_slice(array_unique(array_filter(array_map('absint',$ids))),0,100);$kind=$this->post('kind');$action=$this->post('bulk_action');$role=sanitize_key($this->post('role'));$ok=0;$skip=0;
        $inv=$GLOBALS['rex2fa_invitations'];global $wpdb;
        foreach($ids as $id){
            if($kind==='requests'&&in_array($action,['approve','reject','resend'],true)){$r=$inv->decide($id,$action,$role);if(is_wp_error($r)){$skip++;}else{$ok++;}}
            elseif($kind==='invites'&&$action==='revoke'){$r=$wpdb->update($wpdb->prefix.'rex2fa_invitations',['revoked'=>1],['id'=>$id,'revoked'=>0],['%d'],['%d','%d']);if($r===1){$ok++;$this->audit('invite_revoked',0,'Uitnodiging #'.$id.' ingetrokken');}else{$skip++;}}
            elseif($kind==='invites'&&$action==='delete'){$r=$wpdb->delete($wpdb->prefix.'rex2fa_invitations',['id'=>$id,'revoked'=>1],['%d','%d']);if($r===1){$ok++;$this->audit('invite_deleted',0,'Ingetrokken uitnodiging #'.$id.' verwijderd');}else{$skip++;}}
            else{$skip++;}
        }
        $this->back($ok.' uitgevoerd; '.$skip.' overgeslagen of geweigerd.','rex2fa-invitations');
    }
    private function tabs($active) {
        echo '<h2 class="nav-tab-wrapper">';foreach(['requests'=>'Accountaanvragen','invites'=>'Uitnodigingen','setup'=>'Registratie-instellingen'] as $key=>$label){echo '<a class="nav-tab '.($key===$active?'nav-tab-active':'').'" href="'.esc_url(add_query_arg(['page'=>'rex2fa-invitations','tab'=>$key],admin_url('users.php'))).'">'.esc_html($label).'</a>';}
        echo '<a class="nav-tab" href="'.esc_url(admin_url('options-general.php?page=dares2fa-tools')).'">Logboek, sessies en vormgeving</a></h2>';
    }
    private function pagination($total,$page,$size=25) {
        if($total<=$size){return;}echo '<div class="tablenav"><div class="tablenav-pages">'.wp_kses_post(paginate_links(['base'=>add_query_arg('paged','%#%'),'format'=>'','current'=>$page,'total'=>(int)ceil($total/$size)])).'</div></div>';
    }
    public function invitations_page($inv) {
        if(!current_user_can('manage_options')){return;}$tab=$this->query('tab');if(!in_array($tab,['requests','invites','setup'],true)){$tab='requests';}
        $roles=$inv->safe_roles();$opts=(array)get_option('rex2fa_inv_options');echo '<div class="wrap"><h1>Dares E-mail 2FA: uitnodigingen en aanvragen</h1>';$this->tabs($tab);
        $notice=$this->query('dares_notice')?:$this->query('rex_inv_notice');if($notice){echo '<div class="notice notice-info"><p>'.esc_html($notice).'</p></div>';}
        if($tab==='setup'){$this->invitation_setup($inv,$roles,$opts);}
        elseif($tab==='invites'){$this->invitation_list($inv);}
        else{$this->request_list($inv,$roles,$opts);}echo '</div>';
    }
    private function invitation_setup($inv,$roles,$opts) { ?>
        <p>Een uitnodiging geeft alleen recht om een aanvraag te doen. E-mailbevestiging en beheerdergoedkeuring blijven verplicht.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('rex2fa_inv_settings'); ?><input type="hidden" name="action" value="rex2fa_inv_settings"><p><label><input type="checkbox" name="enabled" value="1" <?php checked(!empty($opts['enabled'])); ?>> Registratie op uitnodiging inschakelen</label></p><p>Voorgestelde rol <select name="role"><?php $this->role_options($roles,$opts['role']??'subscriber'); ?></select></p><?php submit_button('Instellingen opslaan'); ?></form>
        <p>Registratieadres: <a href="<?php echo esc_url($inv->url()); ?>"><?php echo esc_html($inv->url()); ?></a>. Eigen pagina: <code>[rex_register]</code>.</p>
        <h2>Uitnodiging maken of mailen</h2><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('rex2fa_inv_create'); ?><input type="hidden" name="action" value="rex2fa_inv_create"><table class="form-table"><tr><th>Omschrijving</th><td><input class="regular-text" name="label" maxlength="190" required></td></tr><tr><th>Type</th><td><select name="kind"><option value="link">Persoonlijke link (één keer)</option><option value="code">Deelbare code</option></select></td></tr><tr><th>E-mailadres (optioneel)</th><td><input class="regular-text" name="email" type="email"><p class="description">Een ingevuld adres bindt de uitnodiging aan die persoon.</p></td></tr><tr><th>Geldigheid in dagen</th><td><input name="days" type="number" min="1" max="365" value="7"></td></tr><tr><th>Gebruikslimiet bij een code</th><td><input name="max_uses" type="number" min="1" max="1000" value="1"></td></tr><tr><th>Direct mailen</th><td><label><input type="checkbox" name="send_email" value="1"> Mail deze uitnodiging naar het ingevulde adres</label><p class="description">Het geheime adres wordt één keer getoond. Later opnieuw mailen vereist een nieuwe uitnodiging.</p></td></tr></table><?php submit_button('Uitnodiging maken','secondary'); ?></form>
        <?php
    }
    private function role_options($roles,$selected) {foreach($roles as $key=>$role){echo '<option value="'.esc_attr($key).'" '.selected($selected,$key,false).'>'.esc_html(translate_user_role($role['name'])).'</option>';}}
    private function request_list($inv,$roles,$opts) {
        $q=sanitize_text_field($this->query('q'));$status=$this->query('status');$role=sanitize_key($this->query('role_filter'));$page=max(1,absint($this->query('paged')));
        $states=['open'=>'Openstaand','all'=>'Alle aanvragen','pending_email'=>'E-mail nog niet bevestigd','pending'=>'Wacht op goedkeuring','approved'=>'Goedgekeurd','rejected'=>'Afgewezen'];if(!isset($states[$status])){$status='open';}
        $values=$status==='all'?['pending_email','pending','approved','rejected','approving']:($status==='open'?['pending_email','pending']:[$status]);
        $args=['meta_query'=>[['key'=>'_rex2fa_status','value'=>$values,'compare'=>'IN']],'number'=>25,'offset'=>($page-1)*25,'orderby'=>'registered','order'=>'DESC','count_total'=>true];
        if($q!==''){$args['search']='*'.$q.'*';$args['search_columns']=['user_login','user_email','display_name'];}if($role&&get_role($role)){$args['role']=$role;}
        $query=new WP_User_Query($args);$users=$query->get_results(); ?>
        <h2>Accountaanvragen</h2><form method="get"><input type="hidden" name="page" value="rex2fa-invitations"><input type="hidden" name="tab" value="requests"><input name="q" placeholder="Naam of e-mailadres" value="<?php echo esc_attr($q); ?>"><select name="status"><?php foreach($states as $key=>$label): ?><option value="<?php echo esc_attr($key); ?>" <?php selected($status,$key); ?>><?php echo esc_html($label); ?></option><?php endforeach; ?></select><select name="role_filter"><option value="">Alle rollen</option><?php $this->role_options(wp_roles()->roles,$role); ?></select><button class="button">Zoeken / filteren</button></form>
        <form id="dares-bulk" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('dares2fa_bulk'); ?><input type="hidden" name="action" value="dares2fa_bulk"><input type="hidden" name="kind" value="requests"><p><select name="bulk_action"><option value="approve">Geselecteerde aanvragen goedkeuren</option><option value="reject">Geselecteerde aanvragen afwijzen</option><option value="resend">Bevestigingsmail opnieuw versturen</option></select> <select name="role"><?php $this->role_options($roles,$opts['role']??'subscriber'); ?></select> <button class="button">Uitvoeren op selectie</button></p></form>
        <table class="widefat striped"><thead><tr><th><input type="checkbox" aria-label="Alles op deze pagina selecteren" onclick="document.querySelectorAll('.dares-select').forEach(e=>e.checked=this.checked)"></th><th>Naam / e-mail</th><th>Status</th><th>Acties</th></tr></thead><tbody>
        <?php foreach($users as $user):$s=get_user_meta($user->ID,'_rex2fa_status',true); ?><tr><td><input form="dares-bulk" class="dares-select" type="checkbox" name="ids[]" value="<?php echo esc_attr($user->ID); ?>" aria-label="<?php echo esc_attr($user->display_name.' selecteren'); ?>"></td><td><a href="<?php echo esc_url(get_edit_user_link($user->ID)); ?>"><?php echo esc_html($user->display_name); ?></a><br><?php echo esc_html($user->user_email); ?></td><td><?php echo esc_html($states[$s]??$s); ?></td><td>
        <?php if(in_array($s,['pending_email','pending'],true)): ?><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('rex2fa_inv_review_'.$user->ID); ?><input type="hidden" name="action" value="rex2fa_inv_review"><input type="hidden" name="uid" value="<?php echo esc_attr($user->ID); ?>"><?php if($s==='pending'): ?><select name="role"><?php $this->role_options($roles,$opts['role']??'subscriber'); ?></select> <button class="button button-primary" name="decision" value="approve">Goedkeuren</button><?php else: ?><button class="button" name="decision" value="resend">Bevestigingsmail opnieuw</button><?php endif; ?> <button class="button" name="decision" value="reject">Afwijzen</button></form><?php else: ?>Afgehandeld<?php endif; ?></td></tr><?php endforeach; ?>
        <?php if(!$users): ?><tr><td colspan="4">Geen aanvragen voor deze filters.</td></tr><?php endif; ?></tbody></table>
        <?php $this->pagination($query->get_total(),$page);
    }
    private function invitation_list($inv) {
        global $wpdb;$table=$wpdb->prefix.'rex2fa_invitations';$q=sanitize_text_field($this->query('q'));$status=$this->query('status');$page=max(1,absint($this->query('paged')));
        $states=['all'=>'Alle uitnodigingen','active'=>'Actief','revoked'=>'Ingetrokken','expired'=>'Verlopen','used'=>'Opgebruikt'];if(!isset($states[$status])){$status='all';}$where='1=1';$params=[];
        if($q!==''){$like='%'.$wpdb->esc_like($q).'%';$where.=' AND (label LIKE %s OR email LIKE %s)';$params=[$like,$like];}
        if($status==='revoked'){$where.=' AND revoked=1';}elseif($status==='active'){$where.=' AND revoked=0 AND expires>%d AND uses<max_uses';$params[]=time();}elseif($status==='expired'){$where.=' AND revoked=0 AND expires<=%d';$params[]=time();}elseif($status==='used'){$where.=' AND revoked=0 AND uses>=max_uses';}
        $sql='SELECT COUNT(*) FROM '.$table.' WHERE '.$where;$total=(int)$wpdb->get_var($params?$wpdb->prepare($sql,$params):$sql);
        $sql='SELECT * FROM '.$table.' WHERE '.$where.' ORDER BY id DESC LIMIT %d OFFSET %d';$rows=$wpdb->get_results($wpdb->prepare($sql,array_merge($params,[25,($page-1)*25]))); ?>
        <h2>Uitnodigingen</h2><p><a class="button button-primary" href="<?php echo esc_url(admin_url('users.php?page=rex2fa-invitations&tab=setup')); ?>">Nieuwe uitnodiging / mailen</a></p><form method="get"><input type="hidden" name="page" value="rex2fa-invitations"><input type="hidden" name="tab" value="invites"><input name="q" placeholder="Omschrijving of e-mailadres" value="<?php echo esc_attr($q); ?>"><select name="status"><?php foreach($states as $key=>$label): ?><option value="<?php echo esc_attr($key); ?>" <?php selected($status,$key); ?>><?php echo esc_html($label); ?></option><?php endforeach; ?></select> <button class="button">Zoeken / filteren</button></form>
        <form id="dares-bulk" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('dares2fa_bulk'); ?><input type="hidden" name="action" value="dares2fa_bulk"><input type="hidden" name="kind" value="invites"><p><select name="bulk_action"><option value="revoke">Selectie intrekken</option><option value="delete">Ingetrokken uitnodigingen uit selectie verwijderen</option></select> <button class="button">Uitvoeren op selectie</button></p></form>
        <table class="widefat striped"><thead><tr><th><input type="checkbox" aria-label="Alles op deze pagina selecteren" onclick="document.querySelectorAll('.dares-select').forEach(e=>e.checked=this.checked)"></th><th>Omschrijving</th><th>E-mail</th><th>Gebruik</th><th>Geldig tot</th><th>Status / actie</th></tr></thead><tbody>
        <?php foreach($rows as $row): ?><tr><td><input form="dares-bulk" class="dares-select" type="checkbox" name="ids[]" value="<?php echo esc_attr($row->id); ?>" aria-label="Uitnodiging selecteren"></td><td><?php echo esc_html($row->label); ?></td><td><?php echo esc_html($row->email?:'Iedere genodigde'); ?></td><td><?php echo esc_html($row->uses.' / '.$row->max_uses); ?></td><td><?php echo esc_html(wp_date('d-m-Y H:i',$row->expires)); ?></td><td><?php echo esc_html($row->revoked?'Ingetrokken':($row->expires<=time()?'Verlopen':($row->uses>=$row->max_uses?'Opgebruikt':'Actief'))); ?><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php $action=$row->revoked?'delete':'revoke';wp_nonce_field('rex2fa_inv_'.$action.'_'.$row->id); ?><input type="hidden" name="action" value="rex2fa_inv_<?php echo esc_attr($action); ?>"><input type="hidden" name="id" value="<?php echo esc_attr($row->id); ?>"><button class="button"><?php echo $row->revoked?'Verwijderen':'Intrekken'; ?></button></form></td></tr><?php endforeach; ?><?php if(!$rows): ?><tr><td colspan="6">Geen uitnodigingen voor deze filters.</td></tr><?php endif; ?></tbody></table>
        <?php $this->pagination($total,$page);
    }
    public function tools_page() {
        if(!current_user_can('manage_options')){return;}$tab=$this->query('tab');if(!in_array($tab,['log','sessions','settings'],true)){$tab='log';}
        echo '<div class="wrap"><h1>Dares 2FA beheer</h1><h2 class="nav-tab-wrapper">';foreach(['log'=>'Logboek','sessions'=>'Sessies','settings'=>'Vormgeving, e-mails en opruimen'] as $key=>$label){echo '<a class="nav-tab '.($tab===$key?'nav-tab-active':'').'" href="'.esc_url(add_query_arg(['page'=>'dares2fa-tools','tab'=>$key],admin_url('options-general.php'))).'">'.esc_html($label).'</a>';}echo '</h2>';
        if($this->query('dares_notice')){echo '<div class="notice notice-info"><p>'.esc_html($this->query('dares_notice')).'</p></div>';}
        if($tab==='settings'){$this->settings_form();}elseif($tab==='sessions'){$this->sessions_page();}else{$this->log_page();}echo '</div>';
    }
    private function event_label($event) {
        $labels=['login_success'=>'Inloggen geslaagd','login_failed'=>'Inloggen geweigerd','logout'=>'Uitgelogd','code_sent'=>'Inlogcode verstuurd','code_failed'=>'Onjuiste inlogcode','code_verified'=>'E-mailcode gecontroleerd','invite_created'=>'Uitnodiging aangemaakt','invite_mailed'=>'Uitnodiging gemaild','invite_mail_failed'=>'Uitnodiging mailen mislukt','invite_revoked'=>'Uitnodiging ingetrokken','invite_deleted'=>'Uitnodiging verwijderd','application_created'=>'Account aangevraagd','email_confirmed'=>'E-mailadres bevestigd','application_approved'=>'Account goedgekeurd','application_rejected'=>'Aanvraag afgewezen','confirmation_sent'=>'Bevestigingsmail verstuurd','confirmation_resent'=>'Bevestigingsmail opnieuw','confirmation_mail_failed'=>'Bevestigingsmail mislukt','application_expired'=>'Oude aanvraag opgeruimd','user_2fa_policy'=>'Persoonlijke 2FA-instelling','sessions_ended'=>'Sessies beëindigd','settings_updated'=>'Beheerinstellingen bijgewerkt','registration_settings'=>'Registratie-instellingen','2fa_settings'=>'Algemene 2FA-instellingen'];
        return $labels[$event]??ucfirst(str_replace('_',' ',$event));
    }
    private function log_page() {
        global $wpdb;$page=max(1,absint($this->query('paged')));$q=sanitize_text_field($this->query('q'));$event=sanitize_key($this->query('event'));$where='1=1';$params=[];
        if($q!==''){$where.=' AND detail LIKE %s';$params[]='%'.$wpdb->esc_like($q).'%';}if($event){$where.=' AND event=%s';$params[]=$event;}
        $sql='SELECT COUNT(*) FROM '.$this->table().' WHERE '.$where;$total=(int)$wpdb->get_var($params?$wpdb->prepare($sql,$params):$sql);$sql='SELECT * FROM '.$this->table().' WHERE '.$where.' ORDER BY id DESC LIMIT %d OFFSET %d';$rows=$wpdb->get_results($wpdb->prepare($sql,array_merge($params,[25,($page-1)*25])));
        $events=$wpdb->get_col('SELECT DISTINCT event FROM '.$this->table().' ORDER BY event'); ?>
        <p>Vanaf deze update worden acties vastgelegd. Geen wachtwoorden, codes, uitnodigingslinks of IP-adressen. Standaard bewaartermijn: 90 dagen.</p><form method="get"><input type="hidden" name="page" value="dares2fa-tools"><input type="hidden" name="tab" value="log"><input name="q" placeholder="Zoek in omschrijving" value="<?php echo esc_attr($q); ?>"><select name="event"><option value="">Alle gebeurtenissen</option><?php foreach($events as $e): ?><option value="<?php echo esc_attr($e); ?>" <?php selected($event,$e); ?>><?php echo esc_html($this->event_label($e)); ?></option><?php endforeach; ?></select> <button class="button">Zoeken / filteren</button></form><table class="widefat striped"><thead><tr><th>Datum</th><th>Actie</th><th>Uitvoerder</th><th>Account</th><th>Omschrijving</th></tr></thead><tbody>
        <?php foreach($rows as $row): ?><tr><td><?php echo esc_html(wp_date('d-m-Y H:i:s',$row->created)); ?></td><td><?php echo esc_html($this->event_label($row->event)); ?></td><td><?php echo esc_html($this->actor_label($row->actor)); ?></td><td><?php echo esc_html($row->subject?'#'.$row->subject:'—'); ?></td><td><?php echo esc_html($row->detail); ?></td></tr><?php endforeach; ?><?php if(!$rows): ?><tr><td colspan="5">Geen gebeurtenissen.</td></tr><?php endif; ?></tbody></table><?php $this->pagination($total,$page);
    }
    private function actor_label($id) {$user=$id?get_user_by('id',$id):false;return $user?$user->display_name:($id?'Account #'.$id:'Bezoeker / automatisch');}
    private function sessions_page() {
        $q=sanitize_text_field($this->query('q'));$uid=absint($this->query('uid'));$page=max(1,absint($this->query('paged')));$args=['number'=>25,'offset'=>($page-1)*25,'count_total'=>true];if($uid){$args['include']=[$uid];}elseif($q!==''){$args['search']='*'.$q.'*';$args['search_columns']=['user_login','user_email','display_name'];}$query=new WP_User_Query($args); ?>
        <p>Beëindigen logt de gebruiker op alle apparaten uit en trekt openstaande inlogcodes in. Bij je eigen account beëindig je ook je huidige sessie.</p><form method="get"><input type="hidden" name="page" value="dares2fa-tools"><input type="hidden" name="tab" value="sessions"><input name="q" placeholder="Naam of e-mailadres" value="<?php echo esc_attr($q); ?>"><button class="button">Zoeken</button></form><table class="widefat striped"><thead><tr><th>Gebruiker</th><th>Actieve sessies</th><th>Actie</th></tr></thead><tbody>
        <?php foreach($query->get_results() as $user): ?><tr><td><?php echo esc_html($user->display_name.' — '.$user->user_email); ?></td><td><?php echo esc_html(count(WP_Session_Tokens::get_instance($user->ID)->get_all())); ?></td><td><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('dares2fa_sessions_'.$user->ID); ?><input type="hidden" name="action" value="dares2fa_sessions"><input type="hidden" name="uid" value="<?php echo esc_attr($user->ID); ?>"><button class="button">Alle sessies beëindigen</button></form></td></tr><?php endforeach; ?></tbody></table><?php $this->pagination($query->get_total(),$page);
    }
    private function settings_form() {
        $opts=$this->opts();if(function_exists('wp_enqueue_media')){wp_enqueue_media();} ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('dares2fa_tools'); ?><input type="hidden" name="action" value="dares2fa_tools">
        <h2>Dares-vormgeving</h2><table class="form-table"><tr><th>Titel / merknaam</th><td><input class="regular-text" name="brand_title" value="<?php echo esc_attr($opts['brand_title']??''); ?>"></td></tr><tr><th>Logo uit media</th><td><input id="dares-logo-id" name="logo_id" type="number" min="0" value="<?php echo esc_attr($opts['logo_id']??0); ?>"> <button class="button" type="button" id="dares-logo-pick">Afbeelding kiezen</button><p class="description">0 verwijdert het logo. Het nummer is het WordPress-media-ID.</p></td></tr>
        <?php foreach(['accent'=>'Accentkleur','background'=>'Achtergrondkleur','text'=>'Tekstkleur'] as $key=>$label): ?><tr><th><?php echo esc_html($label); ?></th><td><input name="<?php echo esc_attr($key); ?>" type="color" value="<?php echo esc_attr($opts[$key]??['accent'=>'#38bdf8','background'=>'#111c2e','text'=>'#e8eef8'][$key]); ?>"></td></tr><?php endforeach; ?></table>
        <h2>E-mails</h2><p>Deze teksten gelden voor uitnodiging, bevestiging en beoordeling. De 2FA-code-e-mail staat bij Instellingen → Dares E-mail 2FA. Variabelen: {site}, {name}, {email}, {link}, {expires}. E-mails worden als tekst verstuurd.</p><table class="form-table"><tr><th>Afzendernaam</th><td><input name="sender_name" value="<?php echo esc_attr($opts['sender_name']??'Dares'); ?>"></td></tr><tr><th>Afzenderadres (optioneel)</th><td><input class="regular-text" name="sender_email" type="email" value="<?php echo esc_attr($opts['sender_email']??''); ?>"><p class="description">Leeg gebruikt WordPress/SMTP. Je SMTP-plugin kan een vaste afzender afdwingen.</p></td></tr></table>
        <?php foreach($this->defaults() as $type=>$default):$t=$opts['templates'][$type]??$default; ?><h3><?php echo esc_html(['invite'=>'Uitnodiging','confirm'=>'E-mailbevestiging','approved'=>'Goedkeuring','rejected'=>'Afwijzing'][$type]); ?></h3><p><input class="large-text" name="<?php echo esc_attr($type); ?>_subject" value="<?php echo esc_attr($t['subject']); ?>"></p><textarea class="large-text" rows="5" name="<?php echo esc_attr($type); ?>_body"><?php echo esc_textarea($t['body']); ?></textarea><?php endforeach; ?>
        <h2>Automatisch opruimen</h2><p><label><input type="checkbox" name="cleanup_enabled" value="1" <?php checked(!empty($opts['cleanup_enabled'])); ?>> Verwijder oude onbevestigde aanvragen automatisch</label></p><p>Na <input name="cleanup_days" type="number" min="1" max="365" value="<?php echo esc_attr($opts['cleanup_days']??30); ?>"> dagen. Alleen accounts die nog op e-mailbevestiging wachten en geen rol hebben. Bevestigde, goedgekeurde en bestaande accounts worden behouden. Accounts met eigen berichten of uploads worden overgeslagen.</p><p>Logboek bewaren: <input name="log_days" type="number" min="1" max="365" value="<?php echo esc_attr($opts['log_days']??90); ?>"> dagen. Opruimen gebeurt via de bestaande uurtaak van WP-Cron.</p><?php submit_button('Instellingen opslaan'); ?></form>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><?php wp_nonce_field('dares2fa_cleanup'); ?><input type="hidden" name="action" value="dares2fa_cleanup"><button class="button">Opruimen nu uitvoeren met opgeslagen instellingen</button></form>
        <script>document.getElementById('dares-logo-pick').addEventListener('click',function(){if(!window.wp||!wp.media)return;const f=wp.media({title:'Dares-logo kiezen',library:{type:'image'},multiple:false});f.on('select',function(){document.getElementById('dares-logo-id').value=f.state().get('selection').first().toJSON().id;});f.open();});</script>
        <?php
    }
}
// Avoid requiring mbstring on hosting environments that only provide core PHP.
function dares2fa_substr($value,$start,$length) { return function_exists('mb_substr')?mb_substr($value,$start,$length):substr($value,$start,$length); }
$GLOBALS['dares2fa_management']=new Dares_2FA_Management();
