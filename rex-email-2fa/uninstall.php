<?php
if (!defined('WP_UNINSTALL_PLUGIN')) { exit; }
// Network activation is not supported; only this site's data is removed.
global $wpdb;
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}rex2fa_challenges");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}rex2fa_limits");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}rex2fa_invitations");
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}dares2fa_audit");
delete_option('dares2fa_management');
delete_option('dares2fa_schema');
delete_option('dares2fa_cleanup_offset');
delete_option('rex2fa_inv_options');
delete_option('rex2fa_inv_schema');
delete_option('rex2fa_options');
delete_option('rex2fa_page_id');
wp_clear_scheduled_hook('rex2fa_cleanup');
