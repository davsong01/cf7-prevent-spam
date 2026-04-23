<?php
/**
 * Plugin Name: CF7 Advanced Anti-Spam Shield
 * Description: Advanced anti-spam protection for Contact Form 7 + CFDB7 + Admin Management
 * Version: 3.4.1
 * Author: David Oghi
 */

if (!defined('ABSPATH')) exit;

define( 'CF7ASP_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );


require_once CF7ASP_PLUGIN_DIR . 'inc/plugin-update-checker/plugin-update-checker.php';

// Integrate auto update
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;
$myUpdateChecker = PucFactory::buildUpdateChecker(
	'https://github.com/davsong01/cf7-prevent-spam/', // Your repo URL
	__FILE__, // Full path to the main plugin file
	'cf7-prevent-spam' // Plugin slug
);

/*
|--------------------------------------------------------------------------
| DATABASE SETUP
|--------------------------------------------------------------------------
*/
register_activation_hook(__FILE__, function () {
    global $wpdb;
    $table_name = $wpdb->prefix . 'cf7_spam_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE {$table_name} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ip VARCHAR(100) NULL,
        email VARCHAR(255) NULL,
        message LONGTEXT NULL,
        reason VARCHAR(255) NULL,
        score INT DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
    ) {$charset_collate};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
});

/*
|--------------------------------------------------------------------------
| CONFIG & UTILITIES
|--------------------------------------------------------------------------
*/
function cf7asp_config($type) {
    $data = [
        'keywords' => ['bitcoin', 'btc', 'crypto', 'wallet', 'withdraw', 'urgent', 'investment', 'profit', 'click here', 'guaranteed', 'transfer', 'loan offer', 'double your money', 'earn fast'],
        'tlds' => ['.xyz', '.top', '.click', '.gq', '.tk', '.ru', '.work', '.loan', '.biz']
    ];
    return $data[$type] ?? [];
}

function cf7asp_get_ip() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return sanitize_text_field(trim($ips[0]));
    }
    return sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

/*
|--------------------------------------------------------------------------
| SPAM ENGINE LOGIC
|--------------------------------------------------------------------------
*/
function cf7asp_analyze_submission($posted_data) {
    $score = 0;
    $reasons = [];
    
    $email = strtolower(trim(sanitize_email($posted_data['email'] ?? '')));
    $message = (string) ($posted_data['message'] ?? '');
    $message_lower = strtolower($message);

    // 1. Honeypot check
    if (!empty($posted_data['website'])) {
        $score += 100;
        $reasons[] = 'honeypot';
    }

    // 2. TLD check
    foreach (cf7asp_config('tlds') as $tld) {
        if (str_ends_with($email, $tld)) {
            $score += 40;
            $reasons[] = 'blocked_tld';
            break;
        }
    }

    // 3. URL detection
    if (preg_match('/https?:\/\//i', $message) || preg_match('/www\./i', $message)) {
        $score += 50;
        $reasons[] = 'url_detected';
    }

    // 4. Keyword detection
    foreach (cf7asp_config('keywords') as $keyword) {
        if (strpos($message_lower, strtolower($keyword)) !== false) {
            $score += 15;
            $reasons[] = 'keyword:' . $keyword;
        }
    }

    // 5. Speed detection (Reduced to 3 seconds for better UX)
    if (!empty($posted_data['form_time'])) {
        $diff = (round(microtime(true) * 1000)) - (int)$posted_data['form_time'];
        if ($diff < 3000) {
            $score += 30;
            $reasons[] = 'bot_speed';
        }
    }

    return [
        'score'   => $score,
        'reasons' => array_unique($reasons),
        'status'  => ($score >= 50 ? 'blocked' : ($score >= 20 ? 'suspicious' : 'clean')),
        'email'   => $email,
        'message' => $message
    ];
}

/*
|--------------------------------------------------------------------------
| MAIN HOOK: SPAM BLOCKING
|--------------------------------------------------------------------------
*/
add_filter('wpcf7_spam', function ($spam) {
    if ($spam) return $spam; 

    $submission = WPCF7_Submission::get_instance();
    if (!$submission) return $spam;

    $posted_data = $submission->get_posted_data();
    $ip = cf7asp_get_ip();

    // Check IP Blacklist FIRST
    $blacklist = get_option('cf7asp_blacklist_ips', []);
    if (in_array($ip, (array)$blacklist, true)) {
        return true; 
    }

    $result = cf7asp_analyze_submission($posted_data);

    // Hard block if score is 50+
    if ($result['score'] >= 50) {
        global $wpdb;
        $wpdb->insert($wpdb->prefix . 'cf7_spam_logs', [
            'ip'      => $ip,
            'email'   => $result['email'],
            'message' => substr($result['message'], 0, 1000),
            'reason'  => implode(', ', $result['reasons']),
            'score'   => $result['score'],
        ]);

        // Blacklist if score is extremely high
        if ($result['score'] >= 85) {
            $blacklist[] = $ip;
            update_option('cf7asp_blacklist_ips', array_unique($blacklist));
        }

        return true; 
    }

    return $spam;
}, 10, 1);

/*
|--------------------------------------------------------------------------
| CFDB7 INTEGRATION (FOR CLEAN EMAILS)
|--------------------------------------------------------------------------
*/
add_action('wpcf7_mail_sent', function ($contact_form) {
    $submission = WPCF7_Submission::get_instance();
    if (!$submission) return;

    $posted_data = $submission->get_posted_data();
    $result = cf7asp_analyze_submission($posted_data);

    global $wpdb;
    $table = $wpdb->prefix . 'db7_forms';

    $row = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$table} WHERE form_value LIKE %s ORDER BY form_date DESC LIMIT 1",
        '%' . $wpdb->esc_like($result['email']) . '%'
    ));

    if ($row) {
        $data = maybe_unserialize($row->form_value);
        if (is_array($data)) {
            $data['spam_score'] = $result['score'];
            $data['spam_status'] = $result['status'];
            $wpdb->update($table, ['form_value' => maybe_serialize($data)], ['form_id' => $row->form_id]);
        }
    }
});

/*
|--------------------------------------------------------------------------
| ADMIN MENU & ACTION HANDLER
|--------------------------------------------------------------------------
*/
add_action('admin_menu', function () {
    add_menu_page('Spam Logs', 'Spam Logs', 'manage_options', 'cf7asp-logs', 'cf7asp_render_logs', 'dashicons-shield-alt', 25);
});

add_action('admin_init', function() {
    if (!isset($_GET['page']) || $_GET['page'] !== 'cf7asp-logs') return;
    global $wpdb;

    if (isset($_POST['cf7asp_del_logs']) && check_admin_referer('cf7asp_clear_logs')) {
        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}cf7_spam_logs");
        wp_redirect(admin_url('admin.php?page=cf7asp-logs&msg=1'));
        exit;
    }

    if (isset($_POST['cf7asp_clear_bl']) && check_admin_referer('cf7asp_clear_bl_act')) {
        update_option('cf7asp_blacklist_ips', []);
        wp_redirect(admin_url('admin.php?page=cf7asp-logs&msg=2'));
        exit;
    }
});

function cf7asp_render_logs() {
    global $wpdb;
    $logs = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}cf7_spam_logs ORDER BY created_at DESC LIMIT 100");
    
    echo '<div class="wrap"><h1>CF7 Spam Logs</h1>';
    
    if (isset($_GET['msg'])) {
        $msg = $_GET['msg'] == 1 ? 'Logs cleared.' : 'Blacklist reset. You are now unblocked.';
        echo "<div class='updated'><p>$msg</p></div>";
    }

    echo '<div style="margin: 20px 0; display: flex; gap: 10px;">
        <form method="post">'.wp_nonce_field('cf7asp_clear_logs').'<input type="submit" name="cf7asp_del_logs" class="button" value="Delete All Logs"></form>
        <form method="post">'.wp_nonce_field('cf7asp_clear_bl_act').'<input type="submit" name="cf7asp_clear_bl" class="button button-primary" value="Clear IP Blacklist (Unblock Me)"></form>
    </div>';

    echo '<table class="widefat striped"><thead><tr><th>IP</th><th>Email</th><th>Reason</th><th>Score</th><th>Date</th></tr></thead><tbody>';
    foreach ($logs as $log) {
        echo "<tr><td><strong>".esc_html($log->ip)."</strong></td><td>".esc_html($log->email)."</td><td>".esc_html($log->reason)."</td><td>".esc_html($log->score)."</td><td>".esc_html($log->created_at)."</td></tr>";
    }
    if (empty($logs)) echo '<tr><td colspan="5">No logs found.</td></tr>';
    echo '</tbody></table></div>';
}

/*
|--------------------------------------------------------------------------
| FOOTER SCRIPT (Bot Timing)
|--------------------------------------------------------------------------
*/
add_action('wp_footer', function () {
    if (is_admin()) return; ?>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('form.wpcf7-form').forEach(function (form) {
            if (!form.querySelector('input[name="form_time"]')) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'form_time';
                input.value = Date.now();
                form.appendChild(input);
            }
        });
    });
    </script>
<?php });