<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Safe Corridor — password-gated temporary plugin installation window.
 *
 * The full install lockdown (PluginInstallLocker) blocks every plugin
 * installation vector across the board. When you genuinely need to install
 * something, the Safe Corridor provides a controlled, audited unlock:
 *
 *  1. Set a corridor password from the Settings → Salient Hook dashboard.
 *     It is stored as a bcrypt hash in wp_options — never in plain text.
 *
 *  2. When a plugin install is needed, enter the password to open the corridor.
 *     A 15-minute time-limited token is created (WordPress transient).
 *
 *  3. PluginInstallLocker checks for this token on every request and steps aside
 *     while it is valid — the Add New Plugin screen, upload routes, and ZIP MIME
 *     type all become available again for that window.
 *
 *  4. The token auto-expires; lockdown resumes without any further action.
 *     You can also revoke early from the banner that appears while the
 *     corridor is active.
 *
 *  5. Every event (password set, unlock attempt, unlock, revoke) is written
 *     to the WordPress error log with user login and IP address.
 */
final class SafeCorridor
{
    /** Transient key — presence indicates an active open corridor. */
    public const TRANSIENT_OPEN    = 'salienthook_corridor_open';

    /** wp_options key — stores the bcrypt-hashed corridor password. */
    public const OPTION_PASSWORD   = 'salienthook_corridor_password';

    /** wp_options key — stores the Unix timestamp when the corridor expires. */
    public const OPTION_EXPIRY     = 'salienthook_corridor_expiry';

    /** How long (seconds) the corridor stays open after a successful unlock. */
    public const CORRIDOR_DURATION = 900; // 15 minutes.

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        // Red banner across all admin pages when the corridor is open.
        add_action('admin_notices', [$this, 'renderCorridorBanner']);

        // AJAX: save or change the corridor password.
        add_action('wp_ajax_salienthook_corridor_set_password', [$this, 'handleSetPassword']);

        // AJAX: verify password and open the corridor.
        add_action('wp_ajax_salienthook_corridor_unlock', [$this, 'handleUnlock']);

        // AJAX: close the corridor before it expires.
        add_action('wp_ajax_salienthook_corridor_revoke', [$this, 'handleRevoke']);
    }

    // =========================================================================
    // Public API — used by PluginInstallLocker
    // =========================================================================

    /**
     * Returns true if a valid corridor token is currently active.
     *
     * PluginInstallLocker calls this before blocking any install vector.
     * Static so it can be called without an instance reference.
     */
    public static function isOpen(): bool
    {
        return (bool) get_transient(self::TRANSIENT_OPEN);
    }

    // =========================================================================
    // Admin banner
    // =========================================================================

    /**
     * Show a persistent red banner while the corridor is open, with a countdown
     * and an inline "Close Now" link that revokes the token via AJAX.
     */
    public function renderCorridorBanner(): void
    {
        if (! self::isOpen()) {
            return;
        }

        if (! current_user_can('manage_options')) {
            return;
        }

        $expiry    = (int) get_option(self::OPTION_EXPIRY, 0);
        $remaining = \max(0, $expiry - \time());
        $minutes   = (int) \ceil($remaining / 60);

        echo '<div class="notice notice-error" '
            . 'style="border-left-color:#d63638;border-left-width:5px;padding:12px 15px;" '
            . 'id="salienthook-corridor-banner">'
            . '<p style="margin:0;">'
            . '<strong>&#128275; Salient Hook — Safe Corridor Active</strong> &nbsp;|&nbsp; '
            . 'Plugin installation is temporarily unlocked. '
            . 'Closes automatically in <span id="salienthook-corridor-countdown">'
            . \sprintf(
                /* translators: %d = minutes remaining */
                esc_html__('%d minute(s)', 'salienthook'),
                $minutes
            )
            . '</span>. &nbsp;'
            . '<a href="#" id="salienthook-corridor-close-now" '
            . 'style="color:#d63638;font-weight:700;text-decoration:underline;">'
            . esc_html__('Close Now', 'salienthook')
            . '</a>'
            . '</p></div>';
    }

    // =========================================================================
    // AJAX: set / change password
    // =========================================================================

    public function handleSetPassword(): void
    {
        check_ajax_referer('salienthook_corridor', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        $password = isset($_POST['password']) ? (string) $_POST['password'] : '';

        if (\strlen($password) < 12) {
            wp_send_json_error(['message' => 'Password must be at least 12 characters.']);
        }

        $hash = \password_hash($password, PASSWORD_BCRYPT);

        if ($hash === false) {
            wp_send_json_error(['message' => 'Failed to hash password. Please try again.']);
        }

        update_option(self::OPTION_PASSWORD, $hash, false);
        $this->logEvent('password_set', get_current_user_id());

        wp_send_json_success(['message' => 'Corridor password saved successfully.']);
    }

    // =========================================================================
    // AJAX: unlock
    // =========================================================================

    public function handleUnlock(): void
    {
        check_ajax_referer('salienthook_corridor', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        $storedHash = (string) get_option(self::OPTION_PASSWORD, '');

        if (empty($storedHash)) {
            wp_send_json_error([
                'message' => 'No corridor password has been set. Set one first in the Safe Corridor panel.',
            ]);
        }

        $password = isset($_POST['password']) ? (string) $_POST['password'] : '';

        if (! \password_verify($password, $storedHash)) {
            $this->logEvent('failed_unlock', get_current_user_id());
            // Deliberate vague message — don't confirm whether a password exists.
            wp_send_json_error(['message' => 'Incorrect password.']);
        }

        $expiry = \time() + self::CORRIDOR_DURATION;
        set_transient(self::TRANSIENT_OPEN, 1, self::CORRIDOR_DURATION);
        update_option(self::OPTION_EXPIRY, $expiry, false);

        $this->logEvent('unlock', get_current_user_id());

        wp_send_json_success([
            'message'    => 'Corridor open. Plugin installation is unlocked for 15 minutes.',
            'expiresIn'  => self::CORRIDOR_DURATION,
            'expiryTime' => $expiry,
        ]);
    }

    // =========================================================================
    // AJAX: revoke
    // =========================================================================

    public function handleRevoke(): void
    {
        check_ajax_referer('salienthook_corridor', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        delete_transient(self::TRANSIENT_OPEN);
        delete_option(self::OPTION_EXPIRY);

        $this->logEvent('revoke', get_current_user_id());

        wp_send_json_success(['message' => 'Corridor closed. Plugin installation is locked again.']);
    }

    // =========================================================================
    // Logging
    // =========================================================================

    private function logEvent(string $event, int $userId): void
    {
        $user      = get_userdata($userId);
        $userLogin = ($user instanceof \WP_User) ? $user->user_login : 'unknown';
        $ip        = $this->resolveClientIp();

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        \error_log(
            \sprintf(
                '[Salient Hook] Safe Corridor — %s | user: %s | IP: %s',
                $event,
                $userLogin,
                $ip
            )
        );
    }

    private function resolveClientIp(): string
    {
        $candidates = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($candidates as $key) {
            if (! empty($_SERVER[$key])) {
                $ip = \trim(\explode(',', sanitize_text_field(wp_unslash($_SERVER[$key])))[0]);

                if (\filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return 'unknown';
    }
}
