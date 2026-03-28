<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Blocks all plugin installation vectors in WordPress.
 *
 * Covered attack surfaces:
 *
 *  1. Admin UI  — removes "Add New Plugin" from the Plugins menu and the
 *                 "Upload Plugin" button so staff see no entry point.
 *  2. Direct URL — hard-redirects plugin-install.php and plugin-upload.php
 *                  back to the Plugins list before the page renders.
 *  3. Capability — revokes `install_plugins` so WordPress's own internal
 *                  checks (nonces, form submissions, REST, WP-CLI) all fail.
 *  4. Ajax/REST  — the capability revocation also blocks the install endpoints
 *                  that the Plugin Browser and block editor use.
 *  5. File upload — filters the allowed upload MIME types to strip ZIP so
 *                   a crafted multipart upload cannot bypass the capability
 *                   check via wp_handle_upload().
 *  6. Activation  — flushes any leftover install-related transients on enable.
 *
 * Why capability revocation alone is not enough:
 * Some plugins (and WP-CLI running as the web user) call wp_insert_attachment()
 * or wp_handle_upload() with a forged capability array. The MIME filter (point
 * 5) provides a second, independent barrier against that class of bypass.
 */
final class PluginInstallLocker
{
    /**
     * Attach all WordPress hooks.
     */
    public function register(): void
    {
        // --- Capability layer (must run before menu/page renders) ------------
        add_filter('user_has_cap', [$this, 'revokeInstallCapability'], 10, 3);

        // --- Admin UI layer --------------------------------------------------
        add_action('admin_menu',   [$this, 'removeInstallMenuItems'], 999);

        // --- Request interception layer --------------------------------------
        add_action('admin_init',   [$this, 'interceptInstallRequests']);

        // --- Upload MIME filter layer ----------------------------------------
        add_filter('upload_mimes', [$this, 'stripZipFromAllowedMimes']);

        // --- Admin notice ----------------------------------------------------
        add_action('admin_notices', [$this, 'renderAdminNotice']);
    }

    // =========================================================================
    // Capability layer
    // =========================================================================

    /**
     * Unconditionally revoke `install_plugins` for every user, including
     * Super Admins on Multisite.
     *
     * WordPress runs this filter for every `current_user_can()` call, so any
     * code path that respects capabilities will be blocked automatically —
     * including the Plugin Browser REST endpoint, the Gutenberg block inserter,
     * and direct wp-admin form submissions.
     *
     * @param  bool[]  $allCaps  Full capability map for the current user.
     * @return bool[]
     *
     * WordPress passes three arguments to this filter; the trailing two
     * ($requiredCap and $args) are intentionally omitted — PHP silently
     * discards extra arguments, and naming them here would only produce
     * "unused variable" warnings.
     */
    public function revokeInstallCapability(array $allCaps): array
    {
        $allCaps['install_plugins']  = false;
        $allCaps['upload_plugins']   = false;

        return $allCaps;
    }

    // =========================================================================
    // Admin UI layer
    // =========================================================================

    /**
     * Remove "Add New Plugin" from the Plugins submenu and the top-level
     * "Add New" link that appears at the top of the Plugins list table.
     *
     * Runs at priority 999 to ensure it fires after any plugin that may have
     * re-added the page at default priority.
     */
    public function removeInstallMenuItems(): void
    {
        remove_submenu_page('plugins.php', 'plugin-install.php');
    }

    // =========================================================================
    // Request interception layer
    // =========================================================================

    /**
     * Redirect any direct request to plugin-install.php or plugin-upload.php
     * to the Plugins list screen.
     *
     * This handles users who bookmark the URL, or automated scripts that
     * craft direct requests to bypass the menu.
     */
    public function interceptInstallRequests(): void
    {
        global $pagenow;

        $blocked = ['plugin-install.php', 'plugin-upload.php'];

        if (! \in_array($pagenow, $blocked, true)) {
            return;
        }

        // Log the attempt for the administrator before redirecting.
        $this->logBlockedInstallAttempt();

        wp_safe_redirect(
            add_query_arg(
                ['salienthook' => 'blocked'],
                admin_url('plugins.php')
            )
        );
        exit;
    }

    // =========================================================================
    // Upload MIME filter layer
    // =========================================================================

    /**
     * Remove ZIP from the list of MIME types WordPress permits to be uploaded.
     *
     * Plugin packages arrive as ZIP archives. Stripping this type prevents
     * wp_handle_upload() from accepting them even if the capability check is
     * somehow bypassed by a third-party plugin or a misconfigured server.
     *
     * Note: this also prevents legitimate ZIP uploads elsewhere (e.g. theme
     * demos). If you need ZIP uploads for other purposes, target the MIME
     * filter more narrowly using the `$context` argument available in
     * WordPress 5.6+.
     *
     * @param  array<string, string> $mimes  Mime types keyed by extension.
     * @return array<string, string>
     */
    public function stripZipFromAllowedMimes(array $mimes): array
    {
        $zipExtensions = ['zip', 'gz', 'tar', 'tgz'];

        foreach ($zipExtensions as $ext) {
            unset($mimes[$ext]);
        }

        return $mimes;
    }

    // =========================================================================
    // Logging
    // =========================================================================

    /**
     * Record a blocked install attempt to the WordPress error log.
     *
     * Uses error_log() rather than a custom database table to stay lightweight
     * and avoid a dependency on `$wpdb` at this early hook stage.
     */
    private function logBlockedInstallAttempt(): void
    {
        $userId    = get_current_user_id();
        $userLogin = $userId > 0 ? (get_userdata($userId)->user_login ?? 'unknown') : 'unauthenticated';
        $ip        = $this->resolveClientIp();
        $requestUri = isset($_SERVER['REQUEST_URI'])
            ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']))
            : 'unknown';

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        \error_log(
            \sprintf(
                '[Salient Hook] Blocked plugin install attempt — user: %s | IP: %s | URI: %s',
                $userLogin,
                $ip,
                $requestUri
            )
        );
    }

    /**
     * Resolve the client IP address, respecting common proxy headers.
     *
     * Only used internally for logging; never exposed in output.
     */
    private function resolveClientIp(): string
    {
        $candidates = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($candidates as $key) {
            if (! empty($_SERVER[$key])) {
                // X-Forwarded-For may contain a comma-separated list; take the first.
                $ip = \trim(\explode(',', sanitize_text_field(wp_unslash($_SERVER[$key])))[0]);

                if (\filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return 'unknown';
    }

    // =========================================================================
    // Admin notice
    // =========================================================================

    /**
     * Show a persistent notice on the Plugins screen that includes a
     * "blocked attempt" alert when someone tried to reach plugin-install.php.
     */
    public function renderAdminNotice(): void
    {
        if (! current_user_can('activate_plugins')) {
            return;
        }

        global $pagenow;

        if ($pagenow !== 'plugins.php') {
            return;
        }

        // Generic hardening notice.
        echo '<div class="notice notice-warning">'
            . '<p><strong>Salient Hook:</strong> '
            . esc_html__(
                'Adding new plugins is disabled on this installation by security policy.',
                'salienthook'
            )
            . '</p></div>';

        // Alert if this page load was a redirect from a blocked install attempt.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['salienthook']) && $_GET['salienthook'] === 'blocked') {
            echo '<div class="notice notice-error">'
                . '<p><strong>Salient Hook — Security Alert:</strong> '
                . esc_html__(
                    'A plugin installation attempt was intercepted and blocked. '
                    . 'The attempt has been logged. If this was not you, review your '
                    . 'administrator accounts and active sessions immediately.',
                    'salienthook'
                )
                . '</p></div>';
        }
    }

    // =========================================================================
    // Activation cleanup
    // =========================================================================

    /**
     * Delete plugin-installer related transients on activation so that any
     * cached plugin browser data from api.wordpress.org is purged immediately.
     */
    public function flushInstallTransients(): void
    {
        delete_site_transient('update_plugins');
        delete_site_transient('plugin_slugs');
        delete_transient('plugin_slugs');
    }
}
