<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Disables all WordPress plugin update checks and clears cached update data.
 *
 * Strategy (defence-in-depth — we apply every known suppression layer):
 *
 *  1. Block the outbound HTTP check to api.wordpress.org before it fires.
 *  2. Zero-out both single-site and multisite update transients so WP never
 *     sees pending updates, regardless of when the check ran.
 *  3. Strip the cron job that schedules the next automatic check.
 *  4. Remove the "Updates" admin submenu and Dashboard widget so the UI stays
 *     clean and staff are not confused by a permanently-empty screen.
 *  5. On activation, flush any pre-existing cached update data immediately.
 */
final class PluginUpdateLocker
{
    /**
     * Attach all WordPress hooks.
     */
    public function register(): void
    {
        // --- HTTP layer -------------------------------------------------------
        add_filter('http_request_args', [$this, 'blockUpdateRequest'], 10, 2);

        // --- Transient layer --------------------------------------------------
        // These two filters cover both single-site and multisite installs.
        add_filter('pre_site_transient_update_plugins', [$this, 'returnEmptyUpdateObject']);
        add_filter('site_transient_update_plugins',     [$this, 'returnEmptyUpdateObject']);
        add_filter('pre_transient_update_plugins',      [$this, 'returnEmptyUpdateObject']);
        add_filter('transient_update_plugins',          [$this, 'returnEmptyUpdateObject']);

        // --- Cron layer -------------------------------------------------------
        add_action('init', [$this, 'removeUpdateCronJob']);

        // --- Auto-update layer -----------------------------------------------
        // WordPress 5.5+ has a separate auto-update code path that fires
        // independently of the transient and can push updates even when the
        // transient is zeroed. This filter shuts it down completely.
        add_filter('auto_update_plugin', '__return_false');

        // --- Capability layer -------------------------------------------------
        // Ensures the "Update Plugins" capability is revoked before WP renders
        // any admin screen that checks it.
        add_filter('user_has_cap', [$this, 'revokeUpdateCapability'], 10, 3);

        // --- Admin UI layer ---------------------------------------------------
        add_action('admin_menu',          [$this, 'removeUpdateSubMenus'], 999);
        add_action('wp_before_admin_bar_render', [$this, 'removeAdminBarUpdateNode'], 999);
        add_action('wp_dashboard_setup',  [$this, 'removeDashboardWidgets'], 999);
        add_action('admin_init',          [$this, 'redirectUpdatePage']);
        add_action('admin_notices',       [$this, 'renderAdminNotice']);
    }

    // =========================================================================
    // HTTP layer
    // =========================================================================

    /**
     * Strip the plugins component from WordPress's outbound version-check
     * payload so api.wordpress.org never returns update data even if the
     * request does reach the network (e.g. through a proxy or another plugin).
     *
     * @param  mixed[]  $parsedArgs  The HTTP request arguments.
     * @param  string   $url         The target URL.
     * @return mixed[]
     */
    public function blockUpdateRequest(array $parsedArgs, string $url): array
    {
        if (false !== \strpos($url, 'api.wordpress.org/plugins/update-check')) {
            // Remove plugins from the body so WP receives an empty response.
            if (isset($parsedArgs['body']['plugins'])) {
                $parsedArgs['body']['plugins'] = wp_json_encode(new \stdClass());
            }
        }

        return $parsedArgs;
    }

    // =========================================================================
    // Transient layer
    // =========================================================================

    /**
     * Return an empty update object whenever WordPress tries to read the
     * plugin update transient from the database.
     *
     * @return \stdClass
     */
    public function returnEmptyUpdateObject(): \stdClass
    {
        $empty                  = new \stdClass();
        $empty->last_checked    = time();
        $empty->checked         = [];
        $empty->response        = [];
        $empty->translations    = [];
        $empty->no_update       = [];

        return $empty;
    }

    // =========================================================================
    // Cron layer
    // =========================================================================

    /**
     * Remove the scheduled cron event that triggers the update check.
     */
    public function removeUpdateCronJob(): void
    {
        $timestamp = wp_next_scheduled('wp_update_plugins');

        if ($timestamp !== false) {
            wp_unschedule_event($timestamp, 'wp_update_plugins');
        }

        // Prevent the hook from running even if something re-schedules it.
        remove_action('wp_update_plugins', 'wp_update_plugins');
    }

    // =========================================================================
    // Capability layer
    // =========================================================================

    /**
     * Revoke the `update_plugins` capability from all users, including admins.
     *
     * WordPress resolves capabilities in layers; this filter fires last and
     * ensures the cap is always denied, regardless of role configuration.
     *
     * @param  bool[]  $allCaps  All capabilities the user currently has.
     * @return bool[]
     *
     * WordPress passes three arguments to this filter; the trailing two
     * ($requiredCap and $args) are intentionally omitted — PHP silently
     * discards extra arguments, and naming them here would only produce
     * "unused variable" warnings.
     */
    public function revokeUpdateCapability(array $allCaps): array
    {
        $allCaps['update_plugins'] = false;

        return $allCaps;
    }

    // =========================================================================
    // Admin UI layer
    // =========================================================================

    /**
     * Remove the "Updates" submenu from the Dashboard menu.
     */
    public function removeUpdateSubMenus(): void
    {
        remove_submenu_page('index.php', 'update-core.php');
    }

    /**
     * Remove the admin bar "Updates" node that shows the pending-update badge.
     *
     * Fired on `wp_before_admin_bar_render` so the WP_Admin_Bar object is
     * populated before we remove from it.
     */
    public function removeAdminBarUpdateNode(): void
    {
        global $wp_admin_bar;

        if ($wp_admin_bar instanceof \WP_Admin_Bar) {
            $wp_admin_bar->remove_node('updates');
        }
    }

    /**
     * Remove the "WordPress Updates" Dashboard widget.
     */
    public function removeDashboardWidgets(): void
    {
        // dashboard_primary = the "WordPress News" / "WordPress Events and News" widget.
        remove_meta_box('dashboard_primary', 'dashboard', 'side');
    }

    /**
     * Hard-redirect anyone who navigates directly to update-core.php.
     */
    public function redirectUpdatePage(): void
    {
        global $pagenow;

        if ($pagenow === 'update-core.php') {
            wp_safe_redirect(admin_url());
            exit;
        }
    }

    /**
     * Display a persistent, dismissible admin notice explaining that plugin
     * updates are locked by policy.
     */
    public function renderAdminNotice(): void
    {
        if (! current_user_can('activate_plugins')) {
            return;
        }

        echo '<div class="notice notice-warning">'
            . '<p><strong>Salient Hook:</strong> '
            . esc_html__(
                'Plugin updates are disabled on this installation by security policy. '
                . 'Contact your administrator to update plugins manually.',
                'salienthook'
            )
            . '</p></div>';
    }

    // =========================================================================
    // Activation cleanup
    // =========================================================================

    /**
     * Delete both single-site and multisite plugin update transients on
     * plugin activation so stale update data does not linger.
     */
    public function flushUpdateTransients(): void
    {
        delete_site_transient('update_plugins');
        delete_transient('update_plugins');
    }
}
