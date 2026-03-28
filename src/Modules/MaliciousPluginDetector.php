<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Detects and force-deactivates plugins matching known malware signatures.
 *
 * Two scan modes:
 *
 *  - Auto-scan  (admin_init + hourly cron): metadata-only — fast, runs on
 *    every admin page load to catch re-activation attempts immediately.
 *
 *  - Full scan  (on-demand via settings page): adds deep file-content scan
 *    for code-level IOCs (function names, C2 domains, GET parameters).
 *
 * Confirmed signature: "WP Performance Analytics" / "Developer Tools Team"
 * — user-verified to deliver the fake Cloudflare / LummaStealer campaign.
 */
final class MaliciousPluginDetector
{
    private const CRON_HOOK = 'salienthook_plugin_scan';

    /**
     * Metadata-only signatures — matched against plugin header fields.
     * Each entry must match ALL provided keys to trigger a hit.
     *
     * @var array<int, array<string, string>>
     */
    private const META_SIGNATURES = [
        [
            'name_contains'        => 'WP Performance Analytics',
            'author_contains'      => 'Developer Tools Team',
        ],
        [
            'description_contains' => 'Lightweight site performance monitoring, page load analytics',
        ],
    ];

    /**
     * Code-level IOC strings — any plugin file containing one of these
     * strings is treated as malicious regardless of its displayed name.
     *
     * @var array<string, string>
     */
    private const CODE_IOCS = [
        'emergency_login_all_admins' => 'Known malware function name',
        'execute_admin_command'      => 'Known malware function name',
        'harp_interesting'           => 'Known malware GET parameter',
        'terrorise_seriously'        => 'Known malware GET parameter',
        'workaem'                    => 'Known C2 domain fragment',
        '45.61.136.85'               => 'Known C2 IP address',
    ];

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        // Auto-scan on every admin request — catches re-activation immediately.
        add_action('admin_init', [$this, 'scanAndDeactivate'], 1);

        // Cron hook handler.
        add_action(self::CRON_HOOK, [$this, 'runScheduledScan']);
    }

    /**
     * Schedule the hourly background scan on plugin activation.
     */
    public function registerCron(): void
    {
        if (! wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(\time(), 'hourly', self::CRON_HOOK);
        }
    }

    /**
     * Remove the cron event on plugin deactivation.
     */
    public function deregisterCron(): void
    {
        $timestamp = wp_next_scheduled(self::CRON_HOOK);

        if ($timestamp !== false) {
            wp_unschedule_event($timestamp, self::CRON_HOOK);
        }
    }

    // =========================================================================
    // Auto-scan (metadata only — runs on every admin load)
    // =========================================================================

    /**
     * Lightweight scan of active plugins against header metadata signatures.
     * Deactivates any match immediately and queues an admin notice.
     */
    public function scanAndDeactivate(): void
    {
        $this->loadPluginFunctions();

        $activePlugins = (array) get_option('active_plugins', []);
        $allPlugins    = get_plugins();
        $deactivated   = [];

        foreach ($activePlugins as $pluginFile) {
            if (! isset($allPlugins[$pluginFile])) {
                continue;
            }

            if ($this->matchesMetaSignature($allPlugins[$pluginFile])) {
                deactivate_plugins($pluginFile);
                $deactivated[] = $allPlugins[$pluginFile]['Name'];
                $this->logDeactivation($pluginFile, $allPlugins[$pluginFile]['Name'], 'meta-signature');
            }
        }

        if (! empty($deactivated)) {
            set_transient('salienthook_auto_deactivated', $deactivated, HOUR_IN_SECONDS);
            add_action('admin_notices', [$this, 'renderDeactivationNotice']);
        }
    }

    // =========================================================================
    // Scheduled scan (runs hourly via cron — includes code-level IOC scan)
    // =========================================================================

    public function runScheduledScan(): void
    {
        $results = $this->runFullScan();
        set_transient('salienthook_plugin_scan_results', $results, DAY_IN_SECONDS);
        update_option('salienthook_last_plugin_scan', \time(), false);
    }

    // =========================================================================
    // Full scan (on-demand from settings page)
    // =========================================================================

    /**
     * Scan all installed plugins — both metadata and code-level IOCs.
     *
     * Active malicious plugins are deactivated automatically as part of
     * the scan. Returns a structured findings array for the settings page.
     *
     * @return array<int, array<string, mixed>>
     */
    public function runFullScan(): array
    {
        $this->loadPluginFunctions();

        $allPlugins    = get_plugins();
        $activePlugins = (array) get_option('active_plugins', []);
        $findings      = [];

        foreach ($allPlugins as $pluginFile => $pluginData) {
            $matchedSignature = $this->matchesMetaSignature($pluginData);
            $codeIoc          = null;

            if (! $matchedSignature) {
                $codeIoc = $this->scanPluginFileForIocs($pluginFile);
            }

            if (! $matchedSignature && $codeIoc === null) {
                continue;
            }

            $isActive = \in_array($pluginFile, $activePlugins, true);

            // Deactivate if still active.
            if ($isActive) {
                deactivate_plugins($pluginFile);
                $this->logDeactivation($pluginFile, $pluginData['Name'], $codeIoc ?? 'meta-signature');
            }

            $findings[] = [
                'file'             => $pluginFile,
                'name'             => $pluginData['Name'],
                'author'           => \strip_tags($pluginData['AuthorName'] ?? $pluginData['Author'] ?? ''),
                'version'          => $pluginData['Version'] ?? '',
                'was_active'       => $isActive,
                'match_reason'     => $codeIoc ?? 'Matched known malware metadata signature',
            ];
        }

        return $findings;
    }

    // =========================================================================
    // Signature matching
    // =========================================================================

    /**
     * @param  array<string, string> $pluginData
     */
    private function matchesMetaSignature(array $pluginData): bool
    {
        $name        = \strtolower($pluginData['Name']        ?? '');
        $author      = \strtolower(\strip_tags($pluginData['Author'] ?? ''));
        $description = \strtolower($pluginData['Description'] ?? '');

        foreach (self::META_SIGNATURES as $signature) {
            $hit = true;

            if (
                isset($signature['name_contains']) &&
                \strpos($name, \strtolower($signature['name_contains'])) === false
            ) {
                $hit = false;
            }

            if (
                $hit &&
                isset($signature['author_contains']) &&
                \strpos($author, \strtolower($signature['author_contains'])) === false
            ) {
                $hit = false;
            }

            if (
                $hit &&
                isset($signature['description_contains']) &&
                \strpos($description, \strtolower($signature['description_contains'])) === false
            ) {
                $hit = false;
            }

            if ($hit) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scan the main plugin PHP file for code-level IOC strings.
     * Returns the matched IOC description, or null if clean.
     */
    private function scanPluginFileForIocs(string $pluginFile): ?string
    {
        $pluginPath = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $pluginFile;

        if (! \is_readable($pluginPath)) {
            return null;
        }

        $content = \file_get_contents($pluginPath);

        if ($content === false) {
            return null;
        }

        foreach (self::CODE_IOCS as $ioc => $description) {
            if (\strpos($content, $ioc) !== false) {
                return $description . ' (' . $ioc . ')';
            }
        }

        return null;
    }

    // =========================================================================
    // Logging
    // =========================================================================

    private function logDeactivation(string $pluginFile, string $pluginName, string $reason): void
    {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        \error_log(
            \sprintf(
                '[Salient Hook] Force-deactivated malicious plugin — name: %s | file: %s | reason: %s',
                $pluginName,
                $pluginFile,
                $reason
            )
        );
    }

    // =========================================================================
    // Admin notice
    // =========================================================================

    public function renderDeactivationNotice(): void
    {
        $deactivated = get_transient('salienthook_auto_deactivated');

        if (! $deactivated) {
            return;
        }

        delete_transient('salienthook_auto_deactivated');

        echo '<div class="notice notice-error">'
            . '<p><strong>&#9888; Salient Hook — Malicious Plugin Removed:</strong> '
            . esc_html__(
                'The following plugin(s) were automatically deactivated — they match known malware signatures. Delete them immediately.',
                'salienthook'
            )
            . '</p><ul style="list-style:disc;padding-left:20px;">';

        foreach ((array) $deactivated as $name) {
            echo '<li><strong>' . esc_html($name) . '</strong></li>';
        }

        echo '</ul>'
            . '<p><a href="' . esc_url(admin_url('plugins.php?plugin_status=inactive')) . '" class="button button-primary">View Inactive Plugins</a></p>'
            . '</div>';
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Ensure get_plugins() is available outside the admin context (cron).
     */
    private function loadPluginFunctions(): void
    {
        if (! \function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
    }
}
