<?php

declare(strict_types=1);

namespace SalientHook\Admin;

use SalientHook\Modules\DatabaseScanner;
use SalientHook\Modules\MaliciousPluginDetector;
use SalientHook\Modules\SafeCorridor;
use SalientHook\Modules\ThemeIntegrityScanner;
use SalientHook\Modules\ThreatScanner;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Settings > Salient Hook — Security Dashboard.
 *
 * Six panels:
 *  1. Lockdown Status        — live badges for every enforcement layer.
 *  2. Malicious Plugin Scanner — known-malware signatures + code IOCs.
 *  3. Theme Integrity Scanner  — theme files scanned for IOCs + JS injection.
 *  4. Threat Scanner           — uploads, .htaccess, Timthumb, cron, new admins.
 *  5. Database Scanner         — wp_options scanned for injected JS payloads.
 *  6. Safe Corridor            — password-gated temporary install window.
 *
 * Fonts: Sora (headings) + Sen (body), loaded from Google Fonts on this page only.
 */
final class SettingsPage
{
    private MaliciousPluginDetector $pluginDetector;
    private ThemeIntegrityScanner   $themeScanner;
    private ThreatScanner           $threatScanner;
    private DatabaseScanner         $dbScanner;
    private SafeCorridor            $safeCorridor;

    public function __construct(
        MaliciousPluginDetector $pluginDetector,
        ThemeIntegrityScanner   $themeScanner,
        ThreatScanner           $threatScanner,
        DatabaseScanner         $dbScanner,
        SafeCorridor            $safeCorridor
    ) {
        $this->pluginDetector = $pluginDetector;
        $this->themeScanner   = $themeScanner;
        $this->threatScanner  = $threatScanner;
        $this->dbScanner      = $dbScanner;
        $this->safeCorridor   = $safeCorridor;
    }

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        add_action('admin_menu',            [$this, 'registerMenu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAssets']);
        add_action('wp_ajax_salienthook_plugin_scan', [$this, 'handlePluginScanAjax']);
        add_action('wp_ajax_salienthook_theme_scan',  [$this, 'handleThemeScanAjax']);
        add_action('wp_ajax_salienthook_threat_scan', [$this, 'handleThreatScanAjax']);
        add_action('wp_ajax_salienthook_db_scan',     [$this, 'handleDbScanAjax']);
    }

    public function registerMenu(): void
    {
        add_submenu_page(
            'options-general.php',
            __('Salient Hook', 'salienthook'),
            __('Salient Hook', 'salienthook'),
            'manage_options',
            'salienthook',
            [$this, 'renderPage']
        );
    }

    public function enqueueAssets(string $hook): void
    {
        if ($hook !== 'settings_page_salienthook') {
            return;
        }

        wp_enqueue_style(
            'salienthook-fonts',
            'https://fonts.googleapis.com/css2?family=Sora:wght@400;600;700&family=Sen:wght@400;700&display=swap',
            [],
            null
        );
    }

    // =========================================================================
    // Page render
    // =========================================================================

    public function renderPage(): void
    {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('Insufficient permissions.', 'salienthook'));
        }

        $pluginResults  = get_transient('salienthook_plugin_scan_results');
        $themeResults   = get_transient('salienthook_theme_scan_results');
        $threatResults  = get_transient(ThreatScanner::TRANSIENT_KEY);
        $dbResults      = get_transient(DatabaseScanner::TRANSIENT_KEY);
        $lastPluginScan = (int) get_option('salienthook_last_plugin_scan', 0);
        $lastThemeScan  = (int) get_option('salienthook_last_theme_scan', 0);
        $lastThreatScan = (int) get_option(ThreatScanner::OPTION_LAST, 0);
        $lastDbScan     = (int) get_option(DatabaseScanner::OPTION_LAST, 0);
        $pluginResults  = ($pluginResults !== false) ? (array) $pluginResults : null;
        $themeResults   = ($themeResults  !== false) ? (array) $themeResults  : null;
        $threatResults  = ($threatResults !== false) ? (array) $threatResults : null;
        $dbResults      = ($dbResults     !== false) ? (array) $dbResults     : null;

        $corridorOpen    = SafeCorridor::isOpen();
        $corridorExpiry  = (int) get_option(SafeCorridor::OPTION_EXPIRY, 0);
        $hasCorridorPass = ! empty(get_option(SafeCorridor::OPTION_PASSWORD, ''));

        $scanNonce     = wp_create_nonce('salienthook_scan');
        $corridorNonce = wp_create_nonce('salienthook_corridor');

        $this->renderStyles();
        ?>
        <div class="sh-wrap">

            <div class="sh-page-header">
                <div class="sh-logo-icon">
                    <span class="dashicons dashicons-shield-alt"></span>
                </div>
                <div>
                    <h1><?php esc_html_e('Salient Hook', 'salienthook'); ?></h1>
                    <p><?php esc_html_e('Security hardening against unauthorised plugin injection and malware delivery.', 'salienthook'); ?></p>
                </div>
            </div>

            <?php
            $this->renderLockdownPanel();
            $this->renderScanPanel(
                'plugin',
                'dashicons-search',
                __('Malicious Plugin Scanner', 'salienthook'),
                __('Detects active plugins matching known malware signatures and code-level IOCs. Matches are deactivated immediately.', 'salienthook'),
                $pluginResults,
                $lastPluginScan,
                $scanNonce
            );
            $this->renderScanPanel(
                'theme',
                'dashicons-editor-code',
                __('Theme Integrity Scanner', 'salienthook'),
                __('Scans theme PHP and JS files for IOCs from both the LummaStealer and ClickFix campaigns, plus generic obfuscation patterns.', 'salienthook'),
                $themeResults,
                $lastThemeScan,
                $scanNonce
            );
            $this->renderScanPanel(
                'threat',
                'dashicons-warning',
                __('Threat Scanner', 'salienthook'),
                __('Checks for PHP web shells in uploads, malicious .htaccess directives, Timthumb remnants, obfuscated cron jobs, and newly created admin accounts.', 'salienthook'),
                $threatResults,
                $lastThreatScan,
                $scanNonce
            );
            $this->renderScanPanel(
                'db',
                'dashicons-database',
                __('Database Scanner', 'salienthook'),
                __('Scans wp_options (widgets, theme mods, custom keys) for injected JavaScript. The ClickFix campaign hides its payload from logged-in admins — this scanner reads raw DB values and bypasses that evasion.', 'salienthook'),
                $dbResults,
                $lastDbScan,
                $scanNonce
            );
            $this->renderSafeCorridorPanel($corridorOpen, $corridorExpiry, $hasCorridorPass, $corridorNonce);
            $this->renderInlineScript($scanNonce, $corridorNonce, $corridorOpen, $corridorExpiry);
            ?>

        </div>
        <?php
    }

    // =========================================================================
    // Panel 1 — Lockdown Status
    // =========================================================================

    private function renderLockdownPanel(): void
    {
        $checks = [
            [
                'label'  => 'Plugin updates blocked',
                'detail' => 'Update transients zeroed, HTTP check intercepted, auto-update filter applied.',
                'active' => has_filter('pre_site_transient_update_plugins'),
            ],
            [
                'label'  => 'Auto-updates off (WP 5.5+)',
                'detail' => 'auto_update_plugin filter always returns false.',
                'active' => has_filter('auto_update_plugin'),
            ],
            [
                'label'  => 'Plugin install blocked',
                'detail' => 'Capability revoked, plugin-install.php intercepted, ZIP uploads stripped.',
                'active' => has_filter('user_has_cap'),
            ],
            [
                'label'  => 'Auto-deactivation active',
                'detail' => 'Malware signatures checked on every admin page load.',
                'active' => has_action('admin_init', [MaliciousPluginDetector::class, 'scanAndDeactivate']),
            ],
            [
                'label'  => 'Corridor password set',
                'detail' => 'A password is required before any temporary install is granted.',
                'active' => ! empty(get_option(SafeCorridor::OPTION_PASSWORD, '')),
            ],
        ];

        echo '<div class="sh-card" style="margin-bottom:20px;">';
        echo '<div class="sh-card-header">';
        echo '<div class="sh-card-icon"><span class="dashicons dashicons-lock"></span></div>';
        echo '<div>';
        echo '<h2 class="sh-card-title">' . esc_html__('Lockdown Status', 'salienthook') . '</h2>';
        echo '<p class="sh-card-desc">' . esc_html__('Live status of every enforcement layer. All items should be active.', 'salienthook') . '</p>';
        echo '</div></div>';
        echo '<div class="sh-card-body">';
        echo '<div class="sh-status-grid">';

        foreach ($checks as $check) {
            $stateClass = $check['active'] ? 'sh-status-active' : 'sh-status-inactive';
            $badgeClass = $check['active'] ? 'sh-badge-success' : 'sh-badge-danger';
            $badgeLabel = $check['active'] ? 'Active' : 'Inactive';

            echo '<div class="sh-status-item ' . $stateClass . '">';
            echo '<div class="sh-status-dot"></div>';
            echo '<div class="sh-status-info">';
            echo '<div class="sh-status-name">' . esc_html($check['label']) . '</div>';
            echo '<div class="sh-status-desc">' . esc_html($check['detail']) . '</div>';
            echo '</div>';
            echo '<span class="sh-badge ' . $badgeClass . '">' . esc_html($badgeLabel) . '</span>';
            echo '</div>';
        }

        echo '</div></div></div>';
    }

    // =========================================================================
    // Generic scan panel (panels 2–5)
    // =========================================================================

    private function renderScanPanel(
        string  $key,
        string  $icon,
        string  $title,
        string  $description,
        ?array  $results,
        int     $lastScan,
        string  $nonce
    ): void {
        $buttonId   = 'sh-run-' . $key . '-scan';
        $resultsId  = 'sh-' . $key . '-scan-results';
        $timestampId = 'sh-last-' . $key . '-scan';

        $lastLabel = $lastScan > 0
            ? esc_html($this->formatTimestamp($lastScan))
            : esc_html__('Never', 'salienthook');

        echo '<div class="sh-card" style="margin-bottom:20px;">';
        echo '<div class="sh-card-header">';
        echo '<div class="sh-card-icon"><span class="dashicons ' . esc_attr($icon) . '"></span></div>';
        echo '<div>';
        echo '<h2 class="sh-card-title">' . esc_html($title) . '</h2>';
        echo '<p class="sh-card-desc">' . esc_html($description) . '</p>';
        echo '</div></div>';
        echo '<div class="sh-card-body">';
        echo '<div class="sh-scan-meta">'
            . esc_html__('Last scan:', 'salienthook') . ' '
            . '<span id="' . esc_attr($timestampId) . '">' . $lastLabel . '</span>'
            . '</div>';
        echo '<button id="' . esc_attr($buttonId) . '" class="sh-btn sh-btn-primary">'
            . '<span class="dashicons dashicons-update" style="font-size:16px;width:16px;height:16px;margin-right:4px;vertical-align:middle;"></span>'
            . esc_html__('Run Scan Now', 'salienthook')
            . '</button>';
        echo '<div id="' . esc_attr($resultsId) . '" style="margin-top:16px;">';

        if ($results !== null) {
            if ($key === 'plugin') {
                echo $this->buildPluginResultsHtml($results);
            } elseif ($key === 'theme') {
                echo $this->buildThemeResultsHtml($results);
            } elseif ($key === 'threat') {
                echo $this->buildFlatResultsHtml($results, 'path');
            } else {
                echo $this->buildFlatResultsHtml($results, 'option');
            }
        }

        echo '</div></div></div>';
    }

    // =========================================================================
    // Result builders — plugin scanner
    // =========================================================================

    /**
     * @param  array<int, array<string, mixed>> $results
     */
    private function buildPluginResultsHtml(array $results): string
    {
        if (empty($results)) {
            return $this->alertHtml('success', 'yes-alt', 'No malicious plugins detected.');
        }

        $count = \count($results);
        $html  = $this->alertHtml('danger', 'warning', \sprintf('%d malicious plugin(s) detected and deactivated.', $count));

        $html .= '<table class="sh-table">';
        $html .= '<thead><tr>'
            . '<th>' . esc_html__('Plugin', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Author', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Version', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Match Reason', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Action', 'salienthook') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($results as $finding) {
            $name      = esc_html((string) ($finding['name']         ?? ''));
            $file      = esc_html((string) ($finding['file']         ?? ''));
            $author    = esc_html((string) ($finding['author']       ?? ''));
            $version   = esc_html((string) ($finding['version']      ?? ''));
            $reason    = esc_html((string) ($finding['match_reason'] ?? ''));
            $deleteUrl = esc_url(admin_url('plugins.php?s=' . \urlencode((string) ($finding['name'] ?? ''))));

            $html .= '<tr>';
            $html .= '<td><strong>' . $name . '</strong><br><code>' . $file . '</code></td>';
            $html .= '<td>' . $author . '</td>';
            $html .= '<td>' . $version . '</td>';
            $html .= '<td><span class="sh-badge sh-badge-danger">' . $reason . '</span></td>';
            $html .= '<td><a href="' . $deleteUrl . '" class="sh-btn sh-btn-danger sh-btn-sm">Find &amp; Delete</a></td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table>';
        return $html;
    }

    // =========================================================================
    // Result builders — theme scanner
    // =========================================================================

    /**
     * @param  array<string, array<string, mixed>> $results
     */
    private function buildThemeResultsHtml(array $results): string
    {
        if (empty($results)) {
            return $this->alertHtml('success', 'yes-alt', 'No themes scanned yet.');
        }

        $html     = '';
        $infected = 0;

        foreach ($results as $themeName => $themeData) {
            $status   = (string) ($themeData['status']   ?? 'clean');
            $findings = (array)  ($themeData['findings'] ?? []);
            $critical = (int)    ($themeData['critical'] ?? 0);

            if ($status !== 'clean') {
                $infected++;
            }

            if ($status === 'infected') {
                $badgeClass = 'sh-badge-danger';
                $label      = 'INFECTED';
            } elseif ($status === 'suspicious') {
                $badgeClass = 'sh-badge-warning';
                $label      = 'SUSPICIOUS';
            } else {
                $badgeClass = 'sh-badge-success';
                $label      = 'CLEAN';
            }

            $badge = '<span class="sh-badge ' . $badgeClass . '">' . $label . '</span>';
            $path  = esc_html((string) ($themeData['path'] ?? ''));

            $html .= '<div class="sh-expandable">';

            if (! empty($findings)) {
                $total  = \count($findings);
                $meta   = $critical . ' critical, ' . $total . ' total — click to expand';
                $html  .= '<details>';
                $html  .= '<summary class="sh-expandable-summary">'
                    . $badge . '&nbsp;<strong>' . esc_html($themeName) . '</strong>'
                    . '<span style="color:#94a3b8;font-size:12px;margin-left:8px;">' . $path . '</span>'
                    . '<span style="margin-left:auto;font-size:12px;color:#94a3b8;">' . esc_html($meta) . '</span>'
                    . '</summary>';
                $html  .= $this->buildThemeFindingsTable($findings);
                $html  .= '</details>';
            } else {
                $html .= '<div class="sh-expandable-row">'
                    . $badge . '&nbsp;<strong>' . esc_html($themeName) . '</strong>'
                    . '<span style="color:#94a3b8;font-size:12px;margin-left:8px;">' . $path . '</span>'
                    . '</div>';
            }

            $html .= '</div>';
        }

        $prefix = $infected > 0
            ? $this->alertHtml('danger', 'warning', \sprintf('%d theme(s) show signs of compromise. Expand each entry for details.', $infected))
            : $this->alertHtml('success', 'yes-alt', 'All themes are clean.');

        return $prefix . $html;
    }

    /**
     * @param  list<array<string, string>> $findings
     */
    private function buildThemeFindingsTable(array $findings): string
    {
        $html  = '<div style="padding:0 0 4px;">';
        $html .= '<table class="sh-table">';
        $html .= '<thead><tr>'
            . '<th style="width:80px;">' . esc_html__('Severity', 'salienthook') . '</th>'
            . '<th>' . esc_html__('File', 'salienthook') . '</th>'
            . '<th style="width:50px;">' . esc_html__('Line', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Finding', 'salienthook') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($findings as $finding) {
            $sev    = (string) ($finding['severity'] ?? 'medium');
            $badge  = '<span class="sh-badge sh-badge-' . esc_attr($sev) . '">' . esc_html(\strtoupper($sev)) . '</span>';

            $html .= '<tr>';
            $html .= '<td>' . $badge . '</td>';
            $html .= '<td><code>' . esc_html((string) ($finding['file'] ?? '')) . '</code></td>';
            $html .= '<td>' . esc_html((string) ($finding['line'] ?? '—')) . '</td>';
            $html .= '<td>' . esc_html((string) ($finding['detail'] ?? '')) . '</td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table></div>';
        return $html;
    }

    // =========================================================================
    // Result builders — threat scanner + database scanner (flat findings)
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $results
     */
    private function buildFlatResultsHtml(array $results, string $locationKey): string
    {
        if (empty($results)) {
            return $this->alertHtml('success', 'yes-alt', 'No threats detected.');
        }

        $critical = 0;
        $high     = 0;

        foreach ($results as $f) {
            if (($f['severity'] ?? '') === ThreatScanner::SEV_CRITICAL) {
                $critical++;
            } elseif (($f['severity'] ?? '') === ThreatScanner::SEV_HIGH) {
                $high++;
            }
        }

        $summary = \sprintf('%d critical, %d high — %d total finding(s).', $critical, $high, \count($results));
        $html    = $this->alertHtml('danger', 'warning', $summary);

        $categoryLabels = [
            'uploads_php' => 'PHP in Uploads',
            'htaccess'    => '.htaccess',
            'timthumb'    => 'Timthumb',
            'cron'        => 'WP-Cron',
            'new_admin'   => 'Admin Account',
            'db_ioc'      => 'DB Injection',
            'db_script_tag' => 'DB Script Tag',
        ];

        $html .= '<table class="sh-table">';
        $html .= '<thead><tr>'
            . '<th style="width:90px;">' . esc_html__('Severity', 'salienthook') . '</th>'
            . '<th style="width:120px;">' . esc_html__('Category', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Location', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Finding', 'salienthook') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($results as $finding) {
            $sev      = (string) ($finding['severity']      ?? 'medium');
            $category = (string) ($finding['category']      ?? '');
            $location = (string) ($finding[$locationKey]    ?? '');
            $detail   = (string) ($finding['detail']        ?? '');
            $catLabel = $categoryLabels[$category] ?? $category;
            $badge    = '<span class="sh-badge sh-badge-' . esc_attr($sev) . '">' . esc_html(\strtoupper($sev)) . '</span>';

            $html .= '<tr>';
            $html .= '<td>' . $badge . '</td>';
            $html .= '<td><span class="sh-cat-label">' . esc_html($catLabel) . '</span></td>';
            $html .= '<td><code>' . esc_html($location) . '</code></td>';
            $html .= '<td>' . esc_html($detail) . '</td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table>';
        return $html;
    }

    // =========================================================================
    // Panel 6 — Safe Corridor
    // =========================================================================

    private function renderSafeCorridorPanel(
        bool   $corridorOpen,
        int    $corridorExpiry,
        bool   $hasPassword,
        string $corridorNonce
    ): void {
        $remaining = ($corridorOpen && $corridorExpiry > 0)
            ? \max(0, $corridorExpiry - \time())
            : 0;

        echo '<div class="sh-card" style="margin-bottom:20px;">';
        echo '<div class="sh-card-header">';
        echo '<div class="sh-card-icon"><span class="dashicons dashicons-unlock"></span></div>';
        echo '<div>';
        echo '<h2 class="sh-card-title">' . esc_html__('Safe Corridor', 'salienthook') . '</h2>';
        echo '<p class="sh-card-desc">'
            . esc_html__('The only authorised way to install a plugin while lockdown is active. Enter the corridor password to open a 15-minute install window. All events are logged.', 'salienthook')
            . '</p>';
        echo '</div></div>';
        echo '<div class="sh-card-body">';

        // Status banner.
        if ($corridorOpen) {
            $mins = (int) \ceil($remaining / 60);
            echo '<div class="sh-alert sh-alert-danger" style="margin-bottom:20px;">'
                . '<span class="dashicons dashicons-unlock" style="margin-top:1px;"></span>'
                . '<div><strong>' . esc_html__('Corridor is OPEN', 'salienthook') . '</strong> — '
                . esc_html__('Plugin installation is active. Closes in', 'salienthook') . ' '
                . '<span id="sh-corridor-panel-countdown">' . $mins . esc_html__(' minute(s)', 'salienthook') . '</span>.'
                . ' <a href="#" id="sh-corridor-close-now" style="color:#b91c1c;font-weight:700;">'
                . esc_html__('Close Now', 'salienthook') . '</a></div></div>';
        } else {
            echo '<div class="sh-alert sh-alert-success" style="margin-bottom:20px;">'
                . '<span class="dashicons dashicons-lock" style="margin-top:1px;"></span>'
                . '<div>' . esc_html__('Corridor is closed — plugin installation is locked.', 'salienthook') . '</div>'
                . '</div>';
        }

        echo '<div class="sh-corridor-cols">';

        // Left: set / change password.
        echo '<div>';
        echo '<h3 style="margin-top:0;font-size:14px;">' . esc_html__('Set Corridor Password', 'salienthook') . '</h3>';
        echo '<p style="font-size:12.5px;color:#64748b;margin-bottom:12px;">'
            . esc_html__('Minimum 12 characters. Stored as a bcrypt hash — never in plain text.', 'salienthook')
            . '</p>';

        if ($hasPassword) {
            echo '<p style="font-size:12.5px;color:#16a34a;margin-bottom:10px;display:flex;align-items:center;gap:5px;">'
                . '<span class="dashicons dashicons-yes-alt"></span>'
                . esc_html__('Password is set.', 'salienthook')
                . '</p>';
        }

        echo '<div style="display:flex;gap:8px;flex-wrap:wrap;">'
            . '<input type="password" id="sh-corridor-new-password" '
            . 'placeholder="' . esc_attr__('New password (min 12 chars)', 'salienthook') . '" '
            . 'class="sh-input" style="max-width:260px;">'
            . '<button id="sh-corridor-save-password" class="sh-btn sh-btn-outline">'
            . esc_html__('Save Password', 'salienthook')
            . '</button>'
            . '</div>';

        echo '<div id="sh-corridor-password-msg" style="margin-top:8px;font-size:13px;"></div>';
        echo '</div>';

        // Right: unlock / revoke.
        echo '<div>';
        if ($corridorOpen) {
            echo '<h3 style="margin-top:0;font-size:14px;">' . esc_html__('Close Corridor', 'salienthook') . '</h3>';
            echo '<p style="font-size:12.5px;color:#64748b;margin-bottom:12px;">'
                . esc_html__('The corridor is active. Close it early if you are done installing.', 'salienthook')
                . '</p>';
            echo '<button id="sh-corridor-revoke" class="sh-btn sh-btn-danger">'
                . esc_html__('Close Corridor Now', 'salienthook')
                . '</button>';
        } elseif ($hasPassword) {
            echo '<h3 style="margin-top:0;font-size:14px;">' . esc_html__('Open Corridor', 'salienthook') . '</h3>';
            echo '<p style="font-size:12.5px;color:#64748b;margin-bottom:12px;">'
                . esc_html__('Enter the corridor password to unlock plugin installation for 15 minutes.', 'salienthook')
                . '</p>';
            echo '<div style="display:flex;gap:8px;flex-wrap:wrap;">'
                . '<input type="password" id="sh-corridor-password" '
                . 'placeholder="' . esc_attr__('Corridor password', 'salienthook') . '" '
                . 'class="sh-input" style="max-width:220px;">'
                . '<button id="sh-corridor-unlock" class="sh-btn sh-btn-primary">'
                . esc_html__('Open Corridor', 'salienthook')
                . '</button>'
                . '</div>';
        } else {
            echo '<h3 style="margin-top:0;font-size:14px;">' . esc_html__('Open Corridor', 'salienthook') . '</h3>';
            echo '<p style="font-size:12.5px;color:#b91c1c;">'
                . esc_html__('Set a corridor password first (see left).', 'salienthook')
                . '</p>';
        }

        echo '<div id="sh-corridor-unlock-msg" style="margin-top:8px;font-size:13px;"></div>';
        echo '</div>';

        echo '</div>'; // .sh-corridor-cols
        echo '</div>'; // .sh-card-body
        echo '</div>'; // .sh-card
    }

    // =========================================================================
    // AJAX handlers
    // =========================================================================

    public function handlePluginScanAjax(): void
    {
        check_ajax_referer('salienthook_scan', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        $results = $this->pluginDetector->runFullScan();
        set_transient('salienthook_plugin_scan_results', $results, DAY_IN_SECONDS);
        update_option('salienthook_last_plugin_scan', \time(), false);

        wp_send_json_success([
            'html'      => $this->buildPluginResultsHtml($results),
            'timestamp' => $this->formatTimestamp(\time()),
        ]);
    }

    public function handleThemeScanAjax(): void
    {
        check_ajax_referer('salienthook_scan', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        $results = $this->themeScanner->runScan();
        set_transient('salienthook_theme_scan_results', $results, DAY_IN_SECONDS);
        update_option('salienthook_last_theme_scan', \time(), false);

        wp_send_json_success([
            'html'      => $this->buildThemeResultsHtml($results),
            'timestamp' => $this->formatTimestamp(\time()),
        ]);
    }

    public function handleThreatScanAjax(): void
    {
        check_ajax_referer('salienthook_scan', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        $results = $this->threatScanner->runScan();
        set_transient(ThreatScanner::TRANSIENT_KEY, $results, DAY_IN_SECONDS);
        update_option(ThreatScanner::OPTION_LAST, \time(), false);

        wp_send_json_success([
            'html'      => $this->buildFlatResultsHtml($results, 'path'),
            'timestamp' => $this->formatTimestamp(\time()),
        ]);
    }

    public function handleDbScanAjax(): void
    {
        check_ajax_referer('salienthook_scan', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Insufficient permissions.']);
        }

        $results = $this->dbScanner->runScan();
        set_transient(DatabaseScanner::TRANSIENT_KEY, $results, DAY_IN_SECONDS);
        update_option(DatabaseScanner::OPTION_LAST, \time(), false);

        wp_send_json_success([
            'html'      => $this->buildFlatResultsHtml($results, 'option'),
            'timestamp' => $this->formatTimestamp(\time()),
        ]);
    }

    // =========================================================================
    // Shared helpers
    // =========================================================================

    private function alertHtml(string $type, string $icon, string $message): string
    {
        return '<div class="sh-alert sh-alert-' . esc_attr($type) . '">'
            . '<span class="dashicons dashicons-' . esc_attr($icon) . '" style="margin-top:1px;"></span>'
            . '<div>' . esc_html($message) . '</div>'
            . '</div>';
    }

    private function formatTimestamp(int $timestamp): string
    {
        return wp_date('Y-m-d H:i:s', $timestamp) . ' ' . wp_timezone_string();
    }

    // =========================================================================
    // Styles
    // =========================================================================

    private function renderStyles(): void
    {
        ?>
        <style>
        /* ----------------------------------------------------------------
           Salient Hook — Security Dashboard
           Headings: Sora  |  Body: Sen
        ---------------------------------------------------------------- */

        .sh-wrap {
            font-family: 'Sen', system-ui, -apple-system, sans-serif;
            color: #1e293b;
            max-width: 1100px;
            margin-top: 12px;
        }

        .sh-wrap h1, .sh-wrap h2, .sh-wrap h3, .sh-wrap h4,
        .sh-card-title, .sh-status-name, .sh-badge, .sh-btn {
            font-family: 'Sora', system-ui, -apple-system, sans-serif;
        }

        /* Page header */
        .sh-page-header {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 1px solid #e2e8f0;
        }
        .sh-logo-icon {
            width: 46px;
            height: 46px;
            background: #2271b1;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        .sh-logo-icon .dashicons {
            font-size: 22px;
            width: 22px;
            height: 22px;
            color: #fff;
        }
        .sh-page-header h1 {
            font-size: 21px;
            font-weight: 700;
            line-height: 1.25;
            margin: 0 0 3px;
            color: #0f172a;
        }
        .sh-page-header > div > p {
            font-size: 13px;
            color: #64748b;
            margin: 0;
        }

        /* Cards */
        .sh-card {
            background: #fff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .sh-card-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 18px 22px;
            border-bottom: 1px solid #f1f5f9;
        }
        .sh-card-icon {
            width: 36px;
            height: 36px;
            background: #eff6ff;
            border-radius: 7px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        .sh-card-icon .dashicons {
            font-size: 18px;
            width: 18px;
            height: 18px;
            color: #2271b1;
        }
        .sh-card-title {
            font-size: 14px;
            font-weight: 700;
            margin: 3px 0 3px;
            color: #0f172a;
            line-height: 1.3;
        }
        .sh-card-desc {
            font-size: 12.5px;
            color: #64748b;
            margin: 0;
            line-height: 1.5;
        }
        .sh-card-body {
            padding: 18px 22px;
        }

        /* Status grid */
        .sh-status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
            gap: 10px;
        }
        .sh-status-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 12px 13px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            background: #f8fafc;
        }
        .sh-status-dot {
            width: 9px;
            height: 9px;
            border-radius: 50%;
            flex-shrink: 0;
            margin-top: 3px;
        }
        .sh-status-active .sh-status-dot  { background: #16a34a; }
        .sh-status-inactive .sh-status-dot { background: #dc2626; }
        .sh-status-info { flex: 1; min-width: 0; }
        .sh-status-name {
            font-size: 12.5px;
            font-weight: 600;
            color: #0f172a;
            line-height: 1.3;
            margin-bottom: 3px;
        }
        .sh-status-desc { font-size: 11px; color: #94a3b8; line-height: 1.4; }

        /* Badges */
        .sh-badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 20px;
            font-size: 10.5px;
            font-weight: 700;
            letter-spacing: 0.3px;
            white-space: nowrap;
            flex-shrink: 0;
            text-transform: uppercase;
        }
        .sh-badge-success  { background: #dcfce7; color: #15803d; }
        .sh-badge-danger   { background: #fee2e2; color: #b91c1c; }
        .sh-badge-warning  { background: #fef3c7; color: #b45309; }
        .sh-badge-critical { background: #fee2e2; color: #b91c1c; }
        .sh-badge-high     { background: #fef3c7; color: #b45309; }
        .sh-badge-medium   { background: #e0f2fe; color: #0369a1; }
        .sh-badge-muted    { background: #f1f5f9; color: #475569; }

        /* Scan meta */
        .sh-scan-meta {
            font-size: 12px;
            color: #94a3b8;
            margin-bottom: 12px;
        }

        /* Buttons */
        .sh-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 7px 15px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid transparent;
            text-decoration: none;
            line-height: 1.4;
            vertical-align: middle;
            transition: opacity 0.15s, background 0.15s;
        }
        .sh-btn:disabled { opacity: 0.55; cursor: not-allowed; }
        .sh-btn-primary { background: #2271b1; color: #fff; border-color: #2271b1; }
        .sh-btn-primary:hover:not(:disabled) { background: #135e96; border-color: #135e96; color: #fff; }
        .sh-btn-danger  { background: #dc2626; color: #fff; border-color: #dc2626; }
        .sh-btn-danger:hover:not(:disabled) { background: #b91c1c; border-color: #b91c1c; color: #fff; }
        .sh-btn-outline { background: #fff; color: #2271b1; border-color: #2271b1; }
        .sh-btn-outline:hover:not(:disabled) { background: #eff6ff; color: #2271b1; }
        .sh-btn-sm { padding: 4px 10px; font-size: 12px; }

        /* Tables */
        .sh-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            margin-top: 12px;
        }
        .sh-table th {
            text-align: left;
            font-family: 'Sora', sans-serif;
            font-size: 10.5px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #94a3b8;
            padding: 7px 11px;
            border-bottom: 1px solid #e2e8f0;
        }
        .sh-table td {
            padding: 9px 11px;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
            color: #334155;
        }
        .sh-table tr:last-child td { border-bottom: none; }
        .sh-table tr:hover td { background: #f8fafc; }
        .sh-table code {
            background: #f1f5f9;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 11px;
            color: #475569;
            word-break: break-all;
        }

        /* Category label */
        .sh-cat-label {
            background: #f1f5f9;
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 11px;
            color: #475569;
            font-family: 'Sora', sans-serif;
            font-weight: 600;
        }

        /* Alert boxes */
        .sh-alert {
            display: flex;
            align-items: flex-start;
            gap: 9px;
            padding: 11px 14px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 12px;
            border-width: 1px;
            border-style: solid;
        }
        .sh-alert .dashicons { flex-shrink: 0; margin-top: 1px; }
        .sh-alert-success { background: #f0fdf4; border-color: #bbf7d0; color: #15803d; }
        .sh-alert-danger  { background: #fef2f2; border-color: #fecaca; color: #b91c1c; }
        .sh-alert-warning { background: #fffbeb; border-color: #fed7aa; color: #b45309; }
        .sh-alert-info    { background: #eff6ff; border-color: #bfdbfe; color: #1d4ed8; }

        /* Input */
        .sh-input {
            padding: 7px 11px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-family: 'Sen', sans-serif;
            font-size: 13px;
            color: #1e293b;
            background: #fff;
            width: 100%;
            box-sizing: border-box;
        }
        .sh-input:focus {
            outline: none;
            border-color: #2271b1;
            box-shadow: 0 0 0 2px rgba(34,113,177,0.15);
        }

        /* Corridor columns */
        .sh-corridor-cols {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        /* Expandable theme rows */
        .sh-expandable {
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            margin-bottom: 8px;
            overflow: hidden;
        }
        .sh-expandable-summary, .sh-expandable-row {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 11px 14px;
            background: #f8fafc;
            list-style: none;
        }
        .sh-expandable summary { cursor: pointer; }
        .sh-expandable summary:hover { background: #f1f5f9; }
        .sh-expandable details[open] .sh-expandable-summary,
        .sh-expandable details[open] summary { background: #f1f5f9; }

        /* Spin animation */
        @keyframes sh-spin {
            from { transform: rotate(0deg); }
            to   { transform: rotate(360deg); }
        }
        .sh-spin { display: inline-block; animation: sh-spin 1s linear infinite; }

        /* Responsive */
        @media (max-width: 780px) {
            .sh-status-grid   { grid-template-columns: 1fr 1fr; }
            .sh-corridor-cols { grid-template-columns: 1fr; }
        }
        @media (max-width: 500px) {
            .sh-status-grid { grid-template-columns: 1fr; }
        }
        </style>
        <?php
    }

    // =========================================================================
    // Inline JavaScript
    // =========================================================================

    private function renderInlineScript(
        string $scanNonce,
        string $corridorNonce,
        bool   $corridorOpen,
        int    $corridorExpiry
    ): void {
        $remaining = $corridorOpen ? \max(0, $corridorExpiry - \time()) : 0;
        ?>
        <script>
        (function ($) {
            'use strict';

            // ----------------------------------------------------------------
            // Generic AJAX scan runner
            // ----------------------------------------------------------------
            function runScan(btnId, resultsId, tsId, action) {
                $('#' + btnId).on('click', function (e) {
                    e.preventDefault();
                    var $btn = $(this);
                    var orig = $btn.html();

                    $btn.prop('disabled', true).html(
                        '<span class="dashicons dashicons-update sh-spin" style="font-size:15px;width:15px;height:15px;"></span> <?php echo esc_js(__('Scanning…', 'salienthook')); ?>'
                    );
                    $('#' + resultsId).html(
                        '<p style="color:#94a3b8;font-size:13px;"><?php echo esc_js(__('Scan in progress…', 'salienthook')); ?></p>'
                    );

                    $.post(ajaxurl, { action: action, nonce: '<?php echo esc_js($scanNonce); ?>' })
                        .done(function (r) {
                            if (r.success) {
                                $('#' + resultsId).html(r.data.html);
                                if (tsId) { $('#' + tsId).text(r.data.timestamp); }
                            } else {
                                $('#' + resultsId).html(
                                    '<div class="sh-alert sh-alert-danger"><span class="dashicons dashicons-warning"></span><div><?php echo esc_js(__('Scan failed. Please try again.', 'salienthook')); ?></div></div>'
                                );
                            }
                        })
                        .fail(function () {
                            $('#' + resultsId).html(
                                '<div class="sh-alert sh-alert-danger"><span class="dashicons dashicons-warning"></span><div><?php echo esc_js(__('Request failed.', 'salienthook')); ?></div></div>'
                            );
                        })
                        .always(function () { $btn.prop('disabled', false).html(orig); });
                });
            }

            runScan('sh-run-plugin-scan', 'sh-plugin-scan-results', 'sh-last-plugin-scan', 'salienthook_plugin_scan');
            runScan('sh-run-theme-scan',  'sh-theme-scan-results',  'sh-last-theme-scan',  'salienthook_theme_scan');
            runScan('sh-run-threat-scan', 'sh-threat-scan-results', 'sh-last-threat-scan', 'salienthook_threat_scan');
            runScan('sh-run-db-scan',     'sh-db-scan-results',     'sh-last-db-scan',     'salienthook_db_scan');

            // ----------------------------------------------------------------
            // Corridor countdown
            // ----------------------------------------------------------------
            var remaining = <?php echo (int) $remaining; ?>;

            function fmtTime(s) {
                if (s <= 0) { return '0s'; }
                var m = Math.floor(s / 60), sec = s % 60;
                return m > 0 ? (m + 'min ' + (sec > 0 ? sec + 's' : '')) : (sec + 's');
            }

            if (remaining > 0) {
                var timer = setInterval(function () {
                    remaining--;
                    var label = fmtTime(remaining);
                    $('#salienthook-corridor-countdown, #sh-corridor-panel-countdown').text(label);
                    if (remaining <= 0) { clearInterval(timer); location.reload(); }
                }, 1000);
            }

            // ----------------------------------------------------------------
            // Corridor — set password
            // ----------------------------------------------------------------
            $('#sh-corridor-save-password').on('click', function (e) {
                e.preventDefault();
                var $btn = $(this), $msg = $('#sh-corridor-password-msg');
                $btn.prop('disabled', true);
                $msg.text('<?php echo esc_js(__('Saving…', 'salienthook')); ?>').css('color', '#64748b');

                $.post(ajaxurl, {
                    action:   'salienthook_corridor_set_password',
                    nonce:    '<?php echo esc_js($corridorNonce); ?>',
                    password: $('#sh-corridor-new-password').val()
                })
                .done(function (r) {
                    if (r.success) {
                        $msg.text(r.data.message).css('color', '#16a34a');
                        $('#sh-corridor-new-password').val('');
                    } else {
                        $msg.text(r.data.message).css('color', '#dc2626');
                    }
                })
                .fail(function () { $msg.text('<?php echo esc_js(__('Request failed.', 'salienthook')); ?>').css('color', '#dc2626'); })
                .always(function () { $btn.prop('disabled', false); });
            });

            // ----------------------------------------------------------------
            // Corridor — unlock
            // ----------------------------------------------------------------
            $('#sh-corridor-unlock').on('click', function (e) {
                e.preventDefault();
                var $btn = $(this), $msg = $('#sh-corridor-unlock-msg');
                $btn.prop('disabled', true);
                $msg.text('<?php echo esc_js(__('Verifying…', 'salienthook')); ?>').css('color', '#64748b');

                $.post(ajaxurl, {
                    action:   'salienthook_corridor_unlock',
                    nonce:    '<?php echo esc_js($corridorNonce); ?>',
                    password: $('#sh-corridor-password').val()
                })
                .done(function (r) {
                    if (r.success) {
                        $msg.text(r.data.message).css('color', '#16a34a');
                        $('#sh-corridor-password').val('');
                        setTimeout(function () { location.reload(); }, 1200);
                    } else {
                        $msg.text(r.data.message).css('color', '#dc2626');
                        $btn.prop('disabled', false);
                    }
                })
                .fail(function () {
                    $msg.text('<?php echo esc_js(__('Request failed.', 'salienthook')); ?>').css('color', '#dc2626');
                    $btn.prop('disabled', false);
                });
            });

            // ----------------------------------------------------------------
            // Corridor — revoke (panel button + banner link)
            // ----------------------------------------------------------------
            function revokeHandler(e) {
                e.preventDefault();
                $.post(ajaxurl, { action: 'salienthook_corridor_revoke', nonce: '<?php echo esc_js($corridorNonce); ?>' })
                    .done(function (r) {
                        if (r.success) { location.reload(); }
                        else { $('#sh-corridor-unlock-msg').text(r.data.message).css('color', '#dc2626'); }
                    });
            }

            $('#sh-corridor-revoke, #sh-corridor-close-now').on('click', revokeHandler);
            // Banner "Close Now" link rendered by SafeCorridor::renderCorridorBanner()
            $(document).on('click', '#salienthook-corridor-close-now', revokeHandler);

        }(jQuery));
        </script>
        <?php
    }
}
