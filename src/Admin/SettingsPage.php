<?php

declare(strict_types=1);

namespace SalientHook\Admin;

use SalientHook\Modules\MaliciousPluginDetector;
use SalientHook\Modules\ThemeIntegrityScanner;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Settings > Salient Hook — Security Dashboard.
 *
 * Three panels:
 *  1. Lockdown Status — live badges showing update/install lock state.
 *  2. Malicious Plugin Scanner — detects known-malware plugins; auto-deactivates.
 *  3. Theme Integrity Scanner — scans theme files for IOCs and malware artefacts.
 *
 * Both scanners run via AJAX ("Run Scan Now") so the page never fully reloads.
 * Results are persisted in transients and shown on subsequent visits.
 */
final class SettingsPage
{
    private MaliciousPluginDetector $pluginDetector;
    private ThemeIntegrityScanner   $themeScanner;

    public function __construct(
        MaliciousPluginDetector $pluginDetector,
        ThemeIntegrityScanner   $themeScanner
    ) {
        $this->pluginDetector = $pluginDetector;
        $this->themeScanner   = $themeScanner;
    }

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        add_action('admin_menu', [$this, 'registerMenu']);
        add_action('wp_ajax_salienthook_plugin_scan', [$this, 'handlePluginScanAjax']);
        add_action('wp_ajax_salienthook_theme_scan',  [$this, 'handleThemeScanAjax']);
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
        $lastPluginScan = (int) get_option('salienthook_last_plugin_scan', 0);
        $lastThemeScan  = (int) get_option('salienthook_last_theme_scan', 0);
        $pluginResults  = ($pluginResults !== false) ? (array) $pluginResults : null;
        $themeResults   = ($themeResults !== false)  ? (array) $themeResults  : null;
        ?>
        <div class="wrap">
            <h1 style="display:flex;align-items:center;gap:10px;">
                <span class="dashicons dashicons-shield" style="font-size:28px;width:28px;height:28px;color:#2271b1;"></span>
                <?php esc_html_e('Salient Hook — Security Dashboard', 'salienthook'); ?>
            </h1>
            <p class="description" style="margin-bottom:20px;">
                <?php esc_html_e('Protects this WordPress installation against unauthorised plugin injection and malware delivery.', 'salienthook'); ?>
            </p>

            <?php
            $this->renderLockdownPanel();
            $this->renderPluginScanPanel($pluginResults, $lastPluginScan);
            $this->renderThemeScanPanel($themeResults, $lastThemeScan);
            $this->renderInlineScript();
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
                'label'  => 'Plugin updates disabled',
                'detail' => 'Blocks wp.org update checks, zeroes update transients, removes update UI.',
                'active' => has_filter('pre_site_transient_update_plugins'),
            ],
            [
                'label'  => 'Auto-updates disabled (WP 5.5+)',
                'detail' => 'auto_update_plugin filter always returns false.',
                'active' => has_filter('auto_update_plugin'),
            ],
            [
                'label'  => 'Plugin installation blocked',
                'detail' => 'install_plugins capability revoked, plugin-install.php intercepted, ZIP uploads stripped.',
                'active' => has_filter('user_has_cap'),
            ],
            [
                'label'  => 'Malicious plugin auto-deactivation',
                'detail' => 'Known malware signatures checked on every admin load.',
                'active' => has_action('admin_init', [MaliciousPluginDetector::class, 'scanAndDeactivate']),
            ],
        ];

        echo '<div class="card" style="max-width:none;padding:20px;margin-bottom:20px;">';
        echo '<h2 style="margin-top:0;display:flex;align-items:center;gap:8px;">';
        echo '<span class="dashicons dashicons-lock" style="color:#2271b1;"></span>';
        echo esc_html__('Lockdown Status', 'salienthook');
        echo '</h2>';
        echo '<table class="wp-list-table widefat fixed striped" style="margin-top:0;">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__('Protection', 'salienthook') . '</th>';
        echo '<th style="width:140px;">' . esc_html__('Status', 'salienthook') . '</th>';
        echo '<th>' . esc_html__('Coverage', 'salienthook') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($checks as $check) {
            $badge = $check['active']
                ? '<span style="display:inline-flex;align-items:center;gap:4px;color:#00a32a;font-weight:600;">'
                    . '<span class="dashicons dashicons-yes-alt"></span> Active</span>'
                : '<span style="display:inline-flex;align-items:center;gap:4px;color:#d63638;font-weight:600;">'
                    . '<span class="dashicons dashicons-dismiss"></span> Inactive</span>';

            echo '<tr>';
            echo '<td><strong>' . esc_html($check['label']) . '</strong></td>';
            echo '<td>' . $badge . '</td>';
            echo '<td style="color:#646970;">' . esc_html($check['detail']) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
        echo '</div>';
    }

    // =========================================================================
    // Panel 2 — Malicious Plugin Scanner
    // =========================================================================

    private function renderPluginScanPanel(?array $results, int $lastScan): void
    {
        echo '<div class="card" style="max-width:none;padding:20px;margin-bottom:20px;">';
        echo '<h2 style="margin-top:0;display:flex;align-items:center;gap:8px;">';
        echo '<span class="dashicons dashicons-search" style="color:#2271b1;"></span>';
        echo esc_html__('Malicious Plugin Scanner', 'salienthook');
        echo '</h2>';
        echo '<p>' . esc_html__('Scans all installed plugins against known malware signatures and code-level IOCs. Active malicious plugins are deactivated automatically.', 'salienthook') . '</p>';

        $this->renderScanMeta('salienthook-last-plugin-scan', $lastScan);

        echo '<button id="salienthook-run-plugin-scan" class="button button-primary">'
            . esc_html__('Run Scan Now', 'salienthook') . '</button>';

        echo '<div id="salienthook-plugin-scan-results" style="margin-top:16px;">';
        echo ($results !== null) ? $this->buildPluginResultsHtml($results) : '';
        echo '</div>';
        echo '</div>';
    }

    /**
     * @param  array<int, array<string, mixed>> $results
     */
    private function buildPluginResultsHtml(array $results): string
    {
        if (empty($results)) {
            return '<div class="notice notice-success inline" style="margin:0;">'
                . '<p><span class="dashicons dashicons-yes-alt" style="color:#00a32a;"></span> '
                . esc_html__('No malicious plugins detected.', 'salienthook')
                . '</p></div>';
        }

        $count = \count($results);
        $html  = '<div class="notice notice-error inline" style="margin:0 0 12px;">'
            . '<p><strong>' . \sprintf(
                /* translators: %d = number of plugins */
                esc_html__('%d malicious plugin(s) detected and deactivated.', 'salienthook'),
                $count
            ) . '</strong></p></div>';

        $html .= '<table class="wp-list-table widefat fixed striped">';
        $html .= '<thead><tr>'
            . '<th>' . esc_html__('Plugin', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Author', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Version', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Match Reason', 'salienthook') . '</th>'
            . '<th style="width:120px;">' . esc_html__('Action', 'salienthook') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($results as $finding) {
            $name    = esc_html((string) ($finding['name']         ?? ''));
            $file    = esc_html((string) ($finding['file']         ?? ''));
            $author  = esc_html((string) ($finding['author']       ?? ''));
            $version = esc_html((string) ($finding['version']      ?? ''));
            $reason  = esc_html((string) ($finding['match_reason'] ?? ''));

            $deleteUrl = esc_url(
                admin_url('plugins.php?s=' . \urlencode((string) ($finding['name'] ?? '')))
            );

            $html .= '<tr>';
            $html .= '<td><strong>' . $name . '</strong><br>'
                . '<code style="font-size:11px;color:#999;">' . $file . '</code></td>';
            $html .= '<td>' . $author . '</td>';
            $html .= '<td>' . $version . '</td>';
            $html .= '<td><span style="color:#d63638;">' . $reason . '</span></td>';
            $html .= '<td><a href="' . $deleteUrl . '" class="button button-small button-link-delete">'
                . esc_html__('Find & Delete', 'salienthook') . '</a></td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table>';
        return $html;
    }

    // =========================================================================
    // Panel 3 — Theme Integrity Scanner
    // =========================================================================

    private function renderThemeScanPanel(?array $results, int $lastScan): void
    {
        echo '<div class="card" style="max-width:none;padding:20px;margin-bottom:20px;">';
        echo '<h2 style="margin-top:0;display:flex;align-items:center;gap:8px;">';
        echo '<span class="dashicons dashicons-editor-code" style="color:#2271b1;"></span>';
        echo esc_html__('Theme Integrity Scanner', 'salienthook');
        echo '</h2>';
        echo '<p>' . esc_html__(
            'Scans all installed theme directories for verification.html drops, injected scripts, C2 domain references, and known malware function names.',
            'salienthook'
        ) . '</p>';

        $this->renderScanMeta('salienthook-last-theme-scan', $lastScan);

        echo '<button id="salienthook-run-theme-scan" class="button button-primary">'
            . esc_html__('Run Scan Now', 'salienthook') . '</button>';

        echo '<div id="salienthook-theme-scan-results" style="margin-top:16px;">';
        echo ($results !== null) ? $this->buildThemeResultsHtml($results) : '';
        echo '</div>';
        echo '</div>';
    }

    /**
     * @param  array<string, array<string, mixed>> $results
     */
    private function buildThemeResultsHtml(array $results): string
    {
        if (empty($results)) {
            return '<div class="notice notice-success inline" style="margin:0;">'
                . '<p><span class="dashicons dashicons-yes-alt" style="color:#00a32a;"></span> '
                . esc_html__('No themes scanned yet.', 'salienthook')
                . '</p></div>';
        }

        $html     = '';
        $infected = 0;

        foreach ($results as $themeName => $themeData) {
            $status   = (string) ($themeData['status'] ?? 'clean');
            $findings = (array)  ($themeData['findings'] ?? []);
            $critical = (int)    ($themeData['critical'] ?? 0);

            if ($status !== 'clean') {
                $infected++;
            }

            if ($status === 'infected') {
                $badgeColor = '#d63638';
                $badgeIcon  = 'warning';
            } elseif ($status === 'suspicious') {
                $badgeColor = '#dba617';
                $badgeIcon  = 'flag';
            } else {
                $badgeColor = '#00a32a';
                $badgeIcon  = 'yes-alt';
            }

            $badge = '<span style="display:inline-flex;align-items:center;gap:4px;color:' . $badgeColor . ';font-weight:600;">'
                . '<span class="dashicons dashicons-' . $badgeIcon . '"></span>'
                . \strtoupper($status) . '</span>';

            $html .= '<div style="border:1px solid #c3c4c7;border-radius:4px;margin-bottom:10px;">';

            if (! empty($findings)) {
                $html .= '<details>';
                $html .= '<summary style="padding:12px 16px;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;">';
            } else {
                $html .= '<div style="padding:12px 16px;display:flex;align-items:center;gap:10px;">';
            }

            $html .= $badge;
            $html .= '<strong>' . esc_html($themeName) . '</strong>';
            $html .= '<span style="color:#999;font-size:12px;">' . esc_html((string) ($themeData['path'] ?? '')) . '</span>';

            if (! empty($findings)) {
                $html .= '<span style="margin-left:auto;color:#d63638;font-size:12px;">';
                $html .= \sprintf(
                    /* translators: 1: critical count, 2: total count */
                    esc_html__('%1$d critical, %2$d total finding(s) — click to expand', 'salienthook'),
                    $critical,
                    \count($findings)
                );
                $html .= '</span>';
                $html .= '</summary>';
                $html .= $this->buildFindingsTable($findings);
                $html .= '</details>';
            } else {
                $html .= '</div>';
            }

            $html .= '</div>';
        }

        if ($infected > 0) {
            $summary = '<div class="notice notice-error inline" style="margin:0 0 12px;">'
                . '<p><strong>' . \sprintf(
                    /* translators: %d = infected theme count */
                    esc_html__('%d theme(s) show signs of compromise.', 'salienthook'),
                    $infected
                ) . '</strong> '
                . esc_html__('Expand each theme below to view specific findings and affected file paths.', 'salienthook')
                . '</p></div>';

            $html = $summary . $html;
        } else {
            $html = '<div class="notice notice-success inline" style="margin:0 0 12px;">'
                . '<p><span class="dashicons dashicons-yes-alt" style="color:#00a32a;"></span> '
                . esc_html__('All themes are clean.', 'salienthook')
                . '</p></div>' . $html;
        }

        return $html;
    }

    /**
     * @param  list<array<string, string>> $findings
     */
    private function buildFindingsTable(array $findings): string
    {
        $html  = '<div style="padding:0 16px 16px;">';
        $html .= '<table class="wp-list-table widefat fixed striped" style="font-size:12px;">';
        $html .= '<thead><tr>'
            . '<th style="width:80px;">' . esc_html__('Severity', 'salienthook') . '</th>'
            . '<th>' . esc_html__('File', 'salienthook') . '</th>'
            . '<th style="width:60px;">' . esc_html__('Line', 'salienthook') . '</th>'
            . '<th>' . esc_html__('Finding', 'salienthook') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($findings as $finding) {
            $severity = (string) ($finding['severity'] ?? 'medium');

            if ($severity === 'critical') {
                $sevColor = '#d63638';
            } elseif ($severity === 'high') {
                $sevColor = '#dba617';
            } else {
                $sevColor = '#646970';
            }

            $html .= '<tr>';
            $html .= '<td><strong style="color:' . $sevColor . ';">' . esc_html(\strtoupper($severity)) . '</strong></td>';
            $html .= '<td><code>' . esc_html((string) ($finding['file'] ?? '')) . '</code></td>';
            $html .= '<td>' . esc_html((string) ($finding['line'] ?? '—')) . '</td>';
            $html .= '<td>' . esc_html((string) ($finding['detail'] ?? '')) . '</td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table></div>';
        return $html;
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
            'count'     => \count($results),
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

    // =========================================================================
    // Shared helpers
    // =========================================================================

    private function renderScanMeta(string $elementId, int $timestamp): void
    {
        $label = $timestamp > 0
            ? $this->formatTimestamp($timestamp)
            : esc_html__('Never', 'salienthook');

        echo '<p style="color:#646970;margin-bottom:10px;">'
            . esc_html__('Last scan:', 'salienthook') . ' '
            . '<span id="' . esc_attr($elementId) . '">' . esc_html($label) . '</span>'
            . '</p>';
    }

    private function formatTimestamp(int $timestamp): string
    {
        return wp_date('Y-m-d H:i:s', $timestamp) . ' ' . wp_timezone_string();
    }

    // =========================================================================
    // Inline JavaScript
    // =========================================================================

    private function renderInlineScript(): void
    {
        $nonce = wp_create_nonce('salienthook_scan');
        ?>
        <script>
        (function ($) {
            'use strict';

            function runScan(buttonId, resultsId, timestampId, ajaxAction) {
                var $btn = $('#' + buttonId);

                $btn.on('click', function (e) {
                    e.preventDefault();

                    var originalText = $btn.text();
                    $btn.prop('disabled', true)
                        .html('<span class="dashicons dashicons-update" style="animation:spin 1s linear infinite;display:inline-block;"></span> <?php echo esc_js(__('Scanning…', 'salienthook')); ?>');

                    $('#' + resultsId).html(
                        '<p style="color:#646970;"><?php echo esc_js(__('Scan in progress, please wait…', 'salienthook')); ?></p>'
                    );

                    $.post(ajaxurl, {
                        action: ajaxAction,
                        nonce:  '<?php echo esc_js($nonce); ?>'
                    })
                    .done(function (response) {
                        if (response.success) {
                            $('#' + resultsId).html(response.data.html);
                            $('#' + timestampId).text(response.data.timestamp);
                        } else {
                            $('#' + resultsId).html(
                                '<div class="notice notice-error inline"><p><?php echo esc_js(__('Scan failed. Please try again.', 'salienthook')); ?></p></div>'
                            );
                        }
                    })
                    .fail(function () {
                        $('#' + resultsId).html(
                            '<div class="notice notice-error inline"><p><?php echo esc_js(__('Request failed. Check your browser console.', 'salienthook')); ?></p></div>'
                        );
                    })
                    .always(function () {
                        $btn.prop('disabled', false).text(originalText);
                    });
                });
            }

            runScan(
                'salienthook-run-plugin-scan',
                'salienthook-plugin-scan-results',
                'salienthook-last-plugin-scan',
                'salienthook_plugin_scan'
            );

            runScan(
                'salienthook-run-theme-scan',
                'salienthook-theme-scan-results',
                'salienthook-last-theme-scan',
                'salienthook_theme_scan'
            );
        }(jQuery));
        </script>
        <style>
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        </style>
        <?php
    }
}
