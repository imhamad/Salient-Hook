<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Scans the WordPress database for injected JavaScript payloads.
 *
 * The ClickFix / DoubleDonut campaign (Rapid7, 2025–2026) injects malicious
 * JavaScript directly into wp_options — widget areas, theme customiser settings,
 * and custom option keys — rather than modifying plugin or theme files.
 *
 * Crucially, the injected code checks for the wordpress_logged_in_ cookie and
 * hides itself from logged-in administrators. File-based scanners that run as
 * an admin therefore never see the payload. This scanner reads the raw stored
 * values directly from the database, bypassing any client-side evasion.
 *
 * Scan strategy:
 *  1. High-risk option keys — widget_text, widget_custom_html, sidebars_widgets,
 *     Elementor data, and other option keys commonly abused for JS injection.
 *  2. All widget_* options — catches any widget type, not just the known ones.
 *  3. All theme_mods_* options — theme customiser is a common injection target.
 *  4. IOC matching — every value is checked against both campaigns' IOC lists.
 */
final class DatabaseScanner
{
    public const TRANSIENT_KEY = 'salienthook_db_scan_results';
    public const OPTION_LAST   = 'salienthook_last_db_scan';

    public const SEV_CRITICAL = 'critical';
    public const SEV_HIGH     = 'high';
    public const SEV_MEDIUM   = 'medium';

    /**
     * IOC strings matched against serialised option values.
     *
     * Covers the original LummaStealer campaign (WP Performance Analytics) and
     * the ClickFix / DoubleDonut campaign (Rapid7 TR-2025).
     *
     * @var array<string, array{description: string, severity: string}>
     */
    private const OPTION_IOCS = [
        // --- ClickFix / DoubleDonut campaign (Rapid7 TR-2025) ----------------
        '__performance_optimizer_v6' => ['description' => 'ClickFix campaign JS evasion flag',                    'severity' => self::SEV_CRITICAL],
        'goveanrs.org'               => ['description' => 'ClickFix JS hosting domain',                           'severity' => self::SEV_CRITICAL],
        'getalib.org'                => ['description' => 'ClickFix JS hosting domain',                           'severity' => self::SEV_CRITICAL],
        'ligovera.shop'              => ['description' => 'ClickFix JS hosting domain',                           'severity' => self::SEV_CRITICAL],
        'alianzeg.shop'              => ['description' => 'ClickFix JS hosting domain',                           'severity' => self::SEV_CRITICAL],
        'cptoptious.com'             => ['description' => 'ClickFix implant domain',                              'severity' => self::SEV_CRITICAL],
        'captioto.com'               => ['description' => 'ClickFix implant domain',                              'severity' => self::SEV_CRITICAL],
        'captoolsz.com'              => ['description' => 'ClickFix implant domain',                              'severity' => self::SEV_CRITICAL],
        'capztoolz.com'              => ['description' => 'ClickFix implant domain',                              'severity' => self::SEV_CRITICAL],
        'greecpt.shop'               => ['description' => 'ClickFix implant domain',                              'severity' => self::SEV_CRITICAL],
        '91.92.240.219'              => ['description' => 'ClickFix C2 IP address',                               'severity' => self::SEV_CRITICAL],
        '178.16.53.70'               => ['description' => 'ClickFix C2 IP address',                               'severity' => self::SEV_CRITICAL],
        '94.154.35.115'              => ['description' => 'ClickFix C2 IP address',                               'severity' => self::SEV_CRITICAL],
        '172.94.9.187'               => ['description' => 'ClickFix C2 IP address (updated March 2026)',           'severity' => self::SEV_CRITICAL],
        'ajjs_run'                   => ['description' => 'ClickFix admin-ajax injection action',                  'severity' => self::SEV_CRITICAL],
        'cptch.bin'                  => ['description' => 'ClickFix first-stage shellcode filename',               'severity' => self::SEV_CRITICAL],
        'cptchbuild.bin'             => ['description' => 'ClickFix second-stage shellcode filename',              'severity' => self::SEV_CRITICAL],
        // --- LummaStealer campaign (WP Performance Analytics) ----------------
        'workaem'                    => ['description' => 'LummaStealer C2 domain fragment (workaem.eth.limo)',    'severity' => self::SEV_CRITICAL],
        '45.61.136.85'               => ['description' => 'LummaStealer C2 IP address',                           'severity' => self::SEV_CRITICAL],
        'emergency_login_all_admins' => ['description' => 'LummaStealer malware function name',                    'severity' => self::SEV_CRITICAL],
        'execute_admin_command'      => ['description' => 'LummaStealer malware function name',                    'severity' => self::SEV_CRITICAL],
        // --- Generic evasion indicator ----------------------------------------
        'wordpress_logged_in_'       => ['description' => 'Admin cookie-evasion pattern — payload hides from logged-in users', 'severity' => self::SEV_HIGH],
    ];

    /**
     * Option keys that are high-priority targets for JS injection.
     * Scanned first before the broader wildcard queries.
     *
     * @var string[]
     */
    private const HIGH_RISK_KEYS = [
        'widget_text',
        'widget_custom_html',
        'widget_block',
        'sidebars_widgets',
        'elementor_active_kit',
        '_elementor_global_css',
        'wp_head_scripts',
        'wp_footer_scripts',
    ];

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        // On-demand only — called from the settings page AJAX handler.
    }

    // =========================================================================
    // Full scan
    // =========================================================================

    /**
     * Scan wp_options for known campaign IOCs.
     *
     * @return array<int, array<string, string>>
     */
    public function runScan(): array
    {
        $findings = [];

        $this->scanHighRiskKeys($findings);
        $this->scanWidgetOptions($findings);
        $this->scanThemeMods($findings);

        // Sort critical → high → medium.
        \usort($findings, static function (array $a, array $b): int {
            $order = [self::SEV_CRITICAL => 0, self::SEV_HIGH => 1, self::SEV_MEDIUM => 2];
            return ($order[$a['severity']] ?? 2) <=> ($order[$b['severity']] ?? 2);
        });

        // Deduplicate by option name + IOC key to avoid repeated findings.
        $seen    = [];
        $deduped = [];

        foreach ($findings as $finding) {
            $dedupeKey = ($finding['option'] ?? '') . '||' . ($finding['detail'] ?? '');

            if (! isset($seen[$dedupeKey])) {
                $seen[$dedupeKey] = true;
                $deduped[]        = $finding;
            }
        }

        return $deduped;
    }

    // =========================================================================
    // Scan methods
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function scanHighRiskKeys(array &$findings): void
    {
        foreach (self::HIGH_RISK_KEYS as $key) {
            $raw = get_option($key, null);

            if ($raw === null || $raw === false) {
                continue;
            }

            $serialised = \maybe_serialize($raw);
            $this->matchIocs($serialised, $key, $findings);
        }
    }

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function scanWidgetOptions(array &$findings): void
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT option_name, option_value
             FROM {$wpdb->options}
             WHERE option_name LIKE 'widget\_%'
             LIMIT 200",
            ARRAY_A
        );

        if (empty($rows)) {
            return;
        }

        foreach ($rows as $row) {
            $this->matchIocs((string) $row['option_value'], (string) $row['option_name'], $findings);
        }
    }

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function scanThemeMods(array &$findings): void
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT option_name, option_value
             FROM {$wpdb->options}
             WHERE option_name LIKE 'theme\_mods\_%'
             LIMIT 50",
            ARRAY_A
        );

        if (empty($rows)) {
            return;
        }

        foreach ($rows as $row) {
            $this->matchIocs((string) $row['option_value'], (string) $row['option_name'], $findings);
        }
    }

    // =========================================================================
    // IOC matching
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function matchIocs(string $value, string $optionName, array &$findings): void
    {
        if (empty($value)) {
            return;
        }

        $lower = \strtolower($value);

        foreach (self::OPTION_IOCS as $ioc => $meta) {
            if (\strpos($lower, \strtolower($ioc)) !== false) {
                $findings[] = [
                    'category' => 'db_ioc',
                    'severity' => $meta['severity'],
                    'option'   => $optionName,
                    'detail'   => $meta['description'] . ' — matched: ' . $ioc,
                ];
            }
        }
    }
}
