<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Scans for common WordPress attack artefacts beyond the LummaStealer campaign.
 *
 * Checks performed on every on-demand scan:
 *
 *  1. PHP files inside /wp-content/uploads/ — web shells disguised as uploads.
 *     Any PHP file in the uploads directory is a red flag; eval/obfuscation combos
 *     escalate the finding to CRITICAL.
 *
 *  2. .htaccess inspection — looks for auto_prepend_file, auto_append_file, and
 *     base64_decode directives that attackers use to silently execute dropped files.
 *
 *  3. Timthumb remnants — the 2011 RCE vulnerability is still present on old sites.
 *     Scans theme directories (depth-limited to 3) for timthumb.php and variants.
 *
 *  4. Suspicious WP-Cron hooks — malware often registers obfuscated cron hooks
 *     (base64-looking strings, MD5-length hex) for persistent execution.
 *
 *  5. Recently created admin accounts — flags any administrator account created
 *     within the past 24 hours as a potential privilege escalation artefact.
 *
 *  6. Installed plugins with known critical/high CVEs — checks all installed
 *     plugins against a curated list of plugins that have had unauthenticated
 *     RCE, auth bypass, SQLi, or privilege-escalation vulnerabilities actively
 *     exploited in the wild (e.g. WP File Manager, LiteSpeed Cache, Really
 *     Simple SSL). Findings include the CVE, installed version, and fix advice.
 */
final class ThreatScanner
{
    public const TRANSIENT_KEY = 'salienthook_threat_scan_results';
    public const OPTION_LAST   = 'salienthook_last_threat_scan';

    public const SEV_CRITICAL = 'critical';
    public const SEV_HIGH     = 'high';
    public const SEV_MEDIUM   = 'medium';

    /**
     * Eval/obfuscation patterns that escalate a PHP-in-uploads finding to CRITICAL.
     *
     * @var string[]
     */
    private const EVAL_PATTERNS = [
        'eval(base64_decode(',
        'eval(gzinflate(',
        'eval(str_rot13(',
        'eval(gzuncompress(',
        'eval($_POST[',
        'eval($_GET[',
        'eval($_REQUEST[',
        'assert(base64_decode(',
    ];

    /**
     * .htaccess directive substrings that indicate a dropper or redirect injector.
     *
     * @var array<string, string>
     */
    private const HTACCESS_SUSPECTS = [
        'auto_prepend_file'           => 'Prepends a PHP file before every request — classic dropper technique',
        'auto_append_file'            => 'Appends a PHP file after every request',
        'php_value auto_prepend_file' => 'PHP ini override to silently prepend a malicious file',
        'base64_decode'               => 'base64_decode directive in .htaccess — almost never legitimate',
    ];

    /**
     * Timthumb filenames to search for inside theme directories.
     *
     * @var string[]
     */
    private const TIMTHUMB_FILENAMES = [
        'timthumb.php',
        'thumb.php',
    ];

    /**
     * Regex patterns matching obfuscated-looking WP-Cron hook names.
     *
     * Only patterns that would virtually never appear in legitimate plugin code
     * are included to keep false positives to zero.
     *
     * @var string[]
     */
    private const SUSPICIOUS_CRON_PATTERNS = [
        '/^[a-zA-Z0-9+\/]{24,}={0,2}$/', // Looks like base64.
        '/^[a-f0-9]{32}$/',               // MD5-length hex string.
        '/^[a-f0-9]{40}$/',               // SHA1-length hex string.
    ];

    /**
     * High-risk plugins with actively-exploited critical or high-severity CVEs.
     *
     * Keyed by plugin directory slug (the folder name inside wp-content/plugins/).
     * Every entry triggers a finding regardless of installed version — admins
     * should verify they are running the patched version or uninstall if unused.
     *
     * Sources: Wordfence, Patchstack, NVD, Rapid7.
     *
     * @var array<string, array{name: string, cve: string, severity: string, detail: string}>
     */
    private const RISKY_PLUGINS = [
        'wp-file-manager' => [
            'name'     => 'WP File Manager',
            'cve'      => 'CVE-2020-25213',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated RCE via exposed elFinder connector — massively exploited within hours of disclosure (CVSS 10.0). Uninstall unless actively managed; ensure version ≥ 6.9.',
        ],
        'really-simple-ssl' => [
            'name'     => 'Really Simple Security (SSL)',
            'cve'      => 'CVE-2024-10924',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Authentication bypass when 2FA is enabled — unauthenticated attacker can log in as any admin (CVSS 9.8). 4M+ sites affected. Ensure version ≥ 9.1.2.',
        ],
        'litespeed-cache' => [
            'name'     => 'LiteSpeed Cache',
            'cve'      => 'CVE-2024-28000',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated privilege escalation via brute-forceable weak security hash (CVSS 9.8). 6M+ sites affected. Ensure version ≥ 6.4.1.',
        ],
        'essential-addons-for-elementor-lite' => [
            'name'     => 'Essential Addons for Elementor',
            'cve'      => 'CVE-2023-32243',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated privilege escalation via broken password-reset — any visitor can take over any account including admin (CVSS 9.8). Ensure version ≥ 5.7.2.',
        ],
        'iwp-client' => [
            'name'     => 'InfiniteWP Client',
            'cve'      => 'CVE-2020-8772',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Authentication bypass via crafted serialised payload — logs in as admin with no credentials required (CVSS 9.8). Ensure version ≥ 1.9.7.',
        ],
        'wp-database-reset' => [
            'name'     => 'WP Database Reset',
            'cve'      => 'CVE-2020-35234',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated full database wipe and automatic admin privilege escalation. Uninstall immediately if not in active use.',
        ],
        'wp-automatic' => [
            'name'     => 'WordPress Automatic Plugin',
            'cve'      => 'CVE-2024-27956',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated SQL injection bypasses auth and creates rogue admin accounts (CVSS 9.9). 5.5M+ exploit attempts logged. Ensure version ≥ 3.92.1.',
        ],
        'woocommerce-payments' => [
            'name'     => 'WooCommerce Payments',
            'cve'      => 'CVE-2023-28121',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Authentication bypass via forged HTTP header impersonates any user including admin (CVSS 9.8). Metasploit module exists. Ensure version ≥ 5.6.2.',
        ],
        'ottokit' => [
            'name'     => 'OttoKit',
            'cve'      => 'CVE-2025-27007',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated privilege escalation — creates admin accounts when connection setup is incomplete (CVSS 9.8). Exploited within 91 minutes of disclosure. Ensure version ≥ 1.0.82.',
        ],
        'suretriggers' => [
            'name'     => 'SureTriggers (OttoKit legacy)',
            'cve'      => 'CVE-2025-27007',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated privilege escalation — creates admin accounts when connection setup is incomplete (CVSS 9.8). Update or replace with OttoKit ≥ 1.0.82.',
        ],
        'give' => [
            'name'     => 'GiveWP – Donation Plugin',
            'cve'      => 'CVE-2024-8353',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated PHP object injection via donation form — leads to RCE (CVSS 10.0). Ensure version ≥ 3.16.2.',
        ],
        'wpgateway' => [
            'name'     => 'WPGateway',
            'cve'      => 'CVE-2022-3180',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Zero-day unauthenticated admin account creation — exploited before a patch existed (CVSS 9.8). Plugin removed from WordPress.org. Uninstall immediately.',
        ],
        'backupbuddy' => [
            'name'     => 'BackupBuddy',
            'cve'      => 'CVE-2022-31474',
            'severity' => self::SEV_HIGH,
            'detail'   => 'Unauthenticated arbitrary file read — attackers exfiltrated wp-config.php and /etc/passwd (CVSS 7.5). Nearly 5M exploit attempts. Ensure version ≥ 8.7.5.',
        ],
        'themegrill-demo-importer' => [
            'name'     => 'ThemeGrill Demo Importer',
            'cve'      => 'No CVE',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated full database wipe and automatic admin login — actively exploited in the wild. Ensure version ≥ 1.3.5 or uninstall.',
        ],
        'hunk-companion' => [
            'name'     => 'Hunk Companion',
            'cve'      => 'CVE-2024-11972',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated arbitrary plugin installation — attackers install vulnerable plugins to chain into RCE (CVSS 9.8). 8.8M blocked attempts. Ensure version ≥ 1.9.0.',
        ],
        'ultimate-member' => [
            'name'     => 'Ultimate Member',
            'cve'      => 'CVE-2024-1071',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated SQL injection via unsanitised sort parameter — full database extraction possible (CVSS 9.8). Ensure version ≥ 2.8.3.',
        ],
        'wpvivid-backuprestore' => [
            'name'     => 'WPvivid Backup & Migration',
            'cve'      => 'CVE-2024-1357',
            'severity' => self::SEV_CRITICAL,
            'detail'   => 'Unauthenticated arbitrary file upload and RCE via handler with no file-extension validation. Ensure the plugin is fully up to date.',
        ],
    ];

    /**
     * WP core cron hooks — excluded from suspicious-cron checks.
     *
     * @var string[]
     */
    private const KNOWN_CORE_CRON_HOOKS = [
        'wp_scheduled_delete',
        'wp_update_plugins',
        'wp_update_themes',
        'wp_update_user_counts',
        'wp_version_check',
        'wp_scheduled_auto_draft_delete',
        'delete_expired_transients',
        'wp_privacy_delete_old_export_files',
        'wp_site_health_scheduled_check',
        'recovery_mode_clean_expired_keys',
        'salienthook_plugin_scan',
        'salienthook_threat_scan',
    ];

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        // Nothing runs automatically — all checks are on-demand via the dashboard.
        // This method exists so Bootstrap can call it consistently.
    }

    // =========================================================================
    // Full scan — returns structured findings array
    // =========================================================================

    /**
     * Run all threat checks and return a flat array of findings.
     *
     * @return array<int, array<string, string>>
     */
    public function runScan(): array
    {
        $findings = [];

        $this->scanUploadsForPhp($findings);
        $this->scanHtaccess($findings);
        $this->scanTimthumb($findings);
        $this->checkSuspiciousCronHooks($findings);
        $this->checkRecentAdminAccounts($findings);
        $this->checkRiskyPluginsInstalled($findings);

        // Sort by severity: critical → high → medium.
        \usort($findings, static function (array $a, array $b): int {
            $order = [self::SEV_CRITICAL => 0, self::SEV_HIGH => 1, self::SEV_MEDIUM => 2];
            $aRank = $order[$a['severity']] ?? 2;
            $bRank = $order[$b['severity']] ?? 2;
            return $aRank <=> $bRank;
        });

        return $findings;
    }

    // =========================================================================
    // Check 1: PHP files in /wp-content/uploads/
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function scanUploadsForPhp(array &$findings): void
    {
        $uploadsDir = wp_upload_dir();
        $basedir    = (string) ($uploadsDir['basedir'] ?? '');

        if (empty($basedir) || ! \is_dir($basedir)) {
            return;
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($basedir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );
        } catch (\Exception $e) {
            return;
        }

        $scanned = 0;

        foreach ($iterator as $file) {
            if (! ($file instanceof \SplFileInfo)) {
                continue;
            }

            // Scan at most 1,000 files — protect against enormous upload directories.
            if ($scanned >= 1000) {
                break;
            }

            $ext = \strtolower((string) $file->getExtension());

            if (! \in_array($ext, ['php', 'php3', 'php4', 'php5', 'phtml', 'phar'], true)) {
                continue;
            }

            $scanned++;
            $path     = (string) $file->getPathname();
            $severity = self::SEV_HIGH;
            $detail   = 'PHP file found in uploads directory — potential web shell or dropper.';

            // Skip files larger than 512 KB for the deep eval check.
            if ($file->isReadable() && $file->getSize() <= 524288) {
                $content = \file_get_contents($path);

                if ($content !== false) {
                    foreach (self::EVAL_PATTERNS as $pattern) {
                        if (\strpos($content, $pattern) !== false) {
                            $severity = self::SEV_CRITICAL;
                            $detail   = 'Web shell confirmed — eval/obfuscation pattern found: ' . $pattern;
                            break;
                        }
                    }
                }
            }

            $findings[] = [
                'category' => 'uploads_php',
                'severity' => $severity,
                'path'     => $path,
                'detail'   => $detail,
            ];
        }
    }

    // =========================================================================
    // Check 2: .htaccess inspection
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function scanHtaccess(array &$findings): void
    {
        $locations = [
            ABSPATH . '.htaccess',
            WP_CONTENT_DIR . '/.htaccess',
            WP_PLUGIN_DIR . '/.htaccess',
        ];

        foreach ($locations as $path) {
            if (! \is_readable($path)) {
                continue;
            }

            $content = \file_get_contents($path);

            if ($content === false) {
                continue;
            }

            $lower = \strtolower($content);

            foreach (self::HTACCESS_SUSPECTS as $needle => $description) {
                if (\strpos($lower, \strtolower($needle)) !== false) {
                    $findings[] = [
                        'category' => 'htaccess',
                        'severity' => self::SEV_CRITICAL,
                        'path'     => $path,
                        'detail'   => $description . ' (matched: ' . $needle . ')',
                    ];
                }
            }
        }
    }

    // =========================================================================
    // Check 3: Timthumb remnants in theme directories
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function scanTimthumb(array &$findings): void
    {
        $themesDir = get_theme_root();

        if (! \is_dir($themesDir)) {
            return;
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($themesDir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );
            $iterator->setMaxDepth(3);
        } catch (\Exception $e) {
            return;
        }

        foreach ($iterator as $file) {
            if (! ($file instanceof \SplFileInfo)) {
                continue;
            }

            $filename = \strtolower((string) $file->getFilename());

            if (\in_array($filename, self::TIMTHUMB_FILENAMES, true)) {
                $findings[] = [
                    'category' => 'timthumb',
                    'severity' => self::SEV_HIGH,
                    'path'     => (string) $file->getPathname(),
                    'detail'   => 'Timthumb script detected. This file has a known Remote Code Execution vulnerability (CVE-2011-4106 and later variants). Remove it immediately.',
                ];
            }
        }
    }

    // =========================================================================
    // Check 4: Suspicious WP-Cron hooks
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function checkSuspiciousCronHooks(array &$findings): void
    {
        $cronArray = _get_cron_array();

        if (! \is_array($cronArray)) {
            return;
        }

        foreach ($cronArray as $hooks) {
            if (! \is_array($hooks)) {
                continue;
            }

            foreach ($hooks as $hookName => $callbacks) {
                if (\in_array($hookName, self::KNOWN_CORE_CRON_HOOKS, true)) {
                    continue;
                }

                foreach (self::SUSPICIOUS_CRON_PATTERNS as $pattern) {
                    if (\preg_match($pattern, (string) $hookName)) {
                        $findings[] = [
                            'category' => 'cron',
                            'severity' => self::SEV_HIGH,
                            'path'     => 'WP-Cron schedule',
                            'detail'   => 'Obfuscated cron hook name detected: "' . $hookName . '" — looks like a malware persistence hook. Review and remove if unrecognised.',
                        ];
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // Check 5: Admin accounts created in the last 24 hours
    // =========================================================================

    /**
     * @param  array<int, array<string, string>> $findings
     */
    private function checkRecentAdminAccounts(array &$findings): void
    {
        $cutoff = \date('Y-m-d H:i:s', \time() - DAY_IN_SECONDS);

        $newAdmins = get_users([
            'role'       => 'administrator',
            'date_query' => [['after' => $cutoff, 'inclusive' => false]],
            'fields'     => ['ID', 'user_login', 'user_email', 'user_registered'],
        ]);

        if (empty($newAdmins)) {
            return;
        }

        foreach ($newAdmins as $user) {
            $findings[] = [
                'category' => 'new_admin',
                'severity' => self::SEV_CRITICAL,
                'path'     => 'User accounts',
                'detail'   => 'Administrator account created in the last 24 hours: "'
                    . $user->user_login . '" (email: ' . $user->user_email
                    . ', registered: ' . $user->user_registered . '). Verify this was intentional.',
            ];
        }
    }

    // =========================================================================
    // Check 6: Installed plugins with known critical/high CVEs
    // =========================================================================

    /**
     * Flags any installed plugin whose slug appears in the RISKY_PLUGINS list.
     *
     * This does NOT deactivate the plugin — it only creates an advisory finding
     * so the admin can verify the installed version is patched or remove the
     * plugin if it is not needed.
     *
     * @param  array<int, array<string, string>> $findings
     */
    private function checkRiskyPluginsInstalled(array &$findings): void
    {
        if (! \function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $allPlugins = get_plugins();

        foreach ($allPlugins as $pluginFile => $pluginData) {
            // Slug = directory component before the first slash.
            // Single-file plugins have no slash; treat the filename (sans .php) as slug.
            $parts = \explode('/', $pluginFile, 2);
            $slug  = \count($parts) === 2 ? $parts[0] : \pathinfo($pluginFile, PATHINFO_FILENAME);

            if (! isset(self::RISKY_PLUGINS[$slug])) {
                continue;
            }

            $risk    = self::RISKY_PLUGINS[$slug];
            $version = isset($pluginData['Version']) && $pluginData['Version'] !== ''
                ? $pluginData['Version']
                : 'unknown';

            $findings[] = [
                'category' => 'risky_plugin',
                'severity' => $risk['severity'],
                'path'     => 'Plugins — ' . \esc_html($risk['name']),
                'detail'   => '(' . $risk['cve'] . ') ' . $risk['detail']
                    . ' Installed version: ' . \esc_html($version) . '.',
            ];
        }
    }
}
