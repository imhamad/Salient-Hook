<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Scans all installed theme directories for known malware artefacts.
 *
 * Checks performed per theme:
 *
 *  1. Presence of *.html files in the theme root — themes never ship HTML
 *     files; "verification.html" is the confirmed drop file for this campaign.
 *
 *  2. header.php scanned line-by-line for injected <script> tags and IOC
 *     strings — this is the primary injection point reported by Sucuri.
 *
 *  3. All *.php files in the theme root scanned for C2 domain strings,
 *     known malware function names, and campaign-specific GET parameters.
 *
 * Results are returned as a structured array consumed by SettingsPage.
 */
final class ThemeIntegrityScanner
{
    /**
     * Severity levels used in findings.
     */
    private const SEV_CRITICAL = 'critical';
    private const SEV_HIGH     = 'high';
    private const SEV_MEDIUM   = 'medium';

    /**
     * IOC strings mapped to a human-readable description and severity.
     *
     * @var array<string, array{description: string, severity: string}>
     */
    private const IOC_PATTERNS = [
        // --- LummaStealer campaign (WP Performance Analytics) ----------------
        'verification.html'     => ['description' => 'Confirmed malware HTML drop file',                        'severity' => self::SEV_CRITICAL],
        'workaem'               => ['description' => 'LummaStealer C2 domain fragment (workaem.eth.limo)',       'severity' => self::SEV_CRITICAL],
        'eth.limo'              => ['description' => 'LummaStealer C2 TLD (.eth.limo)',                          'severity' => self::SEV_CRITICAL],
        '45.61.136.85'          => ['description' => 'LummaStealer C2 IP address',                              'severity' => self::SEV_CRITICAL],
        'emergency_login'       => ['description' => 'LummaStealer malware function name',                       'severity' => self::SEV_CRITICAL],
        'execute_admin_command' => ['description' => 'LummaStealer malware function name',                       'severity' => self::SEV_CRITICAL],
        'harp_interesting'      => ['description' => 'LummaStealer malware GET parameter',                       'severity' => self::SEV_HIGH],
        'terrorise_seriously'   => ['description' => 'LummaStealer malware GET parameter',                       'severity' => self::SEV_HIGH],
        // --- ClickFix / DoubleDonut campaign (Rapid7 TR-2025) ----------------
        '__performance_optimizer_v6' => ['description' => 'ClickFix JS evasion flag',                           'severity' => self::SEV_CRITICAL],
        'goveanrs.org'          => ['description' => 'ClickFix JS hosting domain',                               'severity' => self::SEV_CRITICAL],
        'getalib.org'           => ['description' => 'ClickFix JS hosting domain',                               'severity' => self::SEV_CRITICAL],
        'ligovera.shop'         => ['description' => 'ClickFix JS hosting domain',                               'severity' => self::SEV_CRITICAL],
        'alianzeg.shop'         => ['description' => 'ClickFix JS hosting domain',                               'severity' => self::SEV_CRITICAL],
        'cptoptious.com'        => ['description' => 'ClickFix implant domain',                                  'severity' => self::SEV_CRITICAL],
        'captioto.com'          => ['description' => 'ClickFix implant domain',                                  'severity' => self::SEV_CRITICAL],
        'captoolsz.com'         => ['description' => 'ClickFix implant domain',                                  'severity' => self::SEV_CRITICAL],
        'capztoolz.com'         => ['description' => 'ClickFix implant domain',                                  'severity' => self::SEV_CRITICAL],
        'greecpt.shop'          => ['description' => 'ClickFix implant domain',                                  'severity' => self::SEV_CRITICAL],
        '91.92.240.219'         => ['description' => 'ClickFix C2 IP address',                                   'severity' => self::SEV_CRITICAL],
        '178.16.53.70'          => ['description' => 'ClickFix C2 IP address',                                   'severity' => self::SEV_CRITICAL],
        '94.154.35.115'         => ['description' => 'ClickFix C2 IP address',                                   'severity' => self::SEV_CRITICAL],
        '172.94.9.187'          => ['description' => 'ClickFix C2 IP address (March 2026)',                      'severity' => self::SEV_CRITICAL],
        'ajjs_run'              => ['description' => 'ClickFix admin-ajax injection action',                     'severity' => self::SEV_CRITICAL],
        'cptch.bin'             => ['description' => 'ClickFix first-stage shellcode reference',                  'severity' => self::SEV_CRITICAL],
        'cptchbuild.bin'        => ['description' => 'ClickFix second-stage shellcode reference',                 'severity' => self::SEV_CRITICAL],
        // --- Generic evasion / obfuscation -----------------------------------
        'wordpress_logged_in_'  => ['description' => 'Admin cookie-evasion — payload hides from logged-in users', 'severity' => self::SEV_HIGH],
        'powershell'            => ['description' => 'PowerShell reference in theme file',                       'severity' => self::SEV_HIGH],
        'base64_decode'         => ['description' => 'base64_decode call (obfuscation indicator)',               'severity' => self::SEV_MEDIUM],
        'eval('                 => ['description' => 'eval() call (code execution indicator)',                   'severity' => self::SEV_MEDIUM],
    ];

    // =========================================================================
    // Registration
    // =========================================================================

    /**
     * No automatic hooks — this scanner is on-demand only.
     * Kept for consistent module interface.
     */
    public function register(): void
    {
        // On-demand only; no hooks needed.
    }

    // =========================================================================
    // Full scan
    // =========================================================================

    /**
     * Scan all installed theme directories.
     *
     * @return array<string, array{path: string, status: string, critical: int, findings: list<array<string, string>>}>
     */
    public function runScan(): array
    {
        $results   = [];
        $themesDir = get_theme_root();

        if (! \is_dir($themesDir) || ! \is_readable($themesDir)) {
            return $results;
        }

        $themeDirs = \glob($themesDir . DIRECTORY_SEPARATOR . '*', GLOB_ONLYDIR);

        if ($themeDirs === false) {
            return $results;
        }

        foreach ($themeDirs as $themeDir) {
            $findings = $this->scanThemeDirectory($themeDir);
            $critical = \count(\array_filter($findings, static fn ($f) => $f['severity'] === self::SEV_CRITICAL));

            $results[\basename($themeDir)] = [
                'path'     => \str_replace(ABSPATH, '', $themeDir),
                'status'   => empty($findings) ? 'clean' : ($critical > 0 ? 'infected' : 'suspicious'),
                'critical' => $critical,
                'findings' => $findings,
            ];
        }

        return $results;
    }

    // =========================================================================
    // Per-theme scanning
    // =========================================================================

    /**
     * @return list<array<string, string>>
     */
    private function scanThemeDirectory(string $themeDir): array
    {
        $findings = [];

        // --- Check 1: HTML files in theme root --------------------------------
        $htmlFiles = \glob($themeDir . DIRECTORY_SEPARATOR . '*.html');

        if ($htmlFiles !== false) {
            foreach ($htmlFiles as $htmlFile) {
                $severity = (\basename($htmlFile) === 'verification.html')
                    ? self::SEV_CRITICAL
                    : self::SEV_HIGH;

                $findings[] = [
                    'type'     => 'suspicious_file',
                    'severity' => $severity,
                    'file'     => \str_replace(ABSPATH, '', $htmlFile),
                    'line'     => '—',
                    'detail'   => 'Unexpected HTML file in theme root'
                        . (\basename($htmlFile) === 'verification.html'
                            ? ' — this is the confirmed LummaStealer campaign drop file'
                            : ' — themes do not ship standalone HTML files'),
                ];
            }
        }

        // --- Check 2: header.php — highest-priority injection target ----------
        $headerPhp = $themeDir . DIRECTORY_SEPARATOR . 'header.php';

        if (\is_readable($headerPhp)) {
            $findings = \array_merge($findings, $this->scanFileLineByLine($headerPhp));
        }

        // --- Check 3: All other PHP files in theme root -----------------------
        $phpFiles = \glob($themeDir . DIRECTORY_SEPARATOR . '*.php');

        if ($phpFiles !== false) {
            foreach ($phpFiles as $phpFile) {
                if ($phpFile === $headerPhp) {
                    continue;
                }
                $findings = \array_merge($findings, $this->scanFileLineByLine($phpFile));
            }
        }

        // --- Check 4: JS files in theme root — ClickFix injects into .js -----
        // The ClickFix campaign injects its payload into JavaScript files, not
        // just PHP. Scanning root-level JS files catches this without the
        // performance cost of recursing into subdirectories.
        $jsFiles = \glob($themeDir . DIRECTORY_SEPARATOR . '*.js');

        if ($jsFiles !== false) {
            foreach ($jsFiles as $jsFile) {
                $findings = \array_merge($findings, $this->scanFileLineByLine($jsFile));
            }
        }

        return $findings;
    }

    // =========================================================================
    // File scanning
    // =========================================================================

    /**
     * Scan a single file line-by-line against all IOC patterns.
     *
     * @return list<array<string, string>>
     */
    private function scanFileLineByLine(string $filePath): array
    {
        $findings = [];

        if (! \is_readable($filePath)) {
            return $findings;
        }

        $lines = \file($filePath, FILE_IGNORE_NEW_LINES);

        if ($lines === false) {
            return $findings;
        }

        foreach ($lines as $index => $line) {
            foreach (self::IOC_PATTERNS as $pattern => $meta) {
                if (\strpos($line, $pattern) === false) {
                    continue;
                }

                $findings[] = [
                    'type'     => 'ioc_match',
                    'severity' => $meta['severity'],
                    'file'     => \str_replace(ABSPATH, '', $filePath),
                    'line'     => (string) ($index + 1),
                    'detail'   => $meta['description'] . ' — matched: ' . \trim(\substr($line, 0, 120)),
                ];
            }
        }

        return $findings;
    }
}
