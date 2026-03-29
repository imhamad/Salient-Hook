<?php

declare(strict_types=1);

namespace SalientHook\Modules;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Detects and removes spam user accounts by analysing registered email addresses.
 *
 * Three detection layers run in order of speed — fast checks first:
 *
 *  1. Disposable / throwaway domain list — ~150 known providers (Mailinator,
 *     Guerrilla Mail, 10MinuteMail, Trashmail, YOPmail, etc.).
 *
 *  2. Pattern analysis — high-consonant-density local part combined with
 *     known abused free TLDs (.gq, .ml, .cf, .tk, .ga, .xyz, .top, etc.).
 *
 *  3. StopForumSpam API (optional, capped at 50 requests per scan) — checks
 *     the email against a crowd-sourced live database of known spammers.
 *     Flags at >= 50% confidence score.
 *
 * Administrator accounts and the currently logged-in user are never
 * flagged or deleted under any circumstance.
 */
final class SpamUserScanner
{
    public const TRANSIENT_KEY = 'salienthook_spam_scan_results';
    public const OPTION_LAST   = 'salienthook_last_spam_scan';
    public const OPTION_BLOCK  = 'salienthook_spam_block_registrations';
    public const OPTION_SFS    = 'salienthook_spam_use_sfs';

    private const SFS_API_URL        = 'https://api.stopforumspam.org/api';
    private const SFS_CAP            = 50;
    private const SFS_MIN_CONFIDENCE = 50;

    /**
     * Known disposable / throwaway email domains.
     *
     * @var string[]
     */
    private const DISPOSABLE_DOMAINS = [
        // --- Mailinator family ---
        'mailinator.com', 'mailinator.net', 'mailinator.org', 'mailinator2.com',
        'suremail.info', 'spamherelots.com', 'spamhereplease.com',
        // --- Guerrilla Mail family ---
        'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
        'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.info',
        'guerrillamailblock.com', 'grr.la', 'sharklasers.com', 'spam4.me',
        // --- YOPmail ---
        'yopmail.com', 'yopmail.net', 'yopmail.pp.ua', 'yopmail.fr',
        'courriel.fr.nf', 'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
        'cool.fr.nf', 'jetable.fr.nf',
        // --- 10 Minute Mail ---
        '10minutemail.com', '10minutemail.net', '10minutemail.org',
        '10minutemail.co.uk', '10minutemail.de', '10minutemail.ru',
        '10minutemail.nl', '10minutemail.be', '10minutemail.ga',
        '10minemail.com', '20minutemail.com', 'minutemail.com', 'mintemail.com',
        // --- Temp-Mail ---
        'temp-mail.org', 'temp-mail.io', 'tempmail.com', 'tempmail.net',
        'tempmail.org', 'tempmail.de', 'temp-mail.ru', 'tmpmail.net',
        'tmpmail.org', 'tmpeml.com', 'discard.email',
        // --- Throwaway services ---
        'throwam.com', 'throwam.net', 'throwaway.email', 'throwaminute.com',
        'maildrop.cc', 'mailnull.com', 'mailnull.net',
        'dispostable.com', 'dispostable.net',
        'fakeinbox.com', 'fakeinbox.net',
        'mailforspam.com', 'spam.la', 'spambox.us', 'spambox.me',
        'spambox.info', 'spambog.com', 'spamgourmet.com',
        'spamgourmet.net', 'spamgourmet.org',
        'spamtrail.com', 'spamtrap.ro',
        // --- Trashmail ---
        'trashmail.com', 'trashmail.me', 'trashmail.at', 'trashmail.io',
        'trashmail.net', 'trashmail.org', 'trashmail.xyz',
        // --- Getairmail / Mailsac ---
        'getairmail.com', 'getairmail.net', 'mailsac.com', 'mailsac.io',
        // --- Various popular services ---
        'inboxkitten.com', 'getnada.com', 'nada.email',
        'mohmal.com', 'mohmal.in', 'mohmal.tech',
        'mailexpire.com', 'objectmail.com',
        // --- German / European services ---
        'weg-werf-email.de', 'kasmail.com', 'shortmail.net', 'spaminator.de',
        'sofort-mail.de', 'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org',
        // --- Anonymous / Jetable ---
        'anonymbox.com', 'jetable.net', 'jetable.org', 'jetable.pp.ua',
        'nomail.xl.cx', 'nospam.ze.tc',
        // --- Meltmail / Binkmail / Filzmail ---
        'meltmail.com', 'binkmail.com', 'filzmail.com',
        // --- Temporaryemail ---
        'temporaryemail.net', 'temporaryemail.us',
        // --- Mytrashmail ---
        'mytrashmail.com', 'mytrashmail.net', 'mytrashmail.org',
        // --- Fake-identity / Blur mailers ---
        'armyspy.com', 'cuvox.de', 'dayrep.com', 'einrot.com',
        'fleckens.hu', 'gustr.com', 'jourrapide.com', 'rhyta.com',
        'superrito.com', 'teleworm.us',
        // --- Mailnesia / Mailnew ---
        'mailnesia.com', 'mailnew.com',
        // --- Generator mail ---
        'generator.email', 'generatoremail.com',
        // --- Emailondeck ---
        'emailondeck.com',
        // --- E4ward / Rcpt.at ---
        'e4ward.com', 'rcpt.at',
        // --- Easytrashmail / Safetymail ---
        'easytrashmail.com', 'safetymail.info',
        // --- Pookmail ---
        'pookmail.com',
        // --- French temp services ---
        'mail-temporaire.fr', 'mail-temporaire.com',
        // --- Tempinbox ---
        'tempinbox.com', 'tempinbox.co.uk',
        // --- Tempemail ---
        'tempemail.net', 'tempemail.biz',
        // --- SpamFree ---
        'spamfree24.org', 'spamfree24.de', 'spamfree24.eu',
        'spamfree24.net', 'spamfree24.info', 'spamfree24.com',
        // --- Incognito mail ---
        'incognitomail.com', 'incognitomail.net', 'incognitomail.org',
        // --- Trashmail2/3 ---
        'trashmail2.com', 'trashmail3.com',
        // --- Spoofmail ---
        'spoofmail.de',
        // --- Mailmetrash ---
        'mailmetrash.com', 'trashmailer.com',
    ];

    /**
     * TLDs with very high spam-to-legitimate ratios.
     * Used only as a secondary signal, never alone.
     *
     * @var string[]
     */
    private const SUSPICIOUS_TLDS = [
        'gq', 'ml', 'cf', 'tk', 'ga',               // Freenom free TLDs — massively abused.
        'pw',                                          // Palau TLD, hijacked for spam.
        'top', 'xyz', 'click', 'work',               // Cheap gTLDs with highest spam rates.
        'date', 'faith', 'racing', 'win',
        'download', 'party', 'science',
        'accountant', 'loan', 'review',
        'stream', 'trade', 'webcam',
    ];

    // =========================================================================
    // Registration
    // =========================================================================

    public function register(): void
    {
        if (get_option(self::OPTION_BLOCK, '0') === '1') {
            add_filter('registration_errors', [$this, 'checkRegistration'], 10, 3);
        }
    }

    // =========================================================================
    // Real-time registration hook
    // =========================================================================

    /**
     * Blocks spam registrations before the account is created.
     * Called via the registration_errors filter when blocking is enabled.
     */
    public function checkRegistration(\WP_Error $errors, string $sanitized_user_login, string $user_email): \WP_Error
    {
        if (empty($user_email)) {
            return $errors;
        }

        $atPos = \strpos($user_email, '@');

        if ($atPos === false) {
            return $errors;
        }

        $domain = \strtolower(\trim(\substr($user_email, $atPos + 1)));

        // Fast local check.
        if ($this->isDisposableDomain($domain)) {
            $errors->add(
                'salienthook_spam_email',
                '<strong>' . esc_html__('Error', 'salienthook') . '</strong>: '
                . esc_html__('Registrations from disposable email addresses are not allowed.', 'salienthook')
            );
            return $errors;
        }

        // StopForumSpam check (optional).
        if (get_option(self::OPTION_SFS, '0') === '1') {
            $sfs = $this->queryStopForumSpam($user_email);

            if ($sfs !== null && $sfs['confidence'] >= self::SFS_MIN_CONFIDENCE) {
                $errors->add(
                    'salienthook_spam_email',
                    '<strong>' . esc_html__('Error', 'salienthook') . '</strong>: '
                    . esc_html__('This email address is associated with known spam activity and cannot be used for registration.', 'salienthook')
                );
            }
        }

        return $errors;
    }

    // =========================================================================
    // Full scan
    // =========================================================================

    /**
     * Scan all non-administrator users and return an array of flagged accounts.
     *
     * @return array<int, array<string, mixed>>
     */
    public function runScan(): array
    {
        $currentUserId = get_current_user_id();
        $useSfs        = get_option(self::OPTION_SFS, '0') === '1';
        $sfsCallsMade  = 0;
        $findings      = [];

        $users = get_users([
            'role__not_in' => ['administrator'],
            'number'       => 2000,
            'fields'       => 'all',
        ]);

        foreach ($users as $user) {
            if (! ($user instanceof \WP_User)) {
                continue;
            }

            if ((int) $user->ID === $currentUserId) {
                continue;
            }

            $result = $this->analyzeUser($user, $useSfs, $sfsCallsMade);

            if ($result !== null) {
                $findings[] = $result;
            }
        }

        // Sort: high first.
        \usort($findings, static function (array $a, array $b): int {
            $order = ['high' => 0, 'medium' => 1];
            $aRank = $order[$a['severity']] ?? 1;
            $bRank = $order[$b['severity']] ?? 1;
            return $aRank <=> $bRank;
        });

        return $findings;
    }

    // =========================================================================
    // Deletion
    // =========================================================================

    /**
     * Delete users by ID.
     * Administrators and the currently logged-in user are always skipped.
     *
     * @param  int[] $userIds
     * @return int   Number of users successfully deleted.
     */
    public function deleteUsers(array $userIds): int
    {
        if (! \function_exists('wp_delete_user')) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }

        $currentUserId = get_current_user_id();
        $deleted       = 0;

        foreach ($userIds as $userId) {
            $userId = (int) $userId;

            if ($userId <= 0 || $userId === $currentUserId) {
                continue;
            }

            $user = get_userdata($userId);

            if (! ($user instanceof \WP_User)) {
                continue;
            }

            if (\in_array('administrator', (array) $user->roles, true)) {
                continue;
            }

            if (wp_delete_user($userId)) {
                $deleted++;
            }
        }

        return $deleted;
    }

    // =========================================================================
    // Per-user analysis
    // =========================================================================

    /**
     * @param  int $sfsCallsMade Passed by reference — incremented on each API call.
     * @return array<string, mixed>|null  Returns null if the user is clean.
     */
    private function analyzeUser(\WP_User $user, bool $useSfs, int &$sfsCallsMade): ?array
    {
        $email = \strtolower(\trim((string) $user->user_email));
        $atPos = \strpos($email, '@');

        if ($atPos === false || $atPos === 0) {
            return null;
        }

        $domain   = \substr($email, $atPos + 1);
        $local    = \substr($email, 0, $atPos);
        $severity = 'medium';
        $reason   = null;

        // --- Check 1: disposable domain ---
        if ($this->isDisposableDomain($domain)) {
            $reason   = 'Disposable / throwaway email domain (' . $domain . ')';
            $severity = 'high';
        }

        // --- Check 2: suspicious TLD + random-looking local part ---
        if ($reason === null) {
            $tld = $this->extractTld($domain);
            if (\in_array($tld, self::SUSPICIOUS_TLDS, true) && $this->isRandomLookingLocal($local)) {
                $reason   = 'Suspicious TLD (.' . $tld . ') combined with randomised local part';
                $severity = 'medium';
            }
        }

        // --- Check 3: StopForumSpam API ---
        $sfsConfidence = 0;

        if ($useSfs && $sfsCallsMade < self::SFS_CAP) {
            $sfsCallsMade++;
            $sfs = $this->queryStopForumSpam($email);

            if ($sfs !== null && $sfs['confidence'] >= self::SFS_MIN_CONFIDENCE) {
                $sfsConfidence = $sfs['confidence'];
                $freq          = $sfs['frequency'];

                if ($reason === null) {
                    $reason = \sprintf(
                        'Known spammer (StopForumSpam: %.0f%% confidence, seen %d time(s))',
                        $sfsConfidence,
                        $freq
                    );
                } else {
                    $reason .= \sprintf(' + SFS %.0f%% confidence', $sfsConfidence);
                }

                $severity = $sfsConfidence >= 80 ? 'high' : 'medium';
            }
        }

        if ($reason === null) {
            return null;
        }

        return [
            'user_id'    => (int) $user->ID,
            'login'      => (string) $user->user_login,
            'email'      => $email,
            'display'    => (string) $user->display_name,
            'registered' => (string) $user->user_registered,
            'reason'     => $reason,
            'severity'   => $severity,
            'sfs_score'  => $sfsConfidence,
        ];
    }

    // =========================================================================
    // Detection helpers
    // =========================================================================

    private function isDisposableDomain(string $domain): bool
    {
        return \in_array(\strtolower($domain), self::DISPOSABLE_DOMAINS, true);
    }

    private function extractTld(string $domain): string
    {
        $parts = \explode('.', $domain);
        return \strtolower((string) \end($parts));
    }

    /**
     * Returns true if the local part looks machine-generated.
     *
     * Signals: ≥ 7 all-digit chars (e.g. "12345678@top.xyz"), or ≥ 8 alpha
     * chars with ≤ 1 vowel (high consonant density typical of random strings).
     */
    private function isRandomLookingLocal(string $local): bool
    {
        if (\strlen($local) < 6) {
            return false;
        }

        // All-digit local part of 7+ chars.
        if (\preg_match('/^\d{7,}$/', $local)) {
            return true;
        }

        // Strip non-alpha and check vowel density.
        $alpha  = (string) \preg_replace('/[^a-zA-Z]/', '', $local);
        $length = \strlen($alpha);

        if ($length < 8) {
            return false;
        }

        $vowels = \preg_match_all('/[aeiou]/i', $alpha);

        return $vowels !== false && $vowels <= 1;
    }

    // =========================================================================
    // StopForumSpam API
    // =========================================================================

    /**
     * Query StopForumSpam for a single email address.
     *
     * Returns ['confidence' => float, 'frequency' => int] on a positive match,
     * or null if the email is clean / the API is unreachable / times out.
     *
     * @return array{confidence: float, frequency: int}|null
     */
    private function queryStopForumSpam(string $email): ?array
    {
        $url = self::SFS_API_URL . '?emailonly&email=' . \rawurlencode($email) . '&f=json';

        $response = wp_remote_get($url, [
            'timeout'    => 5,
            'user-agent' => 'SalientHook/' . \SALIENTHOOK_VERSION . ' WordPress/' . get_bloginfo('version'),
        ]);

        if (is_wp_error($response)) {
            return null;
        }

        $body = (string) wp_remote_retrieve_body($response);
        $data = \json_decode($body, true);

        if (
            ! \is_array($data) ||
            ! isset($data['success']) ||
            (int) $data['success'] !== 1
        ) {
            return null;
        }

        $emailData = isset($data['email']) && \is_array($data['email']) ? $data['email'] : null;

        if (
            $emailData === null ||
            ! isset($emailData['appears']) ||
            (int) $emailData['appears'] !== 1
        ) {
            return null;
        }

        return [
            'confidence' => (float) ($emailData['confidence'] ?? 0),
            'frequency'  => (int)   ($emailData['frequency']  ?? 0),
        ];
    }
}
