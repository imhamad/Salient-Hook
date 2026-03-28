<?php

declare(strict_types=1);

namespace SalientHook;

use SalientHook\Admin\SettingsPage;
use SalientHook\Modules\MaliciousPluginDetector;
use SalientHook\Modules\PluginInstallLocker;
use SalientHook\Modules\PluginUpdateLocker;
use SalientHook\Modules\ThemeIntegrityScanner;

if (! \defined('ABSPATH')) {
    exit;
}

/**
 * Central bootstrapper — wires up all modules at the correct hook priority.
 *
 * Loaded once from the main plugin file; never instantiated directly.
 */
final class Bootstrap
{
    /**
     * Register every module with WordPress.
     *
     * Called directly from the main plugin file (outside any action) so that
     * activation hooks fire at the correct point in the lifecycle — before
     * plugins_loaded, where the runtime hooks are registered.
     */
    public static function init(): void
    {
        require_once SALIENTHOOK_DIR . 'src/Modules/PluginUpdateLocker.php';
        require_once SALIENTHOOK_DIR . 'src/Modules/PluginInstallLocker.php';
        require_once SALIENTHOOK_DIR . 'src/Modules/MaliciousPluginDetector.php';
        require_once SALIENTHOOK_DIR . 'src/Modules/ThemeIntegrityScanner.php';
        require_once SALIENTHOOK_DIR . 'src/Admin/SettingsPage.php';

        $updateLocker   = new PluginUpdateLocker();
        $installLocker  = new PluginInstallLocker();
        $pluginDetector = new MaliciousPluginDetector();
        $themeScanner   = new ThemeIntegrityScanner();
        $settingsPage   = new SettingsPage($pluginDetector, $themeScanner);

        // --- Runtime hooks (priority 0 = beat competing plugins) ---
        add_action('plugins_loaded', [$updateLocker,   'register'], 0);
        add_action('plugins_loaded', [$installLocker,  'register'], 0);
        add_action('plugins_loaded', [$pluginDetector, 'register'], 0);
        add_action('plugins_loaded', [$themeScanner,   'register'], 0);
        add_action('plugins_loaded', [$settingsPage,   'register'], 0);

        // --- Activation hooks ---
        // Must be registered here (top-level), NOT inside plugins_loaded callbacks,
        // because the activate_{plugin} hook fires before plugins_loaded.
        register_activation_hook(\SALIENTHOOK_FILE, [$updateLocker,   'flushUpdateTransients']);
        register_activation_hook(\SALIENTHOOK_FILE, [$installLocker,  'flushInstallTransients']);
        register_activation_hook(\SALIENTHOOK_FILE, [$pluginDetector, 'registerCron']);

        // --- Deactivation hook ---
        register_deactivation_hook(\SALIENTHOOK_FILE, [$pluginDetector, 'deregisterCron']);
    }
}
