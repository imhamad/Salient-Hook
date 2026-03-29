<?php

/**
 * Plugin Name:       Salient Hook — Plugin Lockdown
 * Plugin URI:        https://hamadhere.de
 * Description:       Disables plugin updates and blocks new plugin installation to harden WordPress against unauthorised plugin injection.
 * Version:           1.2.1
 * Requires at least: 5.9
 * Requires PHP:      7.4
 * Author:            Hamad K - Lead Developer
 * Author URI:        https://hamadhere.de
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       salienthook
 */

declare(strict_types=1);

namespace SalientHook;

// Bail if accessed directly.
if (! \defined('ABSPATH')) {
    exit;
}

\define('SALIENTHOOK_VERSION', '1.2.1');
\define('SALIENTHOOK_FILE', __FILE__);
\define('SALIENTHOOK_DIR', plugin_dir_path(__FILE__));

require_once SALIENTHOOK_DIR . 'src/Bootstrap.php';

Bootstrap::init();
