<?php
/*
Plugin Name: TOTP
Plugin URI: https://george.botsev.it
Description: TOPT authentication for WordPress.
Version: 1.0
Author: George Botsev
Author URI: https://george.botsev.it
License: GPL3
*/

require 'vendor/autoload.php';

use OTPHP\TOTP;
use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;

function generate_totp_secret() {
    return TOTP::create()->getSecret();
}

function get_qr_code_url($secret, $username) {
    $totp = TOTP::create($secret);
    $totp->setLabel($username);
    $totp->setIssuer(get_bloginfo('name'));

    $qrOptions = new QROptions([
        'version' => 10,
        'outputType' => QRCode::OUTPUT_MARKUP_SVG,
        'eccLevel' => QRCode::ECC_L,
    ]);

    return (new QRCode($qrOptions))->render($totp->getProvisioningUri());
}

function show_totp_qr_code($user) {
    $secret = get_user_meta($user->ID, 'totp_secret', true);
    $totp_config_completed = get_user_meta($user->ID, 'totp_config_completed', true);

    if (empty($secret)) {
        $secret = generate_totp_secret();
        update_user_meta($user->ID, 'totp_secret', $secret);
    }

    wp_nonce_field('totp_config_save', 'totp_config_nonce');

    echo '<h3>TOTP Two-Factor Authentication</h3>';
    echo '<p><input type="checkbox" name="totp_config_completed" id="totp_config_completed" value="1" ' . checked(1, $totp_config_completed, false) . ' />';
    echo '<label for="totp_config_completed">Configuration completed</label></p>';

    if (!$totp_config_completed) {
        $qrCodeUrl = get_qr_code_url($secret, $user->user_login);
        echo '<p>Scan this QR code with your TOTP application:</p>';
        echo '<div class="qr-code-container"><img src="'.$qrCodeUrl.'" alt="QR Code" /></div>';
        echo '<style>.qr-code-container img { width: 200px; height: auto; }</style>';
    }
}

function save_totp_user_profile_fields($user_id) {
    if (!current_user_can('edit_user', $user_id)) {
        return false;
    }

    if (!isset($_POST['totp_config_nonce']) || !wp_verify_nonce($_POST['totp_config_nonce'], 'totp_config_save')) {
        return false;
    }

    if (isset($_POST['totp_config_completed']) && $_POST['totp_config_completed'] == 1) {
        update_user_meta($user_id, 'totp_config_completed', 1);
    } else {
        update_user_meta($user_id, 'totp_config_completed', 0);
        delete_user_meta($user_id, 'totp_secret');
    }
}

add_action('show_user_profile', 'show_totp_qr_code');
add_action('edit_user_profile', 'show_totp_qr_code');
add_action('personal_options_update', 'save_totp_user_profile_fields');
add_action('edit_user_profile_update', 'save_totp_user_profile_fields');

function verify_totp_code($user, $password) {
    if (!isset($_POST['totp_code'])) {
        return $user;
    }

    $totp_code = sanitize_text_field($_POST['totp_code']);

    if (!ctype_digit($totp_code) || strlen($totp_code) != 6) {
        return new WP_Error('invalid_totp', '<strong>ERROR</strong>: Invalid TOTP code.');
    }

    $secret = get_user_meta($user->ID, 'totp_secret', true);

    $totp = TOTP::create($secret);

    if (!$totp->verify($totp_code)) {
        return new WP_Error('invalid_totp', '<strong>ERROR</strong>: Invalid TOTP code.');
    }

    return $user;
}

add_filter('authenticate', 'verify_totp_code', 30, 2);

function add_totp_field_to_login() {
    echo '<p><label for="totp_code">TOTP Code<br><input type="text" name="totp_code" id="totp_code" class="input" value="" size="20" /></label></p>';
}

add_action('login_form', 'add_totp_field_to_login');
