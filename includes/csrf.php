<?php
/*
 * Simple CSRF token helper.
 */

final class CSRF {
  private static function ensure_session_started() {
    if (session_status() === PHP_SESSION_ACTIVE) {
      return;
    }
    // Avoid warnings if output has already started.
    if (headers_sent()) {
      return;
    }
    session_start();
  }

  public static function get_token() {
    self::ensure_session_started();
    if (!isset($_SESSION['csrf_token'])) {
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    self::set_cookie($_SESSION['csrf_token']);
    return $_SESSION['csrf_token'];
  }

  public static function validate($token) {
    self::ensure_session_started();
    if (!is_string($token) || $token === '') {
      return false;
    }
    if (isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token)) {
      return true;
    }
    if (isset($_COOKIE['csrf_token']) && hash_equals($_COOKIE['csrf_token'], $token)) {
      return true;
    }
    return false;
  }

  private static function set_cookie($token) {
    if (headers_sent()) {
      return;
    }
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
      (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    setcookie('csrf_token', $token, array(
      'path' => '/',
      'secure' => $secure,
      'httponly' => true,
      'samesite' => 'Lax'
    ));
  }
}

// End of csrf.php
