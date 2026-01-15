<?php
/*
 * Simple rate limiter using SQLite.
 */

require_once('includes/utils.php');

class RateLimiter {
  private $database;
  private $allow_list;
  private $per_minute;
  private $per_hour;

  public function __construct($config) {
    $database_file = $config['database_file'] ?? 'looking-glass.db';
    $this->per_minute = isset($config['per_minute']) ? intval($config['per_minute']) : 0;
    $this->per_hour = isset($config['per_hour']) ? intval($config['per_hour']) : 0;
    $this->allow_list = $config['allow_list'] ?? array();

    try {
      $this->database = new PDO('sqlite:'.$database_file);
      $this->database->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);
      $this->database->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    } catch(PDOException $e) {
      die('Unable to open database: '.$e->getMessage());
    }

    $this->database->exec(
      'CREATE TABLE if not exists rate_limits (
        bucket PRIMARY KEY,
        count INTEGER,
        expires INTEGER
      );'
    );

    $this->clean_expired();
  }

  public function __destruct() {
    $this->database = null;
  }

  private function clean_expired() {
    $this->database->exec(
      'DELETE FROM rate_limits WHERE strftime ("%s", "now") > expires;'
    );
  }

  private function is_allowed_ip($ip_address) {
    if (empty($this->allow_list)) {
      return false;
    }

    $address = \IPLib\Factory::parseAddressString($ip_address);
    foreach ($this->allow_list as $network) {
      $prefix = \IPLib\Factory::parseRangeString($network);
      if (is_ip_address_in_prefix($address, $prefix)) {
        return true;
      }
    }

    return false;
  }

  private function reject_rate_limit() {
    reject_requester('Rate limit exceeded');
  }

  private function increment_bucket($bucket, $ttl) {
    $query = $this->database->prepare(
      'SELECT count FROM rate_limits WHERE bucket = :bucket'
    );
    $query->bindValue(':bucket', $bucket, PDO::PARAM_STR);
    $query->execute();
    $result = $query->fetch();

    $count = !empty($result) ? intval($result['count']) : 0;
    $count += 1;
    $expires = time() + $ttl;

    $query = $this->database->prepare(
      'REPLACE INTO rate_limits (bucket, count, expires) VALUES (:bucket, :count, :expires);'
    );
    $query->bindValue(':bucket', $bucket, PDO::PARAM_STR);
    $query->bindValue(':count', $count, PDO::PARAM_INT);
    $query->bindValue(':expires', $expires, PDO::PARAM_INT);
    $query->execute();

    return $count;
  }

  private function check_bucket($bucket, $limit, $ttl) {
    if ($limit <= 0) {
      return;
    }

    $query = $this->database->prepare(
      'SELECT count FROM rate_limits WHERE bucket = :bucket'
    );
    $query->bindValue(':bucket', $bucket, PDO::PARAM_STR);
    $query->execute();
    $result = $query->fetch();

    $count = !empty($result) ? intval($result['count']) : 0;
    if ($count >= $limit) {
      $this->reject_rate_limit();
    }

    $this->increment_bucket($bucket, $ttl);
  }

  public function check_rate_limit($remote_address) {
    if ($this->is_allowed_ip($remote_address)) {
      return;
    }

    $hash = sha1($remote_address);
    $minute_bucket = 'min:'.$hash.':'.date('YmdHi');
    $hour_bucket = 'hour:'.$hash.':'.date('YmdH');

    $this->check_bucket($minute_bucket, $this->per_minute, 60);
    $this->check_bucket($hour_bucket, $this->per_hour, 3600);
  }
}

// End of rate_limit.php
