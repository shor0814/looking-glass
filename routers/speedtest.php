<?php

/*
 * Looking Glass - An easy to deploy Looking Glass
 * Copyright (C) 2014-2024 Guillaume Mazoyer <guillaume@mazoyer.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

require_once('unix.php');
require_once('includes/command_builder.php');
require_once('includes/utils.php');

final class Speedtest extends UNIX {
  private function get_bird_binary($ipv6 = true) {
    return $ipv6 ? 'birdc6' : 'birdc';
  }

  protected function build_bgp($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

  protected function build_aspath_regexp($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

  protected function build_as($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

  protected function build_speed_test($command, $parameter, $routing_instance = false) {
    // Determine file size based on command
    $file_sizes = array(
      'speed-test-1mb' => 1,
      'speed-test-10mb' => 10,
      'speed-test-100mb' => 100
    );

    if (!isset($file_sizes[$command])) {
      throw new Exception('Invalid speed test command.');
    }

    $size_mb = $file_sizes[$command];
    $size_bytes = $size_mb * 1024 * 1024;
    
    // Get the base URL for test files
    // Priority: router config > datacenter config > global config > auto-detect
    global $config;
    $base_url = null;
    
    // 1. Check router-specific config
    if (isset($this->config['speed_test']['base_url']) && !empty($this->config['speed_test']['base_url'])) {
      $base_url = rtrim($this->config['speed_test']['base_url'], '/');
    }
    // 2. Check datacenter-specific config
    elseif ($this->datacenter_id && isset($config['datacenters'][$this->datacenter_id]['speed_test']['base_url']) && 
            !empty($config['datacenters'][$this->datacenter_id]['speed_test']['base_url'])) {
      $base_url = rtrim($config['datacenters'][$this->datacenter_id]['speed_test']['base_url'], '/');
    }
    // 3. Check global config
    elseif (isset($config['speed_test']['base_url']) && !empty($config['speed_test']['base_url'])) {
      $base_url = rtrim($config['speed_test']['base_url'], '/');
    }
    // 4. Auto-detect from current request (works with reverse proxies like Caddy)
    else {
      $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || 
                (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
                (isset($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME'] === 'https')
                ? 'https' : 'http';
      $host = isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? $_SERVER['HTTP_X_FORWARDED_HOST'] : $_SERVER['HTTP_HOST'];
      $base_url = $scheme . '://' . $host . dirname($_SERVER['SCRIPT_NAME']);
      $base_url = rtrim($base_url, '/');
    }
    
    $test_file_url = $base_url . '/testfiles/test-' . $size_mb . 'mb.bin';

    $cmd = new CommandBuilder();
    // Use curl to download and measure speed, then calculate all speed formats
    // -o /dev/null to discard output, -w to write statistics, -s for silent
    $cmd->add('echo "=== Download Speed Test (' . $size_mb . ' MB) ===" && ');
    // Run curl once and capture all stats, then parse and calculate conversions
    $cmd->add('CURL_OUTPUT=$(curl -o /dev/null -s -S --max-time 300 -w "%{time_total}|%{size_download}|%{speed_download}|%{http_code}" ');
    $cmd->add(escapeshellarg($test_file_url));
    $cmd->add(') && ');
    $cmd->add('TIME_TOTAL=$(echo "${CURL_OUTPUT}" | cut -d"|" -f1) && ');
    $cmd->add('SIZE_DOWN=$(echo "${CURL_OUTPUT}" | cut -d"|" -f2) && ');
    $cmd->add('SPEED_BYTES=$(echo "${CURL_OUTPUT}" | cut -d"|" -f3) && ');
    $cmd->add('HTTP_CODE=$(echo "${CURL_OUTPUT}" | cut -d"|" -f4) && ');
    $cmd->add('echo "File Size: ' . $size_mb . ' MB (' . $size_bytes . ' bytes)" && ');
    $cmd->add('echo "Time Total: ${TIME_TOTAL}s" && ');
    $cmd->add('echo "Size Downloaded: ${SIZE_DOWN} bytes" && ');
    $cmd->add('echo "HTTP Code: ${HTTP_CODE}" && ');
    $cmd->add('echo "" && ');
    $cmd->add('echo "=== Download Speed ===" && ');
    // Use awk to format and calculate all speed conversions
    $cmd->add("awk -v speed=\${SPEED_BYTES} 'BEGIN {printf \"%.2f bytes/sec\\n%.2f Mb/sec\\n%.2f Gb/sec\\n%.2f MB/sec\\n%.2f GB/sec\\n\", speed, speed * 8 / 1000000, speed * 8 / 1000000000, speed / 1000000, speed / 1000000000}'");

    return array($cmd);
  }

  protected function build_dns_lookup($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

  protected function build_whois_lookup($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

  protected function build_interface_stats($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

  protected function build_system_info($parameter, $routing_instance = false) {
    throw new \LogicException(__CLASS__ . ' driver does not support ' . __FUNCTION__);
  }

}

// End of speedtest.php
