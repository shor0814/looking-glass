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
require_once('includes/config.defaults.php');
require_once('config.php');
require_once('routers/router.php');
require_once('includes/antispam.php');
require_once('includes/captcha.php');
require_once('includes/csrf.php');
require_once('includes/rate_limit.php');
require_once('includes/utils.php');

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no');

while (ob_get_level() > 0) {
  ob_end_flush();
}
ob_implicit_flush(true);
set_time_limit(0);
ignore_user_abort(true);

function stream_event($type, $payload = array()) {
  $data = array_merge(array('type' => $type), $payload);
  echo 'data: '.json_encode($data)."\n\n";
  flush();
}

// From where the user *really* comes from.
$requester = get_requester_ip();

/**
 * Enforce CSRF protection for stateful actions.
 */
function enforce_csrf_if_enabled_stream($input) {
  global $config;

  if (!isset($config['security']['csrf']) || $config['security']['csrf']['enabled'] !== true) {
    return;
  }

  $csrf_token = $input['csrf_token'] ?? '';
  if (!CSRF::validate($csrf_token)) {
    stream_event('error', array('error' => 'Invalid CSRF token.'));
    exit;
  }
}

/**
 * Validate router or datacenter ID format for security.
 * Only allows alphanumeric characters, underscores, and hyphens.
 */
function validate_router_id_stream($id) {
  if (empty($id) || !is_string($id)) {
    return false;
  }
  return preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $id) === 1;
}

function router_supports_speed_tests($router_type) {
  $router_type = strtolower($router_type);
  return ($router_type === 'justlinux' || $router_type === 'speedtest');
}

function router_supports_dns_whois($router_type) {
  $router_type = strtolower($router_type);
  return ($router_type === 'justlinux' || $router_type === 'speedtest');
}

function speed_tests_available($router_config, $datacenter_config = null) {
  $router_type = strtolower($router_config['type'] ?? '');

  if (isset($router_config['speed_test']['router']) && !empty($router_config['speed_test']['router'])) {
    return true;
  }
  if ($datacenter_config && isset($datacenter_config['speed_test']['router']) && !empty($datacenter_config['speed_test']['router'])) {
    return true;
  }
  if (isset($router_config['speed_test']['disabled']) && $router_config['speed_test']['disabled'] === false) {
    if (router_supports_speed_tests($router_type)) {
      return true;
    }
  }
  return false;
}

function dns_whois_available($router_config, $datacenter_config = null, $command_type = 'dns-lookup') {
  $router_type = strtolower($router_config['type'] ?? '');
  $config_key = ($command_type === 'whois-lookup') ? 'whois_lookup' : 'dns_lookup';

  if (isset($router_config[$config_key]['router']) && !empty($router_config[$config_key]['router'])) {
    return true;
  }
  if ($datacenter_config && isset($datacenter_config[$config_key]['router']) && !empty($datacenter_config[$config_key]['router'])) {
    return true;
  }
  if (isset($router_config[$config_key]['disabled']) && $router_config[$config_key]['disabled'] === false) {
    if (router_supports_dns_whois($router_type)) {
      return true;
    }
  }
  return false;
}

// Check for spam
if ($config['antispam']['enabled']) {
  $antispam = new AntiSpam($config['antispam']);
  $antispam->check_spammer($requester);
}

// Rate limiting (if enabled)
if (isset($config['rate_limit']) && $config['rate_limit']['enabled'] === true) {
  $rate_limit_config = $config['rate_limit'];
  if (empty($rate_limit_config['database_file']) && isset($config['antispam']['database_file'])) {
    $rate_limit_config['database_file'] = $config['antispam']['database_file'];
  }
  if (empty($rate_limit_config['allow_list']) && isset($config['antispam']['allow_list'])) {
    $rate_limit_config['allow_list'] = $config['antispam']['allow_list'];
  }

  $rate_limiter = new RateLimiter($rate_limit_config);
  $rate_limiter->check_rate_limit($requester);
}

$input = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;

if (empty($input['query']) || empty($input['routers'])) {
  stream_event('error', array('error' => 'Missing command or router.'));
  exit;
}

// Enforce CSRF for command execution requests
enforce_csrf_if_enabled_stream($input);

$query = trim($input['query']);
$hostname = trim($input['routers']);
$parameter = isset($input['parameter']) ? trim($input['parameter']) : '';
$datacenterID = isset($input['datacenters']) ? trim($input['datacenters']) : null;

if (!validate_router_id_stream($hostname)) {
  stream_event('error', array('error' => 'Invalid router ID format.'));
  exit;
}

if ($datacenterID !== null && $datacenterID !== '' && !validate_router_id_stream($datacenterID)) {
  stream_event('error', array('error' => 'Invalid datacenter ID format.'));
  exit;
}

// Commands that don't require parameters
$no_parameter_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 'system-info');
if (!in_array($query, $no_parameter_commands) && empty($parameter)) {
  stream_event('error', array('error' => 'This command requires a parameter.'));
  exit;
}

if (!isset($config['doc'][$query]['command'])) {
  stream_event('error', array('error' => 'This query has been disabled in the configuration.'));
  exit;
}

// Process captcha if it is enabled
if (isset($config['captcha']) && $config['captcha']['enabled']) {
  $captcha = new Captcha($config['captcha']);
  if (!$captcha->validate($requester)) {
    stream_event('error', array('error' => 'Are you a robot?'));
    exit;
  }
}

// Validate that the router exists in the selected datacenter (if datacenter is provided)
if ($datacenterID) {
  if (!isset($config['datacenters'][$datacenterID]['routers'][$hostname]) &&
      !isset($config['routers'][$hostname])) {
    stream_event('error', array('error' => 'Router not found in selected datacenter.'));
    exit;
  }
}

// Get router config to check for disabled commands - check datacenter-scoped first, then global
$router_config_for_check = null;
if ($datacenterID && isset($config['datacenters'][$datacenterID]['routers'][$hostname])) {
  $router_config_for_check = $config['datacenters'][$datacenterID]['routers'][$hostname];
} elseif (isset($config['routers'][$hostname])) {
  $router_config_for_check = $config['routers'][$hostname];
}

if ($router_config_for_check && isset($router_config_for_check[$query]['disable']) && $router_config_for_check[$query]['disable']) {
  stream_event('error', array('error' => 'This command has been disabled for this router.'));
  exit;
}

if (isset($config['doc'][$query]['enabled']) && !$config['doc'][$query]['enabled']) {
  stream_event('error', array('error' => 'This command has been disabled in the configuration.'));
  exit;
}

// Get datacenter config for delegation checks
$datacenter_config_for_check = null;
if ($datacenterID && isset($config['datacenters'][$datacenterID])) {
  $datacenter_config_for_check = $config['datacenters'][$datacenterID];
}

// Auto-disable justlinux-only commands
if ($router_config_for_check) {
  $router_type = strtolower($router_config_for_check['type'] ?? '');
  $justlinux_only_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb',
                                   'dns-lookup', 'whois-lookup', 'interface-stats', 'system-info');
  if (in_array($query, $justlinux_only_commands)) {
    if (in_array($query, array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb'))) {
      if (!speed_tests_available($router_config_for_check, $datacenter_config_for_check)) {
        stream_event('error', array('error' => 'Speed tests are disabled by default.'));
        exit;
      }
    } elseif (in_array($query, array('dns-lookup', 'whois-lookup'))) {
      if (!dns_whois_available($router_config_for_check, $datacenter_config_for_check, $query)) {
        stream_event('error', array('error' => 'DNS/WHOIS lookup is disabled by default.'));
        exit;
      }
    } else {
      if ($router_type !== 'justlinux') {
        stream_event('error', array('error' => 'This command is only available for justlinux router type.'));
        exit;
      }
    }
  }
}

// Delegation handling (speed tests, DNS/WHOIS)
$actual_router_id = $hostname;
$actual_datacenter_id = $datacenterID;
$speed_test_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb');
$dns_whois_commands = array('dns-lookup', 'whois-lookup');

if ($router_config_for_check && (in_array($query, $speed_test_commands) || in_array($query, $dns_whois_commands))) {
  $delegated_router = null;
  $config_key = null;

  if (in_array($query, $speed_test_commands)) {
    $config_key = 'speed_test';
  } elseif ($query === 'dns-lookup') {
    $config_key = 'dns_lookup';
  } elseif ($query === 'whois-lookup') {
    $config_key = 'whois_lookup';
  }

  if ($config_key) {
    if (isset($router_config_for_check[$config_key]['router']) && !empty($router_config_for_check[$config_key]['router'])) {
      $delegated_router = $router_config_for_check[$config_key]['router'];
    } elseif ($datacenter_config_for_check && isset($datacenter_config_for_check[$config_key]['router']) &&
              !empty($datacenter_config_for_check[$config_key]['router'])) {
      $delegated_router = $datacenter_config_for_check[$config_key]['router'];
    }

    if ($delegated_router) {
      $actual_router_id = $delegated_router;
      if ($datacenterID && isset($config['datacenters'][$datacenterID]['routers'][$actual_router_id])) {
        $actual_datacenter_id = $datacenterID;
      } elseif (isset($config['routers'][$actual_router_id])) {
        $actual_datacenter_id = null;
      } else {
        stream_event('error', array('error' => 'Delegated router not found.'));
        exit;
      }
    }
  }
}

$router = Router::instance($actual_router_id, $requester, $actual_datacenter_id);
$router_config = $router->get_config();

$non_ip_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 'system-info', 'interface-stats');
if (!in_array($query, $non_ip_commands) && !empty($parameter)) {
  if (match_ipv6($parameter) && $router_config['disable_ipv6']) {
    stream_event('error', array('error' => 'IPv6 has been disabled for this router, you can only use IPv4.'));
    exit;
  }
  if (match_ipv4($parameter) && $router_config['disable_ipv4']) {
    stream_event('error', array('error' => 'IPv4 has been disabled for this router, you can only use IPv6.'));
    exit;
  }
}

$routing_instance = false;
if (isset($input['routing_instance']) &&
    mb_strtolower($input['routing_instance']) !== 'none' &&
    count($config['routing_instances']) > 0) {
  $routing_instance_param = trim($input['routing_instance']);
  if (empty($routing_instance_param)) {
    stream_event('error', array('error' => 'Empty routing instance.'));
    exit;
  } elseif (!validate_router_id_stream($routing_instance_param)) {
    stream_event('error', array('error' => 'Invalid routing instance ID format.'));
    exit;
  } elseif (!array_key_exists($routing_instance_param, $config['routing_instances'])) {
    stream_event('error', array('error' => 'Invalid routing instance. Given routing instance is not configured.'));
    exit;
  } else {
    $routing_instance = $routing_instance_param;
  }
}

log_to_file($routing_instance);

try {
  $router->send_command_stream($query, $parameter, $routing_instance, function ($type, $payload) {
    stream_event($type, $payload);
  });
  stream_event('done', array());
} catch (Exception $e) {
  stream_event('error', array('error' => $e->getMessage()));
}

// End of execute-stream.php
