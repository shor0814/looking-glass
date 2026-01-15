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

// From where the user *really* comes from.
$requester = get_requester_ip();

/**
 * Enforce CSRF protection for stateful actions.
 */
function enforce_csrf_if_enabled() {
  global $config;

  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    return;
  }
  if (!isset($config['security']['csrf']) || $config['security']['csrf']['enabled'] !== true) {
    return;
  }

  $csrf_token = $_POST['csrf_token'] ?? '';
  if (!CSRF::validate($csrf_token)) {
    header('Content-Type: application/json');
    print(json_encode(array('error' => 'Invalid CSRF token.')));
    exit;
  }
}

/**
 * Validate router or datacenter ID format for security.
 * Only allows alphanumeric characters, underscores, and hyphens.
 * 
 * @param  string  $id the ID to validate.
 * @return boolean true if the ID is valid, false otherwise.
 */
function validate_router_id($id) {
  if (empty($id) || !is_string($id)) {
    return false;
  }
  // Alphanumeric, underscore, hyphen only, max 64 characters
  return preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $id) === 1;
}

/**
 * Check if a router type has speed test implementation
 * Only justlinux and speedtest router types have implementations
 * 
 * @param string $router_type The router type
 * @return bool True if router type supports speed tests
 */
function router_supports_speed_tests($router_type) {
  $router_type = strtolower($router_type);
  return ($router_type === 'justlinux' || $router_type === 'speedtest');
}

/**
 * Check if a router type has DNS/WHOIS lookup implementation
 * Only justlinux and speedtest router types have implementation
 * 
 * @param string $router_type The router type
 * @return bool True if router type supports DNS/WHOIS
 */
function router_supports_dns_whois($router_type) {
  $router_type = strtolower($router_type);
  return ($router_type === 'justlinux' || $router_type === 'speedtest');
}

/**
 * Check if speed tests are available for a router
 * Speed tests are available if:
 * 1. Router has speed_test['router'] configured (router-level delegation), OR
 * 2. Datacenter has speed_test['router'] configured (DC-level delegation), OR
 * 3. Router has speed_test['disabled'] = false AND router type supports speed tests
 * 
 * Default: speed tests are disabled (disabled=true) for all router types
 * 
 * @param array $router_config The router configuration
 * @param array $datacenter_config The datacenter configuration (optional)
 * @return bool True if speed tests are available
 */
function speed_tests_available($router_config, $datacenter_config = null) {
  $router_type = strtolower($router_config['type'] ?? '');
  
  // Check if router has router-level delegation (highest priority)
  if (isset($router_config['speed_test']['router']) && !empty($router_config['speed_test']['router'])) {
    return true;
  }
  
  // Check if datacenter has DC-level delegation
  if ($datacenter_config && isset($datacenter_config['speed_test']['router']) && !empty($datacenter_config['speed_test']['router'])) {
    return true;
  }
  
  // Check if router explicitly enabled speed tests (disabled=false)
  // Only allow this if the router type has speed test implementation
  if (isset($router_config['speed_test']['disabled']) && $router_config['speed_test']['disabled'] === false) {
    if (router_supports_speed_tests($router_type)) {
      return true;
    }
    // Router type doesn't support speed tests, ignore disabled=false
  }
  
  // Default: speed tests are disabled
  return false;
}

/**
 * Check if DNS/WHOIS lookup is available for a router
 * DNS/WHOIS is available if:
 * 1. Router has dns_lookup['router'] or whois_lookup['router'] configured (router-level delegation), OR
 * 2. Datacenter has dns_lookup['router'] or whois_lookup['router'] configured (DC-level delegation), OR
 * 3. Router has dns_lookup['disabled'] = false or whois_lookup['disabled'] = false AND router type supports it
 * 
 * Default: DNS/WHOIS are disabled (disabled=true) for all router types
 * 
 * @param array $router_config The router configuration
 * @param array $datacenter_config The datacenter configuration (optional)
 * @param string $command_type Either 'dns-lookup' or 'whois-lookup'
 * @return bool True if DNS/WHOIS is available
 */
function dns_whois_available($router_config, $datacenter_config = null, $command_type = 'dns-lookup') {
  $router_type = strtolower($router_config['type'] ?? '');
  $config_key = ($command_type === 'whois-lookup') ? 'whois_lookup' : 'dns_lookup';
  
  // Check if router has router-level delegation (highest priority)
  if (isset($router_config[$config_key]['router']) && !empty($router_config[$config_key]['router'])) {
    return true;
  }
  
  // Check if datacenter has DC-level delegation
  if ($datacenter_config && isset($datacenter_config[$config_key]['router']) && !empty($datacenter_config[$config_key]['router'])) {
    return true;
  }
  
  // Check if router explicitly enabled DNS/WHOIS (disabled=false)
  // Only allow this if the router type has DNS/WHOIS implementation
  if (isset($router_config[$config_key]['disabled']) && $router_config[$config_key]['disabled'] === false) {
    if (router_supports_dns_whois($router_type)) {
      return true;
    }
    // Router type doesn't support DNS/WHOIS, ignore disabled=false
  }
  
  // Default: DNS/WHOIS are disabled
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

// Just asked for the documentation
if (isset($_POST['doc']) && !empty($_POST['doc'])) {
  header('Content-Type: application/json');
  $query = htmlspecialchars($_POST['doc']);
  
  if (isset($config['doc'][$query])) {
  print(json_encode($config['doc'][$query]));
  } else {
    print(json_encode(array('error' => 'Documentation not found for command: ' . $query)));
  }
  return;
}

// Just updating the router commands (check this FIRST to avoid conflicts)
if (isset($_POST['selectedRouterValue']) && !empty($_POST['selectedRouterValue'])) {
  $routerID = trim($_POST['selectedRouterValue']);
  $datacenterID = isset($_POST['selectedDatacenterValue']) ? trim($_POST['selectedDatacenterValue']) : null;
  
  // Validate router ID format
  if (!validate_router_id($routerID)) {
    print(json_encode(array('error' => 'Invalid router ID format.')));
    return;
  }
  
  // Validate datacenter ID format if provided
  if ($datacenterID !== null && !validate_router_id($datacenterID)) {
    print(json_encode(array('error' => 'Invalid datacenter ID format.')));
    return;
  }
  $doc = $config['doc'];
  
  // Get router config - check datacenter-scoped first, then global
  $router_config = null;
  $datacenter_config = null;
  if ($datacenterID && isset($config['datacenters'][$datacenterID])) {
    $datacenter_config = $config['datacenters'][$datacenterID];
    if (isset($datacenter_config['routers'][$routerID])) {
      $router_config = $datacenter_config['routers'][$routerID];
    }
  }
  if (!$router_config && isset($config['routers'][$routerID])) {
    $router_config = $config['routers'][$routerID];
  }
  
  if (!$router_config) {
    // Router not found, return empty
  return;
  }
  
  $html = '';
  $selected = ' selected="selected"';
  
  // Get router type to auto-disable justlinux-only commands
  $router_type = strtolower($router_config['type'] ?? '');
  $justlinux_only_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 
                                   'dns-lookup', 'whois-lookup', 'interface-stats', 'system-info');
  
  foreach (array_keys($doc) as $cmd) {
    // Check if command is enabled in config (for commands that are disabled by default)
    $command_enabled = true;
    if (isset($config['doc'][$cmd]['enabled']) && !$config['doc'][$cmd]['enabled']) {
      $command_enabled = false;
    }
    
    // Check if command is disabled for this router
    $is_disabled = false;
    if (isset($router_config[$cmd]['disable']) && $router_config[$cmd]['disable']) {
      $is_disabled = true;
    }
    
    // Speed tests: Check if enabled via delegation or explicit disabled=false
    if (!$is_disabled && in_array($cmd, array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb'))) {
      // Speed tests are disabled by default - check if enabled
      if (!speed_tests_available($router_config, $datacenter_config)) {
        $is_disabled = true;
      }
    }
    // DNS/WHOIS lookup: Check if enabled via delegation or explicit disabled=false
    elseif (!$is_disabled && in_array($cmd, array('dns-lookup', 'whois-lookup'))) {
      // DNS/WHOIS are disabled by default - check if enabled
      if (!dns_whois_available($router_config, $datacenter_config, $cmd)) {
        $is_disabled = true;
      }
    }
    // Other justlinux-only commands (interface-stats, system-info) still require justlinux
    elseif (!$is_disabled && in_array($cmd, $justlinux_only_commands) && $router_type !== 'justlinux') {
      $is_disabled = true;
    }
    
    if (isset($config['doc'][$cmd]['command']) && $command_enabled && !$is_disabled) {
      $html .= '<option value="' . htmlspecialchars($cmd) . '"' . $selected . '>';
      $html .= htmlspecialchars($config['doc'][$cmd]['command']);
      $html .= '</option>';
      $selected = '';
    }
  }
  
  print($html);
  return;
}

// Just updating the datacenter routers
if (isset($_POST['selectedDatacenterValue']) && !empty($_POST['selectedDatacenterValue']) && 
    (!isset($_POST['selectedRouterValue']) || empty($_POST['selectedRouterValue']))) {
  $datacenterID = trim($_POST['selectedDatacenterValue']);
  
  // Validate datacenter ID format
  if (!validate_router_id($datacenterID)) {
    print(json_encode(array('error' => 'Invalid datacenter ID format.')));
    return;
  }
  
  if (!isset($config['datacenters'][$datacenterID])) {
    print(''); // Return empty if datacenter not found
    return;
  }
  
  $datacenter = $config['datacenters'][$datacenterID];
  $html = '';
  $selected = ' selected="selected"';
  
  // Get routers for this datacenter
  if (isset($datacenter['routers']) && is_array($datacenter['routers'])) {
    // Array of routers (nested format)
    foreach ($datacenter['routers'] as $routerID => $router_config) {
      // Skip if both IPv4 and IPv6 are disabled
      if (isset($router_config['disable_ipv6']) && $router_config['disable_ipv6'] &&
          isset($router_config['disable_ipv4']) && $router_config['disable_ipv4']) {
        continue;
      }
      
      // Hide speedtest routers from UI by default (they're for delegation only)
      $router_type = strtolower($router_config['type'] ?? '');
      if ($router_type === 'speedtest') {
        continue;
      }
      
      $html .= '<option value="' . htmlspecialchars($routerID) . '"' . $selected . '>';
      $html .= htmlspecialchars($router_config['desc'] ?? $routerID);
      $html .= '</option>';
      $selected = '';
    }
  } elseif (isset($datacenter['routers']) && is_string($datacenter['routers'])) {
    // Comma-separated list (legacy format)
    $routerArray = array_map('trim', explode(',', $datacenter['routers']));
    foreach ($routerArray as $routerID) {
      // Get router config from global routers
      if (isset($config['routers'][$routerID])) {
        $router_config = $config['routers'][$routerID];
        // Skip if both IPv4 and IPv6 are disabled
        if (isset($router_config['disable_ipv6']) && $router_config['disable_ipv6'] &&
            isset($router_config['disable_ipv4']) && $router_config['disable_ipv4']) {
          continue;
        }
        
        // Hide speedtest routers from UI by default (they're for delegation only)
        $router_type = strtolower($router_config['type'] ?? '');
        if ($router_type === 'speedtest') {
          continue;
        }
        
        $html .= '<option value="' . htmlspecialchars($routerID) . '"' . $selected . '>';
        $html .= htmlspecialchars($router_config['desc'] ?? $routerID);
	$html .= '</option>';
	$selected = '';
      }
    }
  }
  
  print($html);
  return;
}

if (isset($_POST['query']) && !empty($_POST['query']) &&
    isset($_POST['routers']) && !empty($_POST['routers'])) {
  // Enforce CSRF for command execution requests
  enforce_csrf_if_enabled();
  $query = trim($_POST['query']);
  $hostname = trim($_POST['routers']);
  $parameter = isset($_POST['parameter']) ? trim($_POST['parameter']) : '';
  
  // Validate router ID format
  if (!validate_router_id($hostname)) {
    $error = 'Invalid router ID format.';
    print(json_encode(array('error' => $error)));
    return;
  }

  // Commands that don't require parameters
  $no_parameter_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 'system-info');
  
  // Check if parameter is required for this command
  if (!in_array($query, $no_parameter_commands) && empty($parameter)) {
    $error = 'This command requires a parameter.';
    print(json_encode(array('error' => $error)));
    return;
  }

  // Check if query is disabled
  if (!isset($config['doc'][$query]['command'])) {
    $error = 'This query has been disabled in the configuration.';
    print(json_encode(array('error' => $error)));
    return;
  }

  // Process captcha if it is enabled
  if (isset($config['captcha']) && $config['captcha']['enabled']) {
    $captcha = new Captcha($config['captcha']);
    if (!$captcha->validate($requester)) {
      reject_requester('Are you a robot?');
    }
  }

  // Get datacenter ID if provided
  $datacenterID = isset($_POST['datacenters']) ? trim($_POST['datacenters']) : null;
  
  // Validate datacenter ID format if provided
  if ($datacenterID !== null && !validate_router_id($datacenterID)) {
    $error = 'Invalid datacenter ID format.';
    print(json_encode(array('error' => $error)));
    return;
  }
  
  // Validate that the router exists in the selected datacenter (if datacenter is provided)
  if ($datacenterID) {
    // Check if router exists in the selected datacenter
    if (!isset($config['datacenters'][$datacenterID]['routers'][$hostname]) && 
        !isset($config['routers'][$hostname])) {
      $error = 'Router "' . htmlspecialchars($hostname) . '" not found in datacenter "' . htmlspecialchars($datacenterID) . '".';
      print(json_encode(array('error' => $error)));
      return;
    }
  }
  
  // Get router config to check for disabled commands - check datacenter-scoped first, then global
  $router_config_for_check = null;
  if ($datacenterID && isset($config['datacenters'][$datacenterID]['routers'][$hostname])) {
    $router_config_for_check = $config['datacenters'][$datacenterID]['routers'][$hostname];
  } elseif (isset($config['routers'][$hostname])) {
    $router_config_for_check = $config['routers'][$hostname];
  }
  
  // Check if command is disabled for this router
  if ($router_config_for_check && isset($router_config_for_check[$query]['disable']) && $router_config_for_check[$query]['disable']) {
    $error = 'This command has been disabled for this router.';
    print(json_encode(array('error' => $error)));
    return;
  }
  
  // Check if command is enabled in config (for commands that are disabled by default)
  if (isset($config['doc'][$query]['enabled']) && !$config['doc'][$query]['enabled']) {
    $error = 'This command has been disabled in the configuration.';
    print(json_encode(array('error' => $error)));
    return;
  }
  
  // Get datacenter config for delegation checks
  $datacenter_config_for_check = null;
  if ($datacenterID && isset($config['datacenters'][$datacenterID])) {
    $datacenter_config_for_check = $config['datacenters'][$datacenterID];
  }
  
  // Auto-disable justlinux-only commands
  // Speed tests and DNS/WHOIS are disabled by default - check if enabled
  if ($router_config_for_check) {
    $router_type = strtolower($router_config_for_check['type'] ?? '');
    $justlinux_only_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 
                                     'dns-lookup', 'whois-lookup', 'interface-stats', 'system-info');
    if (in_array($query, $justlinux_only_commands)) {
      // Check if speed tests are available
      if (in_array($query, array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb'))) {
        if (!speed_tests_available($router_config_for_check, $datacenter_config_for_check)) {
          $error = 'Speed tests are disabled by default. Enable via DC-level or router-level delegation, or set disabled=false with implementation.';
          print(json_encode(array('error' => $error)));
          return;
        }
      }
      // Check if DNS/WHOIS lookup is available
      elseif (in_array($query, array('dns-lookup', 'whois-lookup'))) {
        if (!dns_whois_available($router_config_for_check, $datacenter_config_for_check, $query)) {
          $error = 'DNS/WHOIS lookup is disabled by default. Enable via DC-level or router-level delegation, or set disabled=false with implementation.';
          print(json_encode(array('error' => $error)));
          return;
        }
      }
      // Other justlinux-only commands (interface-stats, system-info) still require justlinux
      else {
        if ($router_type !== 'justlinux') {
          $error = 'This command is only available for justlinux router type.';
          print(json_encode(array('error' => $error)));
          return;
        }
      }
    }
  }

  // Check if command should be delegated to another router
  $actual_router_id = $hostname;
  $actual_datacenter_id = $datacenterID;
  $speed_test_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb');
  $dns_whois_commands = array('dns-lookup', 'whois-lookup');
  
  if ($router_config_for_check && (in_array($query, $speed_test_commands) || in_array($query, $dns_whois_commands))) {
    // Priority: router-level delegation > DC-level delegation > use router itself (if disabled=false)
    $delegated_router = null;
    $config_key = null;
    
    // Determine config key based on command type
    if (in_array($query, $speed_test_commands)) {
      $config_key = 'speed_test';
    } elseif ($query === 'dns-lookup') {
      $config_key = 'dns_lookup';
    } elseif ($query === 'whois-lookup') {
      $config_key = 'whois_lookup';
    }
    
    if ($config_key) {
      // 1. Check router-level delegation (highest priority)
      if (isset($router_config_for_check[$config_key]['router']) && !empty($router_config_for_check[$config_key]['router'])) {
        $delegated_router = $router_config_for_check[$config_key]['router'];
      }
      // 2. Check DC-level delegation
      elseif ($datacenter_config_for_check && isset($datacenter_config_for_check[$config_key]['router']) && !empty($datacenter_config_for_check[$config_key]['router'])) {
        $delegated_router = $datacenter_config_for_check[$config_key]['router'];
      }
      
      // If delegation is configured, use the delegated router
      if ($delegated_router) {
        $actual_router_id = $delegated_router;
        // Verify the delegated router exists
        if ($datacenterID && isset($config['datacenters'][$datacenterID]['routers'][$actual_router_id])) {
          // Delegated router exists in the same datacenter
          $actual_datacenter_id = $datacenterID;
        } elseif (isset($config['routers'][$actual_router_id])) {
          // Delegated router exists in global routers (legacy)
          $actual_datacenter_id = null;
        } else {
          $error = 'Delegated router "' . htmlspecialchars($actual_router_id) . '" for ' . $query . ' not found.';
          print(json_encode(array('error' => $error)));
          return;
        }
      }
      // If no delegation and disabled=false, use the router itself (must have implementation)
    }
  }

  // Do the processing - use actual router (delegated if specified)
  $router = Router::instance($actual_router_id, $requester, $actual_datacenter_id);
  $router_config = $router->get_config();

  // Commands that don't use IP addresses (skip IP validation)
  $non_ip_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 'system-info', 'interface-stats');
  
  // Check if parameter is an IPv6 and if IPv6 is disabled (only for IP-based commands)
  if (!in_array($query, $non_ip_commands) && !empty($parameter)) {
  if (match_ipv6($parameter) && $router_config['disable_ipv6']) {
    $error = 'IPv6 has been disabled for this router, you can only use IPv4.';
    print(json_encode(array('error' => $error)));
    return;
  }

  // Check if parameter is an IPv4 and if IPv4 is disabled
  if (match_ipv4($parameter) && $router_config['disable_ipv4']) {
    $error = 'IPv4 has been disabled for this router, you can only use IPv6.';
    print(json_encode(array('error' => $error)));
    return;
    }
  }

  $routing_instance = false;
  if (isset($_POST['routing_instance']) &&
      mb_strtolower($_POST['routing_instance']) !== 'none' &&
      count($config['routing_instances']) > 0) {
    $routing_instance_param = trim($_POST['routing_instance']);
    if (empty($routing_instance_param)) {
      $error = 'Empty routing instance.';
      print(json_encode(array('error' => $error)));
    } elseif (!validate_router_id($routing_instance_param)) {
      // Validate routing instance ID format
      $error = 'Invalid routing instance ID format.';
      print(json_encode(array('error' => $error)));
    } elseif (!array_key_exists($routing_instance_param, $config['routing_instances'])) {
      // Avoid people trying to use a crafted routing instance name
      $error = 'Invalid routing instance. Given routing instance is not configured.';
      print(json_encode(array('error' => $error)));
    } else {
      $routing_instance = $routing_instance_param;
    }
  }
  log_to_file($routing_instance);

  try {
    $output = $router->send_command($query, $parameter, $routing_instance);
  } catch (Exception $e) {
    $error = $e->getMessage();
  }

  if (isset($output)) {
    // Display the result of the command
    $data = array('result' => $output);
  } else {
    // Display the error
    $data = array('error' => $error);
  }

  print(json_encode($data));
}

// End of execute.php
