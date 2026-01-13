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
require_once('includes/utils.php');

// From where the user *really* comes from.
$requester = get_requester_ip();

/**
 * Check if speed tests are available for a router
 * Speed tests are available if:
 * 1. Router is justlinux or speedtest (native support), OR
 * 2. Router has speed_test['router'] configured (delegation)
 * 
 * @param array $router_config The router configuration
 * @return bool True if speed tests are available
 */
function speed_tests_available($router_config) {
  $router_type = strtolower($router_config['type'] ?? '');
  
  // Native support for justlinux and speedtest routers
  if ($router_type === 'justlinux' || $router_type === 'speedtest') {
    return true;
  }
  
  // Delegation support - check if router delegates to another router
  if (isset($router_config['speed_test']['router']) && !empty($router_config['speed_test']['router'])) {
    return true;
  }
  
  return false;
}

// Check for spam
if ($config['antispam']['enabled']) {
  $antispam = new AntiSpam($config['antispam']);
  $antispam->check_spammer($requester);
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
  $routerID = $_POST['selectedRouterValue'];
  $datacenterID = isset($_POST['selectedDatacenterValue']) ? $_POST['selectedDatacenterValue'] : null;
  $doc = $config['doc'];
  
  // Get router config - check datacenter-scoped first, then global
  $router_config = null;
  if ($datacenterID && isset($config['datacenters'][$datacenterID]['routers'][$routerID])) {
    $router_config = $config['datacenters'][$datacenterID]['routers'][$routerID];
  } elseif (isset($config['routers'][$routerID])) {
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
    
    // Auto-disable justlinux-only commands for non-justlinux routers
    // Speed tests are available if router is justlinux OR delegates to another router
    if (!$is_disabled && in_array($cmd, $justlinux_only_commands) && $router_type !== 'justlinux') {
      // Check if speed test is available (native justlinux OR delegation)
      if (in_array($cmd, array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb'))) {
        if (!speed_tests_available($router_config)) {
          $is_disabled = true;
        }
      } else {
        // Other justlinux-only commands (DNS, WHOIS, etc.) still require justlinux
        $is_disabled = true;
      }
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
  $query = trim($_POST['query']);
  $hostname = trim($_POST['routers']);
  $parameter = isset($_POST['parameter']) ? trim($_POST['parameter']) : '';

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
  $datacenterID = isset($_POST['datacenters']) ? $_POST['datacenters'] : null;
  
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
  
  // Auto-disable justlinux-only commands for non-justlinux routers
  // Speed tests are available if router is justlinux OR delegates to another router
  if ($router_config_for_check) {
    $router_type = strtolower($router_config_for_check['type'] ?? '');
    $justlinux_only_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb', 
                                     'dns-lookup', 'whois-lookup', 'interface-stats', 'system-info');
    if (in_array($query, $justlinux_only_commands) && $router_type !== 'justlinux') {
      // Check if speed tests are available (native justlinux OR delegation)
      if (in_array($query, array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb'))) {
        if (!speed_tests_available($router_config_for_check)) {
          $error = 'Speed tests are only available for justlinux/speedtest router types, or when delegated to another router.';
          print(json_encode(array('error' => $error)));
          return;
        }
      } else {
        // Other justlinux-only commands still require justlinux
        $error = 'This command is only available for justlinux router type.';
        print(json_encode(array('error' => $error)));
        return;
      }
    }
  }

  // Check if speed test should be delegated to another router
  $actual_router_id = $hostname;
  $actual_datacenter_id = $datacenterID;
  $speed_test_commands = array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb');
  
  if ($router_config_for_check && in_array($query, $speed_test_commands)) {
    // Check if router delegates speed tests to another router
    if (isset($router_config_for_check['speed_test']['router']) && !empty($router_config_for_check['speed_test']['router'])) {
      $actual_router_id = $router_config_for_check['speed_test']['router'];
      // Delegated router should be in the same datacenter
      // Verify the delegated router exists
      if ($datacenterID && isset($config['datacenters'][$datacenterID]['routers'][$actual_router_id])) {
        // Delegated router exists in the same datacenter
      } elseif (isset($config['routers'][$actual_router_id])) {
        // Delegated router exists in global routers (legacy)
        $actual_datacenter_id = null;
      } else {
        $error = 'Delegated speed test router "' . htmlspecialchars($actual_router_id) . '" not found.';
        print(json_encode(array('error' => $error)));
        return;
      }
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
    if (empty(trim($_POST['routing_instance']))) {
      $error = 'Empty routing instance.';
      print(json_encode(array('error' => $error)));
    } elseif (!array_key_exists($_POST['routing_instance'], $config['routing_instances'])) {
      // Avoid people trying to use a crafted routing instance name
      $error = 'Invalid routing instance. Given routing instance is not configured.';
      print(json_encode(array('error' => $error)));
    } else {
      $routing_instance = $_POST['routing_instance'];
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
