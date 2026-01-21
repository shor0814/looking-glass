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
require_once('arista.php');
require_once('bird.php');
require_once('bird2.php');
require_once('cisco.php');
require_once('cisco_iosxr.php');
require_once('extreme_netiron.php');
require_once('juniper.php');
require_once('mikrotik.php');
require_once('nokia.php');
require_once('openbgpd.php');
require_once('quagga.php');
require_once('frr.php');
require_once('vyatta.php');
require_once('vyos.php');
require_once('huawei.php');
require_once('tnsr.php');
require_once('justlinux.php');
require_once('speedtest.php');
require_once('includes/utils.php');
require_once('auth/authentication.php');

abstract class Router {
  protected $global_config;
  protected $config;
  protected $id;
  protected $requester;
  protected $datacenter_id;

  public function __construct($global_config, $config, $id, $requester, $datacenter_id = null) {
    $this->global_config = $global_config;
    $this->config = $config;
    $this->id = $id;
    $this->requester = $requester;
    $this->datacenter_id = $datacenter_id;

    // Set defaults if not present
    if (!isset($this->config['timeout'])) {
      $this->config['timeout'] = 180;
    }
    if (!isset($this->config['disable_ipv6'])) {
      $this->config['disable_ipv6'] = false;
    }
    if (!isset($this->config['disable_ipv4'])) {
      $this->config['disable_ipv4'] = false;
    }
    if (!isset($this->config['bgp_detail'])) {
      $this->config['bgp_detail'] = false;
    }
  }

  private function sanitize_output($output) {
    // No filters defined
    if (count($this->global_config['filters']['output']) < 1) {
      return preg_replace('/(?:\n|\r\n|\r)$/D', '', $output);
    }

    $filtered = '';

    foreach (preg_split("/((\r?\n)|(\r\n?))/", $output) as $line) {
      $valid = true;

      foreach ($this->global_config['filters']['output'] as $filter) {
        if (is_array($filter)) {
          $line = preg_replace($filter[0], $filter[1], $line);
        } else {
          // Line has been marked as invalid
          // Or filtered based on the configuration
          if (!$valid || (preg_match($filter, $line) === 1)) {
            $valid = false;
            break;
          }
        }
      }
      if ($valid) {
        // The line is valid, print it
        $filtered .= $line."\n";
      }
    }

    return preg_replace('/(?:\n|\r\n|\r)$/D', '', $filtered);
  }

  private function sanitize_output_line($line) {
    if (count($this->global_config['filters']['output']) < 1) {
      return $line;
    }

    $valid = true;
    $filtered_line = $line;

    foreach ($this->global_config['filters']['output'] as $filter) {
      if (is_array($filter)) {
        $filtered_line = preg_replace($filter[0], $filter[1], $filtered_line);
      } else {
        if (!$valid || (preg_match($filter, $filtered_line) === 1)) {
          $valid = false;
          break;
        }
      }
    }

    return $valid ? $filtered_line : null;
  }

  private function sanitize_output_stream_chunk($chunk, &$carry) {
    $data = $carry.$chunk;
    $lines = preg_split("/((\r?\n)|(\r\n?))/", $data);
    $ends_with_newline = preg_match("/(\r?\n|\r)$/", $data) === 1;

    if ($ends_with_newline) {
      $carry = '';
    } else {
      $carry = array_pop($lines);
    }

    $filtered = '';
    foreach ($lines as $line) {
      $filtered_line = $this->sanitize_output_line($line);
      if ($filtered_line !== null) {
        $filtered .= $filtered_line."\n";
      }
    }

    return $filtered;
  }

  private function sanitize_output_stream_flush($carry) {
    if ($carry === '') {
      return '';
    }

    $filtered_line = $this->sanitize_output_line($carry);
    if ($filtered_line === null) {
      return '';
    }

    return $filtered_line;
  }

  protected function format_output($command, $output) {
    $displayable = '';

    if ($this->global_config['output']['show_command']) {
      $displayable .= '<p><kbd>Command: '.$command.'</kdb></p>';
    }
    if ($this->global_config['output']['scroll']) {
      $displayable .= '<pre class="pre-scrollable">';
    } else {
      $displayable .= '<pre>';
    }
    $displayable .= htmlspecialchars($output, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').'</pre>';

    return $displayable;
  }

  protected function format_output_start($command) {
    $displayable = '';

    if ($this->global_config['output']['show_command']) {
      $displayable .= '<p><kbd>Command: '.$command.'</kdb></p>';
    }
    if ($this->global_config['output']['scroll']) {
      $displayable .= '<pre class="pre-scrollable">';
    } else {
      $displayable .= '<pre>';
    }

    return $displayable;
  }

  protected function format_output_end() {
    return '</pre>';
  }

  protected function has_source_interface_id() {
    return isset($this->config['source-interface-id']);
  }

  protected function get_source_interface_id($ip_version = 'ipv6') {
    // No source interface ID specified
    if (!$this->has_source_interface_id()) {
      return null;
    }

    $source_interface_id = $this->config['source-interface-id'];

    if (!is_array($source_interface_id)) {
      // Interface not being IP version specific
      return $source_interface_id;
    }
    return $source_interface_id[$ip_version];
  }

  protected abstract function build_bgp($parameter, $routing_instance = false);

  protected abstract function build_aspath_regexp($parameter, $routing_instance = false);

  protected abstract function build_as($parameter, $routing_instance = false);

  protected abstract function build_ping($parameter, $routing_instance = false);

  protected abstract function build_traceroute($parameter, $routing_instance = false);

  // Optional methods for justlinux-specific features
  // Default implementations throw exceptions, can be overridden in subclasses
  protected function build_speed_test($command, $parameter, $routing_instance = false) {
    throw new Exception('Speed test is only available for justlinux router type.');
  }

  protected function build_dns_lookup($parameter, $routing_instance = false) {
    throw new Exception('DNS lookup is only available for justlinux router type.');
  }

  protected function build_whois_lookup($parameter, $routing_instance = false) {
    throw new Exception('WHOIS lookup is only available for justlinux router type.');
  }

  protected function build_interface_stats($parameter, $routing_instance = false) {
    throw new Exception('Interface statistics is only available for justlinux router type.');
  }

  protected function build_system_info($parameter, $routing_instance = false) {
    throw new Exception('System information is only available for justlinux router type.');
  }
  
  private function build_commands($command, $parameter, $routing_instance = false) {
    switch ($command) {
      case 'bgp':
        if (!is_valid_ip_address($parameter)) {
          throw new Exception('The parameter is not an IP address.');
        }
        return $this->build_bgp($parameter, $routing_instance);

      case 'as-path-regex':
        if (!match_aspath_regexp($parameter)) {
          throw new Exception('The parameter is not an AS-Path regular expression.');
        }
        return $this->build_aspath_regexp($parameter, $routing_instance);

      case 'as':
        if (!match_as($parameter)) {
          throw new Exception('The parameter is not an AS number.');
        }
        return $this->build_as($parameter, $routing_instance);

      case 'ping':
        return $this->build_ping($parameter, $routing_instance);

      case 'traceroute':
        return $this->build_traceroute($parameter, $routing_instance);

      case 'mtr':
	return $this->build_mtr($parameter, $routing_instance);

      case 'speed-test-1mb':
      case 'speed-test-10mb':
      case 'speed-test-100mb':
        return $this->build_speed_test($command, $parameter, $routing_instance);

      case 'dns-lookup':
        return $this->build_dns_lookup($parameter, $routing_instance);

      case 'whois-lookup':
        return $this->build_whois_lookup($parameter, $routing_instance);

      case 'interface-stats':
        return $this->build_interface_stats($parameter, $routing_instance);

      case 'system-info':
        return $this->build_system_info($parameter, $routing_instance);

      default:
        throw new Exception('Command not supported.');
    }

    return null;
  }

  public function get_config() {
    return $this->config;
  }

  public function send_command($command, $parameter, $routing_instance = false) {
    if ($routing_instance !== false) {
      // Defense in depth: validate routing instance format and existence.
      if (!is_string($routing_instance) ||
          preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $routing_instance) !== 1) {
        throw new Exception('Invalid routing instance format.');
      }
      if (isset($this->global_config['routing_instances']) &&
          !array_key_exists($routing_instance, $this->global_config['routing_instances'])) {
        throw new Exception('Invalid routing instance. Given routing instance is not configured.');
      }
    }

    $commands = $this->build_commands($command, $parameter, $routing_instance);
    $auth = Authentication::instance($this->config,
      $this->global_config['logs']['auth_debug']);

    $data = '';

    foreach ($commands as $selected) {
      $log = str_replace(array('%D', '%R', '%H', '%C'),
        array(date('Y-m-d H:i:s'), $this->requester, $this->config['host'],
        '[BEGIN] '.$selected), $this->global_config['logs']['format']);
      log_to_file($log);

      $output = $auth->send_command((string) $selected);
      $output = $this->sanitize_output($output);

      $data .= $this->format_output($selected, $output);

      $log = str_replace(array('%D', '%R', '%H', '%C'),
        array(date('Y-m-d H:i:s'), $this->requester, $this->config['host'],
        '[END] '.$selected), $this->global_config['logs']['format']);
      log_to_file($log);
    }

    return $data;
  }

  public function send_command_stream($command, $parameter, $routing_instance, $emit) {
    if ($routing_instance !== false) {
      // Defense in depth: validate routing instance format and existence.
      if (!is_string($routing_instance) ||
          preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $routing_instance) !== 1) {
        throw new Exception('Invalid routing instance format.');
      }
      if (isset($this->global_config['routing_instances']) &&
          !array_key_exists($routing_instance, $this->global_config['routing_instances'])) {
        throw new Exception('Invalid routing instance. Given routing instance is not configured.');
      }
    }

    if (!is_callable($emit)) {
      throw new Exception('Streaming emitter is not callable.');
    }

    $commands = $this->build_commands($command, $parameter, $routing_instance);
    $auth = Authentication::instance($this->config,
      $this->global_config['logs']['auth_debug']);

    foreach ($commands as $selected) {
      $log = str_replace(array('%D', '%R', '%H', '%C'),
        array(date('Y-m-d H:i:s'), $this->requester, $this->config['host'],
        '[BEGIN] '.$selected), $this->global_config['logs']['format']);
      log_to_file($log);

      $emit('command_start', array(
        'html' => $this->format_output_start($selected)
      ));

      $carry = '';
      $auth->send_command_stream((string) $selected, function ($chunk) use (&$carry, $emit) {
        $filtered = $this->sanitize_output_stream_chunk($chunk, $carry);
        if ($filtered !== '') {
          $emit('output', array(
            'html' => htmlspecialchars($filtered, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
          ));
        }
      });

      $remaining = $this->sanitize_output_stream_flush($carry);
      if ($remaining !== '') {
        $emit('output', array(
          'html' => htmlspecialchars($remaining, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        ));
      }

      $emit('command_end', array(
        'html' => $this->format_output_end()
      ));

      $log = str_replace(array('%D', '%R', '%H', '%C'),
        array(date('Y-m-d H:i:s'), $this->requester, $this->config['host'],
        '[END] '.$selected), $this->global_config['logs']['format']);
      log_to_file($log);
    }
  }

  public static final function instance($id, $requester, $datacenter_id = null) {
    global $config;

    // Try to get router config from datacenter first, then global
    $router_config = null;
    if ($datacenter_id && isset($config['datacenters'][$datacenter_id]['routers'][$id])) {
      $router_config = $config['datacenters'][$datacenter_id]['routers'][$id];
    } elseif (isset($config['routers'][$id])) {
      $router_config = $config['routers'][$id];
    }
    
    if (!$router_config) {
      throw new Exception('Router configuration not found for: ' . $id);
    }

    switch (strtolower($router_config['type'])) {
      case 'arista':
        return new Arista($config, $router_config, $id, $requester, $datacenter_id);

      case 'bird':
        return new Bird($config, $router_config, $id, $requester, $datacenter_id);

      case 'bird2':
        return new Bird2($config, $router_config, $id, $requester, $datacenter_id);

      case 'cisco':
      case 'ios':
        return new Cisco($config, $router_config, $id, $requester, $datacenter_id);

      case 'extreme_netiron':
        return new ExtremeNetIron($config, $router_config, $id, $requester, $datacenter_id);

      case 'huawei':
        return new Huawei($config, $router_config, $id, $requester, $datacenter_id);

      case 'ios-xr':
      case 'iosxr':
        return new IOSXR($config, $router_config, $id, $requester, $datacenter_id);

      case 'juniper':
      case 'junos':
        return new Juniper($config, $router_config, $id, $requester, $datacenter_id);

      case 'mikrotik':
      case 'routeros':
        return new Mikrotik($config, $router_config, $id, $requester, $datacenter_id);

      case 'nokia':
        return new Nokia($config, $router_config, $id, $requester, $datacenter_id);

      case 'openbgpd':
        return new OpenBGPD($config, $router_config, $id, $requester, $datacenter_id);

      case 'quagga':
      case 'zebra':
        return new Quagga($config, $router_config, $id, $requester, $datacenter_id);

      case 'frr':
        return new FRR($config, $router_config, $id, $requester, $datacenter_id);

      case 'tnsr':
        return new TNSR($config, $router_config, $id, $requester, $datacenter_id);

      case 'justlinux':
        return new JustLinux($config, $router_config, $id, $requester, $datacenter_id);

      case 'speedtest':
        return new Speedtest($config, $router_config, $id, $requester, $datacenter_id);

      case 'vyatta':
      case 'edgeos':
        return new Vyatta($config, $router_config, $id, $requester, $datacenter_id);

      case 'vyos':
        return new Vyos($config, $router_config, $id, $requester, $datacenter_id);
  
      default:
        print('Unknown router type "'.$router_config['type'].'".');
        return null;
    }
  }
}

// End of router.php
