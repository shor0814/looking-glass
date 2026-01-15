<?php

/*
 * Looking Glass - An easy to deploy Looking Glass
 * Copyright (C) 2017-2024 Guillaume Mazoyer <guillaume@mazoyer.eu>
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

final class TNSR extends UNIX {
  protected static $wrapper = 'vtysh -N dataplane -c ';

  private function is_safe_source_interface($value) {
    return is_string($value) &&
      preg_match('/^[a-zA-Z0-9_.:-]{1,64}$/', $value) === 1;
  }

  protected function build_bgp($parameter, $routing_instance = false) {
    $cmd = new CommandBuilder();
    // vytsh commands need to be quoted
    $cmd->add(self::$wrapper, '"', 'show bgp');

    if (match_ipv6($parameter, false)) {
      $cmd->add('ipv6');
    }
    if (match_ipv4($parameter, false)) {
      $cmd->add('ipv4');
    }
    $cmd->add('unicast', $parameter, '"');

    return array($cmd);
  }

  protected function build_aspath_regexp($parameter, $routing_instance = false) {
    $commands = array();
    $cmd = new CommandBuilder();
    // vytsh commands need to be quoted
    $cmd->add(self::$wrapper, '"', 'show');

    if (!$this->config['disable_ipv6']) {
      $commands[] = (clone $cmd)->add('bgp ipv6 regexp', $parameter, '"');
    }
    if (!$this->config['disable_ipv4']) {
      $commands[] = (clone $cmd)->add('bgp ipv4 regexp', $parameter, '"');
    }

    return $commands;
  }

  protected function build_ping($parameter, $routing_instance = false) {
    // Resolve hostnames to IP to avoid unsafe shell input
    if (match_hostname($parameter)) {
      $hostname = $parameter;
      $parameter = hostname_to_ip_address($parameter, $this->config);
      if (!$parameter) {
        throw new Exception('No record found for '.$hostname);
      }
    }

    if (!is_valid_ip_address($parameter)) {
      throw new Exception('The parameter does not resolve to an IP address.');
    }

    $cmd = new CommandBuilder();
    $cmd->add('clixon_cli -1 ping ', escapeshellarg($parameter));

    if ($this->has_source_interface_id()) {
      if (is_valid_ip_address($this->get_source_interface_id())) {
        $cmd->add('source ');
	if (match_ipv6($parameter)) {
          $cmd->add(escapeshellarg($this->get_source_interface_id('ipv6')));
        } else {
          $cmd->add(escapeshellarg($this->get_source_interface_id('ipv4')));
        }
      } else {
        $source = $this->get_source_interface_id();
        if (!$this->is_safe_source_interface($source)) {
          throw new Exception('Invalid source interface format.');
        }
        $cmd->add('source '.escapeshellarg($source));
      }
    }

    $cmd->add('count 5');

    return array($cmd);
  }

  protected function build_traceroute($parameter, $routing_instance = false) {
    if (!is_valid_destination($parameter)) {
      throw new Exception('The parameter is not an IP address or a hostname.');
    }

    $cmd = new CommandBuilder();
    $cmd->add('clixon_cli -1 traceroute');

    if (match_hostname($parameter)) {
      $hostname = $parameter;
      $parameter = hostname_to_ip_address($hostname, $this->config);

      if (!$parameter) {
        throw new Exception('No record found for '.$hostname);
      }

      if (match_ipv6($parameter)) {
        $cmd->add('ipv6');
      }
      $cmd->add(isset($hostname) ? escapeshellarg($hostname) : escapeshellarg($parameter));
    } else {
      if (match_ipv6($parameter)) {
        $cmd->add('ipv6');
      }
      $cmd->add(escapeshellarg($parameter));
    }

    if ($this->has_source_interface_id()) {
      $cmd->add('source');

      if (match_ipv6($parameter) && $this->get_source_interface_id('ipv6')) {
        $cmd->add(escapeshellarg($this->get_source_interface_id('ipv6')));
      }
      if (match_ipv4($parameter) && $this->get_source_interface_id('ipv4')) {
        $cmd->add(escapeshellarg($this->get_source_interface_id('ipv4')));
      }
    }

    return array($cmd);
  }

  protected function build_mtr($parameter, $routing_instance = false) {
    // Resolve hostnames to IP to avoid unsafe shell input
    if (match_hostname($parameter)) {
      $hostname = $parameter;
      $parameter = hostname_to_ip_address($parameter, $this->config);
      if (!$parameter) {
        throw new Exception('No record found for '.$hostname);
      }
    }

    if (!is_valid_ip_address($parameter)) {
      throw new Exception('The parameter does not resolve to an IP address.');
    }

    $cmd = new CommandBuilder();
    $cmd->add('clixon_cli -1 dataplane shell mtr', escapeshellarg($parameter));

    if ($this->has_source_interface_id()) {
      if (is_valid_ip_address($this->get_source_interface_id())) {
        $cmd->add('--address ');
        if (match_ipv6($parameter)) {
          $cmd->add(escapeshellarg($this->get_source_interface_id('ipv6')));
        } else {
          $cmd->add(escapeshellarg($this->get_source_interface_id('ipv4')));
        }
      } else {
        $source = $this->get_source_interface_id();
        if (!$this->is_safe_source_interface($source)) {
          throw new Exception('Invalid source interface format.');
        }
        $cmd->add('--address '.escapeshellarg($source));
      }
    }

    $cmd->add('-c3 -w');

    return array($cmd);
  }

  protected function build_as($parameter, $routing_instance = false) {
    $parameter = '^'.$parameter.'_';
    return $this->build_aspath_regexp($parameter, $routing_instance);
  }
}

// End of frr.php
