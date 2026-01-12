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

// Check for spam
if ($config['antispam']['enabled']) {
  $antispam = new AntiSpam($config['antispam']);
  $antispam->check_spammer($requester);
}

// Just asked for the documentation
if (isset($_POST['doc']) && !empty($_POST['doc'])) {
  $query = htmlspecialchars($_POST['doc']);
  print(json_encode($config['doc'][$query]));
  return;
}

// Just updating the datacenter routers
if (isset($_POST['selectedDatacenterValue']) && !empty($_POST['selectedDatacenterValue'])) {
  $datacenterID= ($_POST['selectedDatacenterValue']);
  $datacenter=$config['datacenters'][$datacenterID];
  print("DatacenterID: $datacenterID");
  print_r($datacenter);
  // Get command count
  $router_count = 0;
  if (isset($config['datacenter'][$datacenter]['routers'])) {
    $routerArray = explode(',', $config['datacenters'][$datacenter]['routers']);
    $router_count = count($routerArray);
    print ("Router Count: $router_count");
  }

  $html = null;
  //$selected = ' selected="selected"';
  //foreach (array_keys($doc) as $cmd) {
  //        //DEBUG print("inside foreach");
  //      if (isset($config['doc'][$cmd]['command']) && !isset($config['routers'][$routerID][$cmd]['disable'])) {
  //      $html .= '<option value="';
  //      $html .= $cmd;
  //      $html .= '"';
  //      $html .= $selected;
  //      $html .= '>';
  //      $html .= $config['doc'][$cmd]['command'];
  //      $html .= '</option>';
  //      $selected = '';
  //    }
  //  }
  //print($html);
  return;

}

// Just updating the router commands
if (isset($_POST['selectedRouterValue']) && !empty($_POST['selectedRouterValue'])) {
  $routerID= ($_POST['selectedRouterValue']);
  $doc=$config['doc'];	  
  //DEBUG print("RouterID: $routerID");
  // Get command count
  if ($config['frontpage']['command_count'] > 0) {
    $command_count = $config['frontpage']['command_count'];
    //DEBUG print("Command Count from Front Page $command_count");
  }
  else {
    $command_count = 0;
    foreach (array_keys($doc) as $cmd) {
      if (isset($config['doc'][$cmd]['command'])) {
       $command_count++;
      }
    }
    //DEBUG print("Command Count from doc $command_count");
  }
  
  $html = null;
  $selected = ' selected="selected"';
//  $html = '<select size="6" class="form-select" name="query" id="query">';
  foreach (array_keys($doc) as $cmd) {
	  //DEBUG print("inside foreach");
        if (isset($config['doc'][$cmd]['command']) && !isset($config['routers'][$routerID][$cmd]['disable'])) {
	$html .= '<option value="';
	$html .= $cmd;
	$html .= '"';
	$html .= $selected;
	$html .= '>';
	$html .= $config['doc'][$cmd]['command'];
	$html .= '</option>';
	$selected = '';
      }
    }
 // $html .= '</select>';
  print($html);
  return;

}

if (isset($_POST['query']) && !empty($_POST['query']) &&
    isset($_POST['routers']) && !empty($_POST['routers']) &&
    isset($_POST['parameter']) && !empty($_POST['parameter'])) {
  $query = trim($_POST['query']);
  $hostname = trim($_POST['routers']);
  $parameter = trim($_POST['parameter']);

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

  // Do the processing
  $router = Router::instance($hostname, $requester);
  $router_config = $router->get_config();

  // Check if parameter is an IPv6 and if IPv6 is disabled
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
