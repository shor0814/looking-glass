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

final class JustLinux extends UNIX {
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

}

// End of bird.php
