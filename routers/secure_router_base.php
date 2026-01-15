<?php

/*
 * Incremental security base class for router drivers.
 * Provides shared validation helpers without changing behavior.
 */

require_once('router.php');
require_once('includes/utils.php');

abstract class SecureRouterBase extends Router {
  /**
   * Validate a routing instance name format.
   *
   * @param string $routing_instance
   * @return bool
   */
  protected function is_valid_routing_instance_name($routing_instance) {
    return is_string($routing_instance) &&
      preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $routing_instance) === 1;
  }

  /**
   * Validate destination as hostname or IP address.
   *
   * @param string $destination
   * @return bool
   */
  protected function is_valid_destination_param($destination) {
    return is_valid_destination($destination);
  }

  /**
   * Validate AS number format.
   *
   * @param string $asn
   * @return bool
   */
  protected function is_valid_as_param($asn) {
    return match_as($asn);
  }

  /**
   * Validate AS-path regex format.
   *
   * @param string $aspath
   * @return bool
   */
  protected function is_valid_aspath_param($aspath) {
    return match_aspath_regexp($aspath);
  }
}

// End of secure_router_base.php
