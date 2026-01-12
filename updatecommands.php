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
//require_once('index.php');
//require_once('config.php');
//require_once('routers/router.php');

require_once('includes/config.defaults.php');
require_once('config.php');
require_once('routers/router.php');
require_once('includes/antispam.php');
require_once('includes/captcha.php');
require_once('includes/utils.php');

// Just updating the router commands
if (isset($_POST['selectedFieldValue']) && !empty($_POST['selectedFieldValue'])) {
        $routerID= ($_POST['selectedFieldValue']);
        print("RouterID: $routerID");
        return;
}
//else {
//        print("something is empty");
//        return;
//}
// End of updatecommands.php
