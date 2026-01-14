![Build Status](https://github.com/gmazoyer/looking-glass/workflows/syntax/badge.svg)
[![Documentation Status](https://readthedocs.org/projects/looking-glass/badge/?version=latest)](http://looking-glass.readthedocs.io/)

# Looking Glass

Easy to deploy Looking Glass made in PHP.

**This is a fork with enhanced features including datacenter-scoped routers, speed tests, DNS/WHOIS lookups, and security improvements.**

This project is maintained based on available time and the needs of the author.
If you like it, use it and want to support its development, you can sponsor it
or contribute in any way you can.

## Requirements

  * Webserver such as Apache 2, or Lighttpd, etc…
  * PHP (>= 8.1) module for the webserver (`libapache2-mod-php` for Apache 2
    for example)
  * Composer to install dependencies
  * The PDO extension to interact with SQLite for anti-spam feature
    (`php8.2-sqlite3` on Debian for example)
  * The XML package is required as well (`php8.2-xml` on Debian for example)

## Description

This web application made in PHP is what we call a **Looking Glass**. This is a
tool used to get some information about networks by giving the opportunity to
execute some commands on routers. The output is sent back to the user.

For now this looking glass is quite simple. Here you have some features:

  * Interface using Javascript and AJAX calls (needs a decent browser)
  * **Multi-datacenter support** - Organize routers by datacenter/location
  * Support the following router types:
    * Arista
    * BIRD (v1 and v2)
    * Cisco (IOS and IOS-XR)
    * Extreme/Brocade NetIron
    * FRRouting
    * Huawei (VRP)
    * Juniper
    * Mikrotik/RouterOS
    * Nokia
    * OpenBGPd
    * Quagga
    * **TNSR (Netgate)** - Netgate TNSR router support (NEW)
    * Vyatta/EdgeOS
    * VyOS
    * **justlinux** - Linux-based router for network tools (NEW)
    * **speedtest** - Dedicated speed test server (NEW, hidden from UI by default)
  * Support of Telnet and SSH connection to routers using password
    authentication and SSH keys
  * Configurable list of routers
  * Tweakable interface (title, logo, footer, elements order)
  * Log all commands in a file
  * Customizable output with regular expressions
  * Configurable list of allowed commands
  * Custom routing instances, aka VRFs (Juniper only, for now)
  * **Speed tests** - Download speed tests (1MB, 10MB, 100MB) with multiple format display
  * **DNS lookup** - Forward and reverse DNS lookups
  * **WHOIS lookup** - IP address and ASN information
  * **Interface statistics** - Network interface statistics (justlinux only, disabled by default)
  * **System information** - System info display (justlinux only, disabled by default)
  * **Delegation system** - Delegate speed tests, DNS, and WHOIS to dedicated servers
  * **Enhanced security** - Improved input validation and command injection protection

## Differences from Upstream

This fork includes several enhancements not present in the upstream repository:

### New Features

1. **Multi-Datacenter Support**
   - Organize routers by datacenter/location
   - Dynamic router list based on datacenter selection
   - Datacenter-scoped configuration

2. **Speed Tests**
   - File download speed tests (1MB, 10MB, 100MB)
   - Results displayed in multiple formats (bytes/sec, Mb/sec, Gb/sec, MB/sec, GB/sec)
   - Configurable base URL at global, datacenter, or router level
   - Delegation support to dedicated speed test servers

3. **Network Information Tools**
   - DNS lookup (forward and reverse)
   - WHOIS lookup (IP addresses and ASNs)
   - Interface statistics (justlinux only, disabled by default)
   - System information (justlinux only, disabled by default)

4. **Delegation System**
   - Delegate speed tests, DNS, and WHOIS to dedicated servers
   - Configurable at datacenter or router level
   - Supports `justlinux` and `speedtest` router types as delegates

5. **New Router Types**
   - **TNSR** - Netgate TNSR router support
   - **justlinux** - Linux-based router for network tools
   - **speedtest** - Dedicated speed test server (hidden from UI by default)

6. **Security Improvements**
   - Enhanced AS path regex validation (allows valid regex anchors while blocking injection)
   - Router/datacenter ID format validation
   - Proper shell escaping for all user inputs
   - Mitigation of command injection vulnerabilities (GitHub issue #81)

### Configuration Enhancements

- **Multi-level configuration hierarchy**: Global → Datacenter → Router
- **Flexible delegation**: Configure at datacenter or router level
- **Granular control**: Enable/disable features per router or datacenter

## Configuration

Install [Composer](https://getcomposer.org/) and run `composer install` to
install dependencies for this project. This step is not necessary if you use
Docker.

Copy the configuration **config.php.example** file to create a **config.php**
file. It contains all the values (PHP variables) used to customize the looking
glass. Details about configuration options are available in the
[documentation](docs/configuration.md).

### Configuration Hierarchy

This fork supports a three-level configuration hierarchy:

1. **Global Level** - Applies to all routers unless overridden
2. **Datacenter Level** - Applies to all routers in that datacenter unless overridden
3. **Router Level** - Applies only to that specific router (highest priority)

#### Example: Datacenter-Scoped Routers

```php
// Define datacenters
$config['datacenters']['dc1']['name'] = 'Kansas City 1';
$config['datacenters']['dc1']['desc'] = 'Primary datacenter in Kansas City';

// Router 1 in DC1
$config['datacenters']['dc1']['routers']['router1']['host'] = '10.10.10.3';
$config['datacenters']['dc1']['routers']['router1']['user'] = 'lg';
$config['datacenters']['dc1']['routers']['router1']['auth'] = 'ssh-key';
$config['datacenters']['dc1']['routers']['router1']['type'] = 'tnsr';
$config['datacenters']['dc1']['routers']['router1']['desc'] = 'KC1-TNSR01';

// Router 2 in DC1
$config['datacenters']['dc1']['routers']['router2']['host'] = '10.10.10.4';
$config['datacenters']['dc1']['routers']['router2']['type'] = 'juniper';
$config['datacenters']['dc1']['routers']['router2']['desc'] = 'KC1-Juniper01';
```

#### Example: Speed Test Configuration

Speed tests can be configured at multiple levels with priority: **Router > Datacenter > Global**

```php
// Global level (applies to all routers unless overridden)
$config['speed_test']['base_url'] = 'https://lg.example.com';

// Datacenter level (applies to all routers in that datacenter)
$config['datacenters']['dc1']['speed_test']['base_url'] = 'https://cdn-dc1.example.com';
$config['datacenters']['dc1']['speed_test']['router'] = 'speedtest-server'; // Delegation

// Router level (overrides datacenter/global)
$config['datacenters']['dc1']['routers']['router1']['speed_test']['base_url'] = 'https://cdn-router1.example.com';
$config['datacenters']['dc1']['routers']['router1']['speed_test']['router'] = 'speedtest-server'; // Router-level delegation
```

#### Example: Delegation System

Speed tests, DNS lookups, and WHOIS lookups can be delegated to dedicated servers:

```php
// Datacenter-level delegation (all routers in DC1 use justlinux-router)
$config['datacenters']['dc1']['speed_test']['router'] = 'justlinux-router';
$config['datacenters']['dc1']['dns_lookup']['router'] = 'justlinux-router';
$config['datacenters']['dc1']['whois_lookup']['router'] = 'justlinux-router';

// Router-level delegation (overrides datacenter-level)
$config['datacenters']['dc1']['routers']['router1']['speed_test']['router'] = 'another-speedtest-server';

// Create a justlinux router for network tools
$config['datacenters']['dc1']['routers']['justlinux-router']['type'] = 'justlinux';
$config['datacenters']['dc1']['routers']['justlinux-router']['host'] = 'tools.dc1.example.com';
$config['datacenters']['dc1']['routers']['justlinux-router']['user'] = 'lg';
$config['datacenters']['dc1']['routers']['justlinux-router']['auth'] = 'ssh-password';
$config['datacenters']['dc1']['routers']['justlinux-router']['pass'] = 'password';
$config['datacenters']['dc1']['routers']['justlinux-router']['desc'] = 'DC1 Network Tools Server';

// Explicitly enable tools on justlinux router (uses router itself)
$config['datacenters']['dc1']['routers']['justlinux-router']['speed_test']['disabled'] = false;
$config['datacenters']['dc1']['routers']['justlinux-router']['dns_lookup']['disabled'] = false;
$config['datacenters']['dc1']['routers']['justlinux-router']['whois_lookup']['disabled'] = false;
```

**Note:** `disabled=false` only works for router types with implementation:
- `justlinux` - Supports all tools (speed tests, DNS, WHOIS, interface stats, system info)
- `speedtest` - Supports speed tests, DNS, and WHOIS only

#### Example: Optional justlinux Commands

Interface statistics and system information are disabled by default and must be explicitly enabled:

```php
// Enable interface statistics (justlinux only)
$config['doc']['interface-stats']['enabled'] = true;

// Enable system information (justlinux only)
$config['doc']['system-info']['enabled'] = true;
```

### Configuration Priority Rules

1. **Router-level** configuration always takes precedence
2. **Datacenter-level** configuration applies if router-level is not set
3. **Global-level** configuration applies if neither router nor datacenter level is set
4. **Auto-detection** - If `base_url` is not set, it will be auto-detected from the current HTTP request (recommended for Caddy reverse proxy setups)

### Speed Test Files

Speed test files (1MB, 10MB, 100MB) should be generated and served from your web server. See `testfiles/README.md` for instructions on generating test files.

For Caddy server configuration, see `docs/caddy-config.md`.

## Docker

If you want to run the looking glass inside a Docker container, a Dockerfile
is provided in this repository. More details can be found
[here](docs/docker.md).

This fork also includes a `docker-compose.yml` for a simpler deployment. It
mirrors the common `docker run` usage and mounts `config.php`, `mystyle.css`,
and an SSH key for router access.

```sh
# Build and run using Docker Compose
docker compose up --build
```

If you already built the image, you can omit `--build`:

```sh
docker compose up
```

## Security

This fork includes several security improvements:

- **Enhanced input validation** - AS path regex validation allows valid regex anchors (`^`, `$`) while blocking shell metacharacters
- **Router/datacenter ID validation** - Strict format validation prevents injection via ID fields
- **Proper shell escaping** - All user inputs are properly escaped using `escapeshellarg()`
- **Command injection mitigation** - Addresses GitHub issue #81 (BIRD command injection vulnerability)

See `SECURITY_REVIEW.md` for a comprehensive security audit.

## Documentation

An up-to-date (hopefully) documentation is available in the **docs/**
directory. It gives enough details to setup the looking glass, to configure it
and to prepare your routers.

You can also find it at
[Read the Docs](http://looking-glass.readthedocs.io/en/latest/).

## License

Looking Glass is released under the terms of the GNU GPLv3. Please read the
LICENSE file for more information.

## Contact

If you have any bugs, errors, improvements, patches, ideas, you can create an
issue. You are also welcome to fork and make some pull requests.

## Helping

You can help this project in many ways. Of course you can ask for features,
give some ideas for future development, open issues if you found any and
contribute to the code with pull requests and patches. You can also support the
development of this project by donating some coins.

## Upstream Repository

This fork is based on the upstream repository: https://github.com/gmazoyer/looking-glass

For the original features and documentation, please refer to the upstream repository.
