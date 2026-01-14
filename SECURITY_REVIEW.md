# Security Review - Looking Glass Application

## Executive Summary

This security review focuses on **code injection vulnerabilities** and related security concerns. The application handles user input that flows into shell commands, database queries, and HTML output. While many protections are in place, several areas require attention.

---

## 🔴 CRITICAL VULNERABILITIES

### 1. Command Injection in AS Path Regex (HIGH RISK)

**Location:** `routers/tnsr.php`, `routers/frr.php`, and other router implementations

**Issue:** AS path regex parameters are passed directly to shell commands without proper escaping in some router types.

**Vulnerable Code:**
```php
// routers/tnsr.php:52
$commands[] = (clone $cmd)->add('bgp ipv6 regexp', $parameter, '"');
```

**Risk:** If `$parameter` contains shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``, `\n`, etc.), an attacker could execute arbitrary commands.

**Example Attack:**
```
Parameter: "65001; rm -rf /"
Command: vtysh -N dataplane -c "show bgp ipv6 regexp 65001; rm -rf /"
```

**Mitigation:**
- ✅ **GOOD:** `match_aspath_regexp()` in `includes/utils.php` already filters `;` and `"` characters
- ⚠️ **NEEDS IMPROVEMENT:** The validation should be more comprehensive
- ✅ **GOOD:** Most router types use `quote()` function which wraps in double quotes
- ⚠️ **CONCERN:** Double quotes in the parameter are filtered, but the command is already wrapped in quotes, creating a potential escape scenario

**Recommendation:**
1. Use `escapeshellarg()` for all parameters passed to shell commands
2. Strengthen `match_aspath_regexp()` to reject more shell metacharacters
3. Consider using a whitelist approach for AS path regex patterns

---

### 2. Command Injection in Router ID / Datacenter ID (MEDIUM-HIGH RISK)

**Location:** `execute.php:156-157`, `execute.php:233`, `execute.php:298-299`

**Issue:** Router IDs and datacenter IDs from `$_POST` are used directly in array lookups and potentially in command construction.

**Vulnerable Code:**
```php
// execute.php:156-157
$routerID = $_POST['selectedRouterValue'];
$datacenterID = isset($_POST['selectedDatacenterValue']) ? $_POST['selectedDatacenterValue'] : null;
```

**Risk:** If router IDs are used in shell commands (e.g., logging, file paths), injection is possible.

**Current Protection:**
- ✅ Router IDs are validated against `$config['routers']` and `$config['datacenters']` arrays
- ✅ Router IDs are HTML-escaped when output: `htmlspecialchars($routerID)`
- ⚠️ **CONCERN:** No explicit validation of router ID format (alphanumeric, length limits)

**Recommendation:**
1. Validate router/datacenter IDs with strict regex: `/^[a-zA-Z0-9_-]+$/`
2. Enforce length limits (e.g., max 64 characters)
3. Ensure router IDs are never used in shell commands without escaping

---

### 3. WHOIS Command Injection (MEDIUM RISK)

**Location:** `routers/justlinux.php:157-158`

**Issue:** ASN parameter in WHOIS lookup uses string concatenation instead of `escapeshellarg()`.

**Vulnerable Code:**
```php
// routers/justlinux.php:157-158
$asn = $matches[2];
$cmd->add('echo "=== WHOIS Lookup for AS' . $asn . ' ===" && ');
$cmd->add('whois AS' . $asn . ' 2>&1 | head -100');
```

**Risk:** If ASN validation fails or is bypassed, injection is possible.

**Current Protection:**
- ✅ ASN is validated via regex: `/^(AS)?(\d+)$/i`
- ✅ Only numeric values are extracted
- ⚠️ **MINOR RISK:** If regex fails, `$matches[2]` might be undefined

**Recommendation:**
1. Use `escapeshellarg()` for consistency: `escapeshellarg('AS' . $asn)`
2. Add explicit check: `if (!isset($matches[2])) throw new Exception(...)`

---

## 🟡 MEDIUM RISK VULNERABILITIES

### 4. SQL Injection in AntiSpam (LOW-MEDIUM RISK)

**Location:** `includes/antispam.php:119-124`

**Issue:** While using prepared statements, the hash is computed from user input.

**Code:**
```php
$hash = sha1($remote_address);
$query = $this->database->prepare('SELECT * FROM users WHERE hash = :hash');
$query->bindValue(':hash', $hash, PDO::PARAM_STR);
```

**Risk:** **LOW** - Using prepared statements with parameter binding is secure. The hash is SHA1, which is deterministic and safe.

**Status:** ✅ **SECURE** - No changes needed.

---

### 5. XSS in Error Messages (MEDIUM RISK)

**Location:** `execute.php` - Multiple locations

**Issue:** Error messages include user input that is JSON-encoded but may be displayed in HTML.

**Vulnerable Code:**
```php
// execute.php:335
$error = 'Router "' . htmlspecialchars($hostname) . '" not found...';
print(json_encode(array('error' => $error)));
```

**Current Protection:**
- ✅ User input is HTML-escaped before JSON encoding
- ✅ JSON output is properly encoded
- ⚠️ **CONCERN:** If JSON is parsed and inserted into HTML without escaping, XSS is possible

**Recommendation:**
1. Ensure frontend JavaScript properly escapes JSON error messages when displaying
2. Consider using `json_encode()` with `JSON_HEX_QUOT | JSON_HEX_APOS` flags

---

### 6. Path Traversal in Log File (LOW-MEDIUM RISK)

**Location:** `includes/utils.php:362-366`

**Issue:** Log file path comes from configuration, but if config is compromised, path traversal could occur.

**Code:**
```php
function log_to_file($log) {
  global $config;
  $log .= "\n";
  file_put_contents($config['logs']['file'], $log, FILE_APPEND | LOCK_EX);
}
```

**Risk:** **LOW** - Requires `config.php` compromise. If an attacker controls `config.php`, they already have significant access.

**Recommendation:**
1. Validate log file path in `config.php` to prevent directory traversal
2. Use `realpath()` to resolve absolute paths
3. Ensure log directory has proper permissions

---

### 7. Command Injection via Routing Instance (MEDIUM RISK)

**Location:** `execute.php:477-489`

**Issue:** Routing instance names are validated against config array, but if used in commands, injection is possible.

**Code:**
```php
$routing_instance = $_POST['routing_instance'];
// Later used in: $router->send_command($query, $parameter, $routing_instance);
```

**Current Protection:**
- ✅ Routing instance is validated: `array_key_exists($_POST['routing_instance'], $config['routing_instances'])`
- ⚠️ **CONCERN:** Need to verify routing instance is properly escaped in router implementations

**Recommendation:**
1. Verify all router implementations properly escape routing instance parameter
2. Add format validation: alphanumeric, underscore, hyphen only

---

## 🟢 LOW RISK / SECURE AREAS

### 8. DNS/WHOIS Lookup - ✅ SECURE

**Location:** `routers/justlinux.php:113-168`

**Status:** ✅ **SECURE**
- Uses `escapeshellarg()` for all parameters
- Validates IP addresses with `filter_var()`
- Validates ASN with regex

---

### 9. Speed Test - ✅ SECURE

**Location:** `routers/justlinux.php:75-111`

**Status:** ✅ **SECURE**
- URL is constructed from config, not user input
- Uses `escapeshellarg()` for URL

---

### 10. Interface Statistics - ✅ MOSTLY SECURE

**Location:** `routers/justlinux.php:170-190`

**Status:** ✅ **SECURE**
- Uses `escapeshellarg()` for interface name parameter
- No user input in system commands

---

## 📋 RECOMMENDATIONS SUMMARY

### Immediate Actions (High Priority)

1. **Strengthen AS Path Regex Validation**
   - Add more shell metacharacter filtering
   - Consider using `escapeshellarg()` in router implementations
   - Implement whitelist-based validation

2. **Validate Router/Datacenter IDs**
   - Add format validation: `/^[a-zA-Z0-9_-]+$/`
   - Enforce length limits

3. **Fix WHOIS ASN Handling**
   - Use `escapeshellarg()` for ASN in echo and whois commands
   - Add explicit `$matches[2]` existence check

### Medium Priority

4. **Review All Router Implementations**
   - Audit each router type's `build_*` methods
   - Ensure all user input uses `escapeshellarg()` or `quote()`
   - Document which router types are most secure

5. **Enhance Input Validation**
   - Create centralized validation functions
   - Add length limits for all user inputs
   - Implement rate limiting per IP

6. **Improve Error Handling**
   - Ensure all error messages are properly escaped
   - Use consistent error response format
   - Log security-related errors separately

### Low Priority

7. **Security Headers**
   - Add CSP (Content Security Policy) headers
   - Add X-Frame-Options, X-Content-Type-Options headers

8. **Logging and Monitoring**
   - Log all command executions with parameters
   - Monitor for suspicious patterns (repeated failures, unusual commands)
   - Alert on potential injection attempts

---

## 🔍 CODE REVIEW CHECKLIST

- [x] Command injection vulnerabilities
- [x] SQL injection vulnerabilities
- [x] XSS vulnerabilities
- [x] Path traversal vulnerabilities
- [x] Input validation
- [x] Output encoding
- [x] Authentication/authorization
- [ ] CSRF protection (not reviewed - may need separate review)
- [ ] Session management (not applicable - stateless)
- [ ] File upload security (not applicable)

---

## 📝 NOTES

1. **Good Security Practices Found:**
   - Use of `htmlspecialchars()` for HTML output
   - Use of `escapeshellarg()` in DNS/WHOIS lookups
   - Prepared statements for SQL queries
   - Input validation functions (`match_ipv4`, `match_ipv6`, `match_as`, etc.)
   - Anti-spam and CAPTCHA mechanisms

2. **Areas of Concern:**
   - Inconsistent use of escaping functions across router types
   - Some string concatenation in command building
   - Limited validation of router/datacenter IDs

3. **Testing Recommendations:**
   - Test with malicious AS path regex patterns
   - Test with special characters in router IDs
   - Test with very long input strings
   - Test with null bytes and encoding issues
   - Perform fuzzing on all input parameters

---

## 🛡️ MITIGATION EXAMPLES

### Example 1: Strengthen AS Path Regex Validation

```php
// includes/utils.php
function match_aspath_regexp($aspath_regexp) {
  global $config;

  if (empty($aspath_regexp)) {
    return false;
  }

  // Reject shell metacharacters
  $dangerous_chars = array(';', '"', "'", '|', '&', '$', '`', '\\', "\n", "\r");
  foreach ($dangerous_chars as $char) {
    if (strpos($aspath_regexp, $char) !== false) {
      return false;
    }
  }

  // Reject command substitution attempts
  if (preg_match('/\$\(|`/', $aspath_regexp)) {
    return false;
  }

  // Check against blacklist
  foreach ($config['filters']['aspath_regexp'] as $invalid_aspath_regexp) {
    if ($invalid_aspath_regexp === $aspath_regexp) {
      return false;
    }
  }

  return true;
}
```

### Example 2: Validate Router/Datacenter IDs

```php
// execute.php (add at top)
function validate_router_id($id) {
  if (empty($id) || !is_string($id)) {
    return false;
  }
  // Alphanumeric, underscore, hyphen only, max 64 chars
  return preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $id) === 1;
}

// Then use:
if (!validate_router_id($routerID)) {
  $error = 'Invalid router ID format.';
  print(json_encode(array('error' => $error)));
  return;
}
```

### Example 3: Fix WHOIS ASN Handling

```php
// routers/justlinux.php:155-158
if (preg_match('/^(AS)?(\d+)$/i', $parameter, $matches)) {
  if (!isset($matches[2])) {
    throw new Exception('Invalid ASN format.');
  }
  $asn = escapeshellarg('AS' . $matches[2]);
  $cmd->add('echo "=== WHOIS Lookup for ' . $asn . ' ===" && ');
  $cmd->add('whois ' . $asn . ' 2>&1 | head -100');
}
```

---

**Review Date:** 2024
**Reviewer:** AI Security Analysis
**Next Review:** After implementing high-priority recommendations
