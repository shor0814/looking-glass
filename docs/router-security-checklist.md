# Router Security Checklist

This checklist is intended for reviewing router drivers in `routers/`.

## Input Validation

- Validate destinations with `is_valid_destination()` or `is_valid_ip_address()`.
- Validate AS numbers with `match_as()`.
- Validate AS-path regex with `match_aspath_regexp()` (rejects shell metacharacters).
- Validate routing instances (format and allow-list).

## Command Building

- Avoid concatenating unvalidated user input into command strings.
- Use `quote()` only when the target CLI supports quoted regex/parameters.
- For vtysh-style wrappers, avoid nested quoting and rely on strict validation.

## Delegated Tools

- For DNS/WHOIS/speed tests, use `escapeshellarg()` for parameters.
- Do not add these tools to router types without implementations.

## Logging and Limits

- Log command execution via `log_to_file()`.
- Enforce router timeouts in config (`timeout`).

