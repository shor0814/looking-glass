# Caddy Configuration for Speed Test Files

If you're running the Looking Glass behind Caddy (or another reverse proxy), you'll want to serve the speed test files directly from Caddy rather than from inside the Docker container. This ensures accurate speed test results since clients download directly from your web server.

## Caddyfile Configuration

Add this to your Caddyfile to serve the speed test files:

```caddy
your-domain.com {
    # Serve speed test files directly (before reverse proxy)
    handle /testfiles/* {
        root * /path/to/looking-glass
        file_server
    }

    # Reverse proxy to the Looking Glass Docker container
    handle {
        reverse_proxy localhost:8080
        # Or your Docker container:
        # reverse_proxy http://localhost:8181
    }
}
```

### Example with full configuration:

```caddy
lg.example.com {
    # Enable compression for speed test files
    encode gzip zstd

    # Serve speed test files directly from the host
    handle /testfiles/* {
        root * /opt/looking-glass
        file_server
        header Cache-Control "no-cache"
    }

    # All other requests go to the Looking Glass Docker container
    handle {
        reverse_proxy http://localhost:8181 {
            header_up Host {host}
            header_up X-Real-IP {remote}
            header_up X-Forwarded-For {remote}
            header_up X-Forwarded-Proto {scheme}
        }
    }
}
```

## File Location

Place your test files in `/path/to/looking-glass/testfiles/` on the host machine:
- `test-1mb.bin` (1 MB)
- `test-10mb.bin` (10 MB)  
- `test-100mb.bin` (100 MB)

You can generate these files using:
```bash
php testfiles/generate.php
```

Or manually create them (see `testfiles/README.md` for details).

## Notes

- **By default, the speed test URL is automatically constructed** using the current request's host and scheme. This means it will work correctly with Caddy without any additional configuration - the test files will download from `https://your-domain.com/testfiles/test-1mb.bin` automatically.
- The test files should be accessible at `https://your-domain.com/testfiles/test-1mb.bin`, etc.
- Make sure the path in Caddyfile (`root * /path/to/looking-glass`) matches where your files are located on the host
- Consider adding rate limiting for the `/testfiles/*` path to prevent abuse
- The implementation automatically detects HTTPS from Caddy's `X-Forwarded-Proto` header

## Custom Base URL (Optional)

If you want to serve speed test files from a different domain or CDN, you can optionally configure it in `config.php`:

```php
// Custom base URL for speed test files (optional)
// Only needed if serving from a different domain/CDN
$config['speed_test']['base_url'] = 'https://cdn.example.com';
```

**For most setups with Caddy, you don't need to set this** - the default auto-detection works perfectly.
