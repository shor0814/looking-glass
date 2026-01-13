# Speed Test Files

This directory contains test files for the speed test functionality.

## Generating Test Files

To generate the test files, run:

```bash
php testfiles/generate.php
```

This will create:
- `test-1mb.bin` (1 MB)
- `test-10mb.bin` (10 MB)
- `test-100mb.bin` (100 MB)

## Manual Creation

If you prefer to create the files manually, you can use:

```bash
# Create 1MB file
dd if=/dev/zero of=test-1mb.bin bs=1M count=1

# Create 10MB file
dd if=/dev/zero of=test-10mb.bin bs=1M count=10

# Create 100MB file
dd if=/dev/zero of=test-100mb.bin bs=1M count=100
```

Or on Windows with PowerShell:

```powershell
# Create 1MB file
$bytes = New-Object byte[] (1MB)
[System.IO.File]::WriteAllBytes("test-1mb.bin", $bytes)

# Create 10MB file
$bytes = New-Object byte[] (10MB)
[System.IO.File]::WriteAllBytes("test-10mb.bin", $bytes)

# Create 100MB file
$bytes = New-Object byte[] (100MB)
[System.IO.File]::WriteAllBytes("test-100mb.bin", $bytes)
```

## Notes

- These files are used by the speed test commands (speed-test-1mb, speed-test-10mb, speed-test-100mb)
- The files should be accessible via HTTP/HTTPS from the looking glass server
- Make sure the web server has read permissions for these files
- The `.htaccess` file allows direct access to `.bin` files
