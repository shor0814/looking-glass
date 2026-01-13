<?php
/**
 * Script to generate test files for speed tests
 * Run this once: php testfiles/generate.php
 */

$sizes = array(1, 10, 100); // MB

foreach ($sizes as $size_mb) {
    $filename = __DIR__ . '/test-' . $size_mb . 'mb.bin';
    $size_bytes = $size_mb * 1024 * 1024;
    
    echo "Generating test-{$size_mb}mb.bin ({$size_mb} MB)...\n";
    
    $fp = fopen($filename, 'wb');
    if (!$fp) {
        die("Cannot create file: $filename\n");
    }
    
    // Write in 1MB chunks to avoid memory issues
    $chunk_size = 1024 * 1024; // 1MB chunks
    $chunks = $size_mb;
    
    for ($i = 0; $i < $chunks; $i++) {
        $data = str_repeat('0', $chunk_size);
        fwrite($fp, $data);
    }
    
    fclose($fp);
    echo "Created: $filename (" . filesize($filename) . " bytes)\n";
}

echo "\nAll test files generated successfully!\n";
