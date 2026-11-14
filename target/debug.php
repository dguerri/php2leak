<?php
// Ground-truth addresses for verifying the leak. Reads the worker's own
// /proc/self/maps and prints the Zend MM 2 MB chunks plus the libphp.so mappings.
// Note: kernels with CONFIG_ANON_VMA_NAME label Zend MM chunks [anon:zend_alloc];
// on kernels without it (e.g. COS), they appear as unnamed 2 MB-aligned rw-p VMAs.
header('Content-Type: text/plain');
echo "pid=" . getmypid() . "\n\n";
$maps = file_get_contents('/proc/self/maps');
foreach (explode("\n", $maps) as $line) {
    if (strpos($line, 'zend_alloc') !== false || strpos($line, 'libphp.so') !== false) {
        echo $line, "\n";
    } elseif (preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+rw-p\s+00000000\s+00:00\s+0\s*$/', $line, $m)) {
        $start = hexdec($m[1]);
        $end   = hexdec($m[2]);
        if (($start & 0x1fffff) === 0 && ($end - $start) >= 0x200000) {
            echo rtrim($line) . "  [anon:zend_alloc]\n";
        }
    }
}
