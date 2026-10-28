<?php
// Ground-truth addresses for verifying the leak. Reads the worker's own
// /proc/self/maps and prints the Zend MM chunks ([anon:zend_alloc]) plus the
// libphp.so base. Compare these against the chunk base that leak.py recovers.
header('Content-Type: text/plain');
echo "pid=" . getmypid() . "\n\n";
$maps = file_get_contents('/proc/self/maps');
foreach (explode("\n", $maps) as $line) {
    if (strpos($line, 'zend_alloc') !== false || strpos($line, 'libphp.so') !== false) {
        echo $line, "\n";
    }
}
