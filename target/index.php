<?php
// Completely inert target endpoint: no session_start(), no SID, no reflection.
// The entire ASLR leak runs pre-RINIT inside php_hash_environment() and is
// emitted by PHP itself in the Set-Cookie: PHPSESSID= HTTP response header.
echo "ok\n";
