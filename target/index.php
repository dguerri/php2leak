<?php
// Reflect the SID constant, which php_session_reset_id() built pre-RINIT from
// the dangling PS(id) (smart_str_appends -> strlen, stops at the first NUL).
// The response body therefore carries the raw reclaimed-heap bytes.
echo "SID=" . SID . "\n";
