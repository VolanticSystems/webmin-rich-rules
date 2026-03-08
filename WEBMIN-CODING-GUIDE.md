# Webmin Module Coding Guide — "Old School" Perl CGI

Webmin's codebase dates to the late 1990s. It is pure Perl CGI — no frameworks,
no templating engines, no client-side build tools. Modern Perl idioms and
web patterns will break things. Follow these conventions exactly.

## Architecture

- Each module lives in its own directory under `/usr/libexec/webmin/` (RHEL) or `/usr/share/webmin/` (Debian)
- Each `.cgi` file is a standalone CGI script
- Shared code goes in `-lib.pl` files (e.g., `firewalld-rich-lib.pl`)
- `module.info` declares the module (name, version, category, dependencies)
- `config` has default config values; `config.info` describes them for the UI
- `lang/en` has all UI strings — NEVER hardcode English text in CGI files
- `install_check.pl` verifies the module can run on this system
- `postinstall.pl` runs after module installation

## Required Boilerplate

Every CGI script starts with:
```perl
#!/usr/bin/perl
require './firewalld-rich-lib.pl';    # loads WebminCore, init_config, etc.
&ReadParse();                          # parse GET/POST into %in hash
```

The lib file starts with:
```perl
BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();
```

This gives you: `%text` (lang strings), `%config` (module config), `%in` (form params),
`%access` (ACL), `%gconfig` (global config).

## Key API Functions (from ui-lib.pl and web-lib-funcs.pl)

### Page Structure
```perl
&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
# ... page content ...
&ui_print_footer("/", $text{'index'});
```
- `ui_print_header` outputs the HTML head + page header
- `ui_print_footer` outputs page footer + navigation links
- NEVER output your own <html>, <head>, <body> tags

### Tables (data display)
```perl
print &ui_columns_start(\@header_row);
print &ui_columns_row(\@data_row);
print &ui_checked_columns_row(\@data, \@tds, "name", $value);  # with checkbox
print &ui_columns_end();
```

### Forms
```perl
print &ui_form_start("save.cgi", "post");
print &ui_hidden("zone", $zone);
print &ui_table_start($text{'edit_title'}, undef, 2);
print &ui_table_row($text{'edit_source'}, &ui_textbox("source", $source, 40));
print &ui_table_row($text{'edit_action'}, &ui_select("action", $action, \@options));
print &ui_table_end();
print &ui_form_end([["save", $text{'save'}], ["cancel", $text{'cancel'}]]);
```

### Links and Buttons
```perl
print &ui_links_row(\@links);     # row of action links
print &select_all_link("name");    # select all checkboxes
print &select_invert_link("name"); # invert selection
```

### Confirmation
```perl
print &ui_confirmation_form("delete.cgi", $text{'delete_rusure'},
    [["zone", $zone], ["rule", $rule]],
    [["confirm", $text{'delete_ok'}]]);
```

### Running Commands
```perl
# Simple backtick with logging:
my $output = &backquote_logged("firewall-cmd --list-rich-rules 2>&1");

# Or with execute_command:
my $fh = 'CMD';
&open_execute_command($fh, "command 2>&1 </dev/null", 1);
while(<$fh>) { ... }
close($fh);
```

### Escaping
```perl
&html_escape($text)     # for HTML output
&urlize($text)          # for URL parameters
quotemeta($text)        # for shell commands (Perl builtin)
```

### Redirects
```perl
&redirect("index.cgi?zone=" . &urlize($zone));
```

### Error Handling
```perl
&error($text{'save_efailed'});   # displays error page and stops
```

## Style Rules — DO and DON'T

### DO:
- Use `&` prefix when calling Webmin API functions: `&ui_print_header()`
- Use `$text{'key'}` for ALL user-visible strings (from lang/en)
- Use `print` to output HTML — the CGI writes to stdout
- Use Webmin's `ui_*` functions for ALL UI elements
- Keep CGI scripts short — business logic goes in the lib
- Use `$config{'key'}` for configurable values
- Use `quotemeta()` for shell arguments
- Test with `firewall-cmd` timeout (use `timeout 30` prefix)

### DON'T:
- Don't use modern Perl frameworks (Mojolicious, Dancer, etc.)
- Don't use templates (TT2, Mason, etc.)
- Don't output raw HTML when a `ui_*` function exists
- Don't use JavaScript frameworks (React, Vue, jQuery)
- Don't use CSS frameworks (Bootstrap, Tailwind)
- Don't hardcode English strings — use lang/en
- Don't use `use strict` in CGI files that call Webmin API (conflicts with global vars)
  - The lib can use `use strict` + `use warnings` + `our` declarations
  - CGI files: just `require` the lib and use the globals
- Don't use `exit()` — use `return` or let the script end naturally
- Don't create your own HTML/HEAD/BODY — `ui_print_header` does this
- Don't use `die()` for user errors — use `&error()`
- Don't shell out without `timeout` — firewall-cmd can hang

### Inline CSS — When Needed:
The Authentic theme handles most styling. If you need custom styles,
use inline `style=""` attributes. Don't create external CSS files.
Keep it minimal — match existing Webmin visual patterns.

### JavaScript — Sparingly:
If needed (e.g., select-all checkboxes), use inline `<script>` blocks
with vanilla JS. No external JS files, no frameworks.

## Module File Reference

| File | Purpose |
|------|---------|
| `module.info` | Module metadata (name, version, category, depends) |
| `config` | Default configuration key=value pairs |
| `config.info` | Config UI field definitions |
| `lang/en` | English UI strings |
| `*-lib.pl` | Shared library functions |
| `index.cgi` | Main page |
| `edit.cgi` | Add/edit form |
| `save.cgi` | Form processor (POST handler) |
| `delete.cgi` | Deletion handler |
| `install_check.pl` | System requirements check |
| `postinstall.pl` | Post-install setup |
| `acl_security.pl` | Access control definitions |

## Testing from Command Line

The CGI needs Webmin environment. Set these:
```bash
cd /usr/libexec/webmin/firewalld-rich
WEBMIN_CONFIG=/etc/webmin \
WEBMIN_VAR=/var/webmin \
REMOTE_USER=root \
REQUEST_METHOD=GET \
SERVER_PORT=10000 \
GATEWAY_INTERFACE=CGI/1.1 \
FOREIGN_MODULE_NAME=firewalld-rich \
DOCUMENT_ROOT=/usr/libexec/webmin \
  perl -I/usr/libexec/webmin index.cgi 2>&1 | head -80
```

Or test through curl with session auth:
```bash
# Get session cookie
SID=$(curl -sk -c - "https://localhost:10000/session_login.cgi" \
  -d "user=root&pass=YOURPASS" | grep sid | awk '{print $NF}')

# Hit the module
curl -sk -b "sid=$SID" "https://localhost:10000/firewalld-rich/" | head -100
```

## Webmin Logging
- Errors go to `/var/webmin/miniserv.error`
- Access log: `/var/webmin/miniserv.log`
- Use `&webmin_log("action", "type", $object)` to log admin actions
