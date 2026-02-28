# FirewallD Rich Rules for Webmin

A full-featured Webmin module for managing firewalld rich rules — the complex, expressive firewall rules that `firewall-cmd` supports but most GUIs ignore.

![Version](https://img.shields.io/badge/version-2.1-blue)
![Platform](https://img.shields.io/badge/platform-Linux-green)
![Webmin](https://img.shields.io/badge/Webmin-2.0%2B-orange)
![License](https://img.shields.io/badge/license-GPL--3.0-lightgrey)

## Why This Exists

FirewallD rich rules are powerful — source/destination filtering, per-rule logging, rate limiting, port forwarding, protocol matching, reject types — but managing them from the command line is tedious and error-prone. One misplaced quote and your rule silently fails.

This module gives you a proper UI inside Webmin: browse, search, filter, create, edit, clone, test, and bulk-manage rich rules across all zones. It also auto-categorizes rules by origin (admin-created vs. fail2ban-generated), so you can see at a glance what's what.

## Features

**Rule Management**
- Create, edit, clone, and delete rich rules through a clean form interface
- Full support for all rich rule components: family, source (IP/MAC/interface/ipset), destination, service, port, protocol, action (accept/reject/drop), reject types, logging with prefix/level/rate-limit, audit, masquerade, and port forwarding
- Live rule preview — see the exact `firewall-cmd` syntax as you build the rule
- Inline validation — warnings (yellow) as you edit, errors (red) when you test
- **Test Rule** button — validates against the live firewalld runtime without persisting, so you know it works before you commit

**Browsing and Search**
- Tabbed interface: Admin Rules | Fail2Ban Rules | Other Rules | All Rules
- Auto-categorization detects fail2ban-generated rules vs. manually created ones
- Filter by zone, IP/network, port, protocol, service, action type, or free text
- Rule summaries show source, service/port, and action at a glance

**Bulk Operations**
- Select multiple rules with checkboxes
- Bulk delete across zones
- Bulk clone for rule templates

**fail2ban Integration**
- Identifies fail2ban-managed rules automatically
- IP info lookup with WHOIS
- Unban IPs directly from the interface

## Quick Install

Download the `.wbm.gz` package from this repo and install through the Webmin UI:

1. Download [`firewalld-rich.wbm.gz`](firewalld-rich.wbm.gz) from this repository
2. In Webmin, go to **Webmin → Webmin Configuration → Webmin Modules**
3. Select **From uploaded file**, choose the `.wbm.gz` file, and click **Install Module**
4. The module appears under **Networking → FirewallD Rich Rules**

### Requirements

- Webmin 2.0+
- FirewallD (with rich rules support, version 0.3.0+)
- Linux (RHEL, CentOS, AlmaLinux, Rocky, Fedora, Debian, Ubuntu, etc.)

### Manual Install

```bash
cd /usr/libexec/webmin
tar xzf /path/to/firewalld-rich.wbm.gz
# Refresh modules in Webmin UI, or restart Webmin:
systemctl restart webmin
```

## How It Works

- Rules are fetched via a single `firewall-cmd --list-all-zones` call (no per-zone queries)
- Rules get global sequential indices for reliable edit/delete across zones
- The **Test Rule** feature adds a rule to the runtime (no `--permanent`), checks if firewalld accepts it, then immediately removes it — the rule never persists even if something goes wrong
- Rule categorization uses pattern matching to distinguish admin rules from fail2ban rules from unknown sources
- All shell interactions use proper escaping via `_shell_quote_rule()` — no injection vectors

## Module Structure

```
firewalld-rich/
├── module.info           # Module metadata, dependencies, version
├── config                # Default configuration
├── config.info           # Module Configuration form definition
├── install_check.pl      # Tells Webmin if firewalld is installed (Refresh Modules)
├── postinstall.pl        # Post-install setup (permissions, directories)
├── firewalld-rich-lib.pl # Core library: rule parsing, construction, validation
├── index.cgi             # Main page: tabs, search, rule table, bulk actions
├── edit.cgi              # Rule editor: form, preview, validation, test
├── save.cgi              # Save handler: validates and commits rules
├── test_rule.cgi         # JSON API: test rule against runtime firewalld
├── delete.cgi            # Delete confirmation and handler
├── clone.cgi             # Clone a rule to a new zone or with modifications
├── bulk_actions.cgi      # Bulk delete handler
├── info.cgi              # IP info page (WHOIS, related rules)
├── unban.cgi             # fail2ban unban handler
├── acl_security.pl       # Webmin ACL integration
├── lang/en               # English language strings
└── images/icon.gif       # Module icon (48x48)
```

## Configuration

After installation, click the gear icon on the module page (or go to **Webmin → Webmin Configuration → Webmin Modules → FirewallD Rich Rules → Module Configuration**) to set:

- Path to `firewall-cmd`
- FirewallD config directory
- Debug options
- Default packet handling

## Compatibility

Tested on:
- AlmaLinux 8 / RHEL 8 with Webmin 2.111
- FirewallD 0.9.x and 1.x

Should work on any Linux distribution with Webmin 2.0+ and FirewallD 0.3.0+.

## Contributing

Issues and pull requests welcome. The code is standard Webmin Perl CGI — if you've worked with any Webmin module, you'll feel right at home.

## License

GPL-3.0 — same as Webmin itself.

## Author

**Bob7123** — Built because managing rich rules from the command line is a pain, and no existing Webmin module handled them properly.
