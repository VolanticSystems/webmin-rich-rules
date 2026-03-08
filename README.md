# FirewallD Rich Rules for Webmin

A full-featured Webmin module for managing firewalld rich rules — the complex, expressive firewall rules that `firewall-cmd` supports but most GUIs ignore.

![Version](https://img.shields.io/badge/version-3.1.1-blue)
![Tests](https://img.shields.io/badge/tests-40%20integration-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-green)
![Webmin](https://img.shields.io/badge/Webmin-2.0%2B-orange)
![License](https://img.shields.io/badge/license-GPL--3.0-lightgrey)

## What is Webmin?

[Webmin](https://webmin.com) is an open-source web-based system administration tool for Unix-like servers, created by Jamie Cameron in 1997. It provides a browser UI for managing users, services, packages, cron, DNS, email, and more — replacing the need to hand-edit config files over SSH. With over a million installations worldwide, it's one of the most widely deployed server admin panels. Its companion project [Virtualmin](https://virtualmin.com) adds hosting control (domains, databases, email accounts). Webmin modules are self-contained Perl CGI programs that plug into the framework, each managing one system service.

## Why This Exists

FirewallD rich rules are powerful — source/destination filtering, per-rule logging, rate limiting, port forwarding, protocol matching, reject types — but managing them from the command line is tedious and error-prone. One misplaced quote and your rule silently fails. No existing Webmin module handled them.

This module gives you a proper UI inside Webmin: browse, search, filter, create, edit, clone, test, and bulk-manage rich rules across all zones. It also auto-categorizes rules by origin (admin-created vs. fail2ban-generated), so you can see at a glance what's what.

## Why This is Hard

A rich rule isn't a simple "allow port 80" — it's a combination of:

- **9 element types**: port, source-port, service, protocol, icmp-block, icmp-type, masquerade, forward-port, mark
- **Source options**: IPv4 address, IPv6 address, MAC, ipset, inverted (NOT) variants
- **Destination options**: IPv4/IPv6 address, inverted
- **5 actions**: accept, reject (with 6 reject-type variants), drop, mark, none (for icmp-block)
- **Logging**: syslog with prefix/level/rate-limit, nflog with group/prefix/queue-depth, audit
- **Rate limits**: on the action itself, on logging, with configurable units
- **Priority**: -32768 to 32767
- **Family**: IPv4, IPv6, or both

The permutation space is hundreds of valid configurations, many with subtle interactions (e.g., masquerade can't have an action, icmp-block implies reject, forward-port requires a protocol). The form must handle all of these correctly, the preview must render them in exact `firewall-cmd` syntax, and the parser must round-trip rules from firewalld back into form fields without losing information. Systematic coverage of this space required tooling beyond manual testing.

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

## Testing

The module includes a 40-test integration suite (`test/test_rich_rules.sh`) that exercises the full HTTP interface — not mocked endpoints, but live `save.cgi`, `test_rule.cgi`, `edit.cgi`, and `index.cgi` against a running Webmin instance.

**What the tests cover:**
- All 9 element types (service, port, source-port, protocol, icmp-block, icmp-type, masquerade, forward-port, mark)
- Source/destination options including IPv4, IPv6, MAC, and inverted (NOT) variants
- All actions: accept, reject (default + typed), drop, mark
- Logging: syslog with prefix/level, rate-limited logging, nflog, audit
- Priority, family selection, action rate limits
- Combination rules exercising multiple features at once
- Negative tests: invalid IP, out-of-range port, bad priority, empty rule, duplicate rule

**Safety design:**
- A **failsafe watchdog** (dead-man's switch) runs in the background. If tests don't complete within 15 minutes, it restores the firewall from a pre-test baseline and reboots.
- Tests use an isolated `richtest` zone with no bound interfaces — no live traffic is affected.
- All test addresses are from RFC 5737 (192.0.2.0/24, 203.0.113.0/24) and RFC 3849 (2001:db8::/32) — never routable.
- A safety check after each test category verifies critical ports (SSH, Webmin) remain reachable.

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
├── search_rules.cgi      # Search/filter handler
├── info.cgi              # IP info page (WHOIS, related rules)
├── unban.cgi             # fail2ban unban handler
├── acl_security.pl       # Webmin ACL integration
├── lang/en               # English language strings
├── images/icon.gif       # Module icon (48x48)
└── test/
    ├── test_rich_rules.sh    # 40-test integration suite (bash)
    ├── failsafe_watchdog.sh  # Dead-man's switch for test safety
    └── *.pl                  # Perl unit tests for categorization, parsing
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

## License

GPL-3.0 — same as Webmin itself.

## Author

**Bob7123** — AI-assisted development used for systematic coverage of the combinatorial rule space.
