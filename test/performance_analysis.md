# CRITICAL PERFORMANCE ISSUE - v1.12

## Root Cause: detect_rule_zone() Function

### The Problem
```perl
sub detect_rule_zone {
    foreach my $zone (@zones) {
        # This executes firewall-cmd for EVERY zone for EVERY rule!
        my ($zone_output, $zone_err) = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --list-rich-rules");
    }
}
```

### Performance Disaster
- **140 rules** found by global command
- **9 zones** to check per rule  
- **140 × 9 = 1,260 firewall-cmd executions**
- **Each command takes ~0.4 seconds**
- **Total time: 1,260 × 0.4s = 504 seconds (8+ minutes)**

### Why It's Infinite Loop
1. User loads page
2. `list_all_rich_rules()` gets 140 rules
3. For each rule, calls `detect_rule_zone()`
4. `detect_rule_zone()` executes 9 firewall-cmd commands
5. Browser times out after 2 minutes
6. Webmin keeps running the 1,260 commands in background

## Immediate Fix Needed

Replace `detect_rule_zone()` with simple assignment:

```perl
# WRONG - causes infinite loop:
my $rule_zone = detect_rule_zone($rule) || get_default_zone() || 'public';

# RIGHT - simple assignment:
my $rule_zone = get_default_zone() || 'public';
```

## The Irony

The original problem was zone-by-zone queries being slow.
My "fix" made it 100× worse by doing zone-by-zone queries for every single rule.

**Classic example of "solving" a performance problem by making it catastrophically worse.**

## Version Status

- **v1.11**: Working but only shows 10 rules
- **v1.12**: Infinite loop, unusable
- **Need v1.13**: Remove detect_rule_zone() function completely