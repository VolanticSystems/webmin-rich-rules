#!/usr/bin/perl
# System Evidence Test - Gather facts, make no assumptions
# This validates actual system state and rule processing

use strict;
use warnings;

# Add parent directory to include path for library
BEGIN { 
    use File::Basename;
    my $lib_dir = dirname(dirname(__FILE__));
    unshift @INC, $lib_dir;
}

require 'firewalld-rich-lib.pl';

print "=== System Evidence Test ===\n";
print "Gathering facts, making no assumptions\n\n";

# EVIDENCE 1: fail2ban service status
print "1. FAIL2BAN SERVICE STATUS:\n";
my $f2b_status = `systemctl is-active fail2ban 2>/dev/null`;
chomp($f2b_status);
print "   systemctl is-active fail2ban: $f2b_status\n";

my $f2b_enabled = `systemctl is-enabled fail2ban 2>/dev/null`;
chomp($f2b_enabled);
print "   systemctl is-enabled fail2ban: $f2b_enabled\n";

# EVIDENCE 2: fail2ban jail status
print "\n2. FAIL2BAN JAIL STATUS:\n";
my $jail_status = `fail2ban-client status 2>/dev/null`;
if ($jail_status) {
    print "   fail2ban-client status output:\n";
    print "   " . join("\n   ", split(/\n/, $jail_status)) . "\n";
} else {
    print "   fail2ban-client status: No output or command failed\n";
}

# EVIDENCE 3: Raw firewall rules
print "\n3. RAW FIREWALL RULES:\n";
my $raw_rules = `firewall-cmd --list-rich-rules 2>/dev/null`;
my @rule_lines = split(/\n/, $raw_rules);
my $total_rules = scalar(@rule_lines);
print "   Total rules from firewall-cmd: $total_rules\n";

# Show first 5 rules for pattern analysis
print "   First 5 rules (for pattern analysis):\n";
for my $i (0..4) {
    last if $i >= @rule_lines;
    print "   [$i]: $rule_lines[$i]\n";
}

# EVIDENCE 4: Module rule retrieval
print "\n4. MODULE RULE RETRIEVAL:\n";
my @module_rules = list_all_rich_rules();
my $module_count = scalar(@module_rules);
print "   Module retrieved rules: $module_count\n";

if ($module_count != $total_rules) {
    print "   WARNING: Module count ($module_count) != firewall-cmd count ($total_rules)\n";
}

# EVIDENCE 5: Categorization testing on actual rules
print "\n5. CATEGORIZATION TESTING ON ACTUAL RULES:\n";
my $admin_count = 0;
my $fail2ban_count = 0;
my $unknown_count = 0;

# Test categorization on first 10 actual rules
print "   Testing categorization on first 10 actual rules:\n";
for my $i (0..9) {
    last if $i >= @rule_lines;
    my $rule = $rule_lines[$i];
    next if !$rule || $rule !~ /\S/;
    
    my $category = categorize_rich_rule($rule);
    print "   [$i] Category: $category\n";
    print "   [$i] Rule: $rule\n";
    
    if ($category eq 'admin') { $admin_count++; }
    elsif ($category eq 'fail2ban') { $fail2ban_count++; }
    else { $unknown_count++; }
}

print "\n6. CATEGORIZATION SUMMARY (first 10 rules):\n";
print "   admin: $admin_count\n";
print "   fail2ban: $fail2ban_count\n";
print "   unknown: $unknown_count\n";

# EVIDENCE 6: Pattern matching tests
print "\n7. PATTERN MATCHING TESTS:\n";
print "   Testing specific patterns against actual rules...\n";

my @fail2ban_matches = ();
for my $rule (@rule_lines) {
    next if !$rule || $rule !~ /\S/;
    
    # Test each fail2ban pattern
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        push @fail2ban_matches, "Pattern 1 (email): $rule";
    }
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*(?:ssh|port port="22").*(?:reject|drop)/i) {
        push @fail2ban_matches, "Pattern 2 (ssh): $rule";
    }
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        push @fail2ban_matches, "Pattern 4 (icmp): $rule";
    }
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*(?:reject|drop)/i && $rule =~ /source address="[\d.]+\/32"/) {
        push @fail2ban_matches, "Pattern 5 (single IP): $rule";
    }
}

print "   fail2ban pattern matches found: " . scalar(@fail2ban_matches) . "\n";
if (@fail2ban_matches) {
    print "   First few matches:\n";
    for my $i (0..2) {
        last if $i >= @fail2ban_matches;
        print "   $fail2ban_matches[$i]\n";
    }
}

# EVIDENCE 8: Zone analysis
print "\n8. ZONE ANALYSIS:\n";
my @zones = list_firewalld_zones();
print "   Available zones: " . join(", ", @zones) . "\n";

foreach my $zone (@zones) {
    my $zone_output = `firewall-cmd --zone=$zone --list-rich-rules 2>/dev/null`;
    my $zone_count = scalar(split(/\n/, $zone_output));
    print "   Zone $zone: $zone_count rules\n";
}

print "\n=== EVIDENCE SUMMARY ===\n";
print "fail2ban service: $f2b_status\n";
print "Total firewall rules: $total_rules\n";
print "Module retrieved rules: $module_count\n";
print "fail2ban pattern matches: " . scalar(@fail2ban_matches) . "\n";
print "Categorization results (first 10): admin=$admin_count, fail2ban=$fail2ban_count, unknown=$unknown_count\n";

if ($fail2ban_count == 0 && scalar(@fail2ban_matches) > 0) {
    print "\nCRITICAL FINDING: Patterns match rules but categorization returns 0 fail2ban\n";
    print "This indicates a bug in the categorize_rich_rule function\n";
}

if (scalar(@fail2ban_matches) == 0) {
    print "\nCRITICAL FINDING: No rules match fail2ban patterns\n";
    print "Either fail2ban rules don't exist or patterns are wrong\n";
}

print "\nTest complete - evidence gathered, no assumptions made.\n";