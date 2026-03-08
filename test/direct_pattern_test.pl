#!/usr/bin/perl
# Direct Pattern Test - No dependencies, no file moves, just test the patterns
# This works from the test directory without any setup

use strict;
use warnings;

print "=== Direct Pattern Test ===\n";
print "Testing the exact categorization patterns without module dependencies\n\n";

# Example fail2ban-style rules (RFC 5737 test addresses)
my @fail2ban_rules = (
    'rule family="ipv4" source address="198.51.100.10" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.11" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.12" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.13" port port="pop3s" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.14" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.15" port port="465" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.16" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"'
);

my @admin_rules = (
    'rule family="ipv4" source address="192.0.2.0/20" port port="22" protocol="tcp" accept',
    'rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" accept',
    'rule family="ipv4" source address="198.51.100.0/24" drop',
    'rule family="ipv4" source address="198.51.100.128/24" drop'
);

# Copy the exact categorization logic from the module
sub test_categorize_rule {
    my ($rule_text) = @_;
    
    # Pattern 1: Single IP with email services and reject (most common fail2ban pattern)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        return 'fail2ban';
    }
    
    # Pattern 2: Single IP with SSH and reject/drop (classic fail2ban SSH protection)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*(?:ssh|port port="22").*(?:reject|drop)/i) {
        return 'fail2ban';
    }
    
    # Pattern 3: Single IP with HTTP services and reject/drop (web protection)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*(?:http|port port="80"|port port="443").*(?:reject|drop)/i) {
        return 'fail2ban';
    }
    
    # Pattern 4: Single IP with icmp-port-unreachable (specific fail2ban signature from production)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        return 'fail2ban';
    }
    
    # Pattern 5: Single IP (/32) with reject/drop (general fail2ban pattern)
    if ($rule_text =~ /source address="[\d.]+\/32".*(?:reject|drop)/i) {
        return 'fail2ban';
    }
    
    # Admin patterns: Networks (not single IPs) or accepts
    if ($rule_text =~ /source address="[\d.]+\/(?:8|16|20|24)".*accept/i) {
        return 'admin';
    }
    
    if ($rule_text =~ /source address="[\d.]+\/(?:8|16|20|24)".*drop/i) {
        return 'admin';
    }
    
    return 'unknown';
}

print "1. TESTING FAIL2BAN RULES:\n";
my $fail2ban_detected = 0;
foreach my $rule (@fail2ban_rules) {
    my $result = test_categorize_rule($rule);
    print "   Rule: " . substr($rule, 0, 70) . "...\n";
    print "   Result: $result\n";
    if ($result eq 'fail2ban') {
        $fail2ban_detected++;
        print "   ✅ CORRECTLY detected as fail2ban\n";
    } else {
        print "   ❌ FAILED - should be fail2ban, got $result\n";
    }
    print "\n";
}

print "2. TESTING ADMIN RULES:\n";
my $admin_detected = 0;
foreach my $rule (@admin_rules) {
    my $result = test_categorize_rule($rule);
    print "   Rule: " . substr($rule, 0, 70) . "...\n";
    print "   Result: $result\n";
    if ($result eq 'admin') {
        $admin_detected++;
        print "   ✅ CORRECTLY detected as admin\n";
    } else {
        print "   ⚠️ Got $result (might be acceptable)\n";
    }
    print "\n";
}

print "3. SUMMARY:\n";
print "   fail2ban rules tested: " . scalar(@fail2ban_rules) . "\n";
print "   fail2ban correctly detected: $fail2ban_detected\n";
print "   admin rules tested: " . scalar(@admin_rules) . "\n";
print "   admin correctly detected: $admin_detected\n\n";

print "4. ANALYSIS:\n";
if ($fail2ban_detected == scalar(@fail2ban_rules)) {
    print "   ✅ PATTERNS WORK PERFECTLY\n";
    print "   All fail2ban rules correctly detected\n";
    print "   This proves the categorization logic is correct\n";
    print "   The bug must be in how the module calls this function\n";
} elsif ($fail2ban_detected > 0) {
    print "   ⚠️ PATTERNS PARTIALLY WORK\n";
    print "   Some fail2ban rules detected, but not all\n";
    print "   Patterns may need refinement\n";
} else {
    print "   ❌ PATTERNS COMPLETELY BROKEN\n";
    print "   No fail2ban rules detected\n";
    print "   Categorization logic is fundamentally wrong\n";
}

print "\n5. CONCLUSION:\n";
print "If patterns work here but module shows 0 fail2ban rules:\n";
print "- The categorization logic is correct\n";
print "- The bug is in the module's implementation\n";
print "- Something prevents the function from being called properly\n";
print "- Or the function exists but has different code than this test\n\n";

print "This test should work without any file moves or webmin setup.\n";