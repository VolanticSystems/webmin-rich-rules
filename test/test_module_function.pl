#!/usr/bin/perl
# Test the actual module function directly

use strict;
use warnings;

# Copy the exact categorize_rich_rule function from the module
sub categorize_rich_rule
{
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
    
    # Pattern 5: Single IP with any reject/drop (generic fail2ban pattern)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*(?:reject|drop)/i && $rule_text !~ /\/(?:[0-9]|1[0-9]|2[0-9]|3[01])"/) {
        return 'fail2ban';
    }
    
    # Admin patterns
    if ($rule_text =~ /source address="[\d.]+\/(?:[0-9]|1[0-9]|2[0-9]|3[01])"/ && $rule_text !~ /\/32/) {
        return 'admin';
    }
    
    if ($rule_text =~ /accept/i) {
        return 'admin';
    }
    
    if ($rule_text =~ /masquerade/i) {
        return 'admin';
    }
    
    if ($rule_text =~ /forward-port/i) {
        return 'admin';
    }
    
    if ($rule_text =~ /port="(?:2324|3306|20000|10000)"/i) {
        return 'admin';
    }
    
    return 'unknown';
}

print "=== Testing Module Function Directly ===\n\n";

# Test with the exact same rule that works in simple test
my $test_rule = 'rule family="ipv4" source address="81.30.107.130" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"';

print "Test rule: $test_rule\n";
my $result = categorize_rich_rule($test_rule);
print "Function result: '$result'\n\n";

if ($result eq 'fail2ban') {
    print "✅ MODULE FUNCTION WORKS - returns 'fail2ban'\n";
    print "The bug must be elsewhere in the module\n";
} else {
    print "❌ MODULE FUNCTION BROKEN - returns '$result' instead of 'fail2ban'\n";
    print "This is the source of the bug\n";
}

# Test a few more
my @test_rules = (
    'rule family="ipv4" source address="81.30.107.121" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="62.194.144.0/20" port port="2324" protocol="tcp" accept',
    'rule family="ipv4" source address="141.98.11.0/24" drop'
);

print "\nTesting additional rules:\n";
foreach my $rule (@test_rules) {
    my $result = categorize_rich_rule($rule);
    print "Result: $result -> " . substr($rule, 0, 60) . "...\n";
}

print "\nIf these show correct results, the function itself works.\n";