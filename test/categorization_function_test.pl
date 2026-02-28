#!/usr/bin/perl
# Direct Categorization Function Test
# Tests the actual broken categorize_rich_rule() function with real production rules

use strict;
use warnings;

# Add parent directory to include path for library
BEGIN { 
    use File::Basename;
    my $lib_dir = dirname(dirname(__FILE__));
    unshift @INC, $lib_dir;
}

require 'firewalld-rich-lib.pl';

print "=== Direct Categorization Function Test ===\n";
print "Testing the categorize_rich_rule() function that returns 0 instead of detecting fail2ban\n\n";

# Real production rules that should be categorized as fail2ban
# These are the exact rules from the manual test that found 187 matches
my @test_rules = (
    'rule family="ipv4" source address="81.30.107.130" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="196.251.92.124" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="81.30.107.121" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="81.30.107.173" port port="pop3s" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="81.30.107.90" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="81.30.107.153" port port="465" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="66.63.187.118" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    
    # Admin rules that should NOT be categorized as fail2ban
    'rule family="ipv4" source address="62.194.144.0/20" port port="2324" protocol="tcp" accept',
    'rule family="ipv4" source address="165.22.196.252/24" port port="2324" protocol="tcp" accept',
    
    # Network blocks that might be admin rules
    'rule family="ipv4" source address="141.98.11.0/24" drop',
    'rule family="ipv4" source address="45.129.14.0/24" drop'
);

print "1. TESTING CATEGORIZATION FUNCTION DIRECTLY:\n";
my $fail2ban_detected = 0;
my $admin_detected = 0;
my $unknown_detected = 0;
my $total_tested = 0;

foreach my $rule (@test_rules) {
    print "   Testing rule: $rule\n";
    
    my $result = categorize_rich_rule($rule);
    print "   Result: '$result'\n";
    
    if ($result eq 'fail2ban') {
        $fail2ban_detected++;
        print "   ✅ Correctly detected as fail2ban\n";
    } elsif ($result eq 'admin') {
        $admin_detected++;
        print "   ✅ Detected as admin\n";
    } elsif ($result eq 'unknown') {
        $unknown_detected++;
        print "   ⚠️ Detected as unknown\n";
    } else {
        print "   ❌ Unexpected result: '$result'\n";
    }
    
    $total_tested++;
    print "\n";
}

print "2. CATEGORIZATION SUMMARY:\n";
print "   Total rules tested: $total_tested\n";
print "   fail2ban detected: $fail2ban_detected\n";
print "   admin detected: $admin_detected\n";
print "   unknown detected: $unknown_detected\n\n";

# Test specific patterns manually to see if they work
print "3. MANUAL PATTERN TESTING (same patterns as standalone test):\n";
my $pattern_matches = 0;

foreach my $rule (@test_rules) {
    my $matched = 0;
    
    # Test each pattern individually
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        print "   Pattern 1 match: $rule\n";
        $pattern_matches++;
        $matched = 1;
    }
    
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        if (!$matched) {  # Don't double count
            print "   Pattern 4 match: $rule\n";
            $pattern_matches++;
        }
    }
}

print "   Manual pattern matches: $pattern_matches\n\n";

# Compare function vs manual results
print "4. COMPARISON ANALYSIS:\n";
print "   Function detected fail2ban: $fail2ban_detected\n";
print "   Manual patterns found: $pattern_matches\n";

if ($fail2ban_detected == 0 && $pattern_matches > 0) {
    print "   ❌ CRITICAL BUG: Function returns 0 but patterns work manually\n";
    print "   This confirms the categorize_rich_rule() function is broken\n";
} elsif ($fail2ban_detected > 0 && $fail2ban_detected == $pattern_matches) {
    print "   ✅ Function works correctly - matches manual testing\n";
} elsif ($fail2ban_detected > 0 && $fail2ban_detected != $pattern_matches) {
    print "   ⚠️ Function works but results differ from manual testing\n";
} else {
    print "   ❓ Unexpected result combination\n";
}

print "\n5. DEBUGGING INFORMATION:\n";
print "   Testing if categorize_rich_rule function exists and is callable...\n";

# Test if function exists
if (defined &categorize_rich_rule) {
    print "   ✅ categorize_rich_rule function exists\n";
} else {
    print "   ❌ categorize_rich_rule function does not exist\n";
}

# Test with a simple known pattern
my $simple_test = 'rule family="ipv4" source address="1.2.3.4" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"';
print "   Testing simple rule: $simple_test\n";
my $simple_result = categorize_rich_rule($simple_test);
print "   Simple result: '$simple_result'\n";

print "\n=== TEST COMPLETE ===\n";
print "Expected: Several fail2ban detections from function (should match manual pattern testing)\n";
print "If function returns 0 fail2ban but manual patterns work, the function is broken\n";