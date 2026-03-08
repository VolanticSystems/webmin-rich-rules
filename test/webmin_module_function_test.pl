#!/usr/bin/perl
# Webmin Module Function Test
# This should be run from the actual webmin module directory: /usr/share/webmin/firewalld-rich/
# Tests the categorize_rich_rule() function that's broken in the module

use strict;
use warnings;

print "=== Webmin Module Function Test ===\n";
print "This test should be run from: /usr/share/webmin/firewalld-rich/\n";
print "Current directory: " . `pwd`;
print "\n";

# Check if we're in the right location
unless (-f "firewalld-rich-lib.pl") {
    print "❌ ERROR: firewalld-rich-lib.pl not found in current directory\n";
    print "Please run this test from the webmin module directory:\n";
    print "cd /usr/share/webmin/firewalld-rich/\n";
    print "perl test/webmin_module_function_test.pl\n";
    exit 1;
}

# Load the module library
require './firewalld-rich-lib.pl';

print "✅ Successfully loaded firewalld-rich-lib.pl\n\n";

# Example rules that should be categorized as fail2ban
# RFC 5737 test addresses used throughout
my @test_rules = (
    'rule family="ipv4" source address="198.51.100.10" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.11" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.12" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.13" port port="pop3s" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.14" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.15" port port="465" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.16" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    
    # Admin rules that should NOT be categorized as fail2ban
    'rule family="ipv4" source address="192.0.2.0/20" port port="22" protocol="tcp" accept',
    'rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" accept',
    
    # Network blocks
    'rule family="ipv4" source address="198.51.100.0/24" drop',
    'rule family="ipv4" source address="198.51.100.128/24" drop'
);

print "1. TESTING MODULE'S categorize_rich_rule() FUNCTION:\n";
my $fail2ban_detected = 0;
my $admin_detected = 0;
my $unknown_detected = 0;
my $total_tested = 0;

foreach my $rule (@test_rules) {
    print "   Testing: " . substr($rule, 0, 60) . "...\n";
    
    my $result = categorize_rich_rule($rule);
    print "   Module result: '$result'\n";
    
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

print "2. MODULE FUNCTION RESULTS:\n";
print "   Total rules tested: $total_tested\n";
print "   fail2ban detected by module: $fail2ban_detected\n";
print "   admin detected by module: $admin_detected\n";
print "   unknown detected by module: $unknown_detected\n\n";

# Test the same patterns manually (like the standalone test did)
print "3. MANUAL PATTERN TESTING (for comparison):\n";
my $manual_matches = 0;

foreach my $rule (@test_rules) {
    # Test the same patterns that found 187 matches in standalone test
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        $manual_matches++;
    } elsif ($rule =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        $manual_matches++;
    }
}

print "   Manual pattern matches: $manual_matches\n\n";

# The critical comparison
print "4. CRITICAL COMPARISON:\n";
print "   Module function detected fail2ban: $fail2ban_detected\n";
print "   Manual patterns found matches: $manual_matches\n";
print "   Standalone test found: 187 matches from same patterns\n\n";

if ($fail2ban_detected == 0 && $manual_matches > 0) {
    print "❌ CONFIRMED BUG: Module function returns 0 but patterns work\n";
    print "   This proves the categorize_rich_rule() function in the module is broken\n";
    print "   The patterns are correct, but something in the function prevents them from working\n";
} elsif ($fail2ban_detected > 0) {
    print "✅ Function appears to work - detected $fail2ban_detected fail2ban rules\n";
    print "   This would contradict the user's report of 0 detection\n";
} else {
    print "❓ Both function and manual patterns return 0 - unexpected\n";
}

print "\n5. FUNCTION EXISTENCE CHECK:\n";
if (defined &categorize_rich_rule) {
    print "   ✅ categorize_rich_rule function exists in module\n";
} else {
    print "   ❌ categorize_rich_rule function missing from module\n";
}

print "\n=== INSTRUCTIONS FOR RUNNING THIS TEST ===\n";
print "1. Copy this file to the server\n";
print "2. cd /usr/share/webmin/firewalld-rich/\n";
print "3. perl test/webmin_module_function_test.pl\n";
print "\nThis will test the actual module function that's showing 0 fail2ban rules\n";
print "Expected: Function returns 0, manual patterns find matches = CONFIRMED BUG\n";