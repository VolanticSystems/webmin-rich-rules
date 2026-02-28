#!/usr/bin/perl
# Test script for rule categorization logic
# This validates that fail2ban rules are correctly identified

use strict;
use warnings;

# Add current directory to include path for library
BEGIN { 
    use File::Basename;
    my $lib_dir = dirname(__FILE__);
    unshift @INC, $lib_dir;
}

require 'firewalld-rich-lib.pl';

# Test cases: real fail2ban rules from production systems
my @test_rules = (
    # Real fail2ban rules that should be detected
    {
        rule => 'rule family="ipv4" source address="81.30.107.130" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
        expected => 'fail2ban',
        description => 'fail2ban IMAP rule with reject'
    },
    {
        rule => 'rule family="ipv4" source address="81.30.107.121" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
        expected => 'fail2ban', 
        description => 'fail2ban SMTP rule with reject'
    },
    {
        rule => 'rule family="ipv4" source address="192.168.1.100/32" port port="22" protocol="tcp" reject',
        expected => 'fail2ban',
        description => 'fail2ban SSH rule with CIDR'
    },
    {
        rule => 'rule family="ipv4" source address="10.0.0.50" service name="ssh" reject',
        expected => 'fail2ban',
        description => 'fail2ban SSH service rule'
    },
    
    # Admin rules that should NOT be categorized as fail2ban
    {
        rule => 'rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" accept',
        expected => 'admin',
        description => 'Admin SSH allow rule for network'
    },
    {
        rule => 'rule family="ipv4" source address="0.0.0.0/0" port port="80" protocol="tcp" accept',
        expected => 'admin', 
        description => 'Admin HTTP allow rule for all'
    },
    
    # Unknown rules
    {
        rule => 'rule family="ipv4" masquerade',
        expected => 'unknown',
        description => 'Masquerade rule'
    }
);

print "=== FirewallD Rich Rules Categorization Test ===\n\n";

my $passed = 0;
my $failed = 0;

foreach my $test (@test_rules) {
    my $result = categorize_rich_rule($test->{rule});
    
    print "Test: $test->{description}\n";
    print "Rule: $test->{rule}\n";
    print "Expected: $test->{expected}\n";
    print "Got: $result\n";
    
    if ($result eq $test->{expected}) {
        print "✅ PASS\n";
        $passed++;
    } else {
        print "❌ FAIL\n";
        $failed++;
    }
    print "\n";
}

print "=== Test Summary ===\n";
print "Passed: $passed\n";
print "Failed: $failed\n";
print "Total: " . ($passed + $failed) . "\n";

if ($failed > 0) {
    print "\n❌ CATEGORIZATION LOGIC HAS ISSUES\n";
    exit 1;
} else {
    print "\n✅ ALL TESTS PASSED\n";
    exit 0;
}