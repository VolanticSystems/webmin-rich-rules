#!/usr/bin/perl
# Simple test - just run the pattern test that already works

use strict;
use warnings;

print "=== Simple Test - Just Test The Damn Patterns ===\n\n";

# Get rules the simple way
my $rules_output = `/usr/bin/firewall-cmd --list-rich-rules 2>/dev/null`;
my @rules = split(/\n/, $rules_output);

print "Retrieved " . scalar(@rules) . " rules from firewall-cmd\n\n";

# Test the patterns that we know work
my $fail2ban_count = 0;

foreach my $rule (@rules) {
    next unless $rule =~ /\S/;
    
    # Same patterns that found 187 matches in standalone test
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i ||
        $rule =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        $fail2ban_count++;
        print "FAIL2BAN: $rule\n";
    }
}

print "\n=== RESULTS ===\n";
print "Total rules: " . scalar(@rules) . "\n";
print "fail2ban rules found: $fail2ban_count\n\n";

if ($fail2ban_count > 0) {
    print "✅ PATTERNS WORK - fail2ban rules detected\n";
    print "The issue is in the module's categorize_rich_rule() function\n";
} else {
    print "❌ NO FAIL2BAN RULES FOUND\n";
    print "Either no fail2ban rules exist or patterns are wrong\n";
}

print "\nThis is the simplest possible test.\n";