#!/usr/bin/perl
# Test what list_all_rich_rules actually returns

use strict;
use warnings;

print "=== Testing Rule Retrieval ===\n\n";

# Get rules the simple way we know works
my $rules_output = `/usr/bin/firewall-cmd --list-rich-rules 2>/dev/null`;
my @cmd_rules = split(/\n/, $rules_output);
my $cmd_count = scalar(@cmd_rules);

print "1. DIRECT COMMAND RESULTS:\n";
print "   firewall-cmd returned: $cmd_count rules\n";
print "   First rule: " . ($cmd_rules[0] || "(none)") . "\n\n";

# Now simulate what the module does
print "2. SIMULATING MODULE LOGIC:\n";

# This is what the module code does:
print "   Code: scalar(grep { categorize_rich_rule(\$_->{'text'}) eq 'fail2ban' } &list_all_rich_rules())\n\n";

# Since we can't load the actual module, let's simulate it
my @simulated_rules = ();
foreach my $rule_text (@cmd_rules) {
    next unless $rule_text =~ /\S/;
    push @simulated_rules, {
        'index' => scalar(@simulated_rules),
        'zone' => 'public',
        'text' => $rule_text,
        'parsed' => undef
    };
}

print "3. SIMULATED MODULE RULE STRUCTURE:\n";
print "   Simulated rules created: " . scalar(@simulated_rules) . "\n";
print "   First rule structure:\n";
if (@simulated_rules) {
    my $first = $simulated_rules[0];
    print "     index: " . ($first->{'index'} || 'undef') . "\n";
    print "     zone: " . ($first->{'zone'} || 'undef') . "\n";
    print "     text: " . (substr($first->{'text'} || 'undef', 0, 50)) . "...\n";
}

# Copy the categorize function
sub categorize_rich_rule {
    my ($rule_text) = @_;
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        return 'fail2ban';
    }
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        return 'fail2ban';
    }
    if ($rule_text =~ /accept/i) {
        return 'admin';
    }
    return 'unknown';
}

print "\n4. TESTING CATEGORIZATION ON SIMULATED RULES:\n";
my $fail2ban_count = scalar(grep { categorize_rich_rule($_->{'text'}) eq 'fail2ban' } @simulated_rules);
my $admin_count = scalar(grep { categorize_rich_rule($_->{'text'}) eq 'admin' } @simulated_rules);
my $unknown_count = scalar(grep { categorize_rich_rule($_->{'text'}) eq 'unknown' } @simulated_rules);

print "   fail2ban rules found: $fail2ban_count\n";
print "   admin rules found: $admin_count\n";
print "   unknown rules found: $unknown_count\n";
print "   Total categorized: " . ($fail2ban_count + $admin_count + $unknown_count) . "\n\n";

print "5. DIAGNOSIS:\n";
if ($fail2ban_count > 0) {
    print "   ✅ Categorization works on properly structured rules\n";
    print "   The bug must be that list_all_rich_rules() returns 0 rules\n";
    print "   OR returns rules in wrong format\n";
} else {
    print "   ❌ Even with proper structure, categorization fails\n";
    print "   This shouldn't happen since direct function test worked\n";
}

print "\nConclusion: If categorization works here but module shows 0,\n";
print "then list_all_rich_rules() is returning 0 rules or wrong format.\n";