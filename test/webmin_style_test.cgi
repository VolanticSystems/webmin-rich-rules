#!/usr/bin/perl
# Webmin Style Test - Following exact pattern from working list_rules.cgi
# This tests categorization in the webmin environment

use strict;
use warnings;
no warnings 'redefine';
no warnings 'uninitialized';

# Check if we can load the library (try multiple locations)
my $lib_loaded = 0;
if (-f "../firewalld-rich-lib.pl") {
    require '../firewalld-rich-lib.pl';
    $lib_loaded = 1;
} elsif (-f "./firewalld-rich-lib.pl") {
    require './firewalld-rich-lib.pl';
    $lib_loaded = 1;
} elsif (-f "firewalld-rich-lib.pl") {
    require 'firewalld-rich-lib.pl';
    $lib_loaded = 1;
}

if (!$lib_loaded) {
    print "Content-type: text/plain\n\n";
    print "ERROR: Cannot find firewalld-rich-lib.pl\n";
    print "Current directory: " . `pwd`;
    print "Tried locations:\n";
    print "  ../firewalld-rich-lib.pl\n";
    print "  ./firewalld-rich-lib.pl\n";
    print "  firewalld-rich-lib.pl\n";
    print "Files in current directory:\n";
    print `ls -la`;
    exit 1;
}

our (%in, %text, %config);

# Initialize webmin environment (like working script does)
&ReadParse() if defined(&ReadParse);

print "Content-type: text/html\n\n";
print "<html><head><title>Webmin Style Categorization Test</title></head><body>\n";
print "<h2>Webmin Style Categorization Test</h2>\n";
print "<pre>\n";

print "=== Testing categorization function in webmin environment ===\n\n";

# Get firewall command from config (like working script does)
my $firewall_cmd = $config{'firewall_cmd'} || '/usr/bin/firewall-cmd';
print "Using firewall command: $firewall_cmd\n\n";

# Get rich rules using webmin method (like working script)
print "1. GETTING RICH RULES (webmin method):\n";
my $rcmd = "$firewall_cmd --list-rich-rules";
print "Command: $rcmd\n";

my @all_rules = ();
my $fh = 'rules';
if (&open_execute_command($fh, "$rcmd 2>&1 </dev/null", 1)) {
    while(<$fh>) {
        chomp;
        if ($_ =~ /\S+/) {
            push @all_rules, $_;
        }
    }
    close($fh);
    print "Retrieved " . scalar(@all_rules) . " rules via webmin method\n";
} else {
    print "ERROR: Could not execute firewall command\n";
}

# Test first 10 rules with categorization function
print "\n2. TESTING CATEGORIZATION FUNCTION:\n";
my $fail2ban_count = 0;
my $admin_count = 0;
my $unknown_count = 0;

for my $i (0..9) {
    last if $i >= @all_rules;
    my $rule = $all_rules[$i];
    
    print "Rule [$i]: " . substr($rule, 0, 60) . "...\n";
    
    # Test if categorize_rich_rule function exists
    if (defined(&categorize_rich_rule)) {
        my $result = categorize_rich_rule($rule);
        print "   Function result: '$result'\n";
        
        if ($result eq 'fail2ban') { $fail2ban_count++; }
        elsif ($result eq 'admin') { $admin_count++; }
        else { $unknown_count++; }
    } else {
        print "   ERROR: categorize_rich_rule function not defined\n";
    }
    
    # Manual pattern test for comparison
    my $manual_result = 'unknown';
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        $manual_result = 'fail2ban';
    } elsif ($rule =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        $manual_result = 'fail2ban';
    } elsif ($rule =~ /source address="[\d.]+\/(?:8|16|20|24)".*accept/i) {
        $manual_result = 'admin';
    }
    print "   Manual pattern: '$manual_result'\n\n";
}

print "3. RESULTS SUMMARY:\n";
print "Total rules retrieved: " . scalar(@all_rules) . "\n";
print "Rules tested: " . ($#all_rules >= 9 ? 10 : scalar(@all_rules)) . "\n";
print "Function detected fail2ban: $fail2ban_count\n";
print "Function detected admin: $admin_count\n";
print "Function detected unknown: $unknown_count\n\n";

print "4. FUNCTION EXISTENCE CHECK:\n";
if (defined(&categorize_rich_rule)) {
    print "✅ categorize_rich_rule function exists\n";
} else {
    print "❌ categorize_rich_rule function missing\n";
}

if (defined(&list_all_rich_rules)) {
    print "✅ list_all_rich_rules function exists\n";
} else {
    print "❌ list_all_rich_rules function missing\n";
}

print "\n5. TESTING MODULE'S list_all_rich_rules FUNCTION:\n";
if (defined(&list_all_rich_rules)) {
    my @module_rules = list_all_rich_rules();
    print "Module function returned " . scalar(@module_rules) . " rules\n";
    
    if (@module_rules) {
        print "Testing categorization on module-retrieved rules:\n";
        my $mod_fail2ban = 0;
        
        for my $i (0..4) {  # Test first 5
            last if $i >= @module_rules;
            my $rule_data = $module_rules[$i];
            my $rule_text = ref($rule_data) eq 'HASH' ? $rule_data->{'text'} : $rule_data;
            
            if ($rule_text) {
                my $result = categorize_rich_rule($rule_text);
                print "   Rule [$i]: $result -> " . substr($rule_text, 0, 50) . "...\n";
                $mod_fail2ban++ if $result eq 'fail2ban';
            }
        }
        print "Module rules categorized as fail2ban: $mod_fail2ban\n";
    }
} else {
    print "Cannot test module function - not defined\n";
}

print "\n=== TEST COMPLETE ===\n";
print "This test shows if categorization works in the webmin environment\n";
print "Expected: Should detect fail2ban rules if function works correctly\n";

print "</pre>\n";
print "</body></html>\n";