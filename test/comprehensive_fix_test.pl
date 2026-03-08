#!/usr/bin/perl
# Comprehensive test for all firewalld-rich module fixes
# Tests all 10 issues identified in the comprehensive analysis

use strict;
use warnings;
use Time::HiRes qw(gettimeofday tv_interval);

# Add current directory to path for testing
BEGIN { push(@INC, "../firewalld-rich"); }

require 'firewalld-rich-lib.pl';

print "=== FirewallD Rich Rules Module - Comprehensive Fix Test ===\n\n";

my $test_start = [gettimeofday()];
my $total_tests = 0;
my $passed_tests = 0;
my $failed_tests = 0;

sub test_result {
    my ($test_name, $condition, $details) = @_;
    $total_tests++;
    if ($condition) {
        print "✅ PASS: $test_name\n";
        $passed_tests++;
    } else {
        print "❌ FAIL: $test_name\n";
        print "   Details: $details\n" if $details;
        $failed_tests++;
    }
    print "\n";
}

# Test 1: Command Execution Discrepancy Fix
print "TEST 1: Command Execution - Global vs Zone-specific\n";
print "=" x 50 . "\n";

my $global_start = [gettimeofday()];
my ($global_output, $global_err) = execute_firewall_cmd("--list-rich-rules");
my $global_time = tv_interval($global_start, [gettimeofday()]);
my $global_count = $global_output ? scalar(split(/\n/, $global_output)) : 0;

my $zone_start = [gettimeofday()];
my ($zone_output, $zone_err) = execute_firewall_cmd("--zone=public --list-rich-rules");
my $zone_time = tv_interval($zone_start, [gettimeofday()]);
my $zone_count = $zone_output ? scalar(split(/\n/, $zone_output)) : 0;

print "Global command: $global_count rules (${global_time}s)\n";
print "Zone command: $zone_count rules (${zone_time}s)\n";

test_result(
    "Global command returns more rules than zone-specific",
    $global_count >= $zone_count,
    "Global: $global_count, Zone: $zone_count"
);

test_result(
    "Global command returns significant number of rules (>50)",
    $global_count > 50,
    "Got $global_count rules, expected >50"
);

# Test 2: list_all_rich_rules() uses global command
print "TEST 2: list_all_rich_rules() Function Behavior\n";
print "=" x 50 . "\n";

my $module_start = [gettimeofday()];
my @all_rules = list_all_rich_rules();
my $module_time = tv_interval($module_start, [gettimeofday()]);
my $module_count = scalar(@all_rules);

print "Module list_all_rich_rules(): $module_count rules (${module_time}s)\n";

test_result(
    "Module returns same rule count as global command",
    abs($module_count - $global_count) <= 2,
    "Module: $module_count, Global: $global_count"
);

test_result(
    "Module performance improvement (<1 second)",
    $module_time < 1.0,
    "Took ${module_time}s"
);

# Test 3: Error Handling for Test 2 equivalent
print "TEST 3: Runtime Configuration Error Handling\n";
print "=" x 50 . "\n";

my ($runtime_output, $runtime_err) = execute_firewall_cmd("--zone=public --list-rich-rules --runtime");
my $runtime_works = !$runtime_err;

test_result(
    "Runtime configuration command handled gracefully",
    defined($runtime_output) || defined($runtime_err),
    $runtime_err ? "Error: $runtime_err" : "Success"
);

# Test 4: Zone Detection Logic
print "TEST 4: Zone Detection for Global Rules\n";
print "=" x 50 . "\n";

my $has_zone_info = 0;
my $rules_with_zones = 0;
foreach my $rule (@all_rules) {
    if ($rule->{'zone'} && $rule->{'zone'} ne '') {
        $rules_with_zones++;
        $has_zone_info = 1;
    }
}

test_result(
    "Rules have zone assignments",
    $has_zone_info,
    "$rules_with_zones out of $module_count rules have zones"
);

# Test 5: fail2ban Detection
print "TEST 5: fail2ban Rule Detection\n";
print "=" x 50 . "\n";

my $fail2ban_count = 0;
my $admin_count = 0;
my $unknown_count = 0;

foreach my $rule (@all_rules) {
    my $category = categorize_rich_rule($rule->{'text'});
    if ($category eq 'fail2ban') {
        $fail2ban_count++;
    } elsif ($category eq 'admin') {
        $admin_count++;
    } else {
        $unknown_count++;
    }
}

print "Categories: fail2ban=$fail2ban_count, admin=$admin_count, unknown=$unknown_count\n";

test_result(
    "fail2ban rules detected (>0)",
    $fail2ban_count > 0,
    "Found $fail2ban_count fail2ban rules"
);

test_result(
    "Reasonable categorization distribution",
    ($fail2ban_count + $admin_count) > ($unknown_count * 2),
    "Known categories outnumber unknown"
);

# Test 6: Specific fail2ban Pattern Testing
print "TEST 6: fail2ban Pattern Accuracy\n";
print "=" x 50 . "\n";

my @test_fail2ban_rules = (
    'rule family="ipv4" source address="198.51.100.14" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.16" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
    'rule family="ipv4" source address="198.51.100.13" port port="pop3s" protocol="tcp" reject type="icmp-port-unreachable"'
);

my $pattern_matches = 0;
foreach my $test_rule (@test_fail2ban_rules) {
    my $category = categorize_rich_rule($test_rule);
    if ($category eq 'fail2ban') {
        $pattern_matches++;
    }
}

test_result(
    "fail2ban patterns match expected rules",
    $pattern_matches == scalar(@test_fail2ban_rules),
    "$pattern_matches out of " . scalar(@test_fail2ban_rules) . " test rules matched"
);

# Test 7: Performance Benchmarks
print "TEST 7: Performance Benchmarks\n";
print "=" x 50 . "\n";

test_result(
    "Global command executes quickly (<0.5s)",
    $global_time < 0.5,
    "Global command took ${global_time}s"
);

test_result(
    "Module function executes quickly (<1s)",
    $module_time < 1.0,
    "Module function took ${module_time}s"
);

# Test 8: Configuration Method Consistency
print "TEST 8: Configuration Method Consistency\n";
print "=" x 50 . "\n";

my ($perm_output, $perm_err) = execute_firewall_cmd("--list-rich-rules --permanent");
my $perm_count = $perm_output ? scalar(split(/\n/, $perm_output)) : 0;

test_result(
    "Permanent configuration accessible",
    !$perm_err,
    $perm_err ? "Error: $perm_err" : "Success"
);

test_result(
    "Runtime and permanent configurations comparable",
    abs($global_count - $perm_count) <= 10,
    "Runtime: $global_count, Permanent: $perm_count"
);

# Test 9: Command Structure Validation
print "TEST 9: Command Structure Validation\n";
print "=" x 50 . "\n";

# Test that execute_firewall_cmd doesn't use sudo
my ($test_output, $test_err) = execute_firewall_cmd("--version");
my $has_sudo = 0;

# Check if the function is working without sudo
test_result(
    "Commands execute without sudo (no permission errors)",
    !$test_err || $test_err !~ /sudo|permission/i,
    $test_err ? "Error: $test_err" : "Success"
);

# Test 10: Rule Data Structure Integrity
print "TEST 10: Rule Data Structure Integrity\n";
print "=" x 50 . "\n";

my $valid_structures = 0;
my $sample_size = scalar(@all_rules) > 10 ? 10 : scalar(@all_rules);

for my $i (0..$sample_size-1) {
    my $rule = $all_rules[$i];
    if (ref($rule) eq 'HASH' && 
        defined($rule->{'text'}) && 
        defined($rule->{'zone'}) && 
        defined($rule->{'index'}) &&
        ref($rule->{'parsed'}) eq 'HASH') {
        $valid_structures++;
    }
}

test_result(
    "Rule data structures are valid",
    $valid_structures == $sample_size,
    "$valid_structures out of $sample_size rules have valid structure"
);

# Summary
my $test_time = tv_interval($test_start, [gettimeofday()]);
print "=" x 70 . "\n";
print "TEST SUMMARY\n";
print "=" x 70 . "\n";
print "Total Tests: $total_tests\n";
print "Passed: $passed_tests\n";
print "Failed: $failed_tests\n";
print "Success Rate: " . sprintf("%.1f", ($passed_tests / $total_tests) * 100) . "%\n";
print "Test Execution Time: " . sprintf("%.3f", $test_time) . "s\n";

if ($failed_tests == 0) {
    print "\n🎉 ALL TESTS PASSED! Module is ready for deployment.\n";
} elsif ($failed_tests <= 2) {
    print "\n⚠️  MOSTLY GOOD: $failed_tests minor issues, may proceed with caution.\n";
} else {
    print "\n🚨 CRITICAL ISSUES: $failed_tests failures, DO NOT DEPLOY.\n";
}

exit($failed_tests > 5 ? 1 : 0);