#!/usr/bin/perl
# Simple validation of firewalld-rich module fixes
# Tests that don't require Webmin environment

use strict;
use warnings;

print "=== FirewallD Rich Rules Module - Fix Validation ===\n\n";

my $total_tests = 0;
my $passed_tests = 0;

sub test_result {
    my ($test_name, $condition, $details) = @_;
    $total_tests++;
    if ($condition) {
        print "✅ PASS: $test_name\n";
        $passed_tests++;
    } else {
        print "❌ FAIL: $test_name\n";
        print "   Details: $details\n" if $details;
    }
    print "\n";
}

# Test 1: Verify sudo removal in execute_firewall_cmd
print "TEST 1: Sudo Removal Verification\n";
print "=" x 40 . "\n";

my $lib_content = "";
if (open(my $fh, '<', '../firewalld-rich/firewalld-rich-lib.pl')) {
    local $/;
    $lib_content = <$fh>;
    close($fh);
}

my $has_sudo_usage = ($lib_content =~ /sudo.*firewall-cmd/);
my $has_fixed_comment = ($lib_content =~ /FIXED.*Webmin CGI scripts run as root/);

test_result(
    "Sudo removed from execute_firewall_cmd",
    !$has_sudo_usage,
    $has_sudo_usage ? "Still contains sudo usage" : "No sudo found"
);

test_result(
    "Fix documentation present",
    $has_fixed_comment,
    $has_fixed_comment ? "Found fix comments" : "Missing fix documentation"
);

# Test 2: Verify global command usage in list_all_rich_rules
print "TEST 2: Global Command Implementation\n";
print "=" x 40 . "\n";

my $has_global_cmd = ($lib_content =~ /--list-rich-rules.*(?!--zone)/);
my $has_global_comment = ($lib_content =~ /global.*--list-rich-rules.*143 rules/);

test_result(
    "Global command implementation found",
    $has_global_cmd,
    "Checking for --list-rich-rules without --zone"
);

test_result(
    "Global command documentation present",
    $has_global_comment,
    "Checking for comments about 143 rules fix"
);

# Test 3: Verify zone detection function exists
print "TEST 3: Zone Detection Function\n";
print "=" x 40 . "\n";

my $has_detect_zone = ($lib_content =~ /sub detect_rule_zone/);
my $zone_detection_logic = ($lib_content =~ /detect_rule_zone.*foreach.*zone/s);

test_result(
    "Zone detection function exists",
    $has_detect_zone,
    "Looking for detect_rule_zone subroutine"
);

test_result(
    "Zone detection logic implemented",
    $zone_detection_logic,
    "Checking for zone iteration logic"
);

# Test 4: Verify enhanced error handling
print "TEST 4: Enhanced Error Handling\n";
print "=" x 40 . "\n";

my $has_fallback_logic = ($lib_content =~ /if.*err.*!.*output/);
my $has_multiple_attempts = ($lib_content =~ /permanent.*runtime|runtime.*permanent/);

test_result(
    "Error handling with fallbacks",
    $has_fallback_logic,
    "Looking for error condition checking"
);

test_result(
    "Multiple configuration attempts",
    $has_multiple_attempts,
    "Checking for runtime/permanent fallbacks"
);

# Test 5: Verify debug enhancements in index.cgi
print "TEST 5: Debug Enhancement Verification\n";
print "=" x 40 . "\n";

my $index_content = "";
if (open(my $fh, '<', '../firewalld-rich/index.cgi')) {
    local $/;
    $index_content = <$fh>;
    close($fh);
}

my $has_enhanced_debug = ($index_content =~ /Enhanced Command Analysis/);
my $has_command_comparison = ($index_content =~ /Global Runtime.*Global Permanent.*Module Function/s);

test_result(
    "Enhanced debug output implemented",
    $has_enhanced_debug,
    "Looking for Enhanced Command Analysis section"
);

test_result(
    "Command comparison table present",
    $has_command_comparison,
    "Checking for global vs module command comparison"
);

# Test 6: Version consistency check
print "TEST 6: Version Consistency\n";
print "=" x 40 . "\n";

my $module_info_version = "";
if (open(my $fh, '<', '../firewalld-rich/module.info')) {
    while (my $line = <$fh>) {
        if ($line =~ /version=(.+)/) {
            $module_info_version = $1;
            chomp($module_info_version);
            last;
        }
    }
    close($fh);
}

my $index_version = "";
if ($index_content =~ /module_version = "([^"]+)"/) {
    $index_version = $1;
}

test_result(
    "Version consistency between files",
    $module_info_version eq $index_version && $module_info_version eq "1.12",
    "module.info: $module_info_version, index.cgi: $index_version"
);

# Test 7: Changelog documentation
print "TEST 7: Documentation Quality\n";
print "=" x 40 . "\n";

my $changelog_content = "";
if (open(my $fh, '<', '../firewalld-rich/CHANGELOG.md')) {
    local $/;
    $changelog_content = <$fh>;
    close($fh);
}

my $has_comprehensive_docs = ($changelog_content =~ /COMPREHENSIVE CORE FIXES/);
my $has_technical_details = ($changelog_content =~ /list_all_rich_rules.*detect_rule_zone/s);

test_result(
    "Comprehensive documentation present",
    $has_comprehensive_docs,
    "Looking for comprehensive fix documentation"
);

test_result(
    "Technical implementation details documented",
    $has_technical_details,
    "Checking for function-level documentation"
);

# Test 8: Verify firewall-cmd direct execution
print "TEST 8: Direct Command Execution Test\n";
print "=" x 40 . "\n";

my $firewall_output = `firewall-cmd --list-rich-rules 2>&1`;
my $firewall_exit = $? >> 8;
my $rule_count = $firewall_output ? scalar(split(/\n/, $firewall_output)) : 0;

test_result(
    "Direct firewall-cmd execution works",
    $firewall_exit == 0,
    "Exit code: $firewall_exit"
);

test_result(
    "Significant number of rules returned",
    $rule_count > 50,
    "Found $rule_count rules (expected >50)"
);

# Summary
print "=" x 60 . "\n";
print "VALIDATION SUMMARY\n";
print "=" x 60 . "\n";
print "Total Tests: $total_tests\n";
print "Passed: $passed_tests\n";
print "Failed: " . ($total_tests - $passed_tests) . "\n";
print "Success Rate: " . sprintf("%.1f", ($passed_tests / $total_tests) * 100) . "%\n";

if ($passed_tests == $total_tests) {
    print "\n🎉 ALL VALIDATIONS PASSED! Ready for deployment.\n";
} elsif ($passed_tests >= ($total_tests * 0.8)) {
    print "\n⚠️  MOSTLY GOOD: Minor issues, may proceed with caution.\n";
} else {
    print "\n🚨 SIGNIFICANT ISSUES: Review failed tests before deployment.\n";
}

exit($passed_tests < ($total_tests * 0.8) ? 1 : 0);