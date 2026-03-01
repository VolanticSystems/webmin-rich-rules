#!/usr/bin/perl
# Test a firewalld rich rule against the runtime without persisting it
# Returns JSON: {"success": true/false, "message": "...", "rule": "..."}

$trust_unknown_referers = 1;
require './firewalld-rich-lib.pl';

&ReadParse();

# Always output JSON
sub print_json_response {
    my ($success, $message, $rule) = @_;
    print "Content-type: application/json\n\n";
    # Manual JSON encoding to avoid module dependency
    $message =~ s/\\/\\\\/g;
    $message =~ s/"/\\"/g;
    $message =~ s/\n/\\n/g;
    $rule =~ s/\\/\\\\/g;
    $rule =~ s/"/\\"/g;
    $rule =~ s/\n/\\n/g;
    my $s = $success ? 'true' : 'false';
    print "{\"success\": $s, \"message\": \"$message\", \"rule\": \"$rule\"}\n";
    exit;
}

# Check if firewalld is installed and running
if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    print_json_response(0, "FirewallD is not properly installed or running", "");
}

# Get zone
my $zone = $in{'zone'};

# Validate zone
if (!validate_zone($zone)) {
    print_json_response(0, $text{'save_err_zone'}, "");
}

# Build rule from form using shared function
my ($rule_opts_ref, $errors_ref) = build_rule_from_form(%in);

if (@$errors_ref) {
    my $first_err = $errors_ref->[0];
    print_json_response(0, $text{$first_err} || $first_err, "");
}

# Construct the rule text
my $rule_text = construct_rich_rule(%$rule_opts_ref);

# Validate the constructed rule
my $validate_err = validate_rich_rule($rule_text);
if ($validate_err) {
    print_json_response(0, "Validation failed: $validate_err", $rule_text);
}

# Test the rule: add to runtime (NOT permanent), then immediately remove
my $base_cmd = $config{'firewall_cmd'} || '/usr/bin/firewall-cmd';
my $safe_rule = _shell_quote_rule($rule_text);
my $safe_zone = quotemeta($zone);

# Add rule to runtime only (no --permanent)
my $add_output = `$base_cmd --zone=$safe_zone --add-rich-rule='$safe_rule' 2>&1`;
my $add_rc = $?;

if ($add_rc != 0) {
    chomp($add_output);
    print_json_response(0, $add_output, $rule_text);
}

# Successfully added - now immediately remove it
my $rm_output = `$base_cmd --zone=$safe_zone --remove-rich-rule='$safe_rule' 2>&1`;
# We don't fail on remove errors - the rule will vanish on reload anyway

print_json_response(1, $text{'test_rule_success'}, $rule_text);
