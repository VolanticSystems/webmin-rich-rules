#!/usr/bin/perl
# Save a firewalld rich rule

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    &error($text{'save_err_install'});
}

&error_setup($text{'save_err'});
&ReadParse();

# Check if cancel button was pressed
if ($in{'cancel'}) {
    &redirect("index.cgi");
    exit;
}

# Get form data
my $new = $in{'new'};
my $zone = $in{'zone'};
my $idx = $in{'idx'};

# Validate zone
if (!validate_zone($zone)) {
    &error($text{'save_err_zone'});
}

# Build rule from form using shared function
my ($rule_opts_ref, $errors_ref) = build_rule_from_form(%in);

if (@$errors_ref) {
    my $first_err = $errors_ref->[0];
    &error($text{$first_err} || $first_err);
}

# Validate that rule has meaningful content
my %rule_opts = %$rule_opts_ref;
my $has_content = 0;
foreach my $key (keys %rule_opts) {
    if ($key ne 'action' && $key ne 'priority' && $key ne 'family' && $rule_opts{$key}) {
        $has_content = 1;
        last;
    }
}
if (!$has_content && !$rule_opts{'action'}) {
    &error($text{'save_err_content'});
}

# Construct the rule text
my $rule_text = construct_rich_rule(%rule_opts);

# Validate the constructed rule
my $validate_err = validate_rich_rule($rule_text);
if ($validate_err) {
    &error(&text('save_err_syntax', $validate_err));
}

# Save the rule
my $err;
if ($new) {
    # Add new rule
    $err = add_rich_rule($rule_text, $zone);
} else {
    # Modify existing rule - use old_rule_text passed from edit form
    my $old_rule = $in{'old_rule_text'};
    if ($old_rule) {
        $err = modify_rich_rule($old_rule, $rule_text, $zone);
    } else {
        &error($text{'save_err'} . ": Missing original rule text");
    }
}

if ($err) {
    &error(&text('save_err_command', $err));
}

# Log the action
if ($new) {
    &webmin_log("create", "rich-rule", $rule_text, { 'zone' => $zone });
} else {
    &webmin_log("modify", "rich-rule", $rule_text, { 'zone' => $zone });
}

# Redirect back to main page
&redirect("index.cgi?zone=" . &urlize($zone) . "&saved=1");
