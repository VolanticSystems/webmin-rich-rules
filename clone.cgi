#!/usr/bin/perl
# Clone a rich rule to create a new one

require './firewalld-rich-lib.pl';

# Parse form inputs
&ReadParse();

# Get the rule to clone
my $zone = $in{'zone'};
my $idx = $in{'idx'};

if (!$zone || !defined($idx)) {
    &error($text{'clone_err_params'});
}

# Get the existing rule - use global index like index.cgi
my @all_rules = &list_all_rich_rules();
if ($idx < 0 || $idx >= @all_rules) {
    &error($text{'clone_err_index'});
}

my $rule = $all_rules[$idx];
$zone = $rule->{'zone'};  # Get the actual zone

# Redirect to edit page with the rule pre-populated for cloning
my $clone_params = "new=1&clone=1&zone=" . &urlize($zone) . "&rule_text=" . &urlize($rule->{'text'});
&redirect("edit.cgi?" . $clone_params);