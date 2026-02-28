#!/usr/bin/perl
# Handle bulk operations on rich rules

require './firewalld-rich-lib.pl';

# Parse form inputs
&ReadParse();

# Get selected rules
my @selected = split(/\0/, $in{'selected'});

if (!@selected) {
    &error($text{'bulk_err_none'});
}

# Handle different actions
if ($in{'delete_selected'}) {
    # Delete selected rules
    my @errors;
    my $deleted_count = 0;

    # Get all rules once for lookup by global index
    my @all_rules = &list_all_rich_rules();

    # Sort indices descending so deletions don't shift later indices
    my @sorted = sort {
        my (undef, $ia) = split(/:/, $a);
        my (undef, $ib) = split(/:/, $b);
        $ib <=> $ia;
    } @selected;

    foreach my $sel (@sorted) {
        my ($zone, $idx) = split(/:/, $sel);
        next if (!$zone || !defined($idx) || $idx !~ /^\d+$/);
        next if ($idx < 0 || $idx >= scalar(@all_rules));

        my $rule = $all_rules[$idx];
        my $err = remove_rich_rule($rule->{'text'}, $rule->{'zone'});
        if ($err) {
            push @errors, &text('bulk_err_delete', $rule->{'zone'}, $err);
        } else {
            $deleted_count++;
        }
    }
    
    if (@errors) {
        &error(&text('bulk_err_some', join(", ", @errors)));
    } else {
        &redirect("index.cgi?message=deleted_" . $deleted_count);
    }
    
} elsif ($in{'clone_selected'}) {
    # Clone selected rules - redirect to bulk clone interface
    my $clone_params = "selected=" . join("&selected=", map { &urlize($_) } @selected);
    &redirect("bulk_clone.cgi?" . $clone_params);
    
} else {
    &error($text{'bulk_err_unknown'});
}