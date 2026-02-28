#!/usr/bin/perl
# Delete a firewalld rich rule with confirmation

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    &error($text{'delete_err_install'});
}

&ReadParse();

my $zone = $in{'zone'};
my $idx = $in{'idx'};
my $confirm = $in{'confirm'};  # This will be set when confirm button is clicked

# Handle cancel button first
if ($in{'cancel'}) {
    &redirect("index.cgi?zone=" . &urlize($zone));
}

# Validate zone
if (!validate_zone($zone)) {
    &error($text{'delete_err_zone'});
}

# Get the rule to delete - use global index like index.cgi
my @all_rules = list_all_rich_rules();
if ($idx < 0 || $idx >= @all_rules) {
    &error($text{'delete_err_rule'});
}

my $rule = $all_rules[$idx];
my $rule_text = $rule->{'text'};
$zone = $rule->{'zone'};
get_parsed_rule($rule);  # Ensure parsed data is available

if ($confirm) {
    # User confirmed deletion, proceed with removal
    &error_setup($text{'delete_err'});
    
    my $err = remove_rich_rule($rule_text, $zone);
    if ($err) {
        &error($text{'delete_err'} . ": " . $err);
    }
    
    # Log the action
    &webmin_log("delete", "rich-rule", $rule_text, { 'zone' => $zone });
    
    # Redirect back to main page preserving filters
    &redirect("index.cgi?deleted=1");
} else {
    # Show confirmation dialog
    &ui_print_header(undef, $text{'delete_title'}, "", undef, 1, 1);
    
    print &ui_form_start("delete.cgi", "post");
    print &ui_hidden("zone", $zone);
    print &ui_hidden("idx", $idx);
    # Don't set confirm=1 here - let the button names handle it
    
    print "<div style='margin: 20px 0;'>\n";
    print "<p><strong>" . $text{'delete_rusure'} . "</strong></p>\n";
    print "<p>" . &text('delete_rusure2', "<tt>" . &html_escape($rule_text) . "</tt>") . "</p>\n";
    print "</div>\n";
    
    # Show rule details in a table for better readability
    print &ui_table_start($text{'delete_rule_details'}, "width=100%", 2);
    
    print &ui_table_row($text{'delete_zone'}, "<tt>" . &html_escape($zone) . "</tt>");
    print &ui_table_row($text{'delete_rule'}, "<tt>" . &html_escape($rule_text) . "</tt>");
    
    # Parse and show rule components
    my $parsed = $rule->{'parsed'};
    if ($parsed) {
        if ($parsed->{'family'}) {
            print &ui_table_row($text{'delete_family'}, $parsed->{'family'});
        }
        
        if ($parsed->{'source_address'}) {
            print &ui_table_row($text{'delete_source'}, $parsed->{'source_address'});
        } elsif ($parsed->{'source_mac'}) {
            print &ui_table_row($text{'delete_source'}, "MAC " . $parsed->{'source_mac'});
        } elsif ($parsed->{'source_interface'}) {
            print &ui_table_row($text{'delete_source'}, "Interface " . $parsed->{'source_interface'});
        }
        
        if ($parsed->{'destination_address'}) {
            print &ui_table_row($text{'delete_destination'}, $parsed->{'destination_address'});
        }
        
        if ($parsed->{'service_name'}) {
            print &ui_table_row($text{'delete_service'}, $parsed->{'service_name'});
        } elsif ($parsed->{'port'} && $parsed->{'protocol'}) {
            print &ui_table_row($text{'delete_port'}, $parsed->{'protocol'} . "/" . $parsed->{'port'});
        }
        
        if ($parsed->{'action'}) {
            my $action_text = uc($parsed->{'action'});
            if ($parsed->{'action'} eq 'reject' && $parsed->{'reject_type'}) {
                $action_text .= " (" . $parsed->{'reject_type'} . ")";
            }
            print &ui_table_row($text{'delete_action'}, $action_text);
        }
        
        if ($parsed->{'log'}) {
            my $log_text = "Yes";
            if ($parsed->{'log_level'}) {
                $log_text .= " (" . $parsed->{'log_level'} . ")";
            }
            if ($parsed->{'log_prefix'}) {
                $log_text .= " [" . $parsed->{'log_prefix'} . "]";
            }
            print &ui_table_row($text{'delete_logging'}, $log_text);
        }
        
        if ($parsed->{'masquerade'}) {
            print &ui_table_row($text{'delete_masquerade'}, "Yes");
        }
        
        if ($parsed->{'forward_port'}) {
            my $forward_text = $parsed->{'forward_port'};
            if ($parsed->{'forward_to_port'}) {
                $forward_text .= " → " . $parsed->{'forward_to_port'};
            }
            if ($parsed->{'forward_to_addr'}) {
                $forward_text .= " @ " . $parsed->{'forward_to_addr'};
            }
            print &ui_table_row($text{'delete_forward'}, $forward_text);
        }
    }
    
    print &ui_table_end();
    
    print "<div style='margin: 20px 0;'>\n";
    print &ui_form_end([
        [ "confirm", $text{'delete_confirm'} ],
        [ "cancel", $text{'cancel'} ]
    ]);
    print "</div>\n";
    
    # Add proper JavaScript for delete confirmation 
    print "<script type='text/javascript'>\n";
    print "document.querySelector('input[name=\"confirm\"]').onclick = function() {\n";
    print "    return confirm('Are you sure you want to delete this rule?');\n";
    print "};\n";
    print "</script>\n";
    
    &ui_print_footer("index.cgi", $text{'index_return'});
}