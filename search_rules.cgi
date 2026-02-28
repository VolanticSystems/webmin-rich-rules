#!/usr/bin/perl
# search_rules.cgi
# Advanced search and filtering for firewalld rich rules (following bind8 pattern)

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    &error($text{'index_ecommand'});
}

&ReadParse();

# Get search parameters
my $search_text = $in{'search'} || '';
my $category_filter = $in{'category'} || '';
my $action_filter = $in{'action'} || '';
my $zone_filter = $in{'zone'} || '';
my $ip_filter = $in{'ip'} || '';
my $port_filter = $in{'port'} || '';

&ui_print_header(undef, "Search Firewall Rules", "");

if ($in{'search'} || $in{'category'} || $in{'action'} || $in{'zone'} || $in{'ip'} || $in{'port'}) {
    # Perform search
    my @all_rules = &list_all_rich_rules();
    my @matching_rules = ();
    
    foreach my $rule (@all_rules) {
        my $matches = 1;
        
        # Text search
        if ($search_text && $rule->{'text'} !~ /\Q$search_text\E/i) {
            $matches = 0;
        }
        
        # Category filter
        if ($category_filter) {
            my $category = categorize_rich_rule($rule->{'text'});
            if ($category ne $category_filter) {
                $matches = 0;
            }
        }
        
        # Zone filter
        if ($zone_filter && $rule->{'zone'} ne $zone_filter) {
            $matches = 0;
        }
        
        # Action filter
        if ($action_filter) {
            my $parsed = get_parsed_rule($rule);
            if (!$parsed->{'action'} || $parsed->{'action'} ne $action_filter) {
                $matches = 0;
            }
        }
        
        # IP filter
        if ($ip_filter) {
            my $parsed = get_parsed_rule($rule);
            if (!$parsed->{'source_address'} || $parsed->{'source_address'} !~ /\Q$ip_filter\E/) {
                $matches = 0;
            }
        }
        
        # Port filter
        if ($port_filter) {
            my $parsed = get_parsed_rule($rule);
            if (!$parsed->{'port'} || $parsed->{'port'} !~ /\Q$port_filter\E/) {
                $matches = 0;
            }
        }
        
        if ($matches) {
            push @matching_rules, $rule;
        }
    }
    
    # Display results
    if (@matching_rules == 1) {
        # Single result, redirect to edit page (following bind8 pattern)
        &redirect("edit.cgi?zone=" . &urlize($matching_rules[0]->{'zone'}) . 
                  "&idx=" . $matching_rules[0]->{'index'});
        exit;
    }
    
    # Show search criteria
    print "<p><strong>Search Results:</strong></p>\n";
    print "<ul>\n";
    if ($search_text) {
        print "<li>Text contains: <em>" . &html_escape($search_text) . "</em></li>\n";
    }
    if ($category_filter) {
        print "<li>Category: <em>" . ucfirst($category_filter) . "</em></li>\n";
    }
    if ($action_filter) {
        print "<li>Action: <em>" . uc($action_filter) . "</em></li>\n";
    }
    if ($zone_filter) {
        print "<li>Zone: <em>" . &html_escape($zone_filter) . "</em></li>\n";
    }
    if ($ip_filter) {
        print "<li>IP/Network: <em>" . &html_escape($ip_filter) . "</em></li>\n";
    }
    if ($port_filter) {
        print "<li>Port: <em>" . &html_escape($port_filter) . "</em></li>\n";
    }
    print "</ul>\n";
    
    if (@matching_rules) {
        print "<p>Found " . scalar(@matching_rules) . " matching rules:</p>\n";
        
        # Display results table (following bind8 pattern)
        print &ui_columns_start([
            "Type",
            "Zone",
            "Rule Summary", 
            "Actions"
        ], 100);
        
        foreach my $rule (@matching_rules) {
            my $category = categorize_rich_rule($rule->{'text'});
            my $category_display = ucfirst($category);
            my $category_color = ($category eq 'admin') ? "green" : 
                                ($category eq 'fail2ban') ? "red" : "black";
            
            my $rule_summary = &format_rule_summary($rule);
            
            my $actions = &ui_link("edit.cgi?zone=" . &urlize($rule->{'zone'}) . 
                                  "&idx=" . $rule->{'index'}, "[Edit]");
            $actions .= " | " . &ui_link("clone.cgi?zone=" . &urlize($rule->{'zone'}) . 
                                        "&idx=" . $rule->{'index'}, "[Clone]");
            $actions .= " | " . &ui_link("delete.cgi?zone=" . &urlize($rule->{'zone'}) . 
                                        "&idx=" . $rule->{'index'}, "[Delete]");
            
            print &ui_columns_row([
                "<span style='color: $category_color; font-weight: bold;'>$category_display</span>",
                $rule->{'zone'},
                $rule_summary,
                $actions
            ]);
        }
        
        print &ui_columns_end();
    } else {
        print "<p><strong>No rules found matching the search criteria.</strong></p>\n";
    }
} else {
    # Show search form
    print "<p>Use this form to search for specific firewall rules:</p>\n";
    
    print &ui_form_start("search_rules.cgi");
    print &ui_table_start("Search Criteria", "width=100%", 2);
    
    # Text search
    print &ui_table_row("Search text:",
        &ui_textbox("search", $search_text, 40) . 
        "<br><small>Search in rule text</small>");
    
    # Category filter
    my @category_opts = (["", "Any Category"], ["admin", "Admin Rules"], 
                        ["fail2ban", "fail2ban Rules"], ["unknown", "Other Rules"]);
    print &ui_table_row("Rule type:",
        &ui_select("category", $category_filter, \@category_opts));
    
    # Action filter
    my @action_opts = (["", "Any Action"], ["accept", "Accept"], 
                      ["reject", "Reject"], ["drop", "Drop"]);
    print &ui_table_row("Action:",
        &ui_select("action", $action_filter, \@action_opts));
    
    # Zone filter
    my @zones = &list_firewalld_zones();
    my @zone_opts = (["", "Any Zone"]);
    foreach my $zone (@zones) {
        push @zone_opts, [$zone, $zone];
    }
    print &ui_table_row("Zone:",
        &ui_select("zone", $zone_filter, \@zone_opts));
    
    # IP filter
    print &ui_table_row("IP/Network:",
        &ui_textbox("ip", $ip_filter, 30) .
        "<br><small>e.g. 192.168.1.0 or 10.0.0.0/24</small>");
    
    # Port filter
    print &ui_table_row("Port:",
        &ui_textbox("port", $port_filter, 10) .
        "<br><small>e.g. 22 or 80</small>");
    
    print &ui_table_end();
    print &ui_form_end([ [ "search", "Search Rules" ], [ "clear", "Clear Form" ] ]);
}

&ui_print_footer("index.cgi", "Return to Rules List");