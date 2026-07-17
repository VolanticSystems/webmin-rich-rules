#!/usr/bin/perl
# Main page for firewalld rich rules management

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed()) {
    &ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
    print &ui_hr();
    print &text('index_ecommand', "<tt>$config{'firewall_cmd'}</tt>"), "<p>\n";
    &ui_print_footer("/", $text{'index'});
    exit;
}

if (!is_firewalld_running()) {
    &ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
    print &ui_hr();
    print &text('index_estopped'), "<p>\n";
    &ui_print_footer("/", $text{'index'});
    exit;
}

if (!rich_rules_supported()) {
    &ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
    print &ui_hr();
    print &text('index_eversion'), "<p>\n";
    &ui_print_footer("/", $text{'index'});
    exit;
}

# Parse form inputs
&ReadParse();

# Get current tab mode (browse or search)
my $current_tab = $in{'tab'} || 'browse';

# Tab-specific parameters
my $category_filter = '';
my $debug_enabled = $config{'debug_categorization'} || $config{'debug_search'} || $config{'show_raw_rules'};

# For browse tab, handle category filtering
if ($current_tab eq 'browse') {
    $category_filter = $in{'category'} || '';  # No default - show based on rule count
}

# For search tab, get all search parameters
my $zone_filter = $in{'zone'} || '';
my $search_filter = $in{'search'} || '';
my $ip_filter = $in{'ip'} || '';
my $port_filter = $in{'port'} || '';
my $protocol_filter = $in{'protocol'} || '';
my $service_filter = $in{'service'} || '';
my $action_filter = $in{'action'} || '';
my $source_filter = $in{'source'} || '';
my $action_type_filter = $in{'action_type'} || '';

# Build Add Rule URL (used in tab row and stats area)
my $add_rule_url = "edit.cgi?new=1";
$add_rule_url .= "&zone=" . &urlize($zone_filter) if $zone_filter;

# Performance profiling (Time::HiRes loaded in lib with fallback)
my $start_time = [gettimeofday()] if $debug_enabled;

# Read module version from module.info
my %minfo = &get_module_info($module_name);
my $module_version = $minfo{'version'} || '?';

&ui_print_header("Version $module_version", $text{'index_title'}, "", undef, 1, 1, 0, &help_search_link("firewalld-rich", "intro"));

# Tab interface with proper categorization
my $active_tab = $in{'tab'} || 'admin';  # Default to admin rules tab
my @tab_definitions = (
    { 'id' => 'admin', 'name' => $text{'tab_admin'}, 'filter' => 'admin' },
    { 'id' => 'fail2ban', 'name' => $text{'tab_fail2ban'}, 'filter' => 'fail2ban' },
    { 'id' => 'other', 'name' => $text{'tab_other'}, 'filter' => 'unknown' },
    { 'id' => 'all', 'name' => $text{'tab_all'}, 'filter' => '' }
);

# Tab navigation using ui_links_row (styled by Authentic theme)
my @tab_links;
for my $tab (@tab_definitions) {
    if ($active_tab eq $tab->{'id'}) {
        push @tab_links, "<b>" . $tab->{'name'} . "</b>";
    } else {
        push @tab_links, &ui_link("index.cgi?tab=$tab->{'id'}", $tab->{'name'});
    }
}
push @tab_links, &ui_link($add_rule_url, $text{'tab_add_rule'});
print &ui_links_row(\@tab_links);
print &ui_hr();

# Add minimal JavaScript for bulk operations (following bind8 pattern)
print "<script type='text/javascript'>\n";
print "function toggle_all_checkboxes(source) {\n";
print "    var checkboxes = document.getElementsByName('selected');\n";
print "    for (var i = 0; i < checkboxes.length; i++) {\n";
print "        checkboxes[i].checked = source.checked;\n";
print "    }\n";
print "}\n";
print "// Fix Authentic theme three-way sort cycle (asc->desc->neutral)\n";
print "// The theme's order.dt handler resets ascending sorts to neutral,\n";
print "// causing a 'click twice' issue. Remove it for standard asc<->desc.\n";
print "(function() {\n";
print "    var fix = function() {\n";
print "        try {\n";
print "            var tables = document.querySelectorAll('table.dataTable');\n";
print "            for (var i = 0; i < tables.length; i++) {\n";
print "                \$(tables[i]).off('order.dt');\n";
print "            }\n";
print "        } catch(e) {}\n";
print "    };\n";
print "    setTimeout(fix, 200);\n";
print "    setTimeout(fix, 1000);\n";
print "})();\n";
print "</script>\n";

# Get all rich rules (single query - used for both stats and display)
my @all_rules = &list_all_rich_rules();

# Count statistics and cache category per rule (avoids re-categorizing)
my $total_rules = scalar(@all_rules);
my $admin_rules = 0;
my $fail2ban_rules = 0;
my $unknown_rules = 0;
foreach my $rule (@all_rules) {
    my $cat = categorize_rich_rule($rule->{'text'});
    $rule->{'category'} = $cat;
    # Also ensure parsed data is available for filtering
    get_parsed_rule($rule);
    if ($cat eq 'admin') { $admin_rules++; }
    elsif ($cat eq 'fail2ban') { $fail2ban_rules++; }
    else { $unknown_rules++; }
}

# Apply tab-based filtering
my $current_filter = '';
for my $tab (@tab_definitions) {
    if ($active_tab eq $tab->{'id'}) {
        $current_filter = $tab->{'filter'};
        last;
    }
}

# Filter by tab category (unless "all" tab) - uses cached category
if ($current_filter) {
    @all_rules = grep { $_->{'category'} eq $current_filter } @all_rules;
}

# Apply additional search filters
my %filter_opts;
$filter_opts{'ip'} = $ip_filter if $ip_filter;
$filter_opts{'port'} = $port_filter if $port_filter;
$filter_opts{'protocol'} = $protocol_filter if $protocol_filter;
$filter_opts{'service'} = $service_filter if $service_filter;
$filter_opts{'action'} = $action_filter if $action_filter;
$filter_opts{'source'} = $source_filter if $source_filter;
$filter_opts{'action_type'} = $action_type_filter if $action_type_filter;

# Apply category filter for search tab - uses cached category
$category_filter = $in{'category'} || '';
if ($category_filter) {
    @all_rules = grep { $_->{'category'} eq $category_filter } @all_rules;
}

# Apply detailed filters
if (%filter_opts) {
    @all_rules = filter_rules(\@all_rules, \%filter_opts);
}

# Apply text search filter if specified
if ($search_filter) {
    @all_rules = grep { $_->{'text'} =~ /\Q$search_filter\E/i } @all_rules;
}

# Apply zone filter
if ($zone_filter) {
    @all_rules = grep { $_->{'zone'} eq $zone_filter } @all_rules;
}

# Handle special actions (before displaying content)
if ($in{'reload'}) {
    my $reload_err = reload_firewalld();
    if ($reload_err) {
        print &text('message_reload_error') . ": " . &html_escape($reload_err) . "<p>\n";
    } else {
        print $text{'message_reloaded'} . "<p>\n";
    }
}

if ($in{'sync_fail2ban'}) {
    print $text{'message_sync_fail2ban'} . "<p>\n";
}

# Display search interface for all tabs
display_search_interface($active_tab);

# Display the filtered rules
display_filtered_rules(\@all_rules, $active_tab, $current_filter);

# Search interface function
sub display_search_interface {
    my $current_tab = shift;
    
    print &ui_subheading($text{'search_heading'});
    
    # Filtering form using Webmin ui_table for theme consistency
    print &ui_form_start("index.cgi", "get");
    print &ui_hidden("tab", $current_tab);
    print &ui_table_start($text{'search_heading'}, "width=100%", 4);

    # Action filter
    my @action_type_opts = (["", $text{'search_all_actions'}], ["accept", $text{'edit_action_accept'}], ["reject", $text{'edit_action_reject'}], ["drop", $text{'edit_action_drop'}]);
    print &ui_table_row($text{'search_action'},
        &ui_select("action_type", $action_type_filter, \@action_type_opts, 1, 0, 0, 0));

    # Zone filter
    my @zones = &list_firewalld_zones();
    my @zone_opts = (["", $text{'search_all_zones'}]);
    foreach my $zone (@zones) {
        push @zone_opts, [$zone, $zone];
    }
    print &ui_table_row($text{'search_zone'},
        &ui_select("zone", $zone_filter, \@zone_opts, 1, 0, 0, 0));

    # Source dropdown - only on "All Rules" tab
    if ($current_tab eq 'all') {
        my @category_opts = (["", $text{'search_all_rules'}], ["admin", $text{'tab_admin'}], ["fail2ban", $text{'tab_fail2ban'}], ["unknown", $text{'tab_other'}]);
        print &ui_table_row($text{'search_source'},
            &ui_select("category", $category_filter, \@category_opts, 1, 0, 0, 0));
    }

    # IP filter
    print &ui_table_row($text{'search_ip'},
        &ui_textbox("ip", $ip_filter, 20));

    # Port filter
    print &ui_table_row($text{'search_port'},
        &ui_textbox("port", $port_filter, 10));

    # Protocol filter
    my @protocol_opts = (["", $text{'search_all_protocols'}], ["tcp", "TCP"], ["udp", "UDP"], ["sctp", "SCTP"], ["dccp", "DCCP"]);
    print &ui_table_row($text{'search_protocol'},
        &ui_select("protocol", $protocol_filter, \@protocol_opts, 1, 0, 0, 0));

    # Service filter
    print &ui_table_row($text{'search_service'},
        &ui_textbox("service", $service_filter, 15));

    # Text search
    print &ui_table_row($text{'search_text'},
        &ui_textbox("search", $search_filter, 20));

    print &ui_table_end();
    print &ui_form_end([[$text{'search_submit'}, $text{'search_submit'}]]);
}

# Display filtered rules function
sub display_filtered_rules {
    my ($rules_ref, $active_tab, $current_filter) = @_;
    my @rules = @$rules_ref;

    # Get tab name for display
    my $tab_name = $text{'tab_all'};
    for my $tab (@tab_definitions) {
        if ($active_tab eq $tab->{'id'}) {
            $tab_name = $tab->{'name'};
            last;
        }
    }

    print &ui_subheading($tab_name);

    # Statistics and action links
    my $showing = $current_filter ?
        &text('stats_showing_cat', scalar(@rules), ucfirst($current_filter)) :
        &text('stats_showing', scalar(@rules));
    my $totals = &text('stats_total', $total_rules, $admin_rules, $fail2ban_rules, $unknown_rules);
    print "<p>$showing<br>$totals</p>\n";

    my @action_links;
    push @action_links, &ui_link($add_rule_url, $text{'stats_add_rule'});
    push @action_links, &ui_link("index.cgi?tab=$active_tab&reload=1", $text{'stats_reload'});
    print &ui_links_row(\@action_links);

    # Display rules table
    if (@rules) {
        print &ui_form_start("bulk_actions.cgi", "post");
        print &ui_hidden("tab", $active_tab);

        print &ui_columns_start([
            "<input type='checkbox' onclick='toggle_all_checkboxes(this)'>",
            $text{'col_type'},
            $text{'col_zone'},
            $text{'col_match'},
            $text{'col_source'},
            $text{'col_port'},
            $text{'col_action'},
            $text{'col_actions'}
        ], 100);

        foreach my $rule (@rules) {
            my $parsed = get_parsed_rule($rule);
            my $category = $rule->{'category'} || categorize_rich_rule($rule->{'text'});
            my $category_display = ucfirst($category);

            # Extract individual column values
            my $match_val = extract_match($parsed);
            my $source_val = extract_source($parsed);
            my $port_val = extract_port($parsed);
            my $action_val = extract_action($parsed);

            # Sort keys for DataTables numeric sorting
            my $source_sort = ip_sort_key($source_val);
            my $port_sort = port_sort_key($port_val);

            # Make source a link to edit page
            my $edit_url = "edit.cgi?zone=" . &urlize($rule->{'zone'}) . "&idx=" . $rule->{'index'};

            # Raw HTML row with data-order attributes for numeric sorting
            print "<tr>\n";
            print "<td><input type='checkbox' name='selected' value='" . &html_escape($rule->{'zone'} . ":" . $rule->{'index'}) . "'></td>\n";
            print "<td><b>$category_display</b></td>\n";
            print "<td>" . ($rule->{'zone'} || 'default') . "</td>\n";
            print "<td><tt>" . &html_escape($match_val) . "</tt></td>\n";
            print "<td data-order='" . &html_escape($source_sort) . "'><tt>" . &ui_link($edit_url, &html_escape($source_val)) . "</tt></td>\n";
            print "<td data-order='" . &html_escape($port_sort) . "'><tt>" . &html_escape($port_val) . "</tt></td>\n";
            print "<td><tt>" . &html_escape($action_val) . "</tt></td>\n";
            print "<td>" .
                &ui_link("edit.cgi?idx=" . $rule->{'index'} . "&zone=" . &urlize($rule->{'zone'}), $text{'edit'}) . " | " .
                &ui_link("clone.cgi?idx=" . $rule->{'index'} . "&zone=" . &urlize($rule->{'zone'}), $text{'clone_rule'}) . " | " .
                &ui_link("delete.cgi?idx=" . $rule->{'index'} . "&zone=" . &urlize($rule->{'zone'}), $text{'delete'}) .
                "</td>\n";
            print "</tr>\n";
        }

        print &ui_columns_end();

        # Bulk actions
        print "<div style='margin-top: 10px;'>\n";
        print &ui_submit($text{'index_delete_selected'}, "delete_selected");
        print "</div>\n";

        print &ui_form_end();
    } else {
        print "<p><em>" . $text{'stats_no_rules'} . "</em></p>\n";
        print "<p>" . &ui_link("edit.cgi?new=1", $text{'stats_add_new'}) . "</p>\n";
    }
}

# Extract match element type for display
sub extract_match {
    my ($parsed) = @_;
    if ($parsed->{'service_name'}) {
        return "service";
    } elsif ($parsed->{'port'} && $parsed->{'port_protocol'}) {
        return "port";
    } elsif ($parsed->{'protocol_value'}) {
        return "protocol";
    } elsif ($parsed->{'icmp_block'}) {
        return "icmp-block";
    } elsif ($parsed->{'icmp_type'}) {
        return "icmp-type";
    } elsif ($parsed->{'masquerade'}) {
        return "masquerade";
    } elsif ($parsed->{'forward_port'}) {
        return "forward-port";
    } elsif ($parsed->{'source_port'}) {
        return "source-port";
    }
    return "";
}

# Extract source address for display
sub extract_source {
    my ($parsed) = @_;
    my $not = $parsed->{'source_not'} ? "NOT " : "";
    if ($parsed->{'source_address'}) {
        return "${not}" . $parsed->{'source_address'};
    } elsif ($parsed->{'source_mac'}) {
        return "${not}MAC " . $parsed->{'source_mac'};
    } elsif ($parsed->{'source_ipset'}) {
        return "${not}ipset:" . $parsed->{'source_ipset'};
    }
    # Also show destination if no source
    my $dst_not = $parsed->{'destination_not'} ? "NOT " : "";
    if ($parsed->{'destination_address'}) {
        return "to ${dst_not}" . $parsed->{'destination_address'};
    } elsif ($parsed->{'destination_ipset'}) {
        return "to ${dst_not}ipset:" . $parsed->{'destination_ipset'};
    }
    return "";
}

# Extract port/service detail for display
sub extract_port {
    my ($parsed) = @_;
    my @parts;
    if ($parsed->{'service_name'}) {
        push @parts, $parsed->{'service_name'};
    }
    if ($parsed->{'port'} && $parsed->{'port_protocol'}) {
        push @parts, $parsed->{'port_protocol'} . "/" . $parsed->{'port'};
    }
    if ($parsed->{'source_port'} && $parsed->{'source_port_protocol'}) {
        push @parts, "sport " . $parsed->{'source_port_protocol'} . "/" . $parsed->{'source_port'};
    }
    if ($parsed->{'protocol_value'}) {
        push @parts, "proto " . $parsed->{'protocol_value'};
    }
    if ($parsed->{'icmp_block'}) {
        push @parts, $parsed->{'icmp_block'};
    }
    if ($parsed->{'icmp_type'}) {
        push @parts, $parsed->{'icmp_type'};
    }
    if ($parsed->{'forward_port'}) {
        my $fwd = $parsed->{'forward_protocol'} . "/" . $parsed->{'forward_port'};
        $fwd .= "\x{2192}";
        if ($parsed->{'forward_to_addr'}) {
            $fwd .= $parsed->{'forward_to_addr'} . ":" . ($parsed->{'forward_to_port'} || $parsed->{'forward_port'});
        } else {
            $fwd .= ($parsed->{'forward_to_port'} || $parsed->{'forward_port'});
        }
        push @parts, $fwd;
    }
    return join(", ", @parts);
}

# Extract action for display
sub extract_action {
    my ($parsed) = @_;
    my @parts;
    if ($parsed->{'action'}) {
        push @parts, uc($parsed->{'action'});
    }
    if ($parsed->{'nflog'}) {
        push @parts, "NFLOG";
    } elsif ($parsed->{'log'}) {
        push @parts, "LOG";
    }
    if ($parsed->{'audit'}) {
        push @parts, "AUDIT";
    }
    return join(", ", @parts);
}

# Generate zero-padded IP sort key for DataTables data-order
sub ip_sort_key {
    my ($source_str) = @_;
    return "zzz" unless $source_str;
    my $addr = $source_str;
    $addr =~ s/^(?:NOT |to )+//;
    $addr =~ s/^(?:MAC |ipset:)//;
    if ($addr =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?/) {
        return sprintf("%03d.%03d.%03d.%03d_%03d", $1, $2, $3, $4, $5 || 32);
    }
    return lc($source_str);
}

# Generate numeric port sort key for DataTables data-order
sub port_sort_key {
    my ($port_str) = @_;
    return "zzz" unless $port_str;
    if ($port_str =~ /(\d+)/) {
        return sprintf("%06d", $1);
    }
    return lc($port_str);
}

# Debug: show page generation time if enabled
if ($debug_enabled && $start_time) {
    my $total_time = tv_interval($start_time, [gettimeofday()]);
    print "<!-- Page generated in " . sprintf("%.4f", $total_time) . "s -->\n";
}

&ui_print_footer("/", $text{'index'});