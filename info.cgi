#!/usr/bin/perl
# Display information about an IP address and its fail2ban status

require './firewalld-rich-lib.pl';

# Parse form inputs
&ReadParse();

my $ip = $in{'ip'};

if (!$ip) {
    &error($text{'unban_err_noip'});
}

# Validate IP address format
if ($ip !~ /^[\d.]+$/) {
    &error($text{'unban_err_format'});
}

&ui_print_header(undef, $text{'fail2ban_info_title'}, "", undef, 1, 1);

print "<h3>" . &text('info_heading', &html_escape($ip)) . "</h3>\n";

# Check fail2ban status
my @jails = get_fail2ban_status();
if (@jails) {
    print &ui_subheading($text{'info_f2b_heading'});
    print &ui_columns_start([$text{'info_f2b_jail'}, $text{'info_f2b_status'}, $text{'info_f2b_actions'}]);
    
    my $banned_in_any = 0;
    foreach my $jail (@jails) {
        $jail =~ s/^\s+|\s+$//g;
        my $output = `fail2ban-client status $jail 2>/dev/null`;
        my $status = $text{'info_f2b_not_banned'};
        my $actions = "";
        
        if (!$? && $output =~ /Banned IP list:\s*(.+)/) {
            my $banned_ips = $1;
            if ($banned_ips =~ /\Q$ip\E/) {
                $status = "<b>" . $text{'fail2ban_banned'} . "</b>";
                $actions = &ui_link("unban.cgi?ip=" . &urlize($ip), "[Unban]", undef, undef, "_self");
                $banned_in_any = 1;
            }
        }
        
        print &ui_columns_row([$jail, $status, $actions]);
    }

    print &ui_columns_end();

    if ($banned_in_any) {
        print "<p>" . &ui_link("unban.cgi?ip=" . &urlize($ip), $text{'info_f2b_unban_all'}) . "</p>\n";
    }
} else {
    print "<p><em>" . $text{'fail2ban_no_jails'} . "</em></p>\n";
}

# Check firewall rules containing this IP
print &ui_subheading($text{'info_fw_heading'});
my @all_rules = list_all_rich_rules();
my @matching_rules = grep { $_->{'text'} =~ /\Q$ip\E/ } @all_rules;

if (@matching_rules) {
    print &ui_columns_start([$text{'info_fw_zone'}, $text{'info_fw_rule'}, $text{'info_fw_category'}, $text{'info_fw_actions'}]);
    
    foreach my $rule (@matching_rules) {
        my $category = categorize_rich_rule($rule->{'text'});
        my $actions = &ui_link("edit.cgi?zone=" . &urlize($rule->{'zone'}) .
                              "&idx=" . $rule->{'index'}, $text{'fail2ban_view'});
        if ($category ne 'fail2ban') {
            $actions .= " | " . &ui_link("delete.cgi?zone=" . &urlize($rule->{'zone'}) .
                                        "&idx=" . $rule->{'index'}, $text{'delete'});
        }

        print &ui_columns_row([
            $rule->{'zone'},
            "<tt>" . &html_escape($rule->{'text'}) . "</tt>",
            ucfirst($category),
            $actions
        ]);
    }
    
    print &ui_columns_end();
} else {
    print "<p><em>" . $text{'info_fw_none'} . "</em></p>\n";
}

# Add whois information if available
if (-x "/usr/bin/whois") {
    print &ui_subheading($text{'info_whois_heading'});
    print "<pre>\n";
    my $whois_output = `whois $ip 2>/dev/null | head -50`;
    if ($whois_output) {
        print &html_escape($whois_output);
    } else {
        print $text{'info_whois_na'};
    }
    print "</pre>\n";
}

&ui_print_footer("index.cgi", $text{'index_return'});