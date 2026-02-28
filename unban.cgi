#!/usr/bin/perl
# Unban an IP address from fail2ban

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

# Check if we're just displaying the confirmation form
if (!$in{'confirm'}) {
    &ui_print_header(undef, $text{'fail2ban_unban_title'}, "", undef, 1, 1);

    print "<p><b>" . &text('unban_heading', &html_escape($ip)) . "</b></p>\n";
    print "<p>" . $text{'unban_explain'} . "</p>\n";

    # Show fail2ban status for this IP
    my @jails = get_fail2ban_status();
    if (@jails) {
        print "<p><b>" . $text{'unban_active_jails'} . "</b> " . join(", ", @jails) . "</p>\n";

        # Check which jails have this IP banned
        my @banned_jails;
        foreach my $jail (@jails) {
            $jail =~ s/^\s+|\s+$//g;
            my $output = `fail2ban-client status $jail 2>/dev/null`;
            if (!$? && $output =~ /Banned IP list:\s*(.+)/) {
                my $banned_ips = $1;
                if ($banned_ips =~ /\Q$ip\E/) {
                    push @banned_jails, $jail;
                }
            }
        }

        if (@banned_jails) {
            print "<p><b>" . $text{'unban_banned_jails'} . "</b> " . join(", ", @banned_jails) . "</p>\n";
        } else {
            print "<p><em>" . $text{'unban_not_banned'} . "</em></p>\n";
        }
    } else {
        print "<p><em>" . $text{'fail2ban_no_jails'} . "</em></p>\n";
    }

    print &ui_form_start("unban.cgi", "post");
    print &ui_hidden("ip", $ip);
    print &ui_hidden("confirm", 1);
    print &ui_form_end([[$text{'unban_submit'}, $text{'unban_submit'}], [$text{'cancel'}, $text{'cancel'}]]);

    &ui_print_footer("index.cgi", $text{'index_return'});
    exit;
}

# Handle cancel
if ($in{'cancel'}) {
    &redirect("index.cgi");
}

# Perform the unban
my $err = fail2ban_unban_ip($ip);
if ($err) {
    &error(&text('unban_err_failed', $err));
} else {
    &redirect("index.cgi?message=unbanned_" . &urlize($ip));
}