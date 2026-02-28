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

# Get form data
my $zone = $in{'zone'};

# Validate zone
if (!validate_zone($zone)) {
    print_json_response(0, $text{'save_err_zone'}, "");
}

# Build rule components hash (same logic as save.cgi lines 30-148)
my %rule_opts;

# Family
$rule_opts{'family'} = $in{'family'} if ($in{'family'} && $in{'family'} ne 'both');

# Rule type and corresponding configuration
my $rule_type = $in{'rule_type'};

# Source configuration
my $source_type = $in{'source_type'};
if ($source_type eq 'address' && $in{'source_address'}) {
    $rule_opts{'source_address'} = $in{'source_address'};
    if (!&check_ipaddress($in{'source_address'}) &&
        !&check_ip6address($in{'source_address'}) &&
        $in{'source_address'} !~ /^[\d\.\/]+$/ &&
        $in{'source_address'} !~ /^[a-fA-F0-9:\/]+$/) {
        print_json_response(0, $text{'save_err_source_address'}, "");
    }
} elsif ($source_type eq 'mac' && $in{'source_mac'}) {
    $rule_opts{'source_mac'} = $in{'source_mac'};
    if ($in{'source_mac'} !~ /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/) {
        print_json_response(0, $text{'save_err_source_mac'}, "");
    }
} elsif ($source_type eq 'interface' && $in{'source_interface'}) {
    $rule_opts{'source_interface'} = $in{'source_interface'};
    if ($in{'source_interface'} !~ /^[a-zA-Z0-9_.-]+$/) {
        print_json_response(0, $text{'save_err_source_interface'}, "");
    }
} elsif ($source_type eq 'ipset' && $in{'source_ipset'}) {
    $rule_opts{'source_ipset'} = $in{'source_ipset'};
    if ($in{'source_ipset'} !~ /^[a-zA-Z0-9_.-]+$/) {
        print_json_response(0, $text{'save_err_source_ipset'}, "");
    }
}

# Destination configuration
if ($in{'destination_address'}) {
    $rule_opts{'destination_address'} = $in{'destination_address'};
    if (!&check_ipaddress($in{'destination_address'}) &&
        !&check_ip6address($in{'destination_address'}) &&
        $in{'destination_address'} !~ /^[\d\.\/]+$/ &&
        $in{'destination_address'} !~ /^[a-fA-F0-9:\/]+$/) {
        print_json_response(0, $text{'save_err_destination_address'}, "");
    }
}

if ($in{'destination_interface'}) {
    $rule_opts{'destination_interface'} = $in{'destination_interface'};
    if ($in{'destination_interface'} !~ /^[a-zA-Z0-9_.-]+$/) {
        print_json_response(0, $text{'save_err_destination_interface'}, "");
    }
}

# Service/Port configuration based on rule type
if ($rule_type eq 'service') {
    if ($in{'service_name'}) {
        $rule_opts{'service_name'} = $in{'service_name'};
        if ($in{'service_name'} !~ /^[a-zA-Z0-9_.-]+$/) {
            print_json_response(0, $text{'save_err_service_name'}, "");
        }
    }
} elsif ($rule_type eq 'port') {
    my $port = '';
    if ($in{'port_mode'} eq 'single') {
        $port = $in{'port_single'};
    } else {
        if ($in{'port_from'} && $in{'port_to'}) {
            $port = $in{'port_from'} . '-' . $in{'port_to'};
        }
    }

    if ($port) {
        $rule_opts{'port'} = $port;
        $rule_opts{'protocol'} = $in{'protocol'};

        # Validate port
        if ($port =~ /^(\d+)-(\d+)$/) {
            my ($start, $end) = ($1, $2);
            if ($start < 1 || $end > 65535 || $start > $end) {
                print_json_response(0, $text{'save_err_port_range'}, "");
            }
        } elsif ($port =~ /^\d+$/) {
            if ($port < 1 || $port > 65535) {
                print_json_response(0, $text{'save_err_port'}, "");
            }
        } else {
            print_json_response(0, $text{'save_err_port'}, "");
        }

        # Validate protocol
        if ($in{'protocol'} !~ /^(tcp|udp|sctp|dccp)$/) {
            print_json_response(0, $text{'save_err_protocol'}, "");
        }
    }
} elsif ($rule_type eq 'protocol') {
    if ($in{'protocol_value'}) {
        $rule_opts{'protocol_value'} = $in{'protocol_value'};
        if ($in{'protocol_value'} !~ /^\d+$/ || $in{'protocol_value'} < 0 || $in{'protocol_value'} > 255) {
            print_json_response(0, $text{'save_err_protocol'}, "");
        }
    }
}

# Action configuration
my $action = $in{'action'};
if ($action !~ /^(accept|reject|drop)$/) {
    print_json_response(0, $text{'save_err_action'}, "");
}
$rule_opts{'action'} = $action;

if ($action eq 'reject' && $in{'reject_type'}) {
    $rule_opts{'reject_type'} = $in{'reject_type'};
    if ($in{'reject_type'} !~ /^(icmp6-adm-prohibited|tcp-reset)$/) {
        print_json_response(0, $text{'save_err_reject_type'}, "");
    }
}

# Logging configuration
if ($in{'log_enable'}) {
    $rule_opts{'log'} = 1;

    if ($in{'log_prefix'}) {
        $rule_opts{'log_prefix'} = $in{'log_prefix'};
        if (length($in{'log_prefix'}) > 29) {
            print_json_response(0, $text{'save_err_log_prefix'}, "");
        }
    }

    if ($in{'log_level'}) {
        $rule_opts{'log_level'} = $in{'log_level'};
        if ($in{'log_level'} !~ /^(emerg|alert|crit|err|warn|notice|info|debug)$/) {
            print_json_response(0, $text{'save_err_log_level'}, "");
        }
    }

    if ($in{'log_limit_rate'} && $in{'log_limit_unit'}) {
        $rule_opts{'log_limit'} = $in{'log_limit_rate'} . '/' . $in{'log_limit_unit'};
        if ($in{'log_limit_rate'} !~ /^\d+$/ || $in{'log_limit_rate'} < 1) {
            print_json_response(0, $text{'save_err_log_limit'}, "");
        }
    }
}

# Advanced options
if ($in{'audit'}) {
    $rule_opts{'audit'} = 1;
}

if ($in{'masquerade'}) {
    $rule_opts{'masquerade'} = 1;
}

# Port forwarding
if ($in{'forward_enable'}) {
    if ($in{'forward_to_port'}) {
        $rule_opts{'forward_to_port'} = $in{'forward_to_port'};
        if ($in{'forward_to_port'} !~ /^\d+$/ || $in{'forward_to_port'} < 1 || $in{'forward_to_port'} > 65535) {
            print_json_response(0, $text{'save_err_forward_port'}, "");
        }
    }

    if ($in{'forward_to_addr'}) {
        $rule_opts{'forward_to_addr'} = $in{'forward_to_addr'};
        if (!&check_ipaddress($in{'forward_to_addr'}) && !&check_ip6address($in{'forward_to_addr'})) {
            print_json_response(0, $text{'save_err_forward_addr'}, "");
        }
    }

    if ($rule_opts{'port'} && $rule_opts{'protocol'}) {
        $rule_opts{'forward_port'} = $rule_opts{'port'};
        $rule_opts{'forward_protocol'} = $rule_opts{'protocol'};
    }
}

# Construct the rule text
my $rule_text = construct_rich_rule(%rule_opts);

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
