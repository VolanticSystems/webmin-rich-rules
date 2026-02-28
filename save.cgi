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
}

# Get form data
my $new = $in{'new'};
my $zone = $in{'zone'};
my $idx = $in{'idx'};

# Validate zone
if (!validate_zone($zone)) {
    &error($text{'save_err_zone'});
}

# Build rule components hash
my %rule_opts;

# Family
$rule_opts{'family'} = $in{'family'} if ($in{'family'} && $in{'family'} ne 'both');

# Rule type and corresponding configuration
my $rule_type = $in{'rule_type'};

# Source configuration
my $source_type = $in{'source_type'};
if ($source_type eq 'address' && $in{'source_address'}) {
    $rule_opts{'source_address'} = $in{'source_address'};
    # Validate IP address/network
    if (!&check_ipaddress($in{'source_address'}) && 
        !&check_ip6address($in{'source_address'}) &&
        $in{'source_address'} !~ /^[\d\.\/]+$/ &&
        $in{'source_address'} !~ /^[a-fA-F0-9:\/]+$/) {
        &error($text{'save_err_source_address'});
    }
} elsif ($source_type eq 'mac' && $in{'source_mac'}) {
    $rule_opts{'source_mac'} = $in{'source_mac'};
    # Validate MAC address
    if ($in{'source_mac'} !~ /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/) {
        &error($text{'save_err_source_mac'});
    }
} elsif ($source_type eq 'interface' && $in{'source_interface'}) {
    $rule_opts{'source_interface'} = $in{'source_interface'};
    # Validate interface name
    if ($in{'source_interface'} !~ /^[a-zA-Z0-9_.-]+$/) {
        &error($text{'save_err_source_interface'});
    }
} elsif ($source_type eq 'ipset' && $in{'source_ipset'}) {
    $rule_opts{'source_ipset'} = $in{'source_ipset'};
    # Validate IP set name
    if ($in{'source_ipset'} !~ /^[a-zA-Z0-9_.-]+$/) {
        &error($text{'save_err_source_ipset'});
    }
}

# Destination configuration
if ($in{'destination_address'}) {
    $rule_opts{'destination_address'} = $in{'destination_address'};
    # Validate destination address
    if (!&check_ipaddress($in{'destination_address'}) && 
        !&check_ip6address($in{'destination_address'}) &&
        $in{'destination_address'} !~ /^[\d\.\/]+$/ &&
        $in{'destination_address'} !~ /^[a-fA-F0-9:\/]+$/) {
        &error($text{'save_err_destination_address'});
    }
}

if ($in{'destination_interface'}) {
    $rule_opts{'destination_interface'} = $in{'destination_interface'};
    # Validate interface name
    if ($in{'destination_interface'} !~ /^[a-zA-Z0-9_.-]+$/) {
        &error($text{'save_err_destination_interface'});
    }
}

# Service/Port configuration based on rule type
if ($rule_type eq 'service') {
    if ($in{'service_name'}) {
        $rule_opts{'service_name'} = $in{'service_name'};
        # Validate service name
        my @services = get_firewalld_services();
        if ($in{'service_name'} !~ /^[a-zA-Z0-9_.-]+$/) {
            &error($text{'save_err_service_name'});
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
                &error($text{'save_err_port_range'});
            }
        } elsif ($port =~ /^\d+$/) {
            if ($port < 1 || $port > 65535) {
                &error($text{'save_err_port'});
            }
        } else {
            &error($text{'save_err_port'});
        }
        
        # Validate protocol
        if ($in{'protocol'} !~ /^(tcp|udp|sctp|dccp)$/) {
            &error($text{'save_err_protocol'});
        }
    }
} elsif ($rule_type eq 'protocol') {
    if ($in{'protocol_value'}) {
        $rule_opts{'protocol_value'} = $in{'protocol_value'};
        # Validate protocol number
        if ($in{'protocol_value'} !~ /^\d+$/ || $in{'protocol_value'} < 0 || $in{'protocol_value'} > 255) {
            &error($text{'save_err_protocol'});
        }
    }
}

# Action configuration
my $action = $in{'action'};
if ($action !~ /^(accept|reject|drop)$/) {
    &error($text{'save_err_action'});
}
$rule_opts{'action'} = $action;

if ($action eq 'reject' && $in{'reject_type'}) {
    $rule_opts{'reject_type'} = $in{'reject_type'};
    # Validate reject type
    if ($in{'reject_type'} !~ /^(icmp6-adm-prohibited|tcp-reset)$/) {
        &error($text{'save_err_reject_type'});
    }
}

# Logging configuration
if ($in{'log_enable'}) {
    $rule_opts{'log'} = 1;
    
    if ($in{'log_prefix'}) {
        $rule_opts{'log_prefix'} = $in{'log_prefix'};
        # Validate log prefix
        if (length($in{'log_prefix'}) > 29) {
            &error($text{'save_err_log_prefix'});
        }
    }
    
    if ($in{'log_level'}) {
        $rule_opts{'log_level'} = $in{'log_level'};
        # Validate log level
        if ($in{'log_level'} !~ /^(emerg|alert|crit|err|warn|notice|info|debug)$/) {
            &error($text{'save_err_log_level'});
        }
    }
    
    if ($in{'log_limit_rate'} && $in{'log_limit_unit'}) {
        $rule_opts{'log_limit'} = $in{'log_limit_rate'} . '/' . $in{'log_limit_unit'};
        # Validate rate limit
        if ($in{'log_limit_rate'} !~ /^\d+$/ || $in{'log_limit_rate'} < 1) {
            &error($text{'save_err_log_limit'});
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

# Priority handling
if ($in{'priority'} && $in{'priority'} =~ /^\d+$/) {
    $rule_opts{'priority'} = $in{'priority'};
}

# Port forwarding
if ($in{'forward_enable'}) {
    if ($in{'forward_to_port'}) {
        $rule_opts{'forward_to_port'} = $in{'forward_to_port'};
        # Validate forward port
        if ($in{'forward_to_port'} !~ /^\d+$/ || $in{'forward_to_port'} < 1 || $in{'forward_to_port'} > 65535) {
            &error($text{'save_err_forward_port'});
        }
    }
    
    if ($in{'forward_to_addr'}) {
        $rule_opts{'forward_to_addr'} = $in{'forward_to_addr'};
        # Validate forward address
        if (!&check_ipaddress($in{'forward_to_addr'}) && !&check_ip6address($in{'forward_to_addr'})) {
            &error($text{'save_err_forward_addr'});
        }
    }
    
    # Set forward port and protocol from main port config if forwarding enabled
    if ($rule_opts{'port'} && $rule_opts{'protocol'}) {
        $rule_opts{'forward_port'} = $rule_opts{'port'};
        $rule_opts{'forward_protocol'} = $rule_opts{'protocol'};
    }
}

# Construct the rule text
my $rule_text = construct_rich_rule(%rule_opts);

# Validate that rule has meaningful content (not just action)
my $has_content = 0;
foreach my $key (keys %rule_opts) {
    if ($key ne 'action' && $key ne 'priority' && $rule_opts{$key}) {
        $has_content = 1;
        last;
    }
}
if (!$has_content) {
    &error($text{'save_err_content'});
}

# Validate the constructed rule
my $validate_err = validate_rich_rule($rule_text);
if ($validate_err) {
    &error($text{'save_err_syntax'} . ": " . $validate_err);
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
    &error($text{'save_err_command'} . ": " . $err);
}

# Log the action
if ($new) {
    &webmin_log("create", "rich-rule", $rule_text, { 'zone' => $zone });
} else {
    &webmin_log("modify", "rich-rule", $rule_text, { 'zone' => $zone });
}

# Redirect back to main page
&redirect("index.cgi?zone=" . &urlize($zone) . "&saved=1");