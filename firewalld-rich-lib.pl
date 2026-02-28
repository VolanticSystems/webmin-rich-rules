#!/usr/bin/perl
# Functions for managing firewalld rich rules

BEGIN { push(@INC, ".."); };
use strict;
use warnings;
no warnings 'redefine';
no warnings 'uninitialized';
use WebminCore;
&init_config();

# Import timing functions with error handling
my $timing_available = 0;
eval {
    require Time::HiRes;
    Time::HiRes->import(qw(gettimeofday tv_interval));
    $timing_available = 1;
};
if (!$timing_available) {
    # Fallback timing functions if Time::HiRes not available
    no warnings 'prototype';
    *gettimeofday = sub { return (time(), 0); };
    *tv_interval = sub { return time() - $_[0]->[0]; };
}

# Try to load the existing firewalld module if available
if (&foreign_exists("firewalld")) {
    &foreign_require("firewalld", "firewalld-lib.pl");
}

our ($module_root_directory, %text, %config, %gconfig);
our %access = &get_module_acl();

=head1 firewalld-rich-lib.pl

Library functions for managing firewalld rich rules.

=cut

# Check if firewalld is installed and running
sub check_firewalld_installed
{
#    return &has_command($config{'firewall_cmd'});
    return system("which $config{'firewall_cmd'} >/dev/null 2>&1") == 0;
}

sub is_firewalld_running
{
    my $ex = system("$config{'firewall_cmd'} --state >/dev/null 2>&1 </dev/null");
    return $ex ? 0 : 1;
}

# Execute firewall-cmd with proper error handling
sub execute_firewall_cmd
{
    my ($args, $permanent) = @_;
    my $base_cmd = $config{'firewall_cmd'} || '/usr/bin/firewall-cmd';
    
    # FIXED: Webmin CGI scripts run as root by default - no sudo needed
    # Using sudo was causing the 137 vs 10 rules problem
    my $cmd = "$base_cmd " . $args;
    $cmd .= " --permanent" if $permanent;
    
    # Add timeout and proper error handling
    my $output = &backquote_logged("timeout 30 $cmd 2>&1");
    my $exit_code = $?;
    
    # Log command execution for debugging
    if ($config{'debug_firewall_cmd'}) {
        &error_setup("FIREWALL CMD: $cmd");
        &error_setup("FIREWALL OUTPUT: $output");
        &error_setup("FIREWALL EXIT: $exit_code");
    }
    
    return wantarray ? ($output, $exit_code) : ($exit_code ? $output : undef);
}

# Cached zone list (populated by list_all_rich_rules)
our @_cached_zones;

# Get list of all firewalld zones
sub list_firewalld_zones
{
    # Return cached zones if already populated by list_all_rich_rules
    return @_cached_zones if @_cached_zones;

    my ($output, $err) = execute_firewall_cmd("--get-zones");
    return () if $err;

    my @zones = split(/\s+/, $output);
    return grep { /\S/ } @zones;
}

# Get default zone
sub get_default_zone
{
    my ($output, $err) = execute_firewall_cmd("--get-default-zone");
    return undef if $err;
    
    chomp($output);
    return $output;
}

# Validate zone name
sub validate_zone
{
    my ($zone) = @_;
    return 0 if (!$zone || $zone =~ /[^a-zA-Z0-9_-]/);
    
    my @zones = list_firewalld_zones();
    # If we can't get zones (firewalld not running), allow common zone names
    if (@zones == 0) {
        return ($zone =~ /^(public|private|work|home|internal|external|dmz|trusted|drop|block)$/);
    }
    return grep { $_ eq $zone } @zones;
}

# Get all rich rules for a zone
sub list_rich_rules
{
    my ($zone) = @_;
    
    # ENHANCED ERROR HANDLING: Try multiple approaches with graceful fallbacks
    my ($output, $err);
    
    # Try runtime configuration first (most current)
    ($output, $err) = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --list-rich-rules");
    
    # If runtime fails, try permanent configuration
    if ($err || !$output || $output !~ /\S/) {
        ($output, $err) = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --list-rich-rules --permanent");
    }
    
    # ENHANCED: For default zone, try global list if zone-specific fails
    if (($err || !$output || $output !~ /\S/) && $zone eq get_default_zone()) {
        # Try global runtime first
        ($output, $err) = execute_firewall_cmd("--list-rich-rules");
        
        # Then global permanent
        if ($err || !$output || $output !~ /\S/) {
            ($output, $err) = execute_firewall_cmd("--list-rich-rules --permanent");
        }
    }
    
    # Return empty array if all methods failed
    return () if ($err || !$output || $output !~ /\S/);
    
    my @rules = split(/\n/, $output);
    my @result;
    
    for my $i (0..$#rules) {
        my $rule = $rules[$i];
        next if (!$rule || $rule !~ /\S/);
        
        push @result, {
            'index' => $i,
            'zone' => $zone,
            'text' => $rule,
            'parsed' => parse_rich_rule($rule)
        };
    }
    
    return @result;
}

# Helper function to process rule text into standard format (reduces code duplication)
sub process_rules_to_standard_format
{
    my ($rules_ref, $default_zone) = @_;
    my @processed_rules = ();
    my $rule_index = 0;
    
    for my $rule_data (@$rules_ref) {
        my $rule_text;
        my $rule_zone = $default_zone || 'public';
        
        # Handle different input formats (string vs hash)
        if (ref($rule_data) eq 'HASH') {
            $rule_text = $rule_data->{'text'};
            $rule_zone = $rule_data->{'zone'} || $rule_zone;
        } else {
            $rule_text = $rule_data;
        }
        
        # Skip empty rules
        next if (!$rule_text || $rule_text !~ /\S/);
        chomp($rule_text);
        
        # Try to extract zone from rule text if not already set
        if ($rule_zone eq ($default_zone || 'public') && $rule_text =~ /zone[=\s]+"?([^"\s]+)"?/i) {
            $rule_zone = $1;
        }
        
        push @processed_rules, {
            'index' => $rule_index,
            'zone' => $rule_zone,
            'text' => $rule_text,
            'parsed' => undef
        };
        $rule_index++;
    }
    
    return @processed_rules;
}

# Get all rich rules from all zones using single firewall-cmd call
# Uses --list-all-zones to get everything in one query (~0.5s vs ~4s for per-zone queries)
sub list_all_rich_rules
{
    my @all_rules;

    my ($output, $err) = execute_firewall_cmd("--list-all-zones");
    if ($err) {
        return ();
    }

    # Parse --list-all-zones output: zone names at column 0, rich rules tab-indented
    my $current_zone = '';
    my $in_rich_rules = 0;
    my @cached_zones;

    foreach my $line (split(/\n/, $output)) {
        # Zone name: starts at column 0, no leading whitespace
        if ($line =~ /^(\S+)/) {
            my $zone_name = $1;
            # Zone lines look like "public (active)" or "drop"
            if ($line =~ /^([a-zA-Z0-9_-]+)\s*(\(|$)/) {
                $current_zone = $1;
                push @cached_zones, $current_zone;
                $in_rich_rules = 0;
            }
            next;
        }

        # Indented lines belong to current zone
        if ($line =~ /^\s+rich rules:\s*$/) {
            $in_rich_rules = 1;
            next;
        }

        # Any other section header resets rich rules mode
        if ($line =~ /^\s+\S+:/ && $line !~ /^\t\s*rule\s/) {
            $in_rich_rules = 0;
            next;
        }

        # Tab-indented rule lines under "rich rules:"
        if ($in_rich_rules && $line =~ /^\t\s*(.+)/) {
            my $rule_text = $1;
            next unless $rule_text =~ /\S/;

            push @all_rules, {
                'zone' => $current_zone,
                'text' => $rule_text,
                'parsed' => undef
            };
        }
    }

    # Cache zones for list_firewalld_zones to reuse
    @_cached_zones = @cached_zones;

    # Assign global sequential indices
    for my $i (0 .. $#all_rules) {
        $all_rules[$i]->{'index'} = $i;
    }

    return @all_rules;
}

# Process rich rules from a specific zone
sub process_zone_rules
{
    my ($output, $zone) = @_;
    my @rules = ();
    my $rule_index = 0;
    
    return @rules if (!$output || $output !~ /\S/);
    
    foreach my $line (split(/\n/, $output)) {
        next unless $line =~ /\S/;
        chomp($line);
        
        push @rules, {
            'index' => $rule_index,
            'zone' => $zone,
            'text' => $line,
            'parsed' => undef
        };
        $rule_index++;
    }
    
    return @rules;
}

# Read rich rules from firewalld runtime configuration
sub read_firewalld_runtime_rules
{
    my @rules = ();
    
    # Try multiple paths where firewalld might store runtime configuration
    my @runtime_paths = (
        "/run/firewalld",           # systemd runtime directory
        "/var/run/firewalld",       # traditional runtime directory  
        "/tmp/firewalld",           # fallback runtime directory
    );
    
    foreach my $base_path (@runtime_paths) {
        next unless -d $base_path;
        
        # Look for zone files in runtime directory
        my $zones_path = "$base_path/zones";
        next unless -d $zones_path;
        
        opendir(my $zones_dir, $zones_path) or next;
        my @zone_files = grep { /\.xml$/ && -f "$zones_path/$_" } readdir($zones_dir);
        closedir($zones_dir);
        
        foreach my $zone_file (@zone_files) {
            my $zone_name = $zone_file;
            $zone_name =~ s/\.xml$//;
            
            my @zone_rules = read_zone_config_file("$zones_path/$zone_file", $zone_name);
            push @rules, @zone_rules if @zone_rules;
        }
        
        # If we found rules in this runtime path, use them
        last if @rules > 0;
    }
    
    return @rules;
}

# Read rich rules from firewalld permanent configuration
sub read_firewalld_permanent_rules
{
    my @rules = ();
    
    # Standard firewalld permanent configuration paths
    my @config_paths = (
        "/etc/firewalld",           # Main system configuration
        "/usr/lib/firewalld",       # Distribution defaults
    );
    
    foreach my $base_path (@config_paths) {
        next unless -d $base_path;
        
        # Look for zone files in permanent configuration
        my $zones_path = "$base_path/zones";
        next unless -d $zones_path;
        
        opendir(my $zones_dir, $zones_path) or next;
        my @zone_files = grep { /\.xml$/ && -f "$zones_path/$_" } readdir($zones_dir);
        closedir($zones_dir);
        
        foreach my $zone_file (@zone_files) {
            my $zone_name = $zone_file;
            $zone_name =~ s/\.xml$//;
            
            my @zone_rules = read_zone_config_file("$zones_path/$zone_file", $zone_name);
            push @rules, @zone_rules if @zone_rules;
        }
    }
    
    return @rules;
}

# Read rich rules from a zone XML configuration file
sub read_zone_config_file
{
    my ($file_path, $zone_name) = @_;
    my @rules = ();
    
    return @rules unless -f $file_path && -r $file_path;
    
    # Read the XML file
    if (open(my $fh, '<', $file_path)) {
        my $content = do { local $/; <$fh> };
        close($fh);
        
        # Extract rich rules from XML using regex (faster than XML parsing)
        # Rich rules are stored as: <rule>...rule content...</rule>
        while ($content =~ /<rule[^>]*>(.*?)<\/rule>/gs) {
            my $rule_content = $1;
            
            # Convert XML rule content back to firewall-cmd rich rule format
            my $rule_text = xml_to_rich_rule($rule_content);
            
            if ($rule_text && $rule_text =~ /\S/) {
                push @rules, {
                    'text' => $rule_text,
                    'zone' => $zone_name,
                };
            }
        }
    }
    
    return @rules;
}

# Convert XML rule content to firewall-cmd rich rule text format
sub xml_to_rich_rule
{
    my ($xml_content) = @_;
    return "" unless $xml_content;
    
    my @parts = ();
    
    # Family
    if ($xml_content =~ /family="([^"]+)"/) {
        push @parts, "family=\"$1\"";
    }
    
    # Source
    if ($xml_content =~ /<source[^>]*address="([^"]+)"/) {
        push @parts, "source address=\"$1\"";
    } elsif ($xml_content =~ /<source[^>]*mac="([^"]+)"/) {
        push @parts, "source mac=\"$1\"";
    } elsif ($xml_content =~ /<source[^>]*interface="([^"]+)"/) {
        push @parts, "source interface=\"$1\"";
    } elsif ($xml_content =~ /<source[^>]*ipset="([^"]+)"/) {
        push @parts, "source ipset=\"$1\"";
    }
    
    # Destination
    if ($xml_content =~ /<destination[^>]*address="([^"]+)"/) {
        push @parts, "destination address=\"$1\"";
    } elsif ($xml_content =~ /<destination[^>]*interface="([^"]+)"/) {
        push @parts, "destination interface=\"$1\"";
    }
    
    # Service
    if ($xml_content =~ /<service[^>]*name="([^"]+)"/) {
        push @parts, "service name=\"$1\"";
    }
    
    # Port
    if ($xml_content =~ /<port[^>]*port="([^"]+)"[^>]*protocol="([^"]+)"/) {
        push @parts, "port port=\"$1\" protocol=\"$2\"";
    }
    
    # Protocol
    if ($xml_content =~ /<protocol[^>]*value="([^"]+)"/) {
        push @parts, "protocol value=\"$1\"";
    }
    
    # ICMP block
    if ($xml_content =~ /<icmp-block[^>]*name="([^"]+)"/) {
        push @parts, "icmp-block name=\"$1\"";
    }
    
    # Masquerade
    if ($xml_content =~ /<masquerade/) {
        push @parts, "masquerade";
    }
    
    # Forward port
    if ($xml_content =~ /<forward-port[^>]*port="([^"]+)"[^>]*protocol="([^"]+)"(?:[^>]*to-port="([^"]+)")?(?:[^>]*to-addr="([^"]+)")?/) {
        my $fwd = "forward-port port=\"$1\" protocol=\"$2\"";
        $fwd .= " to-port=\"$3\"" if $3;
        $fwd .= " to-addr=\"$4\"" if $4;
        push @parts, $fwd;
    }
    
    # Log
    if ($xml_content =~ /<log(?:[^>]*prefix="([^"]*)")?(?:[^>]*level="([^"]+)")?(?:[^>]*limit[^>]*value="([^"]+)")?/) {
        my $log = "log";
        $log .= " prefix=\"$1\"" if $1;
        $log .= " level=\"$2\"" if $2;
        $log .= " limit value=\"$3\"" if $3;
        push @parts, $log;
    }
    
    # Audit
    if ($xml_content =~ /<audit/) {
        push @parts, "audit";
    }
    
    # Action (accept, reject, drop)
    if ($xml_content =~ /<accept/) {
        push @parts, "accept";
    } elsif ($xml_content =~ /<reject(?:[^>]*type="([^"]+)")?/) {
        my $action = "reject";
        $action .= " type=\"$1\"" if $1;
        push @parts, $action;
    } elsif ($xml_content =~ /<drop/) {
        push @parts, "drop";
    }
    
    # Build final rule text
    my $rule_text = join(" ", @parts);
    return $rule_text;
}

# Legacy command-based rule loading (fallback only)
sub list_all_rich_rules_legacy
{
    my @all_rules;
    my $rule_index = 0;  # Global index counter for consistency
    
    # CRITICAL FIX: Query ALL zones, not just default zone
    # fail2ban rules are typically in 'public' zone specifically
    my @zones = list_firewalld_zones();
    
    foreach my $zone (@zones) {
        my ($output, $err) = execute_firewall_cmd("--zone=$zone --list-rich-rules");
        
        if (!$err && $output && $output =~ /\S/) {
            my @rule_lines = split(/\n/, $output);
            
            for my $i (0..$#rule_lines) {
                my $rule = $rule_lines[$i];
                next if (!$rule || $rule !~ /\S/);
                
                push @all_rules, {
                    'index' => $rule_index,  # Use incremental index
                    'zone' => $zone,         # Use actual zone, not default
                    'text' => $rule,
                    'parsed' => undef
                };
                $rule_index++;  # Increment for next rule
            }
        }
    }
    
    # Debug output for fail2ban detection
    if ($config{'debug_fail2ban'}) {
        &error_setup("list_all_rich_rules_legacy found " . scalar(@all_rules) . " total rules");
        my $f2b_count = scalar(grep { categorize_rich_rule($_->{'text'}) eq 'fail2ban' } @all_rules);
        &error_setup("Categorized $f2b_count rules as fail2ban");
    }
    
    return @all_rules;
}

# Get parsed rule data on demand (lazy loading for performance)
sub get_parsed_rule
{
    my ($rule_ref) = @_;
    
    # Parse on first access if not already parsed
    if (!defined $rule_ref->{'parsed'}) {
        $rule_ref->{'parsed'} = parse_rich_rule($rule_ref->{'text'});
    }
    
    return $rule_ref->{'parsed'};
}

# REMOVED: detect_rule_zone function (was causing 9+ minute page loads)
# The function was executing 143 rules × 9 zones = 1,287 firewall-cmd commands
# Simple zone assignment works fine for rule management

# Parse a rich rule text into components
sub parse_rich_rule
{
    my ($rule_text) = @_;
    return undef if (!$rule_text);
    
    my %parsed;
    
    # Extract family
    if ($rule_text =~ /family="([^"]+)"/) {
        $parsed{'family'} = $1;
    }
    
    # Extract source
    if ($rule_text =~ /source\s+address="([^"]+)"/) {
        $parsed{'source_address'} = $1;
    }
    if ($rule_text =~ /source\s+mac="([^"]+)"/) {
        $parsed{'source_mac'} = $1;
    }
    if ($rule_text =~ /source\s+interface="([^"]+)"/) {
        $parsed{'source_interface'} = $1;
    }
    if ($rule_text =~ /source\s+ipset="([^"]+)"/) {
        $parsed{'source_ipset'} = $1;
    }
    
    # Extract destination
    if ($rule_text =~ /destination\s+address="([^"]+)"/) {
        $parsed{'destination_address'} = $1;
    }
    if ($rule_text =~ /destination\s+interface="([^"]+)"/) {
        $parsed{'destination_interface'} = $1;
    }
    
    # Extract service
    if ($rule_text =~ /service\s+name="([^"]+)"/) {
        $parsed{'service_name'} = $1;
    }
    
    # Extract port
    if ($rule_text =~ /port\s+port="([^"]+)"\s+protocol="([^"]+)"/) {
        $parsed{'port'} = $1;
        $parsed{'protocol'} = $2;
    }
    
    # Extract protocol value
    if ($rule_text =~ /protocol\s+value="([^"]+)"/) {
        $parsed{'protocol_value'} = $1;
    }
    
    # Extract ICMP block
    if ($rule_text =~ /icmp-block\s+name="([^"]+)"/) {
        $parsed{'icmp_block'} = $1;
    }
    
    # Extract masquerade
    if ($rule_text =~ /masquerade/) {
        $parsed{'masquerade'} = 1;
    }
    
    # Extract forward port
    if ($rule_text =~ /forward-port\s+port="([^"]+)"\s+protocol="([^"]+)"(?:\s+to-port="([^"]+)")?(?:\s+to-addr="([^"]+)")?/) {
        $parsed{'forward_port'} = $1;
        $parsed{'forward_protocol'} = $2;
        $parsed{'forward_to_port'} = $3 if $3;
        $parsed{'forward_to_addr'} = $4 if $4;
    }
    
    # Extract logging
    if ($rule_text =~ /log(?:\s+prefix="([^"]*)")?(?:\s+level="([^"]+)")?(?:\s+limit\s+value="([^"]+)")?/) {
        $parsed{'log'} = 1;
        $parsed{'log_prefix'} = $1 if defined $1;
        $parsed{'log_level'} = $2 if $2;
        $parsed{'log_limit'} = $3 if $3;
    }
    
    # Extract audit
    if ($rule_text =~ /audit/) {
        $parsed{'audit'} = 1;
    }
    
    # Extract action
    if ($rule_text =~ /accept/) {
        $parsed{'action'} = 'accept';
    } elsif ($rule_text =~ /reject(?:\s+type="([^"]+)")?/) {
        $parsed{'action'} = 'reject';
        $parsed{'reject_type'} = $1 if $1;
    } elsif ($rule_text =~ /drop/) {
        $parsed{'action'} = 'drop';
    }
    
    return \%parsed;
}

# Construct rich rule text from components
sub construct_rich_rule
{
    my (%opts) = @_;
    
    my $rule = "rule";
    
    # Add priority
    if ($opts{'priority'}) {
        $rule .= " priority=\"" . $opts{'priority'} . "\"";
    }
    
    # Add family
    if ($opts{'family'} && $opts{'family'} ne 'both') {
        $rule .= " family=\"" . $opts{'family'} . "\"";
    }
    
    # Add source
    if ($opts{'source_address'}) {
        $rule .= " source address=\"" . $opts{'source_address'} . "\"";
    } elsif ($opts{'source_mac'}) {
        $rule .= " source mac=\"" . $opts{'source_mac'} . "\"";
    } elsif ($opts{'source_interface'}) {
        $rule .= " source interface=\"" . $opts{'source_interface'} . "\"";
    } elsif ($opts{'source_ipset'}) {
        $rule .= " source ipset=\"" . $opts{'source_ipset'} . "\"";
    }
    
    # Add destination
    if ($opts{'destination_address'}) {
        $rule .= " destination address=\"" . $opts{'destination_address'} . "\"";
    } elsif ($opts{'destination_interface'}) {
        $rule .= " destination interface=\"" . $opts{'destination_interface'} . "\"";
    }
    
    # Add service or port
    if ($opts{'service_name'}) {
        $rule .= " service name=\"" . $opts{'service_name'} . "\"";
    } elsif ($opts{'port'} && $opts{'protocol'}) {
        $rule .= " port port=\"" . $opts{'port'} . "\" protocol=\"" . $opts{'protocol'} . "\"";
    }
    
    # Add protocol value
    if ($opts{'protocol_value'}) {
        $rule .= " protocol value=\"" . $opts{'protocol_value'} . "\"";
    }
    
    # Add ICMP block
    if ($opts{'icmp_block'}) {
        $rule .= " icmp-block name=\"" . $opts{'icmp_block'} . "\"";
    }
    
    # Add masquerade
    if ($opts{'masquerade'}) {
        $rule .= " masquerade";
    }
    
    # Add forward port
    if ($opts{'forward_port'} && $opts{'forward_protocol'}) {
        $rule .= " forward-port port=\"" . $opts{'forward_port'} . "\" protocol=\"" . $opts{'forward_protocol'} . "\"";
        if ($opts{'forward_to_port'}) {
            $rule .= " to-port=\"" . $opts{'forward_to_port'} . "\"";
        }
        if ($opts{'forward_to_addr'}) {
            $rule .= " to-addr=\"" . $opts{'forward_to_addr'} . "\"";
        }
    }
    
    # Add logging
    if ($opts{'log'}) {
        $rule .= " log";
        if ($opts{'log_prefix'}) {
            $rule .= " prefix=\"" . $opts{'log_prefix'} . "\"";
        }
        if ($opts{'log_level'}) {
            $rule .= " level=\"" . $opts{'log_level'} . "\"";
        }
        if ($opts{'log_limit'}) {
            $rule .= " limit value=\"" . $opts{'log_limit'} . "\"";
        }
    }
    
    # Add audit
    if ($opts{'audit'}) {
        $rule .= " audit";
    }
    
    # Add action
    if ($opts{'action'} eq 'accept') {
        $rule .= " accept";
    } elsif ($opts{'action'} eq 'reject') {
        $rule .= " reject";
        if ($opts{'reject_type'}) {
            $rule .= " type=\"" . $opts{'reject_type'} . "\"";
        }
    } elsif ($opts{'action'} eq 'drop') {
        $rule .= " drop";
    }
    
    return $rule;
}

# Validate rich rule syntax and components
sub validate_rich_rule
{
    my ($rule_text) = @_;
    
    return "No rule text provided" if (!$rule_text || $rule_text !~ /\S/);
    
    # Basic syntax check
    return "Rule must start with 'rule'" if ($rule_text !~ /^rule\s/);
    
    # Parse the rule to validate components
    my $parsed = parse_rich_rule($rule_text);
    return "Failed to parse rule" if (!$parsed);
    
    # Validate family
    if ($parsed->{'family'} && $parsed->{'family'} !~ /^(ipv4|ipv6)$/) {
        return "Invalid family: must be ipv4 or ipv6";
    }
    
    # Validate source address
    if ($parsed->{'source_address'}) {
        my $addr = $parsed->{'source_address'};
        if ($addr !~ /^[\d\.\/]+$/ && $addr !~ /^[a-fA-F0-9:\/]+$/) {
            return "Invalid source address format";
        }
    }
    
    # Validate MAC address
    if ($parsed->{'source_mac'}) {
        my $mac = $parsed->{'source_mac'};
        if ($mac !~ /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/) {
            return "Invalid MAC address format";
        }
    }
    
    # Validate port
    if ($parsed->{'port'}) {
        my $port = $parsed->{'port'};
        if ($port =~ /^(\d+)-(\d+)$/) {
            my ($start, $end) = ($1, $2);
            return "Invalid port range" if ($start < 1 || $end > 65535 || $start > $end);
        } elsif ($port =~ /^\d+$/) {
            return "Invalid port number" if ($port < 1 || $port > 65535);
        } else {
            return "Invalid port format";
        }
    }
    
    # Validate protocol
    if ($parsed->{'protocol'} && $parsed->{'protocol'} !~ /^(tcp|udp|sctp|dccp)$/) {
        return "Invalid protocol: must be tcp, udp, sctp, or dccp";
    }
    
    # Validate action
    if ($parsed->{'action'} && $parsed->{'action'} !~ /^(accept|reject|drop)$/) {
        return "Invalid action: must be accept, reject, or drop";
    }
    
    # Validate log level
    if ($parsed->{'log_level'} && $parsed->{'log_level'} !~ /^(emerg|alert|crit|err|warn|notice|info|debug)$/) {
        return "Invalid log level";
    }
    
    return undef; # No errors
}

# Shell-escape a rich rule for use inside single quotes
sub _shell_quote_rule
{
    my ($rule) = @_;
    $rule =~ s/'/'\\''/g;
    return $rule;
}

# Add rich rule to zone
sub add_rich_rule
{
    my ($rule_text, $zone) = @_;

    # Validate inputs
    return "Invalid zone" if (!validate_zone($zone));
    my $validate_err = validate_rich_rule($rule_text);
    return $validate_err if ($validate_err);

    # Check for conflicts
    my @existing = list_rich_rules($zone);
    for my $existing_rule (@existing) {
        if ($existing_rule->{'text'} eq $rule_text) {
            return "Rule already exists in zone";
        }
    }

    # Add the rule (permanent)
    my $safe_rule = _shell_quote_rule($rule_text);
    my $err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --add-rich-rule='" . $safe_rule . "'", 1);
    return $err if ($err);

    # Reload to apply changes
    my $reload_err = execute_firewall_cmd("--reload");
    return $reload_err if ($reload_err);

    return undef;
}

# Remove rich rule from zone
sub remove_rich_rule
{
    my ($rule_text, $zone) = @_;

    # Validate inputs
    return "Invalid zone" if (!validate_zone($zone));

    # Remove the rule (permanent)
    my $safe_rule = _shell_quote_rule($rule_text);
    my $err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --remove-rich-rule='" . $safe_rule . "'", 1);
    return $err if ($err);

    # Reload to apply changes
    my $reload_err = execute_firewall_cmd("--reload");
    return $reload_err if ($reload_err);

    return undef;
}

# Modify rich rule (atomic replace)
sub modify_rich_rule
{
    my ($old_rule, $new_rule, $zone) = @_;

    # Validate inputs
    return "Invalid zone" if (!validate_zone($zone));
    my $validate_err = validate_rich_rule($new_rule);
    return $validate_err if ($validate_err);

    # Check if new rule conflicts with existing (except the one being replaced)
    my @existing = list_rich_rules($zone);
    for my $existing_rule (@existing) {
        if ($existing_rule->{'text'} eq $new_rule && $existing_rule->{'text'} ne $old_rule) {
            return "New rule conflicts with existing rule";
        }
    }

    my $safe_old = _shell_quote_rule($old_rule);
    my $safe_new = _shell_quote_rule($new_rule);

    # Remove old rule
    my $remove_err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --remove-rich-rule='" . $safe_old . "'", 1);
    return $remove_err if ($remove_err);

    # Add new rule
    my $add_err = execute_firewall_cmd("--zone=" . quotemeta($zone) . " --add-rich-rule='" . $safe_new . "'", 1);
    if ($add_err) {
        # Try to restore old rule on failure
        execute_firewall_cmd("--zone=" . quotemeta($zone) . " --add-rich-rule='" . $safe_old . "'", 1);
        return $add_err;
    }

    # Reload to apply changes
    my $reload_err = execute_firewall_cmd("--reload");
    return $reload_err if ($reload_err);

    return undef;
}

# Get list of available services
sub get_firewalld_services
{
    my ($output, $err) = execute_firewall_cmd("--get-services");
    return () if $err;
    
    my @services = split(/\s+/, $output);
    return grep { /\S/ } @services;
}

# Get list of available ICMP types
sub get_firewalld_icmp_types
{
    my ($output, $err) = execute_firewall_cmd("--get-icmptypes");
    return () if $err;
    
    my @types = split(/\s+/, $output);
    return grep { /\S/ } @types;
}

# Reload firewalld configuration
sub reload_firewalld
{
    return execute_firewall_cmd("--reload");
}

# Get firewalld version
sub get_firewalld_version
{
    my ($output, $err) = execute_firewall_cmd("--version");
    return undef if $err;
    
    chomp($output);
    return $output;
}

# Check if rich rules are supported
sub rich_rules_supported
{
    my $version = get_firewalld_version();
    return 0 if (!$version);
    
    # Rich rules supported in firewalld >= 0.3.0
    if ($version =~ /^(\d+)\.(\d+)\.(\d+)/) {
        my ($major, $minor, $patch) = ($1, $2, $3);
        return 1 if ($major > 0 || ($major == 0 && $minor >= 3));
    }
    
    return 0;
}

# Backup firewalld configuration
sub backup_firewalld_config
{
    my $backup_dir = "/tmp/firewalld-backup-" . time();
    system("mkdir -p $backup_dir");
    system("cp -r $config{'config_dir'}/* $backup_dir/ 2>/dev/null");
    return $backup_dir;
}

# Categorize rich rule based on patterns
# Enhanced with production data analysis from background/debug/
sub categorize_rich_rule
{
    my ($rule_text) = @_;
    
    # Debug logging if enabled
    if ($config{'debug_categorization'}) {
        &error_setup("Categorizing rule: $rule_text");
        &error_setup("Rule length: " . length($rule_text) . " characters");
        
        # Test specific fail2ban patterns
        if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
            &error_setup("MATCH: Pattern 1 (email services)");
        }
        if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
            &error_setup("MATCH: Pattern 4 (icmp-port-unreachable)");
        }
    }
    
    # Enhanced fail2ban detection based on real production patterns
    # From diagnostic data: fail2ban rules are single IPs with email service rejects
    
    # Pattern 1: Single IP with email services and reject (most common fail2ban pattern)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        return 'fail2ban';
    }
    
    # Pattern 2: Single IP with SSH and reject/drop (classic fail2ban SSH protection)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*(?:ssh|port port="22").*(?:reject|drop)/i) {
        return 'fail2ban';
    }
    
    # Pattern 3: Single IP with HTTP services and reject/drop (web protection)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*(?:http|port port="80"|port port="443").*(?:reject|drop)/i) {
        return 'fail2ban';
    }
    
    # Pattern 4: Single IP with icmp-port-unreachable (specific fail2ban signature from production)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        return 'fail2ban';
    }
    
    # Pattern 5: Single IP with any reject/drop (generic fail2ban pattern)
    if ($rule_text =~ /source address="[\d.]+(?:\/32)?".*(?:reject|drop)/i && $rule_text !~ /\/(?:[0-9]|1[0-9]|2[0-9]|3[01])"/) {
        return 'fail2ban';
    }
    
    # Admin patterns (validated from production data)
    
    # Pattern 1: Network blocks with CIDR (confirmed admin pattern from diagnostic data)
    if ($rule_text =~ /source address="[\d.]+\/(?:[0-9]|1[0-9]|2[0-9]|3[01])"/ && $rule_text !~ /\/32/) {
        return 'admin';
    }
    
    # Pattern 2: Accept rules (most admin rules from production data use accept)
    if ($rule_text =~ /accept/i) {
        return 'admin';
    }
    
    # Pattern 3: Complex rules with logging (confirmed admin pattern)
    if ($rule_text =~ /log.*accept/i || $rule_text =~ /forward-port/i) {
        return 'admin';
    }
    
    # Pattern 4: Rules with masquerade (always admin)
    if ($rule_text =~ /masquerade/i) {
        return 'admin';
    }
    
    # Pattern 5: Port forwarding rules (always admin)
    if ($rule_text =~ /forward-port/i) {
        return 'admin';
    }
    
    # Pattern 6: Rules with specific administrative ports
    if ($rule_text =~ /port="(?:22|3306|20000|10000)"/i) {
        return 'admin';
    }
    
    # Debug logging
    if ($config{'debug_categorization'}) {
        &error_setup("Rule categorized as unknown: $rule_text");
    }
    
    return 'unknown';
}

# Filter rules based on search criteria
sub filter_rules
{
    my ($rules_ref, $filter_opts) = @_;
    my @filtered_rules;
    
    foreach my $rule (@{$rules_ref}) {
        my $include = 1;
        my $parsed = $rule->{'parsed'};
        
        # IP/Network filter
        if ($filter_opts->{'ip'} && $filter_opts->{'ip'} ne '') {
            my $ip_filter = $filter_opts->{'ip'};
            $include = 0;
            
            # Check source address
            if ($parsed->{'source_address'}) {
                if ($ip_filter =~ /\*/) {
                    # Wildcard matching
                    my $pattern = $ip_filter;
                    $pattern =~ s/\*/\.\*/g;
                    $include = 1 if ($parsed->{'source_address'} =~ /$pattern/);
                } elsif ($ip_filter =~ /\//) {
                    # CIDR matching - simple contains check
                    $include = 1 if ($parsed->{'source_address'} =~ /\Q$ip_filter\E/);
                } else {
                    # Direct IP match
                    $include = 1 if ($parsed->{'source_address'} =~ /\Q$ip_filter\E/);
                }
            }
            
            # Check destination address
            if ($parsed->{'destination_address'}) {
                if ($ip_filter =~ /\*/) {
                    my $pattern = $ip_filter;
                    $pattern =~ s/\*/\.\*/g;
                    $include = 1 if ($parsed->{'destination_address'} =~ /$pattern/);
                } elsif ($parsed->{'destination_address'} =~ /\Q$ip_filter\E/) {
                    $include = 1;
                }
            }
        }
        
        # Port filter
        if ($filter_opts->{'port'} && $filter_opts->{'port'} ne '' && $include) {
            my $port_filter = $filter_opts->{'port'};
            $include = 0;
            
            if ($parsed->{'port'}) {
                if ($port_filter =~ /,/) {
                    # Multiple ports
                    my @ports = split(/,/, $port_filter);
                    foreach my $p (@ports) {
                        $p =~ s/\s+//g;
                        if ($parsed->{'port'} =~ /\Q$p\E/) {
                            $include = 1;
                            last;
                        }
                    }
                } elsif ($port_filter =~ /-/) {
                    # Port range
                    my ($start, $end) = split(/-/, $port_filter);
                    if ($parsed->{'port'} =~ /(\d+)/) {
                        my $rule_port = $1;
                        $include = 1 if ($rule_port >= $start && $rule_port <= $end);
                    }
                } else {
                    # Single port
                    $include = 1 if ($parsed->{'port'} =~ /\Q$port_filter\E/);
                }
            }
            
            # Also check forward ports
            if ($parsed->{'forward_port'}) {
                $include = 1 if ($parsed->{'forward_port'} =~ /\Q$port_filter\E/);
            }
        }
        
        # Protocol filter
        if ($filter_opts->{'protocol'} && $filter_opts->{'protocol'} ne '' && $filter_opts->{'protocol'} ne 'all' && $include) {
            $include = 0;
            if ($parsed->{'protocol'}) {
                $include = 1 if (lc($parsed->{'protocol'}) eq lc($filter_opts->{'protocol'}));
            }
        }
        
        # Service filter
        if ($filter_opts->{'service'} && $filter_opts->{'service'} ne '' && $include) {
            $include = 0;
            if ($parsed->{'service_name'}) {
                $include = 1 if ($parsed->{'service_name'} =~ /\Q$filter_opts->{'service'}\E/i);
            }
        }
        
        # Action filter (legacy)
        if ($filter_opts->{'action'} && $filter_opts->{'action'} ne '' && $filter_opts->{'action'} ne 'all' && $include) {
            $include = 0;
            if ($parsed->{'action'}) {
                $include = 1 if (lc($parsed->{'action'}) eq lc($filter_opts->{'action'}));
            }
        }
        
        # Action Type filter (new enhanced filter)
        if ($filter_opts->{'action_type'} && $filter_opts->{'action_type'} ne '' && $filter_opts->{'action_type'} ne 'all' && $include) {
            $include = 0;
            if ($parsed->{'action'}) {
                $include = 1 if (lc($parsed->{'action'}) eq lc($filter_opts->{'action_type'}));
            }
        }
        
        # Source/Category filter
        if ($filter_opts->{'source'} && $filter_opts->{'source'} ne '' && $filter_opts->{'source'} ne 'all' && $include) {
            my $category = categorize_rich_rule($rule->{'text'});
            $include = 0;
            $include = 1 if ($filter_opts->{'source'} eq $category);
        }
        
        push @filtered_rules, $rule if $include;
    }
    
    return @filtered_rules;
}

# Get fail2ban status and active jails
sub get_fail2ban_status
{
    my $has_fail2ban = system("which fail2ban-client >/dev/null 2>&1") == 0;
    return () unless $has_fail2ban;
    
    my $output = `fail2ban-client status 2>/dev/null`;
    return () if $?;
    
    my @jails;
    if ($output =~ /Jail list:\s*(.+)/) {
        @jails = split(/,\s*/, $1);
    }
    
    return @jails;
}

# Check if IP is banned by fail2ban
sub is_ip_fail2ban_banned
{
    my ($ip) = @_;
    return 0 unless $ip;
    
    my @jails = get_fail2ban_status();
    return 0 unless @jails;
    
    foreach my $jail (@jails) {
        $jail =~ s/^\s+|\s+$//g;
        my $output = `fail2ban-client status $jail 2>/dev/null`;
        next if $?;
        
        if ($output =~ /Banned IP list:\s*(.+)/) {
            my $banned_ips = $1;
            return 1 if ($banned_ips =~ /\Q$ip\E/);
        }
    }
    
    return 0;
}

# Unban IP from fail2ban
sub fail2ban_unban_ip
{
    my ($ip) = @_;
    return "No IP specified" unless $ip;
    
    my @jails = get_fail2ban_status();
    return "fail2ban not available" unless @jails;
    
    foreach my $jail (@jails) {
        $jail =~ s/^\s+|\s+$//g;
        my $output = `fail2ban-client status $jail 2>/dev/null`;
        next if $?;
        
        if ($output =~ /Banned IP list:\s*(.+)/) {
            my $banned_ips = $1;
            if ($banned_ips =~ /\Q$ip\E/) {
                system("fail2ban-client unban $ip 2>/dev/null");
                return undef; # Success
            }
        }
    }
    
    return "IP not found in fail2ban";
}

# Diagnostic functions for production debugging based on real data
sub diagnose_fail2ban_detection
{
    my @all_rules = &list_all_rich_rules();
    my %stats = (
        'total' => scalar(@all_rules),
        'admin' => 0,
        'fail2ban' => 0,
        'unknown' => 0
    );
    
    my @examples;
    
    foreach my $rule (@all_rules) {
        my $category = &categorize_rich_rule($rule->{'text'});
        $stats{$category}++;
        
        # Collect examples for debugging - compare against diagnostic report patterns
        if ($config{'debug_categorization'} && scalar(@examples) < 10) {
            push @examples, {
                'category' => $category,
                'zone' => $rule->{'zone'},
                'text' => $rule->{'text'}
            };
            &error_setup("Example $category rule in " . $rule->{'zone'} . ": " . $rule->{'text'});
        }
    }
    
    return (\%stats, \@examples);
}

# Validate categorization against known production patterns
sub validate_against_diagnostic_data
{
    # Test cases for categorization validation (using RFC 5737 documentation IPs)
    my @test_cases = (
        # fail2ban patterns
        {
            'rule' => 'rule family="ipv4" source address="198.51.100.10" port port="imap" protocol="tcp" reject type="icmp-port-unreachable"',
            'expected' => 'fail2ban',
            'description' => 'Email service fail2ban rule with icmp-port-unreachable'
        },
        {
            'rule' => 'rule family="ipv4" source address="198.51.100.20" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"',
            'expected' => 'fail2ban',
            'description' => 'SMTP fail2ban rule'
        },
        {
            'rule' => 'rule family="ipv4" source address="198.51.100.30" port port="465" protocol="tcp" reject type="icmp-port-unreachable"',
            'expected' => 'fail2ban',
            'description' => 'SMTPS fail2ban rule'
        },
        # Admin patterns
        {
            'rule' => 'rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" accept',
            'expected' => 'admin',
            'description' => 'Network range admin rule with accept'
        },
        {
            'rule' => 'rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept',
            'expected' => 'admin',
            'description' => 'Large network admin rule'
        },
        {
            'rule' => 'rule family="ipv4" source address="203.0.113.0/24" port port="3306" protocol="tcp" accept',
            'expected' => 'admin',
            'description' => 'MySQL admin access rule'
        }
    );
    
    my $passed = 0;
    my $total = scalar(@test_cases);
    my @failures;
    
    foreach my $test (@test_cases) {
        my $result = categorize_rich_rule($test->{'rule'});
        if ($result eq $test->{'expected'}) {
            $passed++;
            if ($config{'debug_categorization'}) {
                &error_setup("PASS: " . $test->{'description'} . " -> $result");
            }
        } else {
            push @failures, {
                'description' => $test->{'description'},
                'rule' => $test->{'rule'},
                'expected' => $test->{'expected'},
                'actual' => $result
            };
            if ($config{'debug_categorization'}) {
                &error_setup("FAIL: " . $test->{'description'} . " -> expected " . $test->{'expected'} . ", got $result");
            }
        }
    }
    
    return {
        'total' => $total,
        'passed' => $passed,
        'failed' => $total - $passed,
        'failures' => \@failures
    };
}

# Enhanced fail2ban integration testing with real jails
sub test_fail2ban_integration
{
    my @jails = get_fail2ban_status();
    my %integration_status = (
        'fail2ban_available' => scalar(@jails) > 0,
        'active_jails' => scalar(@jails),
        'jail_list' => \@jails
    );
    
    if ($integration_status{'fail2ban_available'}) {
        # Test each jail for banned IPs
        foreach my $jail (@jails) {
            $jail =~ s/^\s+|\s+$//g;
            my $output = `fail2ban-client status $jail 2>/dev/null`;
            if (!$? && $output =~ /Banned IP list:\s*(.+)/) {
                my $banned_ips = $1;
                $banned_ips =~ s/^\s+|\s+$//g;
                if ($banned_ips) {
                    my @ips = split(/\s+/, $banned_ips);
                    $integration_status{"jail_$jail"} = \@ips;
                }
            }
        }
    }
    
    return \%integration_status;
}

1;
