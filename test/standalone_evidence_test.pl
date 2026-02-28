#!/usr/bin/perl
# Standalone Evidence Test - No library dependencies
# Gather basic system facts about fail2ban and firewall rules

use strict;
use warnings;

print "=== Standalone System Evidence Test ===\n";
print "Gathering basic system facts (no module dependencies)\n\n";

# EVIDENCE 1: fail2ban service status
print "1. FAIL2BAN SERVICE STATUS:\n";
my $f2b_status = `systemctl is-active fail2ban 2>/dev/null`;
chomp($f2b_status);
print "   systemctl is-active fail2ban: $f2b_status\n";

my $f2b_enabled = `systemctl is-enabled fail2ban 2>/dev/null`;
chomp($f2b_enabled);
print "   systemctl is-enabled fail2ban: $f2b_enabled\n";

# EVIDENCE 2: fail2ban jail status
print "\n2. FAIL2BAN JAIL STATUS:\n";
my $jail_status = `fail2ban-client status 2>/dev/null`;
if ($jail_status) {
    print "   fail2ban-client status output:\n";
    print "   " . join("\n   ", split(/\n/, $jail_status)) . "\n";
} else {
    print "   fail2ban-client status: No output or command failed\n";
}

# EVIDENCE 3: Raw firewall rules
print "\n3. RAW FIREWALL RULES:\n";
my $raw_rules = `firewall-cmd --list-rich-rules 2>/dev/null`;
my @rule_lines = split(/\n/, $raw_rules);
my $total_rules = scalar(@rule_lines);
print "   Total rules from firewall-cmd: $total_rules\n";

# Show first 10 rules for pattern analysis
print "   First 10 rules (for pattern analysis):\n";
for my $i (0..9) {
    last if $i >= @rule_lines;
    print "   [$i]: $rule_lines[$i]\n";
}

# EVIDENCE 4: Pattern matching tests (manual patterns)
print "\n4. MANUAL PATTERN MATCHING TESTS:\n";
print "   Testing fail2ban patterns against actual rules...\n";

my @fail2ban_matches = ();
my @pattern_results = ();

for my $rule (@rule_lines) {
    next if !$rule || $rule !~ /\S/;
    
    # Test each fail2ban pattern manually
    my $match_found = 0;
    
    # Pattern 1: Email services with reject
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*port port="(?:imap|smtp|pop3s?|465|587|995|993|25|143|110)".*reject/i) {
        push @fail2ban_matches, "Pattern 1 (email): $rule";
        $match_found = 1;
    }
    
    # Pattern 2: SSH with reject/drop
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*(?:ssh|port port="22").*(?:reject|drop)/i) {
        push @fail2ban_matches, "Pattern 2 (ssh): $rule";
        $match_found = 1;
    }
    
    # Pattern 3: HTTP services with reject/drop
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*(?:http|port port="80"|port port="443").*(?:reject|drop)/i) {
        push @fail2ban_matches, "Pattern 3 (http): $rule";
        $match_found = 1;
    }
    
    # Pattern 4: icmp-port-unreachable (common fail2ban signature)
    if ($rule =~ /source address="[\d.]+(?:\/32)?".*reject type="icmp-port-unreachable"/i) {
        push @fail2ban_matches, "Pattern 4 (icmp): $rule";
        $match_found = 1;
    }
    
    # Pattern 5: Single IP with reject/drop (general fail2ban pattern)
    if ($rule =~ /source address="[\d.]+\/32".*(?:reject|drop)/i) {
        push @fail2ban_matches, "Pattern 5 (single IP): $rule";
        $match_found = 1;
    }
    
    # Store result for analysis
    push @pattern_results, {
        'rule' => $rule,
        'matched' => $match_found
    };
}

print "   fail2ban pattern matches found: " . scalar(@fail2ban_matches) . "\n";
if (@fail2ban_matches) {
    print "   First few matches:\n";
    for my $i (0..4) {
        last if $i >= @fail2ban_matches;
        print "   $fail2ban_matches[$i]\n";
    }
} else {
    print "   No fail2ban patterns matched any rules\n";
    print "   Sample of rules that didn't match:\n";
    for my $i (0..4) {
        last if $i >= @rule_lines;
        print "   Non-match: $rule_lines[$i]\n";
    }
}

# EVIDENCE 5: Zone analysis
print "\n5. ZONE ANALYSIS:\n";
my $zones_output = `firewall-cmd --get-zones 2>/dev/null`;
my @zones = split(/\s+/, $zones_output);
print "   Available zones: " . join(", ", @zones) . "\n";

foreach my $zone (@zones) {
    my $zone_output = `firewall-cmd --zone=$zone --list-rich-rules 2>/dev/null`;
    my $zone_count = scalar(split(/\n/, $zone_output));
    print "   Zone $zone: $zone_count rules\n";
}

# EVIDENCE 6: IP analysis
print "\n6. IP ADDRESS ANALYSIS:\n";
my %ip_patterns = ();
my $single_ip_count = 0;
my $network_count = 0;

for my $rule (@rule_lines) {
    next if !$rule || $rule !~ /\S/;
    
    if ($rule =~ /source address="([\d.]+\/32)"/i) {
        $single_ip_count++;
        my $ip = $1;
        $ip_patterns{$ip}++;
    } elsif ($rule =~ /source address="([\d.]+\/\d+)"/i) {
        $network_count++;
        my $network = $1;
        $ip_patterns{$network}++;
    }
}

print "   Single IP rules (/32): $single_ip_count\n";
print "   Network rules (other CIDR): $network_count\n";
print "   Most common source addresses:\n";

my @sorted_ips = sort { $ip_patterns{$b} <=> $ip_patterns{$a} } keys %ip_patterns;
for my $i (0..9) {
    last if $i >= @sorted_ips;
    my $ip = $sorted_ips[$i];
    print "   $ip: $ip_patterns{$ip} rules\n";
}

print "\n=== EVIDENCE SUMMARY ===\n";
print "fail2ban service: $f2b_status\n";
print "Total firewall rules: $total_rules\n";
print "fail2ban pattern matches: " . scalar(@fail2ban_matches) . "\n";
print "Single IP rules (/32): $single_ip_count\n";
print "Network rules: $network_count\n";

if (scalar(@fail2ban_matches) == 0) {
    print "\nCRITICAL FINDING: No rules match fail2ban patterns\n";
    print "This suggests either:\n";
    print "- fail2ban rules don't exist on this system\n";
    print "- fail2ban uses different rule format than expected\n";
    print "- Patterns are incorrect for this fail2ban version\n";
} else {
    print "\nCRITICAL FINDING: " . scalar(@fail2ban_matches) . " rules match fail2ban patterns\n";
    print "This suggests fail2ban rules exist and should be detected by module\n";
}

print "\nStandalone test complete - basic evidence gathered.\n";