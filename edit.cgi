#!/usr/bin/perl
# Edit or create a firewalld rich rule

require './firewalld-rich-lib.pl';

# Check if firewalld is installed and running
if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    &error($text{'edit_einstall'});
}

&ReadParse();

# Determine if this is a new rule or editing existing
my $new = $in{'new'};
my $clone = $in{'clone'};
my $zone = $in{'zone'} || get_default_zone();
my $idx = $in{'idx'};

my $rule_text = '';
my $parsed = {};

if (!$new && defined($idx) && $idx ne '') {
    # Editing existing rule - use global index from list_all_rich_rules()
    my @all_rules = list_all_rich_rules();
    if ($idx =~ /^\d+$/ && $idx >= 0 && $idx < scalar(@all_rules)) {
        $rule_text = $all_rules[$idx]->{'text'};
        $parsed = get_parsed_rule($all_rules[$idx]);
        $zone = $all_rules[$idx]->{'zone'};
    } else {
        &error($text{'edit_erule'});
    }
} elsif ($clone && $in{'rule_text'}) {
    # Cloning a rule - parse the provided rule text
    $rule_text = $in{'rule_text'};
    $parsed = parse_rich_rule($rule_text);
}

# Set default values
$parsed->{'family'} ||= 'ipv4';
$parsed->{'action'} ||= 'accept';
$parsed->{'log_level'} ||= 'info';
$parsed->{'protocol'} ||= 'tcp';

# Page header
my $page_title = $text{'edit_title2'};
if ($new) {
    $page_title = $clone ? $text{'edit_title_clone'} : $text{'edit_title1'};
}
&ui_print_header(undef, $page_title, "", undef, 1, 1);

# Start main form
print &ui_form_start("save.cgi", "post");
print &ui_hidden("new", $new);
if (!$new) {
    print &ui_hidden("idx", $idx);
    print &ui_hidden("old_rule_text", $rule_text);
}

# Main configuration table
print &ui_table_start($text{'edit_header'}, "width=100%", 2);

# Zone selection (this is the only "zone" field in the form - no hidden duplicate)
my @zones = list_firewalld_zones();
my @zone_opts = map { [$_, $_] } @zones;
print &ui_table_row($text{'edit_zone'},
    &ui_select("zone", $zone, \@zone_opts, 1, 0, 0, 0));

# IP Family
my @family_opts = (
    ['ipv4', $text{'edit_family_ipv4'}],
    ['ipv6', $text{'edit_family_ipv6'}],
    ['both', $text{'edit_family_both'}]
);
print &ui_table_row($text{'edit_family'}, 
    &ui_radio_table("family", $parsed->{'family'}, \@family_opts));

print &ui_table_end();

# Rule Type Selection
print "<h3>" . $text{'edit_rule_type'} . "</h3>\n";

my $rule_type = 'source';
if ($parsed->{'service_name'}) {
    $rule_type = 'service';
} elsif ($parsed->{'port'}) {
    $rule_type = 'port';
} elsif ($parsed->{'protocol_value'}) {
    $rule_type = 'protocol';
}

my @type_opts = (
    ['source', $text{'edit_rule_source'}],
    ['service', $text{'edit_rule_service'}],
    ['port', $text{'edit_rule_port'}],
    ['protocol', $text{'edit_rule_protocol'}]
);
print &ui_radio_table("rule_type", $rule_type, \@type_opts, 1, 0, "onchange='updateRuleType()'");

# Source Configuration
print "<div id='source_config'>\n";
print "<h3>" . $text{'edit_source'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

my $source_type = 'address';
if ($parsed->{'source_mac'}) {
    $source_type = 'mac';
} elsif ($parsed->{'source_interface'}) {
    $source_type = 'interface';
} elsif ($parsed->{'source_ipset'}) {
    $source_type = 'ipset';
}

my @source_opts = (
    ['address', $text{'edit_source_address'}],
    ['mac', $text{'edit_source_mac'}],
    ['interface', $text{'edit_source_interface'}],
    ['ipset', $text{'edit_source_ipset'}]
);
print &ui_table_row($text{'edit_source_type'}, 
    &ui_radio_table("source_type", $source_type, \@source_opts, 1, 0, "onchange='updateSourceType()'"));

print &ui_table_row($text{'edit_source_address'}, 
    &ui_textbox("source_address", $parsed->{'source_address'} || '', 30) . 
    " <small>e.g. 192.168.1.0/24, 10.0.0.1</small>", 
    undef, "id='source_address_row'");

print &ui_table_row($text{'edit_source_mac'}, 
    &ui_textbox("source_mac", $parsed->{'source_mac'} || '', 20) . 
    " <small>e.g. 00:11:22:33:44:55</small>", 
    undef, "id='source_mac_row'");

print &ui_table_row($text{'edit_source_interface'}, 
    &ui_textbox("source_interface", $parsed->{'source_interface'} || '', 20) . 
    " <small>e.g. eth0, wlan0</small>", 
    undef, "id='source_interface_row'");

print &ui_table_row($text{'edit_source_ipset'}, 
    &ui_textbox("source_ipset", $parsed->{'source_ipset'} || '', 20) . 
    " <small>IP set name</small>", 
    undef, "id='source_ipset_row'");

print &ui_table_end();
print "</div>\n";

# Destination Configuration
print "<div id='destination_config'>\n";
print "<h3>" . $text{'edit_destination'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_destination_address'}, 
    &ui_textbox("destination_address", $parsed->{'destination_address'} || '', 30) . 
    " <small>e.g. 192.168.1.100, 10.0.0.0/8</small>");

print &ui_table_row($text{'edit_destination_interface'}, 
    &ui_textbox("destination_interface", $parsed->{'destination_interface'} || '', 20) . 
    " <small>e.g. eth1, tun0</small>");

print &ui_table_end();
print "</div>\n";

# Service Configuration
print "<div id='service_config'>\n";
print "<h3>" . $text{'edit_service'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

# Get available services for autocomplete
my @services = get_firewalld_services();
my @service_opts = map { [$_, $_] } @services;
print &ui_table_row($text{'edit_service_name'}, 
    &ui_select("service_name", $parsed->{'service_name'} || '', \@service_opts, 1, 1) . 
    " <small>Select or type service name</small>");

print &ui_table_end();
print "</div>\n";

# Port Configuration
print "<div id='port_config'>\n";
print "<h3>" . $text{'edit_port'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

my $port_mode = 'single';
if ($parsed->{'port'} && $parsed->{'port'} =~ /-/) {
    $port_mode = 'range';
}

my ($port_single, $port_from, $port_to) = ('', '', '');
if ($parsed->{'port'}) {
    if ($port_mode eq 'range') {
        ($port_from, $port_to) = split(/-/, $parsed->{'port'}, 2);
    } else {
        $port_single = $parsed->{'port'};
    }
}

my @port_opts = (
    ['single', $text{'edit_port_single'}, &ui_textbox("port_single", $port_single, 8)],
    ['range', $text{'edit_port_range'}, 
     $text{'edit_port_from'} . " " . &ui_textbox("port_from", $port_from, 8) . " " . 
     $text{'edit_port_to'} . " " . &ui_textbox("port_to", $port_to, 8)]
);
print &ui_table_row($text{'edit_port'}, 
    &ui_radio_table("port_mode", $port_mode, \@port_opts));

my @protocol_opts = (
    ['tcp', $text{'edit_protocol_tcp'}],
    ['udp', $text{'edit_protocol_udp'}],
    ['sctp', $text{'edit_protocol_sctp'}],
    ['dccp', $text{'edit_protocol_dccp'}]
);
print &ui_table_row($text{'edit_protocol'}, 
    &ui_radio_table("protocol", $parsed->{'protocol'}, \@protocol_opts));

print &ui_table_end();
print "</div>\n";

# Protocol Configuration
print "<div id='protocol_config'>\n";
print "<h3>" . $text{'edit_protocol'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_protocol'}, 
    &ui_textbox("protocol_value", $parsed->{'protocol_value'} || '', 10) . 
    " <small>Protocol number (e.g. 47 for GRE)</small>");

print &ui_table_end();
print "</div>\n";

# Action Configuration
print "<h3>" . $text{'edit_action'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

my @action_opts = (
    ['accept', $text{'edit_action_accept'}],
    ['reject', $text{'edit_action_reject'}],
    ['drop', $text{'edit_action_drop'}]
);
print &ui_table_row($text{'edit_action'}, 
    &ui_radio_table("action", $parsed->{'action'}, \@action_opts, 1, 0, "onchange='updateAction()'"));

# Reject type (only shown for reject action)
my @reject_opts = (
    ['', $text{'edit_reject_icmp'}],
    ['icmp6-adm-prohibited', $text{'edit_reject_icmp6'}],
    ['tcp-reset', $text{'edit_reject_tcp'}]
);
print &ui_table_row($text{'edit_reject_type'}, 
    &ui_select("reject_type", $parsed->{'reject_type'} || '', \@reject_opts, 1, 0, 0, 0, ""),
    undef, "id='reject_type_row'");

print &ui_table_end();

# Logging Configuration
print "<h3>" . $text{'edit_logging'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_log_enable'}, 
    &ui_checkbox("log_enable", 1, "", $parsed->{'log'} || 0, "onchange='updateLogging()'"));

print &ui_table_row($text{'edit_log_prefix'}, 
    &ui_textbox("log_prefix", $parsed->{'log_prefix'} || '', 30), 
    undef, "id='log_prefix_row'");

my @log_levels = qw(emerg alert crit err warn notice info debug);
my @log_level_opts = map { [$_, $text{'edit_log_level_' . $_}] } @log_levels;
print &ui_table_row($text{'edit_log_level'}, 
    &ui_select("log_level", $parsed->{'log_level'} || 'info', \@log_level_opts, 1, 0), 
    undef, "id='log_level_row'");

print &ui_table_row($text{'edit_log_limit'}, 
    &ui_textbox("log_limit_rate", $parsed->{'log_limit'} ? (split(/\//, $parsed->{'log_limit'}))[0] : '', 8) . 
    " " . $text{'edit_log_limit_per'} . " " . 
    &ui_select("log_limit_unit", $parsed->{'log_limit'} ? (split(/\//, $parsed->{'log_limit'}))[1] : 'minute', 
               [['second', $text{'edit_log_limit_second'}], ['minute', $text{'edit_log_limit_minute'}], 
                ['hour', $text{'edit_log_limit_hour'}], ['day', $text{'edit_log_limit_day'}]], 1, 0), 
    undef, "id='log_limit_row'");

print &ui_table_end();

# Advanced Options
print "<h3>" . $text{'edit_advanced'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_audit'}, 
    &ui_checkbox("audit", 1, "", $parsed->{'audit'} || 0));

print &ui_table_row($text{'edit_masquerade'}, 
    &ui_checkbox("masquerade", 1, "", $parsed->{'masquerade'} || 0));

print &ui_table_end();

# Port Forwarding
print "<h3>" . $text{'edit_forward'} . "</h3>\n";
print &ui_table_start("", "width=100%", 2);

print &ui_table_row($text{'edit_forward_enable'}, 
    &ui_checkbox("forward_enable", 1, "", ($parsed->{'forward_port'} ? 1 : 0), "onchange='updateForwarding()'"));

print &ui_table_row($text{'edit_forward_to_port'}, 
    &ui_textbox("forward_to_port", $parsed->{'forward_to_port'} || '', 8), 
    undef, "id='forward_to_port_row'");

print &ui_table_row($text{'edit_forward_to_addr'}, 
    &ui_textbox("forward_to_addr", $parsed->{'forward_to_addr'} || '', 20), 
    undef, "id='forward_to_addr_row'");

print &ui_table_end();

# Rule Preview
print "<h3>" . $text{'edit_preview'} . "</h3>\n";
print "<div id='rule_preview' style='border: 1px solid #ccc; padding: 10px; background-color: #f9f9f9; font-family: monospace;'>\n";
print $text{'edit_preview_text'} . " <span id='preview_text'>" . &html_escape($rule_text) . "</span>\n";
print "</div>\n";
print "<p>";
print "<input type='button' value='" . &html_escape($text{'edit_update_preview'} || 'Update Preview') . "' onclick='updatePreview()' /> ";
print "<input type='button' id='test_rule_btn' value='" . &html_escape($text{'test_rule_button'}) . "' onclick='testRule()' />";
print "</p>\n";
print "<div id='validation_results' style='margin-top: 8px;'></div>\n";
print "<div id='test_results' style='margin-top: 8px;'></div>\n";

# Form buttons
print &ui_form_end([
    [ "save", $text{'save'} ],
    [ "cancel", $text{'cancel'} ]
]);

# JavaScript: emit validation message constants (Perl-interpolated)
print "<script type='text/javascript'>\nvar VMSG = {};\n";
foreach my $k (qw(error_no_action error_no_criteria error_port_range error_port_reversed
                   error_port_no_protocol error_bad_ip error_bad_mac error_family_needed
                   warn_forward_no_port warn_log_no_action heading)) {
    my $val = $text{"validate_$k"} || $k;
    $val =~ s/'/\\'/g;
    print "VMSG['$k'] = '$val';\n";
}
# Also emit test rule messages
foreach my $k (qw(test_rule_testing test_rule_success test_rule_failed test_rule_fix_errors)) {
    my $val = $text{$k} || $k;
    $val =~ s/'/\\'/g;
    (my $jskey = $k) =~ s/^test_rule_//;
    print "VMSG['test_$jskey'] = '$val';\n";
}
print "</script>\n";

# JavaScript for dynamic form behavior
print <<'EOF';
<script type="text/javascript">
function getField(name) {
    var el = document.getElementsByName(name);
    return el && el.length > 0 ? el[0] : null;
}

function getFieldValue(name) {
    var el = getField(name);
    return el ? el.value : '';
}

function getRadioValue(name) {
    var radios = document.getElementsByName(name);
    for (var i = 0; i < radios.length; i++) {
        if (radios[i].checked) return radios[i].value;
    }
    return null;
}

function getChecked(name) {
    var el = getField(name);
    return el ? el.checked : false;
}

function showElement(id) {
    var elem = document.getElementById(id);
    if (elem) elem.style.display = '';
}

function hideElement(id) {
    var elem = document.getElementById(id);
    if (elem) elem.style.display = 'none';
}

function updateRuleType() {
    var type = getRadioValue('rule_type');
    var configs = ['source_config', 'service_config', 'port_config', 'protocol_config'];
    for (var i = 0; i < configs.length; i++) hideElement(configs[i]);

    // source_config and destination_config shown for all types
    showElement('source_config');
    showElement('destination_config');
    if (type == 'service') showElement('service_config');
    else if (type == 'port') showElement('port_config');
    else if (type == 'protocol') showElement('protocol_config');

    updateSourceType();
    updateAction();
    updateLogging();
    updateForwarding();
    updatePreview();
}

function updateSourceType() {
    var type = getRadioValue('source_type');
    var rows = ['source_address_row', 'source_mac_row', 'source_interface_row', 'source_ipset_row'];
    for (var i = 0; i < rows.length; i++) hideElement(rows[i]);
    if (type) showElement('source_' + type + '_row');
    updatePreview();
}

function updateAction() {
    var action = getRadioValue('action');
    var row = document.getElementById('reject_type_row');
    if (row) row.style.display = (action == 'reject') ? '' : 'none';
    updatePreview();
}

function updateLogging() {
    var enabled = getChecked('log_enable');
    var rows = ['log_prefix_row', 'log_level_row', 'log_limit_row'];
    for (var i = 0; i < rows.length; i++) {
        var el = document.getElementById(rows[i]);
        if (el) el.style.display = enabled ? '' : 'none';
    }
    updatePreview();
}

function updateForwarding() {
    var enabled = getChecked('forward_enable');
    var rows = ['forward_to_port_row', 'forward_to_addr_row'];
    for (var i = 0; i < rows.length; i++) {
        var el = document.getElementById(rows[i]);
        if (el) el.style.display = enabled ? '' : 'none';
    }
    updatePreview();
}

function isValidIPorCIDR(val) {
    if (!val) return false;
    // IPv4 with optional CIDR
    var ipv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (ipv4.test(val)) {
        var parts = val.split('/');
        var octets = parts[0].split('.');
        for (var i = 0; i < octets.length; i++) {
            if (parseInt(octets[i], 10) > 255) return false;
        }
        if (parts[1] !== undefined && (parseInt(parts[1], 10) > 32 || parseInt(parts[1], 10) < 0)) return false;
        return true;
    }
    // IPv6 with optional CIDR (simplified: hex digits and colons)
    var ipv6 = /^[a-fA-F0-9:.]+(\/\d{1,3})?$/;
    if (ipv6.test(val) && val.indexOf(':') !== -1) {
        var parts6 = val.split('/');
        if (parts6[1] !== undefined && (parseInt(parts6[1], 10) > 128 || parseInt(parts6[1], 10) < 0)) return false;
        return true;
    }
    return false;
}

function validateRule() {
    var errors = [];
    var ruleType = getRadioValue('rule_type');
    var action = getRadioValue('action');
    var sourceType = getRadioValue('source_type');

    // Check action
    if (!action) {
        errors.push({level: 'error', msg: VMSG['error_no_action']});
    }

    // Check match criteria
    var hasCriteria = false;
    if (sourceType) {
        var srcVal = getFieldValue('source_' + sourceType);
        if (srcVal) hasCriteria = true;
    }
    var destAddr = getFieldValue('destination_address');
    if (destAddr) hasCriteria = true;
    if (ruleType === 'service' && getFieldValue('service_name')) hasCriteria = true;
    if (ruleType === 'port') {
        var portMode = getRadioValue('port_mode');
        if (portMode === 'single' && getFieldValue('port_single')) hasCriteria = true;
        if (portMode === 'range' && getFieldValue('port_from') && getFieldValue('port_to')) hasCriteria = true;
    }
    if (ruleType === 'protocol' && getFieldValue('protocol_value')) hasCriteria = true;
    if (getChecked('masquerade')) hasCriteria = true;
    if (getChecked('forward_enable')) hasCriteria = true;
    if (!hasCriteria) {
        errors.push({level: 'error', msg: VMSG['error_no_criteria']});
    }

    // Port validation
    if (ruleType === 'port') {
        var portMode = getRadioValue('port_mode');
        var proto = getRadioValue('protocol');
        if (portMode === 'single') {
            var ps = getFieldValue('port_single');
            if (ps) {
                var pn = parseInt(ps, 10);
                if (isNaN(pn) || pn < 1 || pn > 65535) {
                    errors.push({level: 'error', msg: VMSG['error_port_range']});
                }
                if (!proto) errors.push({level: 'error', msg: VMSG['error_port_no_protocol']});
            }
        } else {
            var pf = getFieldValue('port_from');
            var pt = getFieldValue('port_to');
            if (pf || pt) {
                var pfn = parseInt(pf, 10);
                var ptn = parseInt(pt, 10);
                if (pf && (isNaN(pfn) || pfn < 1 || pfn > 65535)) {
                    errors.push({level: 'error', msg: VMSG['error_port_range']});
                }
                if (pt && (isNaN(ptn) || ptn < 1 || ptn > 65535)) {
                    errors.push({level: 'error', msg: VMSG['error_port_range']});
                }
                if (pfn && ptn && pfn > ptn) {
                    errors.push({level: 'error', msg: VMSG['error_port_reversed']});
                }
                if (!proto) errors.push({level: 'error', msg: VMSG['error_port_no_protocol']});
            }
        }
    }

    // IP address validation
    var srcType = getRadioValue('source_type');
    if (srcType === 'address') {
        var srcAddr = getFieldValue('source_address');
        if (srcAddr && !isValidIPorCIDR(srcAddr)) {
            errors.push({level: 'error', msg: VMSG['error_bad_ip']});
        }
    }
    if (destAddr && !isValidIPorCIDR(destAddr)) {
        errors.push({level: 'error', msg: VMSG['error_bad_ip']});
    }

    // MAC validation
    if (srcType === 'mac') {
        var mac = getFieldValue('source_mac');
        if (mac && !/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(mac)) {
            errors.push({level: 'error', msg: VMSG['error_bad_mac']});
        }
    }

    // Family warning: IP present but family=both
    var family = getRadioValue('family');
    if (family === 'both') {
        var hasIP = false;
        if (srcType === 'address' && getFieldValue('source_address')) hasIP = true;
        if (destAddr) hasIP = true;
        if (hasIP) {
            errors.push({level: 'warning', msg: VMSG['error_family_needed']});
        }
    }

    // Forward without port warning
    if (getChecked('forward_enable')) {
        if (ruleType !== 'port' || (!getFieldValue('port_single') && !getFieldValue('port_from'))) {
            errors.push({level: 'warning', msg: VMSG['warn_forward_no_port']});
        }
    }

    // Log without action warning
    if (getChecked('log_enable') && !action) {
        errors.push({level: 'warning', msg: VMSG['warn_log_no_action']});
    }

    return errors;
}

function renderValidationResults(errors, strict) {
    var el = document.getElementById('validation_results');
    if (!el) return;
    if (!errors || errors.length === 0) {
        el.innerHTML = '<div style="color: #2e7d32; padding: 6px 10px; background: #e8f5e9; border: 1px solid #a5d6a7; border-radius: 4px;">' +
            '&#10004; ' + VMSG['heading'] + ': Rule looks valid</div>';
        return;
    }
    var html = '';
    for (var i = 0; i < errors.length; i++) {
        var e = errors[i];
        if (strict && e.level === 'error') {
            html += '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px; margin-bottom: 4px;">' +
                '&#10008; ' + e.msg + '</div>';
        } else {
            html += '<div style="color: #e65100; padding: 6px 10px; background: #fff3e0; border: 1px solid #ffcc80; border-radius: 4px; margin-bottom: 4px;">' +
                '&#9888; ' + e.msg + '</div>';
        }
    }
    el.innerHTML = html;
}

function testRule() {
    // Run validation first
    var validationErrors = validateRule();
    var hasErrors = false;
    for (var i = 0; i < validationErrors.length; i++) {
        if (validationErrors[i].level === 'error') { hasErrors = true; break; }
    }
    if (hasErrors) {
        // Show validation in strict mode so errors appear red
        renderValidationResults(validationErrors, true);
        var el = document.getElementById('test_results');
        if (el) {
            el.innerHTML = '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px;">' +
                '&#10008; ' + VMSG['test_fix_errors'] + '</div>';
        }
        return;
    }

    var btn = document.getElementById('test_rule_btn');
    var resultsEl = document.getElementById('test_results');
    if (btn) btn.disabled = true;
    if (resultsEl) {
        resultsEl.innerHTML = '<div style="color: #1565c0; padding: 6px 10px; background: #e3f2fd; border: 1px solid #90caf9; border-radius: 4px;">' +
            '&#8987; ' + VMSG['test_testing'] + '</div>';
    }

    var form = document.querySelector('form[action="save.cgi"]') || document.forms[0];
    var params = [];
    for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (!el.name) continue;
        if (el.type === 'checkbox' || el.type === 'radio') {
            if (!el.checked) continue;
        }
        params.push(encodeURIComponent(el.name) + '=' + encodeURIComponent(el.value));
    }
    var body = params.join('&');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'test_rule.cgi', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.timeout = 15000;
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (btn) btn.disabled = false;
            if (xhr.status === 200) {
                try {
                    var resp = JSON.parse(xhr.responseText);
                    if (resp.success) {
                        resultsEl.innerHTML = '<div style="color: #2e7d32; padding: 6px 10px; background: #e8f5e9; border: 1px solid #a5d6a7; border-radius: 4px;">' +
                            '&#10004; ' + VMSG['test_success'] + '<br><tt>' + escapeHtml(resp.rule || '') + '</tt></div>';
                    } else {
                        resultsEl.innerHTML = '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px;">' +
                            '&#10008; ' + VMSG['test_failed'] + ': ' + escapeHtml(resp.message || '') + '</div>';
                    }
                } catch(e) {
                    resultsEl.innerHTML = '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px;">' +
                        '&#10008; Error parsing response</div>';
                }
            } else {
                resultsEl.innerHTML = '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px;">' +
                    '&#10008; Request failed (HTTP ' + xhr.status + ')</div>';
            }
        }
    };
    xhr.onerror = function() {
        if (btn) btn.disabled = false;
        resultsEl.innerHTML = '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px;">' +
            '&#10008; XHR network error</div>';
    };
    xhr.ontimeout = function() {
        if (btn) btn.disabled = false;
        resultsEl.innerHTML = '<div style="color: #c62828; padding: 6px 10px; background: #ffebee; border: 1px solid #ef9a9a; border-radius: 4px;">' +
            '&#10008; Request timed out</div>';
    };
    xhr.send(body);
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

function updatePreview() {
    var parts = ['rule'];

    var family = getRadioValue('family');
    if (family && family != 'both') parts.push('family="' + family + '"');

    var ruleType = getRadioValue('rule_type');
    var sourceType = getRadioValue('source_type');

    // Source
    if (sourceType) {
        var srcVal = getFieldValue('source_' + sourceType);
        if (srcVal) parts.push('source ' + sourceType + '="' + srcVal + '"');
    }

    // Destination
    var destAddr = getFieldValue('destination_address');
    if (destAddr) parts.push('destination address="' + destAddr + '"');

    // Service / port / protocol
    if (ruleType == 'service') {
        var svc = getFieldValue('service_name');
        if (svc) parts.push('service name="' + svc + '"');
    } else if (ruleType == 'port') {
        var portMode = getRadioValue('port_mode');
        var proto = getRadioValue('protocol');
        var port = '';
        if (portMode == 'single') {
            port = getFieldValue('port_single');
        } else {
            var pf = getFieldValue('port_from');
            var pt = getFieldValue('port_to');
            if (pf && pt) port = pf + '-' + pt;
        }
        if (port && proto) parts.push('port port="' + port + '" protocol="' + proto + '"');
    } else if (ruleType == 'protocol') {
        var pv = getFieldValue('protocol_value');
        if (pv) parts.push('protocol value="' + pv + '"');
    }

    // Logging
    if (getChecked('log_enable')) {
        var logStr = 'log';
        var lp = getFieldValue('log_prefix');
        if (lp) logStr += ' prefix="' + lp + '"';
        var ll = getFieldValue('log_level');
        if (ll) logStr += ' level="' + ll + '"';
        var lr = getFieldValue('log_limit_rate');
        var lu = getFieldValue('log_limit_unit');
        if (lr && lu) logStr += ' limit value="' + lr + '/' + lu + '"';
        parts.push(logStr);
    }

    // Audit
    if (getChecked('audit')) parts.push('audit');

    // Masquerade
    if (getChecked('masquerade')) parts.push('masquerade');

    // Forward port
    if (getChecked('forward_enable')) {
        var fp = getFieldValue('forward_to_port');
        var fa = getFieldValue('forward_to_addr');
        if (fp || fa) {
            var fwd = 'forward-port';
            if (fp) fwd += ' to-port="' + fp + '"';
            if (fa) fwd += ' to-addr="' + fa + '"';
            parts.push(fwd);
        }
    }

    // Action
    var action = getRadioValue('action');
    if (action) {
        var actStr = action;
        if (action == 'reject') {
            var rt = getFieldValue('reject_type');
            if (rt) actStr += ' type="' + rt + '"';
        }
        parts.push(actStr);
    }

    var el = document.getElementById('preview_text');
    if (el) el.textContent = parts.join(' ');

    var validationErrors = validateRule();
    renderValidationResults(validationErrors, false);
}

// Initialize: use both DOMContentLoaded and a delayed fallback for Authentic theme
function initForm() {
    updateRuleType();

    // Use event delegation on the form for robust event capture
    var form = document.querySelector('form[action="save.cgi"]') || document.forms[0];
    if (form) {
        form.addEventListener('input', function() { updatePreview(); });
        form.addEventListener('change', function() {
            updateRuleType();
        });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initForm);
} else {
    initForm();
}
// Fallback: Authentic theme may load content late
setTimeout(initForm, 500);
</script>
EOF

&ui_print_footer("index.cgi", $text{'index_return'});