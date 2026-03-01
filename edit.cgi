#!/usr/bin/perl
# Edit or create a firewalld rich rule — per addnewmockup.md

require './firewalld-rich-lib.pl';

if (!check_firewalld_installed() || !is_firewalld_running() || !rich_rules_supported()) {
    &error($text{'edit_einstall'});
}

&ReadParse();

my $new = $in{'new'};
my $clone = $in{'clone'};
my $zone = $in{'zone'} || get_default_zone();
my $idx = $in{'idx'};

my $rule_text = '';
my $parsed = {};

if (!$new && defined($idx) && $idx ne '') {
    my @all_rules = list_all_rich_rules();
    if ($idx =~ /^\d+$/ && $idx >= 0 && $idx < scalar(@all_rules)) {
        $rule_text = $all_rules[$idx]->{'text'};
        $parsed = get_parsed_rule($all_rules[$idx]);
        $zone = $all_rules[$idx]->{'zone'};
    } else {
        &error($text{'edit_erule'});
    }
} elsif ($clone && $in{'rule_text'}) {
    $rule_text = $in{'rule_text'};
    $parsed = parse_rich_rule($rule_text);
}

if ($new && !$clone) {
    $parsed->{'family'} ||= 'ipv4';
    $parsed->{'action'} ||= 'accept';
}

my $proto_class = determine_protocol_class($parsed);

# Determine element type from parsed rule
my $element_type = 'none';
if ($parsed->{'service_name'}) { $element_type = 'service'; }
elsif ($parsed->{'protocol_value'}) { $element_type = 'protocol'; }
elsif ($parsed->{'icmp_block'}) { $element_type = 'icmp-block'; }
elsif ($parsed->{'icmp_type'}) { $element_type = 'icmp-type'; }
elsif ($parsed->{'masquerade'}) { $element_type = 'masquerade'; }
elsif ($parsed->{'forward_port'}) { $element_type = 'forward-port'; }

my $page_title = $text{'edit_title2'};
if ($new) {
    $page_title = $clone ? $text{'edit_title_clone'} : $text{'edit_title1'};
}
&ui_print_header(undef, $page_title, "", "edit", 1, 1);

print &ui_form_start("save.cgi", "post");
print &ui_hidden("new", $new);
if (!$new) {
    print &ui_hidden("idx", $idx);
    print &ui_hidden("old_rule_text", $rule_text);
}

# Helper: label with help link
sub hlabel {
    my ($text_key, $help_page) = @_;
    return $help_page ? &hlink($text{$text_key}, $help_page) : $text{$text_key};
}

# Page title CSS + help hint
print "<style>.page_title { font-size: 1.6em !important; }</style>\n";
print "<p style='margin: 0 0 12px 0;'><i>" . $text{'edit_help_hint'} . "</i></p>\n";

# Preload data
my @services = get_firewalld_services();
my @service_opts = map { [$_, $_] } @services;
my @icmp_types = get_firewalld_icmp_types();
my @icmp_opts = map { [$_, $_] } @icmp_types;
my @proto_opts = (['tcp', 'TCP'], ['udp', 'UDP'], ['sctp', 'SCTP'], ['dccp', 'DCCP']);
my @time_unit_opts = (
    ['second', $text{'edit_log_limit_second'}], ['minute', $text{'edit_log_limit_minute'}],
    ['hour', $text{'edit_log_limit_hour'}], ['day', $text{'edit_log_limit_day'}]
);

# ============================================================
# Section 1: Rule Basics
# ============================================================
print &ui_table_start($text{'edit_basics'}, "width=100%", 2);

if ($new) {
    my @zones = list_firewalld_zones();
    my @zone_opts = map { [$_, $_] } @zones;
    print &ui_table_row(hlabel('edit_zone', 'zone'),
        &ui_select("zone", $zone, \@zone_opts, 1, 0));
} else {
    print &ui_hidden("zone", $zone);
    print &ui_table_row(hlabel('edit_zone', 'zone'),
        "<tt>" . &html_escape($zone) . "</tt>");
}

my @family_opts = (
    ['ipv4', $text{'edit_family_ipv4'}],
    ['ipv6', $text{'edit_family_ipv6'}],
    ['both', $text{'edit_family_both'}]
);
print &ui_table_row(hlabel('edit_family', 'family'),
    &ui_radio("family", $parsed->{'family'} || 'both', \@family_opts));

my @proto_class_opts = (
    ['tcp_udp', $text{'edit_proto_class_tcp_udp'}],
    ['icmp', $text{'edit_proto_class_icmp'}],
    ['any', $text{'edit_proto_class_any'}]
);
print &ui_table_row(hlabel('edit_proto_class', 'proto_class'),
    &ui_radio("proto_class", $proto_class, \@proto_class_opts));

print &ui_table_row(hlabel('edit_priority', 'priority'),
    &ui_textbox("priority", $parsed->{'priority'} // '', 10) .
    " <small>" . $text{'edit_priority_hint'} . "</small>");

print &ui_table_end();

# ============================================================
# Section 2: Match Element
# ============================================================
print "<div id='elem_section'>\n";
print &ui_table_start($text{'edit_element_type'}, "width=100%", 2);

my @all_element_opts = (
    ['none',         $text{'edit_element_none'}],
    ['service',      $text{'edit_element_service'}],
    ['protocol',     $text{'edit_element_protocol'}],
    ['masquerade',   $text{'edit_element_masquerade'}],
    ['forward-port', $text{'edit_element_forward_port'}],
    ['icmp-block',   $text{'edit_element_icmp_block'}],
    ['icmp-type',    $text{'edit_element_icmp_type'}]
);
my %elem_proto_map = (
    'none' => 'all', 'service' => 'tcp_udp', 'protocol' => 'any',
    'masquerade' => 'tcp_udp', 'forward-port' => 'tcp_udp',
    'icmp-block' => 'icmp', 'icmp-type' => 'icmp'
);
my $elem_select = "<select name='element_type' id='element_type_select'>\n";
for my $opt (@all_element_opts) {
    my $sel = ($opt->[0] eq $element_type) ? " selected" : "";
    my $pc = $elem_proto_map{$opt->[0]} || 'all';
    $elem_select .= "  <option value='$opt->[0]' data-proto='$pc'$sel>$opt->[1]</option>\n";
}
$elem_select .= "</select>";
print &ui_table_row(hlabel('edit_element_type', 'element'), $elem_select);

# Sub-fields shown/hidden by JS based on element type selection
print &ui_table_row($text{'edit_service_name'},
    &ui_select("service_name", $parsed->{'service_name'} || '', \@service_opts, 1, 0));
print &ui_table_row(hlabel('edit_protocol_value', 'protocol_element'),
    &ui_textbox("protocol_value", $parsed->{'protocol_value'} || '', 10) .
    " <small>" . $text{'edit_protocol_value_hint'} . "</small>");
print &ui_table_row(hlabel('edit_icmp_block', 'icmp_block'),
    &ui_select("icmp_block", $parsed->{'icmp_block'} || '', \@icmp_opts, 1, 0));
print &ui_table_row(hlabel('edit_icmp_type', 'icmp_type'),
    &ui_select("icmp_type", $parsed->{'icmp_type'} || '', \@icmp_opts, 1, 0));
print &ui_table_row(hlabel('edit_forward_port', 'forward_port'),
    &ui_textbox("forward_port_value", $parsed->{'forward_port'} || '', 15) .
    " <small>" . $text{'edit_port_hint'} . "</small>");
print &ui_table_row($text{'edit_forward_protocol'},
    &ui_radio("forward_port_protocol", $parsed->{'forward_protocol'} || 'tcp', \@proto_opts));
print &ui_table_row($text{'edit_forward_to_port'},
    &ui_textbox("forward_to_port", $parsed->{'forward_to_port'} || '', 8));
print &ui_table_row($text{'edit_forward_to_addr'},
    &ui_textbox("forward_to_addr", $parsed->{'forward_to_addr'} || '', 20));

print &ui_table_end();
print "</div>\n";

# ============================================================
# Section 2: Source
# ============================================================
print &ui_table_start($text{'edit_source'}, "width=100%", 2);

my $source_type = 'none';
if ($parsed->{'source_address'}) { $source_type = 'address'; }
elsif ($parsed->{'source_mac'}) { $source_type = 'mac'; }
elsif ($parsed->{'source_ipset'}) { $source_type = 'ipset'; }

my @source_opts = (
    ['none', $text{'edit_source_none'}],
    ['address', $text{'edit_source_address'}],
    ['mac', $text{'edit_source_mac'}],
    ['ipset', $text{'edit_source_ipset'}]
);
print &ui_table_row(hlabel('edit_source_type', 'source'),
    &ui_select("source_type", $source_type, \@source_opts, 1, 0));

print &ui_table_row(hlabel('edit_source_not', 'source_not'),
    &ui_checkbox("source_not", 1, $text{'edit_not_desc'}, $parsed->{'source_not'} || 0));

print &ui_table_row($text{'edit_source_address'},
    &ui_textbox("source_address", $parsed->{'source_address'} || '', 30) .
    " <small>e.g. 192.168.1.0/24, 10.0.0.1</small>");

print &ui_table_row($text{'edit_source_mac'},
    &ui_textbox("source_mac", $parsed->{'source_mac'} || '', 20) .
    " <small>e.g. 00:11:22:33:44:55</small>");

print &ui_table_row(hlabel('edit_source_ipset', 'ipset'),
    &ui_textbox("source_ipset", $parsed->{'source_ipset'} || '', 20) .
    " <small>" . $text{'edit_ipset_hint'} . "</small>");

# Source Port
print &ui_table_row(hlabel('edit_source_port', 'source_port'),
    &ui_textbox("source_port_value", $parsed->{'source_port'} || '', 15) .
    " <small>" . $text{'edit_source_port_hint'} . "</small>");
print &ui_table_row($text{'edit_source_port_proto'},
    &ui_radio("source_port_protocol", $parsed->{'source_port_protocol'} || 'tcp', \@proto_opts));

print &ui_table_end();

# ============================================================
# Section 3: Destination
# ============================================================
print &ui_table_start($text{'edit_destination'}, "width=100%", 2);

my $dest_type = 'none';
if ($parsed->{'destination_address'}) { $dest_type = 'address'; }
elsif ($parsed->{'destination_ipset'}) { $dest_type = 'ipset'; }

my @dest_opts = (
    ['none', $text{'edit_destination_none'}],
    ['address', $text{'edit_destination_addr'}],
    ['ipset', $text{'edit_destination_ipset'}]
);
print &ui_table_row(hlabel('edit_destination_type', 'destination'),
    &ui_select("destination_type", $dest_type, \@dest_opts, 1, 0));

print &ui_table_row(hlabel('edit_destination_not', 'dest_not'),
    &ui_checkbox("destination_not", 1, $text{'edit_not_desc'}, $parsed->{'destination_not'} || 0));

print &ui_table_row($text{'edit_destination_address'},
    &ui_textbox("destination_address", $parsed->{'destination_address'} || '', 30) .
    " <small>e.g. 192.168.1.100, 10.0.0.0/8</small>");

print &ui_table_row(hlabel('edit_destination_ipset_val', 'ipset'),
    &ui_textbox("destination_ipset", $parsed->{'destination_ipset'} || '', 20) .
    " <small>" . $text{'edit_ipset_hint'} . "</small>");

# Port (destination port)
print &ui_table_row(hlabel('edit_port', 'port'),
    &ui_textbox("port_value", $parsed->{'port'} || '', 15) .
    " <small>" . $text{'edit_port_hint'} . "</small>");
print &ui_table_row($text{'edit_port_protocol'},
    &ui_radio("port_protocol", $parsed->{'port_protocol'} || 'tcp', \@proto_opts));

print &ui_table_end();

# ============================================================
# Section 4: Action
# ============================================================
print &ui_table_start($text{'edit_action_section'}, "width=100%", 2);

my @action_opts = (
    ['none', $text{'edit_action_none'}],
    ['accept', $text{'edit_action_accept'}],
    ['reject', $text{'edit_action_reject'}],
    ['drop', $text{'edit_action_drop'}],
    ['mark', $text{'edit_action_mark'}]
);
print &ui_table_row(hlabel('edit_action', 'action'),
    &ui_select("action", $parsed->{'action'} || 'none', \@action_opts, 1, 0));

my @reject_opts = (
    ['', $text{'edit_reject_default'}],
    ['icmp-host-prohibited', 'icmp-host-prohibited'],
    ['icmp-net-unreachable', 'icmp-net-unreachable'],
    ['icmp-host-unreachable', 'icmp-host-unreachable'],
    ['icmp-port-unreachable', 'icmp-port-unreachable'],
    ['icmp-proto-unreachable', 'icmp-proto-unreachable'],
    ['icmp-net-prohibited', 'icmp-net-prohibited'],
    ['icmp-admin-prohibited', 'icmp-admin-prohibited'],
    ['icmp6-adm-prohibited', 'icmp6-adm-prohibited'],
    ['icmp6-no-route', 'icmp6-no-route'],
    ['icmp6-addr-unreachable', 'icmp6-addr-unreachable'],
    ['icmp6-port-unreachable', 'icmp6-port-unreachable'],
    ['tcp-reset', 'tcp-reset']
);
print &ui_table_row($text{'edit_reject_type'},
    &ui_select("reject_type", $parsed->{'reject_type'} || '', \@reject_opts, 1, 0));

print &ui_table_row($text{'edit_mark_value'},
    &ui_textbox("mark_value", $parsed->{'mark_value'} || '', 20) .
    " <small>" . $text{'edit_mark_hint'} . "</small>");

my ($action_limit_rate, $action_limit_unit) = ('', 'minute');
if ($parsed->{'action_limit'} && $parsed->{'action_limit'} =~ /^(\d+)\/(\w+)$/) {
    $action_limit_rate = $1; $action_limit_unit = $2;
}
print &ui_table_row(hlabel('edit_action_limit', 'action_limit'),
    &ui_textbox("action_limit_rate", $action_limit_rate, 8) .
    " " . $text{'edit_action_limit_per'} . " " .
    &ui_select("action_limit_unit", $action_limit_unit, \@time_unit_opts, 1, 0));

print &ui_table_end();

# ============================================================
# Section 5: Logging
# ============================================================
print &ui_table_start($text{'edit_logging'}, "width=100%", 2);

my $log_type = 'none';
if ($parsed->{'nflog'}) { $log_type = 'nflog'; }
elsif ($parsed->{'log'}) { $log_type = 'log'; }

my @log_type_opts = (
    ['none', $text{'edit_log_type_none'}],
    ['log', $text{'edit_log_type_log'}],
    ['nflog', $text{'edit_log_type_nflog'}]
);
print &ui_table_row(hlabel('edit_log_type', 'logging'),
    &ui_radio("log_type", $log_type, \@log_type_opts));

my $log_prefix = $parsed->{'log_prefix'} || $parsed->{'nflog_prefix'} || '';
print &ui_table_row($text{'edit_log_prefix'},
    &ui_textbox("log_prefix", $log_prefix, 30));

my $log_limit = $parsed->{'log_limit'} || $parsed->{'nflog_limit'} || '';
my ($log_limit_rate, $log_limit_unit) = ('', 'minute');
if ($log_limit =~ /^(\d+)\/(\w+)$/) { $log_limit_rate = $1; $log_limit_unit = $2; }
print &ui_table_row($text{'edit_log_limit'},
    &ui_textbox("log_limit_rate", $log_limit_rate, 8) .
    " " . $text{'edit_log_limit_per'} . " " .
    &ui_select("log_limit_unit", $log_limit_unit, \@time_unit_opts, 1, 0));

my @log_levels = qw(emerg alert crit err warn notice info debug);
my @log_level_opts = map { [$_, $text{'edit_log_level_' . $_}] } @log_levels;
print &ui_table_row($text{'edit_log_level'},
    &ui_select("log_level", $parsed->{'log_level'} || 'info', \@log_level_opts, 1, 0));

print &ui_table_row($text{'edit_nflog_group'},
    &ui_textbox("nflog_group", $parsed->{'nflog_group'} // '', 8) .
    " <small>" . $text{'edit_nflog_group_hint'} . "</small>");

print &ui_table_row($text{'edit_nflog_queue_size'},
    &ui_textbox("nflog_queue_size", $parsed->{'nflog_queue_size'} // '', 8) .
    " <small>" . $text{'edit_nflog_queue_size_hint'} . "</small>");

# Audit
print &ui_table_row(hlabel('edit_audit', 'audit'),
    &ui_checkbox("audit", 1, $text{'edit_audit_desc'}, $parsed->{'audit'} || 0));

my ($audit_limit_rate, $audit_limit_unit) = ('', 'minute');
if ($parsed->{'audit_limit'} && $parsed->{'audit_limit'} =~ /^(\d+)\/(\w+)$/) {
    $audit_limit_rate = $1; $audit_limit_unit = $2;
}
print &ui_table_row($text{'edit_audit_limit'},
    &ui_textbox("audit_limit_rate", $audit_limit_rate, 8) .
    " " . $text{'edit_log_limit_per'} . " " .
    &ui_select("audit_limit_unit", $audit_limit_unit, \@time_unit_opts, 1, 0));

print &ui_table_end();

# ============================================================
# Section 6: Preview + Test
# ============================================================
print &ui_table_start($text{'edit_preview'}, "width=100%", 1);
print &ui_table_row(undef,
    "<div id='rule_preview' style='font-family: monospace; padding: 8px; background: #f5f5f5; border: 1px solid #ddd; word-break: break-all; user-select: none; -webkit-user-select: none; pointer-events: none;'>" .
    "<span id='preview_text'>" . &html_escape($rule_text) . "</span></div>" .
    "<div style='margin-top: 8px;'>" .
    "<input type='button' value='" . &html_escape($text{'edit_update_preview'}) . "' onclick='updatePreview()' /> " .
    "<input type='button' id='test_rule_btn' value='" . &html_escape($text{'test_rule_button'}) . "' onclick='testRule()' />" .
    "</div>" .
    "<div id='validation_results' style='margin-top: 8px;'></div>" .
    "<div id='test_results' style='margin-top: 8px;'></div>",
    undef);
print &ui_table_end();

print &ui_form_end([
    [ "save", $text{'save'} ],
    [ "cancel", $text{'cancel'} ]
]);

# ============================================================
# JavaScript
# ============================================================
print "<script type='text/javascript'>\nvar VMSG = {};\n";
foreach my $k (qw(error_no_action error_no_criteria error_port_range error_port_format
                   error_bad_ip error_bad_mac error_family_needed
                   error_priority_range error_mark_format error_fwd_needs_port
                   error_element_conflict warn_log_no_action heading)) {
    my $val = $text{"validate_$k"} || $k;
    $val =~ s/'/\\'/g;
    print "VMSG['$k'] = '$val';\n";
}
foreach my $k (qw(test_rule_testing test_rule_success test_rule_failed test_rule_fix_errors)) {
    my $val = $text{$k} || $k;
    $val =~ s/'/\\'/g;
    (my $jskey = $k) =~ s/^test_rule_//;
    print "VMSG['test_$jskey'] = '$val';\n";
}
print "</script>\n";

print <<'JSEOF';
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
function getSelectValue(name) {
    var el = document.getElementById(name) || getField(name);
    return el ? el.value : '';
}
function getChecked(name) {
    var el = getField(name);
    return el ? el.checked : false;
}
function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// Show/hide rows by field name — finds element by name, then walks to parent <tr>
function showFieldRows(fieldNames) {
    for (var i = 0; i < fieldNames.length; i++) {
        var el = getField(fieldNames[i]);
        if (el) { var tr = el.closest('tr'); if (tr) tr.style.display = ''; }
    }
}
function hideFieldRows(fieldNames) {
    for (var i = 0; i < fieldNames.length; i++) {
        var el = getField(fieldNames[i]);
        if (el) { var tr = el.closest('tr'); if (tr) tr.style.display = 'none'; }
    }
}

// Element sub-field mapping: element_type value -> array of field names in that group
var elemFieldMap = {
    'service':      ['service_name'],
    'protocol':     ['protocol_value'],
    'icmp-block':   ['icmp_block'],
    'icmp-type':    ['icmp_type'],
    'forward-port': ['forward_port_value', 'forward_port_protocol', 'forward_to_port', 'forward_to_addr'],
    'masquerade':   []
};
// All element sub-field names (union of all values above)
var allElemFields = ['service_name', 'protocol_value', 'icmp_block', 'icmp_type',
                     'forward_port_value', 'forward_port_protocol', 'forward_to_port', 'forward_to_addr'];

function hideAllElemRows() {
    // Hide all sub-field rows (dropdown row is safe — 'element_type' is not in allElemFields)
    for (var i = 0; i < allElemFields.length; i++) {
        var el = getField(allElemFields[i]);
        if (el) { var tr = el.closest('tr'); if (tr) tr.style.display = 'none'; }
    }
}
function showElemRows(elemType) {
    var fields = elemFieldMap[elemType];
    if (!fields || fields.length === 0) return; // masquerade — no sub-fields
    for (var j = 0; j < fields.length; j++) {
        var el = getField(fields[j]);
        if (el) { var tr = el.closest('tr'); if (tr) tr.style.display = ''; }
    }
}

// Protocol class drives element dropdown and port visibility
function updateProtoClass() {
    var pc = getRadioValue('proto_class');
    var sel = document.getElementById('element_type_select');
    if (!sel) return;
    var opts = sel.options;
    var currentVal = sel.value;
    var needReset = false;
    for (var i = 0; i < opts.length; i++) {
        var proto = opts[i].getAttribute('data-proto');
        if (proto === 'all' || proto === pc || pc === 'any') {
            opts[i].style.display = ''; opts[i].disabled = false;
        } else {
            opts[i].style.display = 'none'; opts[i].disabled = true;
            if (opts[i].value === currentVal) needReset = true;
        }
    }
    if (needReset) {
        sel.value = 'none';
        // Explicitly trigger change so updateElementType runs
        sel.dispatchEvent(new Event('change', {bubbles: true}));
    }

    // Source port + dest port: visible for TCP/UDP or Any
    if (pc === 'tcp_udp' || pc === 'any') {
        showFieldRows(['source_port_value', 'source_port_protocol', 'port_value', 'port_protocol']);
    } else {
        hideFieldRows(['source_port_value', 'source_port_protocol', 'port_value', 'port_protocol']);
    }
    updateElementType();
    updatePreview();
}

function updateSourceType() {
    var type = getSelectValue('source_type');
    hideFieldRows(['source_address', 'source_mac', 'source_ipset', 'source_not']);
    if (type && type !== 'none') {
        showFieldRows(['source_not']);
        if (type === 'address') showFieldRows(['source_address']);
        else if (type === 'mac') showFieldRows(['source_mac']);
        else if (type === 'ipset') showFieldRows(['source_ipset']);
    }
    updatePreview();
}

function updateDestinationType() {
    var type = getSelectValue('destination_type');
    hideFieldRows(['destination_address', 'destination_ipset', 'destination_not']);
    if (type && type !== 'none') {
        showFieldRows(['destination_not']);
        if (type === 'address') showFieldRows(['destination_address']);
        else if (type === 'ipset') showFieldRows(['destination_ipset']);
    }
    updatePreview();
}

// Element type show/hide uses data-elem-field attributes — never hides by field name
function updateElementType() {
    var type = getSelectValue('element_type');
    hideAllElemRows();
    if (type && type !== 'none') {
        showElemRows(type);
    }
    updatePreview();
}

function updateLogType() {
    var type = getRadioValue('log_type');
    var sharedFields = ['log_prefix', 'log_limit_rate'];
    var logFields = ['log_level'];
    var nflogFields = ['nflog_group', 'nflog_queue_size'];
    if (type === 'none') {
        hideFieldRows(sharedFields); hideFieldRows(logFields); hideFieldRows(nflogFields);
    } else {
        showFieldRows(sharedFields);
        if (type === 'log') { showFieldRows(logFields); hideFieldRows(nflogFields); }
        else { hideFieldRows(logFields); showFieldRows(nflogFields); }
    }
    updatePreview();
}

function updateAudit() {
    var checked = getChecked('audit');
    if (checked) { showFieldRows(['audit_limit_rate']); }
    else { hideFieldRows(['audit_limit_rate']); }
    updatePreview();
}

function updateAction() {
    var action = getSelectValue('action');
    hideFieldRows(['reject_type', 'mark_value', 'action_limit_rate']);
    if (action && action !== 'none') {
        showFieldRows(['action_limit_rate']);
        if (action === 'reject') showFieldRows(['reject_type']);
        else if (action === 'mark') showFieldRows(['mark_value']);
    }
    updatePreview();
}

function isValidIPorCIDR(val) {
    if (!val) return false;
    var ipv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (ipv4.test(val)) {
        var parts = val.split('/');
        var octets = parts[0].split('.');
        for (var i = 0; i < octets.length; i++) { if (parseInt(octets[i],10) > 255) return false; }
        if (parts[1] !== undefined && (parseInt(parts[1],10) > 32 || parseInt(parts[1],10) < 0)) return false;
        return true;
    }
    var ipv6 = /^[a-fA-F0-9:.]+(\/\d{1,3})?$/;
    if (ipv6.test(val) && val.indexOf(':') !== -1) {
        var parts6 = val.split('/');
        if (parts6[1] !== undefined && (parseInt(parts6[1],10) > 128 || parseInt(parts6[1],10) < 0)) return false;
        return true;
    }
    return false;
}

function isValidPort(val) {
    if (!val) return false;
    var m = val.match(/^(\d+)(?:-(\d+))?$/);
    if (!m) return false;
    var p1 = parseInt(m[1],10);
    if (p1 < 1 || p1 > 65535) return false;
    if (m[2]) { var p2 = parseInt(m[2],10); if (p2 < 1 || p2 > 65535 || p1 > p2) return false; }
    return true;
}

function validateRule() {
    var errors = [];
    var action = getSelectValue('action');
    var elemType = getSelectValue('element_type');
    var sourceType = getSelectValue('source_type');
    var destType = getSelectValue('destination_type');
    var hasCriteria = false;
    if (sourceType && sourceType !== 'none') {
        var srcVal = getFieldValue('source_' + sourceType);
        if (srcVal) hasCriteria = true;
    }
    if (destType && destType !== 'none') {
        if (destType === 'address' && getFieldValue('destination_address')) hasCriteria = true;
        if (destType === 'ipset' && getFieldValue('destination_ipset')) hasCriteria = true;
    }
    if (elemType && elemType !== 'none') hasCriteria = true;
    if (action && action !== 'none') hasCriteria = true;
    if (getRadioValue('log_type') !== 'none') hasCriteria = true;
    if (getChecked('audit')) hasCriteria = true;
    var pv = getFieldValue('port_value');
    if (pv) hasCriteria = true;
    var spv = getFieldValue('source_port_value');
    if (spv) hasCriteria = true;
    if (!hasCriteria) errors.push({level:'error',msg:VMSG['error_no_criteria']});

    // Element conflict check — firewalld allows only ONE element per rule
    var elemCount = 0;
    if (elemType && elemType !== 'none') elemCount++;
    if (pv) elemCount++;
    if (spv) elemCount++;
    if (elemCount > 1) errors.push({level:'error', msg:VMSG['error_element_conflict']});

    var priority = getFieldValue('priority');
    if (priority !== '') {
        var pn = parseInt(priority,10);
        if (isNaN(pn) || pn < -32768 || pn > 32767 || priority !== ''+pn)
            errors.push({level:'error',msg:VMSG['error_priority_range']});
    }
    if (pv && !isValidPort(pv)) errors.push({level:'error',msg:VMSG['error_port_range']});
    if (spv && !isValidPort(spv)) errors.push({level:'error',msg:VMSG['error_port_range']});
    if (elemType === 'forward-port') {
        var fpv = getFieldValue('forward_port_value');
        if (!fpv) errors.push({level:'error',msg:VMSG['error_fwd_needs_port']});
        else if (!isValidPort(fpv)) errors.push({level:'error',msg:VMSG['error_port_range']});
    }
    if (sourceType === 'address') {
        var sa = getFieldValue('source_address');
        if (sa && !isValidIPorCIDR(sa)) errors.push({level:'error',msg:VMSG['error_bad_ip']});
    }
    if (destType === 'address') {
        var da = getFieldValue('destination_address');
        if (da && !isValidIPorCIDR(da)) errors.push({level:'error',msg:VMSG['error_bad_ip']});
    }
    if (sourceType === 'mac') {
        var mac = getFieldValue('source_mac');
        if (mac && !/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(mac))
            errors.push({level:'error',msg:VMSG['error_bad_mac']});
    }
    var family = getRadioValue('family');
    if (family === 'both') {
        var hasIP = false;
        if (sourceType === 'address' && getFieldValue('source_address')) hasIP = true;
        if (destType === 'address' && getFieldValue('destination_address')) hasIP = true;
        if (hasIP) errors.push({level:'warning',msg:VMSG['error_family_needed']});
    }
    if (action === 'mark') {
        var mv = getFieldValue('mark_value');
        if (mv && !/^(0x[0-9a-fA-F]+(\/0x[0-9a-fA-F]+)?|\d+(\/\d+)?)$/.test(mv))
            errors.push({level:'error',msg:VMSG['error_mark_format']});
    }
    if (getRadioValue('log_type') !== 'none' && (!action || action === 'none'))
        errors.push({level:'warning',msg:VMSG['warn_log_no_action']});
    return errors;
}

function renderValidationResults(errors, strict) {
    var el = document.getElementById('validation_results');
    if (!el) return;
    if (!errors || errors.length === 0) {
        el.innerHTML = '<div style="color:#2e7d32;padding:6px 10px;background:#e8f5e9;border:1px solid #a5d6a7;border-radius:4px;">&#10004; Rule looks valid</div>';
        return;
    }
    var html = '';
    for (var i = 0; i < errors.length; i++) {
        var e = errors[i];
        if (strict && e.level === 'error') {
            html += '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;margin-bottom:4px;">&#10008; '+e.msg+'</div>';
        } else {
            html += '<div style="color:#e65100;padding:6px 10px;background:#fff3e0;border:1px solid #ffcc80;border-radius:4px;margin-bottom:4px;">&#9888; '+e.msg+'</div>';
        }
    }
    el.innerHTML = html;
}

function testRule() {
    var ve = validateRule();
    var hasErrors = false;
    for (var i = 0; i < ve.length; i++) { if (ve[i].level === 'error') { hasErrors = true; break; } }
    if (hasErrors) {
        renderValidationResults(ve, true);
        var el = document.getElementById('test_results');
        if (el) el.innerHTML = '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;">&#10008; '+VMSG['test_fix_errors']+'</div>';
        return;
    }
    var btn = document.getElementById('test_rule_btn');
    var resultsEl = document.getElementById('test_results');
    if (btn) btn.disabled = true;
    if (resultsEl) resultsEl.innerHTML = '<div style="color:#1565c0;padding:6px 10px;background:#e3f2fd;border:1px solid #90caf9;border-radius:4px;">&#8987; '+VMSG['test_testing']+'</div>';
    var form = document.querySelector('form[action="save.cgi"]') || document.forms[0];
    var params = [];
    for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (!el.name) continue;
        if (el.type === 'checkbox' || el.type === 'radio') { if (!el.checked) continue; }
        params.push(encodeURIComponent(el.name)+'='+encodeURIComponent(el.value));
    }
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
                        resultsEl.innerHTML = '<div style="color:#2e7d32;padding:6px 10px;background:#e8f5e9;border:1px solid #a5d6a7;border-radius:4px;">&#10004; '+VMSG['test_success']+'<br><tt>'+escapeHtml(resp.rule||'')+'</tt></div>';
                    } else {
                        resultsEl.innerHTML = '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;">&#10008; '+VMSG['test_failed']+': '+escapeHtml(resp.message||'')+'</div>';
                    }
                } catch(e) { resultsEl.innerHTML = '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;">&#10008; Error parsing response</div>'; }
            } else { resultsEl.innerHTML = '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;">&#10008; Request failed (HTTP '+xhr.status+')</div>'; }
        }
    };
    xhr.onerror = function() { if (btn) btn.disabled = false; resultsEl.innerHTML = '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;">&#10008; XHR error</div>'; };
    xhr.ontimeout = function() { if (btn) btn.disabled = false; resultsEl.innerHTML = '<div style="color:#c62828;padding:6px 10px;background:#ffebee;border:1px solid #ef9a9a;border-radius:4px;">&#10008; Timeout</div>'; };
    xhr.send(params.join('&'));
}

function updatePreview() {
    var parts = ['rule'];
    var priority = getFieldValue('priority');
    if (priority !== '') parts.push('priority="'+priority+'"');
    var family = getRadioValue('family');
    if (family && family !== 'both') parts.push('family="'+family+'"');

    var sourceType = getSelectValue('source_type');
    if (sourceType && sourceType !== 'none') {
        var srcVal = getFieldValue('source_'+sourceType);
        if (srcVal) {
            var srcNot = getChecked('source_not') ? 'NOT ' : '';
            parts.push('source '+srcNot+sourceType+'="'+srcVal+'"');
        }
    }

    var destType = getSelectValue('destination_type');
    if (destType && destType !== 'none') {
        var dstNot = getChecked('destination_not') ? 'NOT ' : '';
        if (destType === 'address') {
            var da = getFieldValue('destination_address');
            if (da) parts.push('destination '+dstNot+'address="'+da+'"');
        } else if (destType === 'ipset') {
            var di = getFieldValue('destination_ipset');
            if (di) parts.push('destination '+dstNot+'ipset="'+di+'"');
        }
    }

    var elemType = getSelectValue('element_type');
    if (elemType === 'service') {
        var svc = getFieldValue('service_name');
        if (svc) parts.push('service name="'+svc+'"');
    } else if (elemType === 'protocol') {
        var prv = getFieldValue('protocol_value');
        if (prv) parts.push('protocol value="'+prv+'"');
    } else if (elemType === 'icmp-block') {
        var ib = getFieldValue('icmp_block');
        if (ib) parts.push('icmp-block name="'+ib+'"');
    } else if (elemType === 'icmp-type') {
        var it = getFieldValue('icmp_type');
        if (it) parts.push('icmp-type name="'+it+'"');
    } else if (elemType === 'masquerade') {
        parts.push('masquerade');
    } else if (elemType === 'forward-port') {
        var fp = getFieldValue('forward_port_value');
        var fpp = getRadioValue('forward_port_protocol');
        if (fp && fpp) {
            var fwd = 'forward-port port="'+fp+'" protocol="'+fpp+'"';
            var ftp = getFieldValue('forward_to_port');
            var fta = getFieldValue('forward_to_addr');
            if (ftp) fwd += ' to-port="'+ftp+'"';
            if (fta) fwd += ' to-addr="'+fta+'"';
            parts.push(fwd);
        }
    }

    // Port (destination port)
    var pv = getFieldValue('port_value');
    var pp = getRadioValue('port_protocol');
    if (pv && pp) parts.push('port port="'+pv+'" protocol="'+pp+'"');

    // Source port
    var spv = getFieldValue('source_port_value');
    var spp = getRadioValue('source_port_protocol');
    if (spv && spp) parts.push('source-port port="'+spv+'" protocol="'+spp+'"');

    var logType = getRadioValue('log_type');
    if (logType === 'log') {
        var logStr = 'log';
        var lp = getFieldValue('log_prefix');
        if (lp) logStr += ' prefix="'+lp+'"';
        var ll = getFieldValue('log_level');
        if (ll) logStr += ' level="'+ll+'"';
        var lr = getFieldValue('log_limit_rate');
        var lu = getFieldValue('log_limit_unit');
        if (lr && lu) logStr += ' limit value="'+lr+'/'+lu+'"';
        parts.push(logStr);
    } else if (logType === 'nflog') {
        var nfStr = 'nflog';
        var ng = getFieldValue('nflog_group');
        if (ng !== '') nfStr += ' group="'+ng+'"';
        var np = getFieldValue('log_prefix');
        if (np) nfStr += ' prefix="'+np+'"';
        var nq = getFieldValue('nflog_queue_size');
        if (nq !== '') nfStr += ' queue-size="'+nq+'"';
        var nlr = getFieldValue('log_limit_rate');
        var nlu = getFieldValue('log_limit_unit');
        if (nlr && nlu) nfStr += ' limit value="'+nlr+'/'+nlu+'"';
        parts.push(nfStr);
    }

    if (getChecked('audit')) {
        var auditStr = 'audit';
        var alr = getFieldValue('audit_limit_rate');
        var alu = getFieldValue('audit_limit_unit');
        if (alr && alu) auditStr += ' limit value="'+alr+'/'+alu+'"';
        parts.push(auditStr);
    }

    var action = getSelectValue('action');
    if (action && action !== 'none') {
        var actStr = action;
        if (action === 'reject') {
            var rt = getFieldValue('reject_type');
            if (rt) actStr += ' type="'+rt+'"';
        } else if (action === 'mark') {
            var mv = getFieldValue('mark_value');
            actStr = 'mark set="'+(mv||'0x1')+'"';
        }
        var alr2 = getFieldValue('action_limit_rate');
        var alu2 = getFieldValue('action_limit_unit');
        if (alr2 && alu2) actStr += ' limit value="'+alr2+'/'+alu2+'"';
        parts.push(actStr);
    }

    var el = document.getElementById('preview_text');
    if (el) el.textContent = parts.join(' ');
    renderValidationResults(validateRule(), false);
}

function initForm() {
    updateProtoClass();
    updateSourceType();
    updateDestinationType();
    updateElementType();
    updateLogType();
    updateAudit();
    updateAction();
    updatePreview();

    var form = document.querySelector('form[action="save.cgi"]') || document.forms[0];
    if (form) {
        form.addEventListener('input', function() { updatePreview(); });
        form.addEventListener('change', function(e) {
            var name = e.target && e.target.name;
            if (name === 'proto_class') updateProtoClass();
            else if (name === 'source_type') updateSourceType();
            else if (name === 'destination_type') updateDestinationType();
            else if (name === 'element_type') updateElementType();
            else if (name === 'log_type') updateLogType();
            else if (name === 'audit') updateAudit();
            else if (name === 'action') updateAction();
            updatePreview();
        });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initForm);
} else {
    initForm();
}
setTimeout(initForm, 500);
</script>
JSEOF

&ui_print_footer("index.cgi", $text{'index_return'});
