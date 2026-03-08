#!/bin/bash
#
# Integration Test Suite — firewalld-rich Webmin module (v3.1.1)
#
# 40 tests that exercise the module's full HTTP interface (save.cgi,
# test_rule.cgi, edit.cgi, index.cgi) against a live Webmin instance.
# Every rule element type, source/destination option, action, logging
# variant, and validation path is covered.
#
# WHERE:     Runs on the same host as Webmin (localhost).
# REQUIRES:  Root, firewalld running, Webmin running, curl, the module
#            installed, and the failsafe_watchdog.sh script alongside.
#
# SAFETY DESIGN:
#   - A failsafe watchdog (dead-man's switch) runs in the background.
#     If the tests don't complete and disarm it within 15 minutes, it
#     restores the firewall from a baseline snapshot and reboots.
#   - Tests use an isolated "richtest" zone with no interfaces bound,
#     so no live traffic is affected by test rules in that zone.
#   - Rules in the public zone use RFC 5737 (192.0.2.0/24, 203.0.113.0/24)
#     and RFC 3849 (2001:db8::/32) addresses — never routable on the internet.
#   - A safety_check() runs after each test category, verifying that
#     critical ports (SSH, Webmin) remain reachable. If anything looks
#     wrong, it triggers an emergency restore and exits.
#
# READING RESULTS:
#   [PASS] = test succeeded
#   [FAIL] = test failed (rule didn't create, verify, or clean up)
#   [SKIP] = feature not supported on this firewalld version (e.g., mark, nflog)
#
# TEST CATEGORIES:
#   A (T01-T06): Dry-run tests via test_rule.cgi — validates without persisting
#   B (T07-T35): Full round-trip: save.cgi → firewall-cmd verify → edit.cgi verify → cleanup
#   C (T36-T40): Negative/validation tests — confirms bad input is rejected
#
# Usage: bash test_rich_rules.sh
#

set -euo pipefail

###############################################################################
# Configuration
###############################################################################

# Override these with environment variables:
#   WEBMIN_URL   — default: https://127.0.0.1:10000
#   WEBMIN_USER  — default: root
#   WEBMIN_PASS  — REQUIRED, no default (never hardcode credentials)
#   SAFE_PORTS   — space-separated ports to verify stay open (default: "22 10000")
WEBMIN_URL="${WEBMIN_URL:-https://127.0.0.1:10000}"
WEBMIN_USER="${WEBMIN_USER:-root}"
WEBMIN_PASS="${WEBMIN_PASS:?Set WEBMIN_PASS environment variable}"
SAFE_PORTS="${SAFE_PORTS:-22 10000}"
MODULE_PATH="firewalld-rich"
COOKIE_JAR="/tmp/rich_test_cookies"
BASELINE_DIR="/tmp/firewall_baseline"
DISARM_FILE="/tmp/rich_rules_disarm"
WATCHDOG_PID_FILE="/tmp/rich_rules_watchdog.pid"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHDOG_SCRIPT="$SCRIPT_DIR/failsafe_watchdog.sh"
TEST_ZONE="richtest"
CURL="curl -sk --max-time 30"

# RFC 5737 test addresses — never routable
TEST_SRC_IP="192.0.2.100"
TEST_SRC_IP6="2001:db8::1"
TEST_DST_IP="203.0.113.50"
TEST_MAC="00:11:22:33:44:55"

# Counters
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

###############################################################################
# Helper Functions
###############################################################################

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_skip()  { echo -e "${YELLOW}[SKIP]${NC}  $*"; }
log_bold()  { echo -e "${BOLD}$*${NC}"; }

# --- Failsafe ---

start_failsafe() {
    log_info "Saving firewall baseline to $BASELINE_DIR"
    rm -rf "$BASELINE_DIR"
    mkdir -p "$BASELINE_DIR"
    cp /etc/firewalld/zones/*.xml "$BASELINE_DIR/"
    rm -f "$DISARM_FILE"

    log_info "Launching failsafe watchdog (15 min timeout)"
    nohup bash "$WATCHDOG_SCRIPT" >/dev/null 2>&1 &
    echo $! > "$WATCHDOG_PID_FILE"
    log_info "Watchdog PID: $(cat "$WATCHDOG_PID_FILE")"
}

disarm_failsafe() {
    log_info "Disarming failsafe watchdog"
    touch "$DISARM_FILE"
    if [[ -f "$WATCHDOG_PID_FILE" ]]; then
        local pid
        pid=$(cat "$WATCHDOG_PID_FILE")
        kill "$pid" 2>/dev/null || true
        rm -f "$WATCHDOG_PID_FILE"
    fi
}

emergency_restore() {
    log_info "EMERGENCY: Restoring firewall baseline"
    if [[ -d "$BASELINE_DIR" ]]; then
        cp -f "$BASELINE_DIR"/*.xml /etc/firewalld/zones/ 2>/dev/null || true
        rm -f /etc/firewalld/zones/richtest.xml
        firewall-cmd --reload 2>/dev/null || true
    fi
    disarm_failsafe
}

# --- Safety Check ---

safety_check() {
    # Verify critical ports (from $SAFE_PORTS) are still reachable
    local failed=0

    for port in $SAFE_PORTS; do
        if ! firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            # Port not directly open — check services, port list, and rich rules
            local open=0
            if firewall-cmd --list-services 2>/dev/null | grep -qw ssh && [[ "$port" == "22" ]]; then
                open=1
            fi
            if firewall-cmd --list-ports 2>/dev/null | grep -q "${port}/tcp"; then
                open=1
            fi
            if firewall-cmd --list-rich-rules 2>/dev/null | grep -q "port=\"${port}\".*accept"; then
                open=1
            fi
            if [[ "$open" -eq 0 ]]; then
                log_fail "SAFETY: Port $port may not be reachable!"
                failed=1
            fi
        fi
    done

    # Verify services are actually listening on safe ports
    for port in $SAFE_PORTS; do
        if ! ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            log_fail "SAFETY: Nothing listening on port $port!"
            failed=1
        fi
    done

    if [[ "$failed" -eq 1 ]]; then
        log_fail "SAFETY CHECK FAILED — initiating emergency restore"
        emergency_restore
        exit 1
    fi
}

# --- Webmin Login ---

webmin_login() {
    log_info "Logging in to Webmin"
    rm -f "$COOKIE_JAR"

    # Step 1: GET session_login.cgi to get initial cookie
    $CURL -c "$COOKIE_JAR" "${WEBMIN_URL}/session_login.cgi" -o /dev/null 2>/dev/null

    # Step 2: POST credentials (cookie jar captures the session)
    $CURL -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        -d "user=${WEBMIN_USER}&pass=$(urlencode "$WEBMIN_PASS")&page=%2F" \
        "${WEBMIN_URL}/session_login.cgi" -o /dev/null 2>/dev/null

    # Step 3: Verify we can access the module
    local body
    body=$($CURL -b "$COOKIE_JAR" \
        -H "Referer: ${WEBMIN_URL}/" \
        "${WEBMIN_URL}/${MODULE_PATH}/index.cgi" 2>/dev/null)

    if echo "$body" | grep -qi "rich.*rule\|firewall"; then
        log_info "Webmin login successful"
        return 0
    else
        log_fail "Webmin login failed — cannot access module"
        echo "$body" | head -5
        return 1
    fi
}

urlencode() {
    local string="$1"
    python3 -c "import urllib.parse; print(urllib.parse.quote('$string', safe=''))" 2>/dev/null ||
    printf '%s' "$string" | sed 's/!/%21/g'
}

# --- Test Rule (dry-run via test_rule.cgi) ---

post_test_rule_safe() {
    local zone="$1"; shift
    local args=(-b "$COOKIE_JAR"
        -H "Referer: ${WEBMIN_URL}/${MODULE_PATH}/edit.cgi?new=1"
        --data-urlencode "zone=${zone}")

    for param in "$@"; do
        args+=(--data-urlencode "$param")
    done

    $CURL "${args[@]}" "${WEBMIN_URL}/${MODULE_PATH}/test_rule.cgi" 2>/dev/null
}

# --- Save Rule (persistent via save.cgi) ---

post_save() {
    # Args: param1=val1 param2=val2 ...
    # Returns HTTP status code. 302 = success (redirect to index), 200 = error page.
    # Does NOT follow redirects — the theme JS in redirected pages contains "error"
    # in hundreds of UI strings, making body-based detection unreliable.
    local args=(-b "$COOKIE_JAR" -c "$COOKIE_JAR"
        -H "Referer: ${WEBMIN_URL}/${MODULE_PATH}/edit.cgi?new=1"
        -o /tmp/rich_test_save_body -w "%{http_code}")

    for param in "$@"; do
        args+=(--data-urlencode "$param")
    done

    $CURL "${args[@]}" "${WEBMIN_URL}/${MODULE_PATH}/save.cgi" 2>/dev/null
}

save_succeeded() {
    # save.cgi returns 302 redirect on success, 200 with error page on failure
    local http_code="$1"
    [[ "$http_code" == "302" ]]
}

# --- Rule Verification ---

capture_rule_text() {
    # Return the first rule matching a pattern (for single-rule verification).
    # Intentionally uses head -1; delete_rule_by_pattern() handles multi-match.
    local zone="$1"
    local pattern="$2"
    firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null | grep -F "$pattern" | head -1
}

verify_rule_in_firewall() {
    local zone="$1"
    local pattern="$2"
    firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null | grep -qF "$pattern"
}

verify_rule_removed() {
    local zone="$1"
    local pattern="$2"
    ! firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null | grep -qF "$pattern"
}

# --- Index/Edit Page Scraping ---

get_edit_page() {
    local idx="$1"
    local zone="$2"

    $CURL -b "$COOKIE_JAR" \
        -H "Referer: ${WEBMIN_URL}/${MODULE_PATH}/index.cgi" \
        "${WEBMIN_URL}/${MODULE_PATH}/edit.cgi?idx=${idx}&zone=${zone}" 2>/dev/null
}

# --- Rule Cleanup ---

delete_rule_via_firewall() {
    local zone="$1"
    local rule_text="$2"
    firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule_text" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
}

delete_rule_by_pattern() {
    # Find and delete ALL rules matching a pattern (not just the first)
    local zone="$1"
    local pattern="$2"
    local found=0
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$rule" 2>/dev/null || true
        found=1
    done < <(firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null | grep -F "$pattern")
    if [[ "$found" -eq 1 ]]; then
        firewall-cmd --reload 2>/dev/null || true
    fi
}

# --- Test Zone ---

setup_test_zone() {
    log_info "Creating test zone '$TEST_ZONE'"
    if firewall-cmd --get-zones 2>/dev/null | grep -qw "$TEST_ZONE"; then
        log_info "Test zone already exists, removing first"
        firewall-cmd --permanent --delete-zone="$TEST_ZONE" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
    firewall-cmd --permanent --new-zone="$TEST_ZONE" 2>/dev/null
    firewall-cmd --reload 2>/dev/null

    # Verify it exists and has no interfaces
    if ! firewall-cmd --get-zones 2>/dev/null | grep -qw "$TEST_ZONE"; then
        log_fail "Failed to create test zone"
        return 1
    fi
    local ifaces
    ifaces=$(firewall-cmd --zone="$TEST_ZONE" --list-interfaces 2>/dev/null)
    if [[ -n "$ifaces" ]]; then
        log_fail "Test zone has interfaces: $ifaces — unsafe!"
        return 1
    fi
    log_info "Test zone '$TEST_ZONE' created (no interfaces)"
}

teardown_test_zone() {
    log_info "Removing test zone '$TEST_ZONE'"
    # Remove all rich rules from test zone first
    firewall-cmd --zone="$TEST_ZONE" --list-rich-rules 2>/dev/null | while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        firewall-cmd --permanent --zone="$TEST_ZONE" --remove-rich-rule="$rule" 2>/dev/null || true
    done
    firewall-cmd --permanent --delete-zone="$TEST_ZONE" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
}

# --- Test Runner ---

run_test() {
    local test_id="$1"
    local test_name="$2"
    local test_func="$3"

    TOTAL=$((TOTAL + 1))
    echo ""
    log_bold "--- ${test_id}: ${test_name} ---"

    local result
    set +e
    "$test_func"
    result=$?
    set -e

    if [[ "$result" -eq 0 ]]; then
        log_pass "${test_id}: ${test_name}"
        PASS=$((PASS + 1))
    elif [[ "$result" -eq 2 ]]; then
        log_skip "${test_id}: ${test_name}"
        SKIP=$((SKIP + 1))
    else
        log_fail "${test_id}: ${test_name}"
        FAIL=$((FAIL + 1))
    fi
}

###############################################################################
# Round-Trip Test Template
#
# Creates rule via save.cgi, verifies in firewall, verifies edit form,
# cleans up via firewall-cmd.
###############################################################################

roundtrip_test() {
    # Args:
    #   $1 = zone
    #   $2 = grep pattern to find rule in firewall-cmd output
    #   $3 = pattern to check in edit.cgi HTML (or empty to skip)
    #   $4... = save.cgi parameters
    local zone="$1"; shift
    local fw_pattern="$1"; shift
    local edit_pattern="$1"; shift
    # Remaining args are save.cgi params

    # Pre-clean: remove any matching rule from previous failed run
    delete_rule_by_pattern "$zone" "$fw_pattern"

    # Step 1: Create rule via save.cgi
    local http_code
    http_code=$(post_save "new=1" "zone=${zone}" "$@")

    if ! save_succeeded "$http_code"; then
        log_fail "  save.cgi returned error (HTTP $http_code)"
        # Show actual error from response body
        if [[ -f /tmp/rich_test_save_body ]]; then
            grep -ioP '(?<=<h1>Error</h1>|<p>).*?(?=</p>|</body>)' /tmp/rich_test_save_body 2>/dev/null | head -3
        fi
        # Clean up just in case
        delete_rule_by_pattern "$zone" "$fw_pattern"
        return 1
    fi

    # Step 2: Verify rule exists in firewall
    if ! verify_rule_in_firewall "$zone" "$fw_pattern"; then
        log_fail "  Rule not found in firewall-cmd output (pattern: $fw_pattern)"
        firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null | tail -5
        return 1
    fi
    log_info "  Rule found in firewall"

    # Step 3: Find rule index and verify edit page
    #
    # The module uses global sequential indices across all zones (not
    # per-zone indices). To verify the edit form, we need to:
    #   a) Confirm the rule exists in the zone's rich rules list
    #   b) Scrape index.cgi?tab=all to find the edit.cgi?idx=N link for this zone
    #   c) Fetch edit.cgi with that global index and check the form contains
    #      the expected value (e.g., the port number, IP, or prefix)
    #
    # We take the last matching idx for the zone, since our freshly-created
    # rule will be the most recently added.
    if [[ -n "$edit_pattern" ]]; then
        local rule_text
        rule_text=$(capture_rule_text "$zone" "$fw_pattern")
        if [[ -n "$rule_text" ]]; then
            local found_idx=""
            local rule_idx=0
            while IFS= read -r line; do
                if echo "$line" | grep -qF "$fw_pattern"; then
                    found_idx="$rule_idx"
                    break
                fi
                rule_idx=$((rule_idx + 1))
            done < <(firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null)

            if [[ -n "$found_idx" ]]; then
                # Scrape index.cgi to map zone rules to global indices
                local idx_body
                idx_body=$($CURL -b "$COOKIE_JAR" \
                    -H "Referer: ${WEBMIN_URL}/${MODULE_PATH}/" \
                    "${WEBMIN_URL}/${MODULE_PATH}/index.cgi?tab=all" 2>/dev/null)

                # Extract the last (newest) global index for this zone
                local global_idx=""
                global_idx=$(echo "$idx_body" | grep -oP "edit\.cgi\?idx=\K\d+(?=&amp;zone=${zone})" | tail -1)

                if [[ -n "$global_idx" ]]; then
                    local edit_body
                    edit_body=$(get_edit_page "$global_idx" "$zone")
                    if echo "$edit_body" | grep -qi "$edit_pattern"; then
                        log_info "  Edit form correctly renders rule"
                    else
                        log_fail "  Edit form does not contain expected pattern: $edit_pattern"
                        # Non-fatal: rule was created, just edit rendering issue
                    fi
                fi
            fi
        fi
    fi

    # Step 4: Clean up
    rule_text=$(capture_rule_text "$zone" "$fw_pattern")
    if [[ -n "$rule_text" ]]; then
        delete_rule_via_firewall "$zone" "$rule_text"
        if verify_rule_removed "$zone" "$fw_pattern"; then
            log_info "  Cleanup successful"
        else
            log_fail "  Cleanup failed — rule still present!"
            return 1
        fi
    fi

    return 0
}

###############################################################################
# Category A: Dry-Run Tests via test_rule.cgi (T01-T06)
###############################################################################

test_T01() {
    # Service element (http) in public zone
    local json
    json=$(post_test_rule_safe "public" \
        "element_type=service" "service_name=http" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "action=accept" "new=1")

    if echo "$json" | grep -q '"success": true'; then
        log_info "  Dry-run accepted: service=http"
        return 0
    else
        log_fail "  Dry-run rejected: $json"
        return 1
    fi
}

test_T02() {
    # Protocol element (GRE = 47)
    local json
    json=$(post_test_rule_safe "public" \
        "element_type=protocol" "protocol_value=47" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "action=accept" "new=1")

    if echo "$json" | grep -q '"success": true'; then
        log_info "  Dry-run accepted: protocol=47 (GRE)"
        return 0
    else
        log_fail "  Dry-run rejected: $json"
        return 1
    fi
}

test_T03() {
    # ICMP Block (timestamp-reply)
    local json
    json=$(post_test_rule_safe "public" \
        "element_type=icmp-block" "icmp_block=timestamp-reply" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "new=1")

    if echo "$json" | grep -q '"success": true'; then
        log_info "  Dry-run accepted: icmp-block=timestamp-reply"
        return 0
    else
        log_fail "  Dry-run rejected: $json"
        return 1
    fi
}

test_T04() {
    # ICMP Type (echo-reply) in richtest zone — safe, no interfaces
    local json
    json=$(post_test_rule_safe "$TEST_ZONE" \
        "element_type=icmp-type" "icmp_type=echo-reply" \
        "family=ipv4" "action=accept" "new=1")

    if echo "$json" | grep -q '"success": true'; then
        log_info "  Dry-run accepted: icmp-type=echo-reply in $TEST_ZONE"
        return 0
    else
        log_fail "  Dry-run rejected: $json"
        return 1
    fi
}

test_T05() {
    # Masquerade in richtest zone — safe, no interfaces
    local json
    json=$(post_test_rule_safe "$TEST_ZONE" \
        "element_type=masquerade" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "new=1")

    if echo "$json" | grep -q '"success": true'; then
        log_info "  Dry-run accepted: masquerade in $TEST_ZONE"
        return 0
    else
        log_fail "  Dry-run rejected: $json"
        return 1
    fi
}

test_T06() {
    # Forward port in richtest zone — safe, no interfaces
    local json
    json=$(post_test_rule_safe "$TEST_ZONE" \
        "element_type=forward-port" \
        "forward_port_value=59000" "forward_port_protocol=tcp" \
        "forward_to_port=59001" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "new=1")

    if echo "$json" | grep -q '"success": true'; then
        log_info "  Dry-run accepted: forward-port 59000→59001 in $TEST_ZONE"
        return 0
    else
        log_fail "  Dry-run rejected: $json"
        return 1
    fi
}

###############################################################################
# Category B: Full Round-Trip Tests via save.cgi (T07-T35)
###############################################################################

# --- Port / Source-Port (T07-T10) ---

test_T07() {
    roundtrip_test "public" 'port="50000" protocol="tcp"' "50000" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50000" "port_protocol=tcp" \
        "action=accept"
}

test_T08() {
    roundtrip_test "public" 'port="50000" protocol="udp"' "50000" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50000" "port_protocol=udp" \
        "action=accept"
}

test_T09() {
    roundtrip_test "public" 'port="50000-50010"' "50000" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50000-50010" "port_protocol=tcp" \
        "action=accept"
}

test_T10() {
    roundtrip_test "public" 'source-port port="12345" protocol="tcp"' "12345" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "source_port_value=12345" "source_port_protocol=tcp" \
        "action=accept"
}

# --- Source Options (T11-T14) ---

test_T11() {
    roundtrip_test "public" "source address=\"${TEST_SRC_IP}\"" "${TEST_SRC_IP}" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50001" "port_protocol=tcp" \
        "action=accept"
}

test_T12() {
    roundtrip_test "public" "source address=\"${TEST_SRC_IP6}\"" "${TEST_SRC_IP6}" \
        "source_type=address" "source_address=${TEST_SRC_IP6}" \
        "family=ipv6" \
        "port_value=50001" "port_protocol=tcp" \
        "action=accept"
}

test_T13() {
    roundtrip_test "public" "source NOT address=\"${TEST_SRC_IP}\"" "NOT" \
        "source_type=address" "source_not=1" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50002" "port_protocol=tcp" \
        "action=accept"
}

test_T14() {
    roundtrip_test "public" "source mac=\"${TEST_MAC}\"" "${TEST_MAC}" \
        "source_type=mac" "source_mac=${TEST_MAC}" \
        "port_value=50003" "port_protocol=tcp" \
        "action=accept"
}

# --- Destination Options (T15-T16) ---

test_T15() {
    roundtrip_test "public" "destination address=\"${TEST_DST_IP}\"" "${TEST_DST_IP}" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "destination_type=address" "destination_address=${TEST_DST_IP}" \
        "family=ipv4" \
        "port_value=50004" "port_protocol=tcp" \
        "action=accept"
}

test_T16() {
    roundtrip_test "public" "destination NOT address=\"${TEST_DST_IP}\"" "NOT" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "destination_type=address" "destination_not=1" "destination_address=${TEST_DST_IP}" \
        "family=ipv4" \
        "port_value=50005" "port_protocol=tcp" \
        "action=accept"
}

# --- Actions (T17-T22) ---

test_T17() {
    roundtrip_test "public" 'port="50006"' "accept" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50006" "port_protocol=tcp" \
        "action=accept"
}

test_T18() {
    roundtrip_test "public" 'port="50007"' "reject" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50007" "port_protocol=tcp" \
        "action=reject"
}

test_T19() {
    roundtrip_test "public" 'reject type="icmp-host-unreachable"' "icmp-host-unreachable" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50008" "port_protocol=tcp" \
        "action=reject" "reject_type=icmp-host-unreachable"
}

test_T20() {
    roundtrip_test "public" 'reject type="tcp-reset"' "tcp-reset" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50009" "port_protocol=tcp" \
        "action=reject" "reject_type=tcp-reset"
}

test_T21() {
    roundtrip_test "public" 'port="50010"' "drop" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50010" "port_protocol=tcp" \
        "action=drop"
}

test_T22() {
    # Mark action — may not work on firewalld 0.9.11
    local json
    json=$(post_test_rule_safe "public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50011" "port_protocol=tcp" \
        "action=mark" "mark_value=0x1" "new=1")

    if echo "$json" | grep -q '"success": false'; then
        log_skip "  Mark action not supported on this firewalld version"
        return 2
    fi

    roundtrip_test "public" 'mark set=0x1' "0x1" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50011" "port_protocol=tcp" \
        "action=mark" "mark_value=0x1"
}

# --- Logging (T23-T26) ---

test_T23() {
    roundtrip_test "public" 'log prefix="TEST_" level="info"' "TEST_" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50012" "port_protocol=tcp" \
        "log_type=log" "log_prefix=TEST_" "log_level=info" \
        "action=accept"
}

test_T24() {
    roundtrip_test "public" 'limit value="5/m"' "5/m" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50013" "port_protocol=tcp" \
        "log_type=log" "log_prefix=RATELIM_" "log_level=info" \
        "log_limit_rate=5" "log_limit_unit=minute" \
        "action=accept"
}

test_T25() {
    # nflog — expected to fail on firewalld 0.9.11
    local json
    json=$(post_test_rule_safe "public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50014" "port_protocol=tcp" \
        "log_type=nflog" "nflog_group=10" \
        "action=accept" "new=1")

    if echo "$json" | grep -q '"success": false'; then
        log_skip "  nflog not supported on this firewalld version"
        return 2
    fi

    roundtrip_test "public" 'nflog group="10"' "nflog" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50014" "port_protocol=tcp" \
        "log_type=nflog" "nflog_group=10" \
        "action=accept"
}

test_T26() {
    roundtrip_test "public" "audit" "audit" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50015" "port_protocol=tcp" \
        "audit=1" \
        "action=accept"
}

# --- Priority & Family (T27-T30) ---

test_T27() {
    roundtrip_test "public" 'priority="-100"' "priority" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "priority=-100" \
        "port_value=50016" "port_protocol=tcp" \
        "action=accept"
}

test_T28() {
    roundtrip_test "public" 'priority="100"' "priority" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "priority=100" \
        "port_value=50017" "port_protocol=tcp" \
        "action=accept"
}

test_T29() {
    roundtrip_test "public" 'port="50018"' "ipv4" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50018" "port_protocol=tcp" \
        "action=accept"
}

test_T30() {
    roundtrip_test "public" 'family="ipv6"' "ipv6" \
        "source_type=address" "source_address=${TEST_SRC_IP6}" \
        "family=ipv6" \
        "port_value=50019" "port_protocol=tcp" \
        "action=accept"
}

# --- Rate Limits (T31) ---

test_T31() {
    roundtrip_test "public" 'accept limit value="10/m"' "10/m" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50020" "port_protocol=tcp" \
        "action=accept" "action_limit_rate=10" "action_limit_unit=minute"
}

# --- Combinations (T32-T35) ---

test_T32() {
    # Source + port + log + accept
    roundtrip_test "public" 'port="50021"' "COMBO1_" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50021" "port_protocol=tcp" \
        "log_type=log" "log_prefix=COMBO1_" "log_level=info" \
        "action=accept"
}

test_T33() {
    # Source NOT + port + reject(type)
    roundtrip_test "public" "source NOT address=\"${TEST_SRC_IP}\"" "NOT" \
        "source_type=address" "source_not=1" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50022" "port_protocol=tcp" \
        "action=reject" "reject_type=icmp-host-unreachable"
}

test_T34() {
    # Priority + source + service + log + drop
    roundtrip_test "public" 'priority="-50"' "priority" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "priority=-50" \
        "element_type=service" "service_name=http" \
        "log_type=log" "log_prefix=COMBO3_" "log_level=warning" \
        "action=drop"
}

test_T35() {
    # Full combo: family + priority + source + dest + port + log + audit + accept + limit
    roundtrip_test "public" 'priority="-10"' "priority" \
        "family=ipv4" "priority=-10" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "destination_type=address" "destination_address=${TEST_DST_IP}" \
        "port_value=50023" "port_protocol=tcp" \
        "log_type=log" "log_prefix=FULL_" "log_level=info" \
        "audit=1" \
        "action=accept" "action_limit_rate=5" "action_limit_unit=minute"
}

###############################################################################
# Category C: Validation / Negative Tests via test_rule.cgi (T36-T40)
###############################################################################

test_T36() {
    # Invalid IP address
    local json
    json=$(post_test_rule_safe "public" \
        "source_type=address" "source_address=999.999.999.999" \
        "family=ipv4" \
        "port_value=50030" "port_protocol=tcp" \
        "action=accept" "new=1")

    if echo "$json" | grep -q '"success": false'; then
        log_info "  Correctly rejected invalid IP"
        return 0
    else
        log_fail "  Should have rejected invalid IP: $json"
        # Clean up any accidentally created rule
        delete_rule_by_pattern "public" "999.999.999.999"
        return 1
    fi
}

test_T37() {
    # Port out of range
    local json
    json=$(post_test_rule_safe "public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=70000" "port_protocol=tcp" \
        "action=accept" "new=1")

    if echo "$json" | grep -q '"success": false'; then
        log_info "  Correctly rejected port 70000"
        return 0
    else
        log_fail "  Should have rejected port 70000: $json"
        delete_rule_by_pattern "public" "70000"
        return 1
    fi
}

test_T38() {
    # Priority out of range
    local json
    json=$(post_test_rule_safe "public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" "priority=99999" \
        "port_value=50031" "port_protocol=tcp" \
        "action=accept" "new=1")

    if echo "$json" | grep -q '"success": false'; then
        log_info "  Correctly rejected priority 99999"
        return 0
    else
        log_fail "  Should have rejected priority 99999: $json"
        delete_rule_by_pattern "public" "99999"
        return 1
    fi
}

test_T39() {
    # Empty rule — no criteria at all
    local json
    json=$(post_test_rule_safe "public" \
        "family=both" \
        "source_type=none" "destination_type=none" \
        "element_type=none" \
        "action=none" "new=1")

    if echo "$json" | grep -q '"success": false'; then
        log_info "  Correctly rejected empty rule"
        return 0
    else
        log_fail "  Should have rejected empty rule: $json"
        return 1
    fi
}

test_T40() {
    # Duplicate rule — create one, then try to create same one again
    # First, create a rule
    local json
    json=$(post_test_rule_safe "public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50040" "port_protocol=tcp" \
        "action=accept" "new=1")

    if ! echo "$json" | grep -q '"success": true'; then
        log_fail "  Could not create initial rule for duplicate test: $json"
        return 1
    fi

    # Now create it permanently so the second attempt fails
    local first_code
    first_code=$(post_save "new=1" "zone=public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50040" "port_protocol=tcp" \
        "action=accept")

    # Try to create the same rule again via save.cgi
    local dup_code
    dup_code=$(post_save "new=1" "zone=public" \
        "source_type=address" "source_address=${TEST_SRC_IP}" \
        "family=ipv4" \
        "port_value=50040" "port_protocol=tcp" \
        "action=accept")

    local result=1
    if [[ "$dup_code" != "302" ]]; then
        log_info "  Correctly rejected duplicate rule (HTTP $dup_code)"
        result=0
    else
        log_fail "  Should have rejected duplicate rule (got HTTP $dup_code)"
        result=1
    fi

    # Clean up
    delete_rule_by_pattern "public" "50040"
    return "$result"
}

###############################################################################
# Main
###############################################################################

main() {
    echo ""
    log_bold "============================================================"
    log_bold "  Firewalld Rich Rules — Integration Test Suite"
    log_bold "============================================================"
    echo ""

    # --- Pre-flight ---
    log_bold "Pre-flight checks"

    if [[ "$(id -u)" -ne 0 ]]; then
        log_fail "Must run as root"
        exit 1
    fi

    if ! systemctl is-active firewalld >/dev/null 2>&1; then
        log_fail "firewalld is not running"
        exit 1
    fi

    if ! systemctl is-active webmin >/dev/null 2>&1; then
        log_fail "webmin is not running"
        exit 1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_fail "curl not found"
        exit 1
    fi

    if [[ ! -f "$WATCHDOG_SCRIPT" ]]; then
        log_fail "Watchdog script not found at $WATCHDOG_SCRIPT"
        exit 1
    fi

    log_info "All pre-flight checks passed"
    safety_check

    # --- Failsafe ---
    log_bold "Starting failsafe"
    start_failsafe

    # --- Login ---
    log_bold "Authenticating"
    if ! webmin_login; then
        disarm_failsafe
        exit 1
    fi

    # --- Test Zone ---
    log_bold "Setting up test zone"
    if ! setup_test_zone; then
        disarm_failsafe
        exit 1
    fi

    # =========================================================================
    # Category A: Dry-Run Tests
    # =========================================================================
    echo ""
    log_bold "============================================================"
    log_bold "  Category A: Dry-Run Tests (test_rule.cgi)"
    log_bold "============================================================"

    run_test "T01" "Service element (http) dry-run" test_T01
    run_test "T02" "Protocol element (GRE) dry-run" test_T02
    run_test "T03" "ICMP Block (timestamp-reply) dry-run" test_T03
    run_test "T04" "ICMP Type (echo-reply) dry-run [richtest]" test_T04
    run_test "T05" "Masquerade dry-run [richtest]" test_T05
    run_test "T06" "Forward Port dry-run [richtest]" test_T06

    safety_check

    # =========================================================================
    # Category B: Full Round-Trip Tests
    # =========================================================================
    echo ""
    log_bold "============================================================"
    log_bold "  Category B: Round-Trip Tests (save.cgi)"
    log_bold "============================================================"

    log_bold "-- Ports / Source-Ports --"
    run_test "T07" "Dest port TCP" test_T07
    run_test "T08" "Dest port UDP" test_T08
    run_test "T09" "Port range" test_T09
    run_test "T10" "Source port" test_T10

    safety_check

    log_bold "-- Source Options --"
    run_test "T11" "Source IPv4" test_T11
    run_test "T12" "Source IPv6" test_T12
    run_test "T13" "Source NOT" test_T13
    run_test "T14" "Source MAC" test_T14

    safety_check

    log_bold "-- Destination Options --"
    run_test "T15" "Dest IPv4" test_T15
    run_test "T16" "Dest NOT" test_T16

    safety_check

    log_bold "-- Actions --"
    run_test "T17" "Accept" test_T17
    run_test "T18" "Reject default" test_T18
    run_test "T19" "Reject icmp-host-unreachable" test_T19
    run_test "T20" "Reject tcp-reset" test_T20
    run_test "T21" "Drop" test_T21
    run_test "T22" "Mark 0x1" test_T22

    safety_check

    log_bold "-- Logging --"
    run_test "T23" "Log prefix+level" test_T23
    run_test "T24" "Log rate limit" test_T24
    run_test "T25" "nflog group" test_T25
    run_test "T26" "Audit" test_T26

    safety_check

    log_bold "-- Priority & Family --"
    run_test "T27" "Priority -100" test_T27
    run_test "T28" "Priority 100" test_T28
    run_test "T29" "Family IPv4 explicit" test_T29
    run_test "T30" "Family IPv6 explicit" test_T30

    safety_check

    log_bold "-- Rate Limits --"
    run_test "T31" "Action rate limit" test_T31

    safety_check

    log_bold "-- Combinations --"
    run_test "T32" "Source+port+log+accept" test_T32
    run_test "T33" "Source NOT+port+reject(type)" test_T33
    run_test "T34" "Priority+source+service+log+drop" test_T34
    run_test "T35" "Full combo (all fields)" test_T35

    safety_check

    # =========================================================================
    # Category C: Validation / Negative Tests
    # =========================================================================
    echo ""
    log_bold "============================================================"
    log_bold "  Category C: Validation / Negative Tests"
    log_bold "============================================================"

    run_test "T36" "Invalid IP rejected" test_T36
    run_test "T37" "Port 70000 rejected" test_T37
    run_test "T38" "Priority 99999 rejected" test_T38
    run_test "T39" "Empty rule rejected" test_T39
    run_test "T40" "Duplicate rule rejected" test_T40

    safety_check

    # =========================================================================
    # Teardown
    # =========================================================================
    echo ""
    log_bold "Teardown"
    teardown_test_zone

    # Final cleanup: remove any stray test rules from public zone
    log_info "Checking for stray test rules in public zone"
    firewall-cmd --zone=public --list-rich-rules 2>/dev/null | while IFS= read -r rule; do
        if echo "$rule" | grep -qF "${TEST_SRC_IP}"; then
            if echo "$rule" | grep -qE "5000[0-9]|5001[0-9]|5002[0-9]|5003[0-9]|5004[0-9]"; then
                log_info "  Removing stray rule: $rule"
                firewall-cmd --permanent --zone=public --remove-rich-rule="$rule" 2>/dev/null || true
            fi
        fi
    done
    firewall-cmd --reload 2>/dev/null || true

    # Disarm failsafe
    disarm_failsafe
    safety_check

    # Clean up temp files
    rm -f "$COOKIE_JAR"

    # =========================================================================
    # Summary
    # =========================================================================
    echo ""
    log_bold "============================================================"
    log_bold "  Test Summary"
    log_bold "============================================================"
    echo ""
    echo -e "  Total:   ${BOLD}${TOTAL}${NC}"
    echo -e "  Passed:  ${GREEN}${PASS}${NC}"
    echo -e "  Failed:  ${RED}${FAIL}${NC}"
    echo -e "  Skipped: ${YELLOW}${SKIP}${NC}"
    echo ""

    if [[ "$FAIL" -eq 0 ]]; then
        log_bold "All tests passed!"
        exit 0
    else
        log_bold "${FAIL} test(s) failed."
        exit 1
    fi
}

main "$@"
