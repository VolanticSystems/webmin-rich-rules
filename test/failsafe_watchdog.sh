#!/bin/bash
#
# Failsafe Watchdog — Dead-Man's Switch for Integration Tests
#
# A safety net that prevents firewall lockout during testing. The test
# suite launches this script via nohup before making any firewall changes.
# It sleeps for 15 minutes, then checks whether the tests disarmed it
# by creating a sentinel file (/tmp/rich_rules_disarm).
#
# If the sentinel exists: tests completed normally, watchdog exits quietly.
# If the sentinel is missing: tests crashed or hung — assume lockout.
#   The watchdog restores the firewall from a pre-test baseline snapshot,
#   removes the test zone, and reboots the server to ensure a clean state.
#
# Invocation (by test_rich_rules.sh):
#   nohup bash failsafe_watchdog.sh >/dev/null 2>&1 &
#
# The nohup ensures the watchdog survives even if the parent shell dies
# (e.g., SSH disconnect during testing). The test suite records the PID
# and kills the watchdog on normal completion.
#

DISARM_FILE="/tmp/rich_rules_disarm"
BASELINE_DIR="/tmp/firewall_baseline"
TIMEOUT=900  # 15 minutes

sleep "$TIMEOUT"

# Check if tests disarmed us
if [[ -f "$DISARM_FILE" ]]; then
    rm -f "$DISARM_FILE"
    exit 0
fi

# Tests did not disarm in time — assume lockout. Restore and reboot.
logger -t "rich-rules-failsafe" "Failsafe triggered: restoring firewall baseline"

if [[ -d "$BASELINE_DIR" ]]; then
    cp -f "$BASELINE_DIR"/*.xml /etc/firewalld/zones/ 2>/dev/null
    # Remove test zone if it exists
    rm -f /etc/firewalld/zones/richtest.xml
    firewall-cmd --reload 2>/dev/null
fi

logger -t "rich-rules-failsafe" "Baseline restored. Rebooting."
reboot
