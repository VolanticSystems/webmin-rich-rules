#!/bin/bash
# Manual test commands to validate the fixes
# Run these commands to test the module fixes

echo "=== FirewallD Rich Rules - Manual Test Commands ==="
echo ""

echo "1. TEST: Direct firewall-cmd (what Test 3 uses)"
echo "Command: firewall-cmd --list-rich-rules"
echo "Expected: 140+ rules"
firewall-cmd --list-rich-rules | wc -l
echo ""

echo "2. TEST: Zone-specific query (what was causing 10 rules)"
echo "Command: firewall-cmd --zone=public --list-rich-rules"
echo "Expected: 10 rules (limited)"
firewall-cmd --zone=public --list-rich-rules | wc -l
echo ""

echo "3. TEST: Check for multiple module installations"
echo "Look for multiple 'FirewallD Rich Rules' entries in Webmin left menu"
echo "Expected: Should clean up to single entry"
echo ""

echo "4. TEST: Install new v1.12 package"
echo "File: firewalld-rich-v1.12_20250711_124651.wbm.gz"
echo "Expected: Should show v1.12 (2025-07-11 13:00) in header"
echo ""

echo "5. TEST: Debug output comparison"
echo "Enable debug mode and look for 'Enhanced Command Analysis' section"
echo "Expected: Global Runtime should show 140+ rules"
echo "Expected: Module Function should match Global Runtime count"
echo ""

echo "6. TEST: fail2ban detection"
echo "Expected: Should show fail2ban rules > 0 with all rules visible"
echo ""

echo "7. TEST: Performance improvement"
echo "Expected: Rule loading time should be < 1 second"
echo ""

echo "DEPLOYMENT INSTRUCTIONS:"
echo "1. Install: firewalld-rich-v1.12_20250711_124651.wbm.gz"
echo "2. Clean up any duplicate module entries"
echo "3. Enable debug mode"
echo "4. Check 'Enhanced Command Analysis' shows 140+ rules for both Global and Module"
echo "5. Verify fail2ban rules are detected"
echo ""