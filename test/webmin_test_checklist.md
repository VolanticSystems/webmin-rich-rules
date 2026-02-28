# Webmin Module Test Checklist

## Before Installing v1.12

### 1. Check Current Rule Count
```bash
firewall-cmd --list-rich-rules | wc -l
```
**Expected**: 140+ rules

### 2. Check Zone-Specific Count  
```bash
firewall-cmd --zone=public --list-rich-rules | wc -l
```
**Expected**: ~10 rules (this is the problem we're fixing)

## After Installing v1.12

### 3. Verify Installation
- **Check version in header**: Should show "v1.12 (2025-07-11 13:00)"
- **Clean up duplicates**: Remove old FirewallD Rich Rules entries from menu

### 4. Main Interface Test
- **Total rules displayed**: Should show 140+ total rules (not 10)
- **fail2ban rules**: Should show > 0 fail2ban rules
- **Performance**: Page should load in < 2 seconds

### 5. Debug Mode Tests
Enable debug mode and verify:

#### Enhanced Command Analysis Table
| Command Type | Rule Count | Status |
|--------------|------------|---------|
| Global Runtime | 140+ | SUCCESS |
| Global Permanent | 140+ | SUCCESS |
| Module Function | 140+ | SUCCESS |

**Critical**: All three should show similar high rule counts

#### Command Execution Tests
- **Test 1**: Should show 140+ rules  
- **Test 2**: May show ERROR (this is expected and explained)
- **Test 3**: Should show 140+ rules

### 6. fail2ban Detection Test
- **Check categories**: fail2ban rules should be > 0
- **Pattern matching**: Rules with single IPs + email ports should be categorized as fail2ban
- **Example rule**: `rule family="ipv4" source address="81.30.107.90" port port="smtp" protocol="tcp" reject type="icmp-port-unreachable"` should be fail2ban

### 7. Performance Test
- **Rule Loading**: Should be < 1 second (shown in debug timing)
- **Total Page Load**: Should be < 2 seconds
- **No timeouts**: All commands should complete successfully

## Success Criteria

✅ **PASS**: Module shows 140+ rules (matches direct command)  
✅ **PASS**: fail2ban rules detected (> 0)  
✅ **PASS**: Performance improved (< 2 seconds)  
✅ **PASS**: Debug shows Global and Module counts match  

❌ **FAIL**: Still showing only 10 rules  
❌ **FAIL**: No fail2ban rules detected  
❌ **FAIL**: Module count doesn't match Global count in debug  

## Troubleshooting

If tests fail:
1. **Clear Webmin cache**: Restart Webmin service
2. **Check multiple installations**: Remove duplicate modules
3. **Verify package**: Ensure v1.12 is actually installed
4. **Check debug output**: Look for error messages in Enhanced Command Analysis

## Quick Test Commands

```bash
# Test the fix directly
./test_patterns/run_manual_tests.sh

# Expected output should show 140+ rules for global command
# and ~10 rules for zone-specific command
```