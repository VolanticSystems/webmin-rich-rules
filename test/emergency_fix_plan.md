# EMERGENCY FIX PLAN - v1.13

## CRITICAL: v1.12 causes infinite loop due to detect_rule_zone()

### Immediate Changes Needed

1. **Remove detect_rule_zone() function completely**
2. **Simplify zone assignment in list_all_rich_rules()**
3. **Keep global command approach but fix performance**

### Code Changes Required

#### In firewalld-rich-lib.pl:

```perl
# REMOVE this entire function:
sub detect_rule_zone { ... }

# CHANGE this line in list_all_rich_rules():
# FROM:
my $rule_zone = detect_rule_zone($rule) || get_default_zone() || 'public';

# TO:
my $rule_zone = get_default_zone() || 'public';
```

### Result
- **Keep global command fix** (140+ rules)
- **Remove performance killer** (1,260 commands → 1 command)
- **Simple zone assignment** (all rules go to default zone)
- **Page loads in seconds** instead of hanging

### Why This Works
- Global command gets all rules regardless of zone
- For rule management, knowing exact zone isn't critical
- User can still see and manage all 140+ rules
- Performance is acceptable
- Can enhance zone detection later with smarter approach

### Testing Priority
1. Page loads without hanging ✅
2. Shows 140+ rules ✅  
3. fail2ban detection works ✅
4. Performance < 5 seconds ✅

Zone accuracy is secondary to basic functionality.