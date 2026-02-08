---
name: Exclusion Request
about: Request a new exclusion rule to reduce log noise
labels: exclusion
---

## Noisy Process / Activity

**What is generating the noise?** (product name, executable, process)

## Sysmon Event

Paste a representative event XML:

```xml
<!-- Event XML here -->
```

## Volume

Approximately how many events per hour does this generate?

## Proposed Exclusion

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Proposed exclusion rule -->
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Safety

Why is it safe to exclude this? Could an attacker abuse this exclusion?
