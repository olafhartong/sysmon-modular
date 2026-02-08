---
name: New Detection Rule
about: Propose a new include rule for detecting suspicious activity
labels: detection-rule
---

## Technique

**MITRE ATT&CK ID (if applicable):** T____

**Description:** What does this rule detect?

## Sysmon Event Type

- [ ] Event ID 1 - Process Create
- [ ] Event ID 3 - Network Connection
- [ ] Event ID 7 - Image Loaded
- [ ] Event ID 8 - CreateRemoteThread
- [ ] Event ID 10 - Process Access
- [ ] Event ID 11 - File Create
- [ ] Event ID 12/13/14 - Registry Event
- [ ] Event ID 15 - FileCreateStreamHash
- [ ] Event ID 17/18 - Pipe Event
- [ ] Event ID 22 - DNS Query
- [ ] Other: ___

## Proposed Rule XML

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- Your rule here -->
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Testing

How was this rule tested? Include sample events if possible.

## False Positive Considerations

What legitimate activity could trigger this rule?
