# Reset — TryHackMe

![](https://img.shields.io/badge/Platform-TryHackMe-darkred?style=for-the-badge&logo=tryhackme&logoColor=white)
![](https://img.shields.io/badge/Difficulty-Hard-red?style=for-the-badge)
![](https://img.shields.io/badge/OS-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![](https://img.shields.io/badge/Category-Active_Directory%20%7C%20Kerberos%20%7C%20Delegation-orange?style=for-the-badge)

<img width="1200" height="630" alt="reset-writeup" src="https://github.com/user-attachments/assets/35eab584-8e2e-4adc-a41c-1127c80d7813" />

## Summary

Reset is a **Hard** Windows machine on TryHackMe that walks through a full Active Directory attack chain — from anonymous SMB access to Domain Administrator via Constrained Delegation abuse. A guest-accessible SMB share contains an onboarding email with a default password. RID brute-forcing reveals domain users, and password spraying identifies the matching account (`LILY_ONEILL`). AS-REP Roasting extracts crackable hashes for `TABATHA_BRITT`, whose RDP access and BloodHound enumeration reveal a lateral movement chain: `GenericAll` on `SHAWNA_BRAY` → `ForceChangePassword` on `CRUZ_HALL` → access to `DARLA_WINTERS`. DARLA has **Constrained Delegation** rights to `cifs/HayStack.thm.corp`, enabling S4U2self/S4U2proxy ticket forgery to impersonate the Domain Administrator. A forged Kerberos service ticket + `wmiexec` delivers a SYSTEM shell — after `smbexec` and `psexec` both refuse to cooperate.

```
SMB Guest Share → Onboarding Password → RID Brute → Password Spray (LILY_ONEILL)
  → AS-REP Roasting → TABATHA_BRITT → BloodHound
  → GenericAll Chain: SHAWNA_BRAY → CRUZ_HALL → DARLA_WINTERS
  → Constrained Delegation (S4U2proxy) → Administrator TGS → wmiexec (Flags)
```

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID |
|:------|:-------|:----------|:---|
| Port scanning & AD enumeration | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `T1046` |
| SMB guest share access | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Share Discovery](https://attack.mitre.org/techniques/T1135/) | `T1135` |
| Password from onboarding file | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) | `T1552.001` |
| RID brute-force user enumeration | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/) | `T1087.002` |
| Password spraying | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | `T1110.003` |
| AS-REP Roasting | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) | `T1558.004` |
| Hashcat password cracking | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/) | `T1110.002` |
| BloodHound domain mapping | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/) | `T1069.002` |
| GenericAll password reset chain | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Account Manipulation](https://attack.mitre.org/techniques/T1098/) | `T1098` |
| S4U2self/S4U2proxy ticket forgery | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) | `T1558` |
| Pass-the-Ticket via wmiexec | [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/) | `T1550.003` |

