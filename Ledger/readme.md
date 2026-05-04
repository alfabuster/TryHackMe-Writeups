# Ledger — TryHackMe

<img width="1900" height="379" alt="Screenshot From 2026-05-04 15-31-27" src="https://github.com/user-attachments/assets/41cb64b8-1582-4e25-86f7-2b5d771181b8" />
<br>

![](https://img.shields.io/badge/Platform-TryHackMe-darkred?style=for-the-badge&logo=tryhackme&logoColor=white)
![](https://img.shields.io/badge/Difficulty-Hard-red?style=for-the-badge)
![](https://img.shields.io/badge/OS-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![](https://img.shields.io/badge/Category-Active_Directory%20%7C%20AD_CS-orange?style=for-the-badge)

## Summary


Ledger is a **Hard** Windows machine on TryHackMe centered around Active Directory Certificate Services (AD CS) misconfiguration. Initial reconnaissance reveals a domain controller (`labyrinth.thm.local`) with SMB null authentication enabled and LDAP exposing user credentials in description fields. RDP access as `SUSANNA_MCKNIGHT` getting the user flag (**Flag 1**). BloodHound mapping reveals paths to Domain Admins, but the real prize comes from `certipy-ad`: the `ServerAuth` certificate template is vulnerable to **ESC1** — allowing any authenticated user to request a certificate impersonating the Domain Administrator. The admin's NT hash is extracted from the forged certificate, and `psexec` delivers a SYSTEM shell (**Flag 2**). An alternative exploitation path via LDAP Schannel authentication is documented for cases where Kerberos PKINIT fails.

```
Nmap → SMB Null Auth → LDAP Password Leak → RDP as SUSANNA_MCKNIGHT (Flag 1)
  → BloodHound → AD CS ESC1 → Forge Admin Certificate → NT Hash → psexec (Flag 2)
```

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID |
|:------|:-------|:----------|:---|
| Port scanning  | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `T1046` |
| SMB null session & RID brute | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/) | `T1087.002` |
| Passwords in LDAP descriptions | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) | `T1552.001` |
| RDP login with leaked creds | [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) | `T1078.002` |
| BloodHound domain mapping | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/) | `T1069.002` |
| AD CS ESC1 certificate forgery | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) | `T1649` |
| NT hash extraction from PFX | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) | `T1003` |
| Pass-the-Hash via psexec | [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) | `T1550.002` |
| Domain Admin user creation | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002/) | `T1136.002` |
<br>
<img width="1344" height="816" alt="Ledger__THM" src="https://github.com/user-attachments/assets/6cba0555-7a72-4223-a469-f7540be90246" />
<br>

## CVSS Reference

| CVE | CVSS 3.1 | Severity | Description |
|:----|:---------|:---------|:------------|
| Passwords in notes | **6.5** (est.) | Medium | LDAP user description fields contain plaintext passwords — unauthenticated readable via guest session CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| [CVE-2024-49019](https://nvd.nist.gov/vuln/detail/CVE-2024-49019) / ESC1 | **7.8** | High | AD CS misconfigured certificate template allows any authenticated user to request client authentication certificates for arbitrary principals, including Domain Administrator |
