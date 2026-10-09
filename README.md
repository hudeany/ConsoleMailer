# ConsoleMailer

**Send emails from the command line: with DKIM signature, S/MIME or PGP signature and encryption, attachments and calendar invitations.**

ConsoleMailer sends a single email via any SMTP server. All settings are given as command line parameters or in reusable parameter files, which makes it a good fit for scripts, cron jobs and monitoring.

---

## Features

- **Any SMTP server**: with STARTTLS, SSL/TLS or unencrypted, with or without authentication
- **Text and HTML**: content given directly or read from files, in any character set
- **Recipients**: To, CC, BCC and Reply-To lists, bounce address (`Return-Path`) and read notification
- **Attachments**: any number of files, the MIME type is detected by the file name
- **DKIM signature**: sign emails with your domain key, so receivers can verify the sender domain
- **S/MIME and PGP**: sign and/or encrypt emails, with configurable signature and encryption methods
- **Calendar invitations**: attach an iCal event with start, end and location
- **Parameter files**: keep server, sender and key settings in files and combine them with `-cfg`
- **Safe testing**: `-test` checks the DKIM and crypto configuration without sending the email
- **Auto update**: check for and install new versions with `update`

## Requirements

- Java 17 or newer

## Getting started

```bash
# Show the help
java -jar ConsoleMailer.jar help

# Send a simple text email
java -jar ConsoleMailer.jar -host smtp.example.com:587 -starttls -user "sender@example.com" -password "secret" \
  -from sender@example.com -to receiver@example.com -subject "Hello" -text "Hello from ConsoleMailer"
```

### Examples

HTML email from a file with attachments to several recipients:

```bash
java -jar ConsoleMailer.jar -host smtp.example.com:465 -ssl -user "reports@example.com" -password "secret" \
  -from "Reports <reports@example.com>" -to "alice@example.com, bob@example.com" -cc team@example.com \
  -subject "Monthly report" -htmlfile ./report.html -attachment ./report.pdf -attachment ./data.csv
```

Email with DKIM signature:

```bash
java -jar ConsoleMailer.jar -host smtp.example.com -from info@example.com -to receiver@example.org \
  -subject "Signed by DKIM" -text "Hello" -dkimkeyfile ./dkim_private.pem -dkimselector mail2026
```

S/MIME signed and encrypted email:

```bash
java -jar ConsoleMailer.jar -host smtp.example.com -from sender@example.com -to receiver@example.org \
  -subject "Confidential" -text "Secret content" -crypto S/MIME \
  -signaturekeyfile ./sender_key.pem -signaturekeypassword "keypass" -signaturecertificatefile ./sender_cert.pem \
  -encryptioncertificatefile ./receiver_cert.pem
```

PGP encrypted email:

```bash
java -jar ConsoleMailer.jar -host smtp.example.com -from sender@example.com -to receiver@example.org \
  -subject "Confidential" -text "Secret content" -crypto PGP -encryptionkeyfile ./receiver_public.asc
```

Meeting invitation:

```bash
java -jar ConsoleMailer.jar -host smtp.example.com -from organizer@example.com -to "alice@example.com, bob@example.com" \
  -subject "Project meeting" -text "See you there" \
  -eventstart "2026-11-02 10:00:00" -eventend "2026-11-02 11:00:00" -eventlocation "Room 4.12"
```

## Parameter files

Parameters that are the same for every email, like the server settings, can be stored in a text file and loaded with `-cfg` (also several files). The file contains the parameters exactly as on the command line, lines starting with `#` are comments:

```
# smtp.cfg
-host smtp.example.com:587
-starttls
-user "sender@example.com"
-password "secret"
-from "Sender <sender@example.com>"
```

```bash
java -jar ConsoleMailer.jar -cfg ./smtp.cfg -to receiver@example.com -subject "Status" -text "All systems running"
```

## Command line reference

```
java -jar ConsoleMailer.jar [optional parameters] -host <host[:port]> -from <from-address> -subject <subject> -to <to-address>
```

### Mandatory parameters

| Parameter | Description |
|---|---|
| `-h`, `-host <hostname[:port]>` | Hostname of the SMTP server, optionally with port (default port: 25) |
| `-from "<email>"` | Email address of the sender |
| `-s`, `-subject "<subject>"` | Subject of the email |
| `-to "<emailList>"` | Recipient addresses (may be used multiple times). Not mandatory, if `-cc` or `-bcc` is used. |

### Server connection

| Parameter | Description |
|---|---|
| `-cfg "<filePath>"` | Parameter file with preconfigured parameters (may be used multiple times) |
| `-port <port>` | Port, if not included in the hostname (default: 25) |
| `-u`, `-user "<username>"` | Username for the authentication at the SMTP server |
| `-p`, `-password "<password>"` | Password for the authentication (mandatory, if a username is set) |
| `-starttls` | STARTTLS connection security (default: none) |
| `-ssl`, `-tls`, `-ssltls` | SSL/TLS connection security (default: none) |

### Recipients and headers

| Parameter | Description |
|---|---|
| `-replyto "<emailList>"` | Reply-To addresses, if they differ from the sender |
| `-cc "<emailList>"` | CC recipients (may be used multiple times) |
| `-bcc "<emailList>"` | BCC recipients (may be used multiple times) |
| `-bounce "<email>"` | Bounce address (header `Return-Path`), which receives technical delivery notifications |
| `-notify "<email>"` | Request a read notification (header `Disposition-Notification-To`) |

### Content

| Parameter | Description |
|---|---|
| `-text "<text>"` | Text content |
| `-textfile "<filePath>"` | File containing the text content |
| `-html "<html>"` | HTML content |
| `-htmlfile "<filePath>"` | File containing the HTML content |
| `-c`, `-charset "<charsetName>"` | Character set of the email and of `-textfile` and `-htmlfile` (default: UTF-8) |
| `-attachment "<filePath>"` | Attach a file (may be used multiple times) |

### Calendar invitation

| Parameter | Description |
|---|---|
| `-eventstart "<yyyy-MM-dd HH:mm:ss>"` | Adds an iCal event invitation with this start time. Participants are all To addresses, the subject is used as event title. |
| `-eventend "<yyyy-MM-dd HH:mm:ss>"` | End time of the event (needs `-eventstart`) |
| `-eventlocation "<location text>"` | Location of the event (needs `-eventstart`) |

### DKIM signature

| Parameter | Description |
|---|---|
| `-dkimkeyfile "<filePath>"` | File containing the private key for the DKIM signature |
| `-dkimselector "<selector>"` | DKIM key selector of the key published in DNS (mandatory with `-dkimkeyfile`) |
| `-dkimdomain "<domainName>"` | Domain of the DKIM signature, if it differs from the domain of the sender address |
| `-dkimidentity "<identity>"` | Identity used in the DKIM signature (default: none) |

### S/MIME and PGP

| Parameter | Description |
|---|---|
| `-crypto "<type>"` | `S/MIME` or `PGP` |
| `-signaturekeyfile "<filePath>"` | Private key for the signature |
| `-signaturekeypassword "<password>"` | Password of the private key, if needed |
| `-signaturecertificatefile "<filePath>"` | Sender's certificate for S/MIME signatures |
| `-signaturemethodname "<methodName>"` | Signature method (default: `SHA512withRSA` for S/MIME, `SHA512` for PGP) |
| `-encryptioncertificatefile "<filePath>"` | Receiver's certificate for S/MIME encryption |
| `-encryptionkeyfile "<filePath>"` | Receiver's public key for PGP encryption |
| `-encryptionmethodname "<methodName>"` | Encryption method (default: `AES256_CBC` for S/MIME, `AES256` for PGP) |

What each combination needs:

| | Signature | Encryption |
|---|---|---|
| **S/MIME** | `-signaturekeyfile` [`-signaturekeypassword`], `-signaturecertificatefile` | `-encryptioncertificatefile` |
| **PGP** | `-signaturekeyfile` [`-signaturekeypassword`] | `-encryptionkeyfile` |

### Execution

| Parameter | Description |
|---|---|
| `-test` | Check the DKIM and crypto configuration only, the email is NOT sent |
| `-f`, `-force` | Send the email, even if there were DKIM or crypto configuration errors |
| `-silent` | No terminal output except for errors, which were not overridden by `-force` |
| `-verbose` | Verbose error messages |

### Global parameters

| Parameter | Description |
|---|---|
| `help` | Show the help (only as single parameter) |
| `version` | Show the installed version (only as single parameter) |
| `update [<username> [<password>]]` | Check for an online update and install it after confirmation (only as first parameter) |

**Exit code:** `0` if the email was sent (or checked with `-test`), otherwise `1`.

## Dependencies

The build job downloads these libraries automatically:

| Library | Version | Download |
|---|---|---|
| Bouncy Castle bcjmail | 1.80 | [bcjmail-jdk18on-1.80.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcjmail-jdk18on/1.80/bcjmail-jdk18on-1.80.jar) |
| Bouncy Castle bcpg | 1.80 | [bcpg-jdk18on-1.80.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpg-jdk18on/1.80/bcpg-jdk18on-1.80.jar) |
| Bouncy Castle bcpkix | 1.80 | [bcpkix-jdk18on-1.80.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk18on/1.80/bcpkix-jdk18on-1.80.jar) |
| Bouncy Castle bcprov | 1.80 | [bcprov-jdk18on-1.80.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.80/bcprov-jdk18on-1.80.jar) |
| Bouncy Castle bcutil | 1.80 | [bcutil-jdk18on-1.80.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcutil-jdk18on/1.80/bcutil-jdk18on-1.80.jar) |
| Jakarta Activation API | 2.1.3 | [jakarta.activation-api-2.1.3.jar](https://repo1.maven.org/maven2/jakarta/activation/jakarta.activation-api/2.1.3/jakarta.activation-api-2.1.3.jar) |
| Jakarta Mail API | 2.1.3 | [jakarta.mail-api-2.1.3.jar](https://repo1.maven.org/maven2/jakarta/mail/jakarta.mail-api/2.1.3/jakarta.mail-api-2.1.3.jar) |
| Eclipse Angus Mail | 2.0.3 | [angus-mail-2.0.3.jar](https://repo1.maven.org/maven2/org/eclipse/angus/angus-mail/2.0.3/angus-mail-2.0.3.jar) |
| Eclipse Angus Activation | 2.0.2 | [angus-activation-2.0.2.jar](https://repo1.maven.org/maven2/org/eclipse/angus/angus-activation/2.0.2/angus-activation-2.0.2.jar) |
| soderer.de dkim | 25.1.0 | [dkim-25.1.0.jar](https://github.com/hudeany/dkim/releases/download/25.1.0/dkim-25.1.0.jar) |
| soderer.de json | 26.1.31 | [json-26.1.31.jar](https://github.com/hudeany/json/releases/download/26.1.38/json-26.1.31.jar) |

