Tool for sending emails with DKIM signature and enrypted or signed content via GPG/PGP and S/MIME

Dependencies (Automatically downloaded by build job:
 - bcjmail-jdk18on-1.80.jar: https://repo1.maven.org/maven2/org/bouncycastle/bcjmail-jdk18on/1.80/bcjmail-jdk18on-1.80.jar
 - bcpg-jdk18on-1.80.jar: "https://repo1.maven.org/maven2/org/bouncycastle/bcpg-jdk18on/1.80/bcpg-jdk18on-1.80.jar
 - bcpkix-jdk18on-1.80.jar: https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk18on/1.80/bcpkix-jdk18on-1.80.jar
 - bcprov-jdk18on-1.80.jar: https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.80/bcprov-jdk18on-1.80.jar
 - bcutil-jdk18on-1.80.jar: <get src="https://repo1.maven.org/maven2/org/bouncycastle/bcutil-jdk18on/1.80/bcutil-jdk18on-1.80.jar

 - jakarta.activation-api-2.1.3.jar: https://repo1.maven.org/maven2/jakarta/activation/jakarta.activation-api/2.1.3/jakarta.activation-api-2.1.3.jar
 - jakarta.mail-api-2.1.3.jar: https://repo1.maven.org/maven2/jakarta/mail/jakarta.mail-api/2.1.3/jakarta.mail-api-2.1.3.jar
 - Eclipse angus-mail-2.0.3.jar: https://repo1.maven.org/maven2/org/eclipse/angus/angus-mail/2.0.3/angus-mail-2.0.3.jar

 - Soderer.de dkim-25.1.0.jar: https://github.com/hudeany/dkim/releases/download/25.1.0/dkim-25.1.0.jar

```
Usage: java -jar ConsoleMailer.jar [optional parameters] -host <host> -port <port> -user <user> -password <password> -from <from-address> -subject <subject> -to <to-address>
Example: java -jar ConsoleMailer.jar -host <hostname>:<port> -starttls -user "<username>" -password "<password>" -from sender@example.com -to receiver@example.com -subject "Subject" -html "HtmlBody"

Mandatory parameters
  -h, -host <hostname[:port]>:             Hostname of the smtp server, optionally with port
  -port <port>:                            Port, if not included in hostname
  -u, -user "<username>":                  Username for authentification to the smtp server
  -p, -password "<password>":              Password for authentification to the smtp server
  -from "<email>":                         Email address of the sender of this email
  -s, -subject "<subject>":                Subject of this email
  -to "<emailList>":                       Receiver email address of this email. This is not mandatory if one of -cc or -bcc is used

Optional parameters
  -cfg "<filePath>":                       Using a text file including any preconfigured parameters            
  -starttls:                               STARTTLS connection security to the smtp server. Default is none
  -ssl:                                    TLS/SSL connection security to the smtp server. Default is none
  -tls:                                    TLS/SSL connection security to the smtp server. Default is none
  -ssltls:                                 TLS/SSL connection security to the smtp server. Default is none
  -c, -charset "<charsetName>":            Characterset (encoding) to be used in this email (UTF-8, ISO-8859-1, ...)
  
  -replyto:                                Reply to email address if it differs from the senders email address
  -cc "<emailList>":                       CC recipient address list
  -bcc "<emailList>":                      BCC recipient address list
  
  -bounce "<email>":                       Bounce address (Email header "Return-Path"), which will receive technical notification about the email distribution
  -notify "<email>":                       Demand a read notification of the recipient (Email header "Disposition-Notification-To")
  
  -text "<text>":                          Text content of this email
  -textfile "<filePath>":                  File containing the text content of this email
  -html "<html>":                          HTML content of this email
  -htmlfile "<filePath>":                  File containing the HTML content of this email
  
  -crypto "<crypto-type>":                 Crypto type for email signatures and encryption ("S/MIME" or "PGP")
                                             Signature with S/MIME needs:
                                               - signaturekeyfile [signaturekeypassword]
                                               - signaturecertificatefile
                                             Encryption with S/MIME needs:
                                               - encryptioncertificatefile
                                             Signature with PGP needs:
                                               - signaturekeyfile [signaturekeypassword]
                                             Encryption with PGP needs:
                                               - encryptionkeyfile

  -signaturekeyfile "<filePath>":          File containing the private key for signatures
  -signaturekeypassword "<password>":      Password for the private key if needed
  -signaturecertificatefile "<filePath>":  File containing the senders public certificate for signatures
  -signaturemethodname "<methodName>":     Signature method name (default: "SHA512withRSA" for S/MIME, "SHA512" for PGP)

  -encryptioncertificatefile "<filePath>": File containing the receivers public certificate for encryption by S/MIME
  -encryptionkeyfile "<filePath>":         File containing the receivers public key for encryption by PGP
  -encryptionmethodname "<methodName>":    Encryption method name (default: "AES256_CBC" for S/MIME, "AES256" for PGP)

  -dkimkeyfile "<filePath>":               File containing the private key for the DKIM signature
  -dkimdomain "<domainName>":              Domain name of the DKIM signature if it differs from the senders email address domain
  -dkimselector "<domainKeySelector>":     DKIM key selector of the single DKIM key available in DKIM keys in DNS system
  -dkimidentity "<identity>":              Identity to be used in DKIM signature. Default none

  -attachment "<filePath>":                Attache multiple files to this email
 
  -test:                                   Check DKIM configuration and crypto key configuration only. Does NOT send the email
  -f, -force:                              Send the email, even if there where DKIM or crypto configuration errors
  -silent:                                 Do not generate any terminal output except for hard errors, which where not overriden by "-force"
  
  -eventstart "<yyyy-MM-dd HH:mm:ss>":     Send an event invitation in iCal format with this email by setting its start time.
                                             Participants are all TO-addresses
                                             Subject
  -eventend "<yyyy-MM-dd HH:mm:ss>":       Event's end time (optional for event invitation)
  -eventlocation "<location text>":        Event's location (optional for event invitation)

Global standalone parameters
  help:                                    Show this help manual
  version:                                 Show current local version of this tool
  update [<username> [<password>]]:        Check for online update and ask, whether an available update shell be installed.
