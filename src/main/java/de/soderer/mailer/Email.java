package de.soderer.mailer;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import de.soderer.crypto.CryptographicUtilities;
import de.soderer.utilities.DateUtilities;
import de.soderer.utilities.Utilities;
import de.soderer.utilities.mail.dkim.DkimUtilities;
import de.soderer.utilities.mail.dkim.DomainKey;
import jakarta.mail.internet.InternetAddress;

/**
 * Email to be sent by a {@link Mailer}, with optional DKIM signature and S/MIME or PGP signature/encryption.
 * Setters return this instance for method chaining.
 */
public class Email {
	private final InternetAddress fromAddress;
	private final String subject;
	private final Charset charset;

	/**
	 * Added to email headers as "Return-Path"
	 */
	private InternetAddress bounceAddress = null;

	/**
	 * Added to email headers as "Disposition-Notification-To"
	 * Needs a bounceAddress to be set, which is using the same domain
	 */
	private InternetAddress notificationAddress = null;

	private final List<InternetAddress> replyToAddressList = new ArrayList<>();

	private List<InternetAddress> toAddressList = new ArrayList<>();
	private List<InternetAddress> ccAddressList = new ArrayList<>();
	private List<InternetAddress> bccAddressList = new ArrayList<>();

	private String bodyText = null;
	private String bodyHtml = null;

	private List<MailAttachment> attachments = new ArrayList<>();
	private List<String> eventInvitations = null;

	private RSAPrivateKey dkimPrivateKey = null;
	private String dkimDomain = null;
	private String dkimSelector = null;
	private String dkimIdentity = null;

	private CryptoType cryptoType = null;
	private PrivateKey signatureKey = null;
	private X509Certificate signatureCertificate = null;
	private String signatureMethodName = null;
	private X509Certificate encryptionCertificate = null;
	private String encryptionMethodName = null;
	private PGPSecretKey pgpSecretKey = null;
	private char[] pgpSecretKeyPassword = null;
	private PGPPublicKey pgpPublicKey = null;

	/**
	 * Create an email.
	 *
	 * @param fromAddress sender address
	 * @param subject subject
	 * @param charset charset of subject and bodies, null for UTF-8
	 */
	public Email(final InternetAddress fromAddress, final String subject, final Charset charset) {
		this.fromAddress = fromAddress;
		this.subject = subject;
		this.charset = charset;
	}

	/**
	 * Create an UTF-8 email.
	 *
	 * @param fromAddress sender address
	 * @param subject subject
	 * @throws Exception if the sender address is invalid
	 */
	public Email(final String fromAddress, final String subject) throws Exception {
		this(new InternetAddress(fromAddress), subject, StandardCharsets.UTF_8);
	}

	/**
	 * Create an email.
	 *
	 * @param fromAddress sender address
	 * @param subject subject
	 * @param charset charset of subject and bodies, null for UTF-8
	 * @throws Exception if the sender address is invalid
	 */
	public Email(final String fromAddress, final String subject, final Charset charset) throws Exception {
		this(new InternetAddress(fromAddress), subject, charset);
	}

	/**
	 * Create an email with a sender display name.
	 *
	 * @param fromAddress sender address
	 * @param fromName display name of the sender
	 * @param subject subject
	 * @param charset charset of subject and bodies, null for UTF-8
	 * @throws Exception if the sender address is invalid
	 */
	public Email(final String fromAddress, final String fromName, final String subject, final Charset charset) throws Exception {
		this(new InternetAddress(fromAddress, fromName), subject, charset);
	}

	/**
	 * Get the sender address.
	 *
	 * @return sender address
	 */
	public InternetAddress getFromAddress() {
		return fromAddress;
	}

	/**
	 * Get the subject.
	 *
	 * @return subject
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * Get the charset of subject and bodies.
	 *
	 * @return charset, UTF-8 if none was set
	 */
	public Charset getCharset() {
		if (charset != null) {
			return charset;
		} else {
			return StandardCharsets.UTF_8;
		}
	}

	/**
	 * Get the bounce address, which is used as envelope sender and "Return-Path".
	 *
	 * @return bounce address, null to use the sender address
	 */
	public InternetAddress getBounceAddress() {
		return bounceAddress;
	}

	/**
	 * Set the bounce address, which is used as envelope sender and "Return-Path".
	 *
	 * @param bounceAddress bounce address, null to use the sender address
	 * @return this email
	 */
	public Email setBounceAddress(final InternetAddress bounceAddress) {
		this.bounceAddress = bounceAddress;
		return this;
	}

	/**
	 * Set the bounce address, which is used as envelope sender and "Return-Path".
	 *
	 * @param bounceAddress bounce address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email setBounceAddress(final String bounceAddress) throws Exception {
		this.bounceAddress = new InternetAddress(bounceAddress);
		return this;
	}

	/**
	 * Set the bounce address, which is used as envelope sender and "Return-Path".
	 *
	 * @param bounceAddress bounce address
	 * @param bounceAddressName display name of the bounce address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email setBounceAddress(final String bounceAddress, final String bounceAddressName) throws Exception {
		this.bounceAddress = new InternetAddress(bounceAddress, bounceAddressName);
		return this;
	}

	/**
	 * Get the address for read receipts, added to the email headers as "Disposition-Notification-To".
	 *
	 * @return notification address, may be null
	 */
	public InternetAddress getNotificationAddress() {
		return notificationAddress;
	}

	/**
	 * Set the address for read receipts, added to the email headers as "Disposition-Notification-To".
	 * Needs a bounce address of the same domain.
	 *
	 * @param notificationAddress notification address, null for none
	 * @return this email
	 */
	public Email setNotificationAddress(final InternetAddress notificationAddress) {
		this.notificationAddress = notificationAddress;
		return this;
	}

	/**
	 * Set the address for read receipts, added to the email headers as "Disposition-Notification-To".
	 * Needs a bounce address of the same domain.
	 *
	 * @param notificationAddress notification address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email setNotificationAddress(final String notificationAddress) throws Exception {
		this.notificationAddress = new InternetAddress(notificationAddress);
		return this;
	}

	/**
	 * Set the address for read receipts, added to the email headers as "Disposition-Notification-To".
	 * Needs a bounce address of the same domain.
	 *
	 * @param notificationAddress notification address
	 * @param notificationAddressName display name of the notification address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email setNotificationAddress(final String notificationAddress, final String notificationAddressName) throws Exception {
		this.notificationAddress = new InternetAddress(notificationAddress, notificationAddressName);
		return this;
	}

	/**
	 * Get the reply-to addresses.
	 *
	 * @return modifiable list of reply-to addresses
	 */
	public List<InternetAddress> getReplyToAddressList() {
		return replyToAddressList;
	}

	/**
	 * Add a reply-to address.
	 *
	 * @param replyToAddress address to add
	 * @return this email
	 */
	public Email addReplyToAddress(final InternetAddress replyToAddress) {
		replyToAddressList.add(replyToAddress);
		return this;
	}

	/**
	 * Add a reply-to address.
	 *
	 * @param replyToAddress address to add
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addReplyToAddress(final String replyToAddress) throws Exception {
		replyToAddressList.add(new InternetAddress(replyToAddress));
		return this;
	}

	/**
	 * Add a reply-to address with display name.
	 *
	 * @param replyToAddress address to add
	 * @param replyToAddressName display name of the address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addReplyToAddress(final String replyToAddress, final String replyToAddressName) throws Exception {
		replyToAddressList.add(new InternetAddress(replyToAddress, replyToAddressName));
		return this;
	}

	/**
	 * Get the to addresses.
	 *
	 * @return modifiable list of to addresses
	 */
	public List<InternetAddress> getToAddressList() {
		return toAddressList;
	}

	/**
	 * Replace the to addresses.
	 *
	 * @param toAddressList list of to addresses (used directly), null for an empty list
	 * @return this email
	 */
	public Email setToAddressList(final List<InternetAddress> toAddressList) {
		this.toAddressList = toAddressList == null ? new ArrayList<>() : toAddressList;
		return this;
	}

	/**
	 * Add a to address.
	 *
	 * @param toAddress address to add
	 * @return this email
	 */
	public Email addToAddress(final InternetAddress toAddress) {
		toAddressList.add(toAddress);
		return this;
	}

	/**
	 * Add a to address.
	 *
	 * @param toAddress address to add
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addToAddress(final String toAddress) throws Exception {
		toAddressList.add(new InternetAddress(toAddress));
		return this;
	}

	/**
	 * Add a to address with display name.
	 *
	 * @param toAddress address to add
	 * @param toAddressName display name of the address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addToAddress(final String toAddress, final String toAddressName) throws Exception {
		toAddressList.add(new InternetAddress(toAddress, toAddressName));
		return this;
	}

	/**
	 * Get the cc addresses.
	 *
	 * @return modifiable list of cc addresses
	 */
	public List<InternetAddress> getCcAddressList() {
		return ccAddressList;
	}

	/**
	 * Replace the cc addresses.
	 *
	 * @param ccAddressList list of cc addresses (used directly), null for an empty list
	 * @return this email
	 */
	public Email setCcAddressList(final List<InternetAddress> ccAddressList) {
		this.ccAddressList = ccAddressList == null ? new ArrayList<>() : ccAddressList;
		return this;
	}

	/**
	 * Add a cc address.
	 *
	 * @param ccAddress address to add
	 * @return this email
	 */
	public Email addCcAddress(final InternetAddress ccAddress) {
		ccAddressList.add(ccAddress);
		return this;
	}

	/**
	 * Add a cc address.
	 *
	 * @param ccAddress address to add
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addCcAddress(final String ccAddress) throws Exception {
		ccAddressList.add(new InternetAddress(ccAddress));
		return this;
	}

	/**
	 * Add a cc address with display name.
	 *
	 * @param ccAddress address to add
	 * @param ccAddressName display name of the address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addCcAddress(final String ccAddress, final String ccAddressName) throws Exception {
		ccAddressList.add(new InternetAddress(ccAddress, ccAddressName));
		return this;
	}

	/**
	 * Get the bcc addresses.
	 *
	 * @return modifiable list of bcc addresses
	 */
	public List<InternetAddress> getBccAddressList() {
		return bccAddressList;
	}

	/**
	 * Replace the bcc addresses.
	 *
	 * @param bccAddressList list of bcc addresses (used directly), null for an empty list
	 * @return this email
	 */
	public Email setBccAddressList(final List<InternetAddress> bccAddressList) {
		this.bccAddressList = bccAddressList == null ? new ArrayList<>() : bccAddressList;
		return this;
	}

	/**
	 * Add a bcc address.
	 *
	 * @param bccAddress address to add
	 * @return this email
	 */
	public Email addBccAddress(final InternetAddress bccAddress) {
		bccAddressList.add(bccAddress);
		return this;
	}

	/**
	 * Add a bcc address.
	 *
	 * @param bccAddress address to add
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addBccAddress(final String bccAddress) throws Exception {
		bccAddressList.add(new InternetAddress(bccAddress));
		return this;
	}

	/**
	 * Add a bcc address with display name.
	 *
	 * @param bccAddress address to add
	 * @param bccAddressName display name of the address
	 * @return this email
	 * @throws Exception if the address is invalid
	 */
	public Email addBccAddress(final String bccAddress, final String bccAddressName) throws Exception {
		bccAddressList.add(new InternetAddress(bccAddress, bccAddressName));
		return this;
	}

	/**
	 * Get the plain text body.
	 *
	 * @return plain text body, may be null
	 */
	public String getBodyText() {
		return bodyText;
	}

	/**
	 * Set the plain text body.
	 *
	 * @param bodyText plain text body, may be null
	 * @return this email
	 */
	public Email setBodyText(final String bodyText) {
		this.bodyText = bodyText;
		return this;
	}

	/**
	 * Get the HTML body.
	 *
	 * @return HTML body, may be null
	 */
	public String getBodyHtml() {
		return bodyHtml;
	}

	/**
	 * Set the HTML body. If a plain text body is set too, both are sent as "multipart/alternative".
	 *
	 * @param bodyHtml HTML body, may be null
	 * @return this email
	 */
	public Email setBodyHtml(final String bodyHtml) {
		this.bodyHtml = bodyHtml;
		return this;
	}

	/**
	 * Get the attachments.
	 *
	 * @return modifiable list of attachments
	 */
	public List<MailAttachment> getAttachments() {
		return attachments;
	}

	/**
	 * Replace the attachments.
	 *
	 * @param attachments list of attachments (used directly), null for an empty list
	 * @return this email
	 */
	public Email setAttachments(final List<MailAttachment> attachments) {
		this.attachments = attachments == null ? new ArrayList<>() : attachments;
		return this;
	}

	/**
	 * Add an attachment.
	 *
	 * @param attachment attachment to add
	 * @return this email
	 */
	public Email addAttachment(final MailAttachment attachment) {
		attachments.add(attachment);
		return this;
	}

	/**
	 * Get the event invitations in iCalendar format.
	 *
	 * @return event invitations, null if none were added
	 */
	public List<String> getEventInvitations() {
		return eventInvitations;
	}

	/**
	 * Add an event invitation in iCalendar format, sent as "text/calendar" part.
	 *
	 * @param eventInvitation event invitation
	 * @return this email
	 */
	public Email addEventInvitation(final String eventInvitation) {
		if (eventInvitations == null) {
			eventInvitations = new ArrayList<>();
		}

		eventInvitations.add(eventInvitation);
		return this;
	}

	/**
	 * Sign the email with DKIM without an agent identity.
	 *
	 * @param domain signing domain (d=)
	 * @param selector key selector (s=)
	 * @param privateKey private key of the DNS published DKIM key
	 * @return this email
	 * @throws Exception if a value is missing
	 */
	public Email setDkimData(final String domain, final String selector, final RSAPrivateKey privateKey) throws Exception {
		return setDkimData(domain, selector, privateKey, null);
	}

	/**
	 * Sign the email with DKIM.
	 *
	 * @param domain signing domain (d=)
	 * @param selector key selector (s=)
	 * @param privateKey private key of the DNS published DKIM key
	 * @param identity agent or user identifier (i=), may be null
	 * @return this email
	 * @throws Exception if a value is missing
	 */
	public Email setDkimData(final String domain, final String selector, final RSAPrivateKey privateKey, final String identity) throws Exception {
		if (Utilities.isBlank(domain)) {
			throw new Exception("DKIM domain may not be empty");
		} else if (Utilities.isBlank(selector)) {
			throw new Exception("DKIM key selector may not be empty");
		} else if (privateKey == null) {
			throw new Exception("DKIM private key may not be empty");
		}

		dkimDomain = domain;
		dkimSelector = selector;
		dkimPrivateKey = privateKey;
		dkimIdentity = identity;

		return this;
	}

	/**
	 * Get the DKIM private key.
	 *
	 * @return DKIM private key, null for no DKIM signature
	 */
	public RSAPrivateKey getDkimPrivateKey() {
		return dkimPrivateKey;
	}

	/**
	 * Get the DKIM signing domain.
	 *
	 * @return DKIM domain
	 */
	public String getDkimDomain() {
		return dkimDomain;
	}

	/**
	 * Get the DKIM key selector.
	 *
	 * @return DKIM selector
	 */
	public String getDkimSelector() {
		return dkimSelector;
	}

	/**
	 * Get the DKIM agent or user identifier.
	 *
	 * @return DKIM identity, may be null
	 */
	public String getDkimIdentity() {
		return dkimIdentity;
	}

	/**
	 * Get the S/MIME signature key.
	 *
	 * @return signature key, null for no S/MIME signature
	 */
	public PrivateKey getSignatureKey() {
		return signatureKey;
	}

	/**
	 * Set the S/MIME signature key. Needs the matching signature certificate and a crypto type.
	 *
	 * @param signatureKey signature key, null for no S/MIME signature
	 * @return this email
	 */
	public Email setSignaturePrivateKey(final PrivateKey signatureKey) {
		this.signatureKey = signatureKey;
		return this;
	}

	/**
	 * Set the S/MIME signature certificate. Its email address must match the sender address.
	 *
	 * @param signatureCertificate signature certificate
	 * @return this email
	 */
	public Email setSignatureCertificate(final X509Certificate signatureCertificate) {
		this.signatureCertificate = signatureCertificate;
		return this;
	}

	/**
	 * Get the S/MIME signature certificate.
	 *
	 * @return signature certificate
	 */
	public X509Certificate getSignatureCertificate() {
		return signatureCertificate;
	}

	/**
	 * Get the S/MIME encryption certificate of the recipient.
	 *
	 * @return encryption certificate, null for no S/MIME encryption
	 */
	public X509Certificate getEncryptionCertificate() {
		return encryptionCertificate;
	}

	/**
	 * Set the S/MIME encryption certificate of the recipient. Only one to-address is allowed for encrypted emails.
	 *
	 * @param encryptionCertificate encryption certificate, null for no S/MIME encryption
	 * @return this email
	 */
	public Email setEncryptionCertificate(final X509Certificate encryptionCertificate) {
		this.encryptionCertificate = encryptionCertificate;
		return this;
	}

	/**
	 * Get the crypto type used for signing and encryption.
	 *
	 * @return crypto type, null for none
	 */
	public CryptoType getCryptoType() {
		return cryptoType;
	}

	/**
	 * Set the crypto type used for signing and encryption.
	 *
	 * @param cryptoType crypto type, null for none
	 * @return this email
	 */
	public Email setCryptoType(final CryptoType cryptoType) {
		this.cryptoType = cryptoType;
		return this;
	}

	/**
	 * Check the email for consistent settings, e.g. DKIM key against the DNS, certificates against the addresses and their validity periods.
	 *
	 * @return list of error messages, empty if the email is valid
	 * @throws Exception if the DKIM DNS lookup or a certificate check fails
	 */
	public List<String> checkValidData() throws Exception {
		final List<String> errors = new ArrayList<>();

		if (dkimPrivateKey != null) {
			final DomainKey domainKey = DkimUtilities.getDomainKey(dkimDomain, dkimSelector);
			if (domainKey == null) {
				errors.add("No DKIM key found in DNS entry for domain '" + dkimDomain + "' and selector '" + dkimSelector + "'");
			} else if (!CryptographicUtilities.checkPrivateKeyFitsPublicKey(dkimPrivateKey, domainKey.getPublicKey())) {
				errors.add("PublicKey of DKIM key found in DNS entry for domain '" + dkimDomain + "' and selector '" + dkimSelector + "' does not fit the given private key");
			}
		}

		if (getCryptoType() == null && signatureKey != null) {
			errors.add("SignatureKey was set, but cryptotype (S/MIME or PGP) was not defined");
		}

		if (getCryptoType() == null && encryptionCertificate != null) {
			errors.add("EncryptionCertificate was set, but cryptotype (S/MIME or PGP) was not defined");
		}

		if (getCryptoType() != null) {
			if (signatureKey != null) {
				if (signatureCertificate == null) {
					errors.add("SignatureCertficate for emailaddress '" + fromAddress.toString() + "' is missing");
				}
			}

			if (signatureKey != null && signatureCertificate != null) {
				String certEmail = null;
				for (final String token : Utilities.parseTokens(signatureCertificate.getSubjectX500Principal().toString(), ',')) {
					final String[] keyValueParts = token.trim().split("=");
					if (keyValueParts.length >= 2 && ("E".equals(keyValueParts[0]) || "EMAILADDRESS".equals(keyValueParts[0]))) {
						certEmail = keyValueParts[1];
						break;
					}
				}

				if (certEmail == null || !certEmail.equalsIgnoreCase(fromAddress.getAddress())) {
					errors.add("SignatureCertficates emailaddress '" + certEmail + "' does not match from-emailaddress '" + fromAddress.toString() + "'");
				}

				if (signatureCertificate != null && signatureCertificate.getNotBefore() != null && DateUtilities.getLocalDateTimeForDate(signatureCertificate.getNotBefore()).isAfter(LocalDateTime.now())) {
					errors.add("SignatureCertficates of emailaddress '" + certEmail + "' may not be used before: " + DateUtilities.formatDate(DateUtilities.DD_MM_YYYY_HH_MM_SS, signatureCertificate.getNotBefore()));
				}
				if (signatureCertificate != null && signatureCertificate.getNotAfter() != null && DateUtilities.getLocalDateTimeForDate(signatureCertificate.getNotAfter()).isBefore(LocalDateTime.now())) {
					errors.add("SignatureCertficates of emailaddress '" + certEmail + "' may not be used after: " + DateUtilities.formatDate(DateUtilities.DD_MM_YYYY_HH_MM_SS, signatureCertificate.getNotAfter()));
				}

				if (!CryptographicUtilities.checkPrivateKeyFitsPublicKey(signatureKey, signatureCertificate.getPublicKey())) {
					errors.add("SignatureCertficate of emailaddress '" + certEmail + "' does not fit to signatureKey");
				}
			}

			if (encryptionCertificate != null) {
				String certEmail = null;
				for (final String token : Utilities.parseTokens(encryptionCertificate.getSubjectX500Principal().toString(), ',')) {
					final String[] keyValueParts = token.trim().split("=");
					if (keyValueParts.length >= 2 && ("E".equals(keyValueParts[0]) || "EMAILADDRESS".equals(keyValueParts[0]))) {
						certEmail = keyValueParts[1];
						break;
					}
				}

				if (toAddressList.size() != 1) {
					errors.add("To many to-address recipients for single encryption certificate");
				} else if (certEmail == null || !certEmail.equalsIgnoreCase(toAddressList.get(0).getAddress())) {
					errors.add("EncryptionCertficates emailaddress '" + certEmail + "' does not match to-emailaddress '" + toAddressList.get(0).toString() + "'");
				}

				if (encryptionCertificate != null && encryptionCertificate.getNotBefore() != null && DateUtilities.getLocalDateTimeForDate(encryptionCertificate.getNotBefore()).isAfter(LocalDateTime.now())) {
					errors.add("EncryptionCertficates of emailaddress '" + certEmail + "' may not be used before: " + DateUtilities.formatDate(DateUtilities.DD_MM_YYYY_HH_MM_SS, encryptionCertificate.getNotBefore()));
				}
				if (encryptionCertificate != null && encryptionCertificate.getNotAfter() != null && DateUtilities.getLocalDateTimeForDate(encryptionCertificate.getNotAfter()).isBefore(LocalDateTime.now())) {
					errors.add("EncrytionCertficates of emailaddress '" + certEmail + "' may not be used after: " + DateUtilities.formatDate(DateUtilities.DD_MM_YYYY_HH_MM_SS, encryptionCertificate.getNotAfter()));
				}

				if (ccAddressList.size() > 0) {
					errors.add("To many cc-address recipients for single encryption certificate");
				}

				if (bccAddressList.size() > 0) {
					errors.add("To many bcc-address recipients for single encryption certificate");
				}
			}
		}

		return errors;
	}

	/**
	 * Get the name of the signature algorithm.
	 *
	 * @return signature algorithm name, null for the default
	 */
	public String getSignatureMethodName() {
		return signatureMethodName;
	}

	/**
	 * Set the name of the signature algorithm (e.g. "SHA256withRSA" for S/MIME).
	 *
	 * @param signatureMethodName signature algorithm name, null for the default
	 * @return this email
	 */
	public Email setSignatureMethodName(final String signatureMethodName) {
		this.signatureMethodName = signatureMethodName;
		return this;
	}

	/**
	 * Get the name of the encryption algorithm.
	 *
	 * @return encryption algorithm name, null for the default
	 */
	public String getEncryptionMethodName() {
		return encryptionMethodName;
	}

	/**
	 * Set the name of the encryption algorithm.
	 *
	 * @param encryptionMethodName encryption algorithm name, null for the default
	 * @return this email
	 */
	public Email setEncryptionMethodName(final String encryptionMethodName) {
		this.encryptionMethodName = encryptionMethodName;
		return this;
	}

	/**
	 * Get the PGP secret key for signing.
	 *
	 * @return PGP secret key, null for no PGP signature
	 */
	public PGPSecretKey getPgpSecretKey() {
		return pgpSecretKey;
	}

	/**
	 * Set the PGP secret key for signing.
	 *
	 * @param pgpSecretKey PGP secret key, null for no PGP signature
	 * @return this email
	 */
	public Email setPgpSecretKey(final PGPSecretKey pgpSecretKey) {
		this.pgpSecretKey = pgpSecretKey;
		return this;
	}

	/**
	 * Get the password of the PGP secret key.
	 *
	 * @return password (not copied)
	 */
	public char[] getPgpSecretKeyPassword() {
		return pgpSecretKeyPassword;
	}

	/**
	 * Set the password of the PGP secret key.
	 *
	 * @param pgpSecretKeyPassword password (not copied)
	 * @return this email
	 */
	public Email setPgpSecretKeyPassword(final char[] pgpSecretKeyPassword) {
		this.pgpSecretKeyPassword = pgpSecretKeyPassword;
		return this;
	}

	/**
	 * Get the PGP public key of the recipient for encryption.
	 *
	 * @return PGP public key, null for no PGP encryption
	 */
	public PGPPublicKey getPgpPublicKey() {
		return pgpPublicKey;
	}

	/**
	 * Set the PGP public key of the recipient for encryption.
	 *
	 * @param pgpPublicKey PGP public key, null for no PGP encryption
	 * @return this email
	 */
	public Email setPgpPublicKey(final PGPPublicKey pgpPublicKey) {
		this.pgpPublicKey = pgpPublicKey;
		return this;
	}
}
