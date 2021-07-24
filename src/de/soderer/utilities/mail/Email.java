package de.soderer.utilities.mail;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.mail.internet.InternetAddress;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import de.soderer.utilities.DateUtilities;
import de.soderer.utilities.Utilities;
import de.soderer.utilities.crypto.CryptographicUtilities;
import de.soderer.utilities.mail.dkim.DomainKey;
import de.soderer.utilities.mail.dkim.DomainKeyUtil;

public class Email {
	private final InternetAddress fromAddress;
	private final String subject;
	private final Charset charset;

	private InternetAddress bounceAddress = null;

	private final List<InternetAddress> replyToAddressList = new ArrayList<>();

	private List<InternetAddress> toAddressList = new ArrayList<>();
	private List<InternetAddress> ccAddressList = new ArrayList<>();
	private List<InternetAddress> bccAddressList = new ArrayList<>();

	private String bodyText = null;
	private String bodyHtml = null;

	private List<MailAttachment> attachments = new ArrayList<>();

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

	public Email(final InternetAddress fromAddress, final String subject, final Charset charset) {
		this.fromAddress = fromAddress;
		this.subject = subject;
		this.charset = charset;
	}

	public Email(final String fromAddress, final String subject) throws Exception {
		this(new InternetAddress(fromAddress), subject, StandardCharsets.UTF_8);
	}

	public Email(final String fromAddress, final String subject, final Charset charset) throws Exception {
		this(new InternetAddress(fromAddress), subject, charset);
	}

	public Email(final String fromAddress, final String fromName, final String subject, final Charset charset) throws Exception {
		this(new InternetAddress(fromAddress, fromName), subject, charset);
	}

	public InternetAddress getFromAddress() {
		return fromAddress;
	}

	public String getSubject() {
		return subject;
	}

	public Charset getCharset() {
		if (charset != null) {
			return charset;
		} else {
			return StandardCharsets.UTF_8;
		}
	}

	public InternetAddress getBounceAddress() {
		return bounceAddress;
	}

	public Email setBounceAddress(final InternetAddress bounceAddress) {
		this.bounceAddress = bounceAddress;
		return this;
	}

	public Email setBounceAddress(final String bounceAddress) throws Exception {
		this.bounceAddress = new InternetAddress(bounceAddress);
		return this;
	}

	public Email setBounceAddress(final String bounceAddress, final String bounceAddressName) throws Exception {
		this.bounceAddress = new InternetAddress(bounceAddress, bounceAddressName);
		return this;
	}

	public List<InternetAddress> getReplyToAddressList() {
		return replyToAddressList;
	}

	public Email addReplyToAddress(final InternetAddress replyToAddress) {
		replyToAddressList.add(replyToAddress);
		return this;
	}

	public Email addReplyToAddress(final String replyToAddress) throws Exception {
		replyToAddressList.add(new InternetAddress(replyToAddress));
		return this;
	}

	public Email addReplyToAddress(final String replyToAddress, final String replyToAddressName) throws Exception {
		replyToAddressList.add(new InternetAddress(replyToAddress, replyToAddressName));
		return this;
	}

	public List<InternetAddress> getToAddressList() {
		return toAddressList;
	}

	public Email setToAddressList(final List<InternetAddress> toAddressList) {
		this.toAddressList = toAddressList;
		return this;
	}

	public Email addToAddress(final InternetAddress toAddress) {
		toAddressList.add(toAddress);
		return this;
	}

	public Email addToAddress(final String toAddress) throws Exception {
		toAddressList.add(new InternetAddress(toAddress));
		return this;
	}

	public Email addToAddress(final String toAddress, final String toAddressName) throws Exception {
		toAddressList.add(new InternetAddress(toAddress, toAddressName));
		return this;
	}

	public List<InternetAddress> getCcAddressList() {
		return ccAddressList;
	}

	public Email setCcAddressList(final List<InternetAddress> ccAddressList) {
		this.ccAddressList = ccAddressList;
		return this;
	}

	public Email addCcAddress(final InternetAddress ccAddress) {
		ccAddressList.add(ccAddress);
		return this;
	}

	public Email addCcAddress(final String ccAddress) throws Exception {
		ccAddressList.add(new InternetAddress(ccAddress));
		return this;
	}

	public Email addCcAddress(final String ccAddress, final String ccAddressName) throws Exception {
		ccAddressList.add(new InternetAddress(ccAddress, ccAddressName));
		return this;
	}

	public List<InternetAddress> getBccAddressList() {
		return bccAddressList;
	}

	public Email setBccAddressList(final List<InternetAddress> bccAddressList) {
		this.bccAddressList = bccAddressList;
		return this;
	}

	public Email addBccAddress(final InternetAddress bccAddress) {
		bccAddressList.add(bccAddress);
		return this;
	}

	public Email addBccAddress(final String bccAddress) throws Exception {
		bccAddressList.add(new InternetAddress(bccAddress));
		return this;
	}

	public Email addBccAddress(final String bccAddress, final String bccAddressName) throws Exception {
		bccAddressList.add(new InternetAddress(bccAddress, bccAddressName));
		return this;
	}

	public String getBodyText() {
		return bodyText;
	}

	public Email setBodyText(final String bodyText) {
		this.bodyText = bodyText;
		return this;
	}

	public String getBodyHtml() {
		return bodyHtml;
	}

	public Email setBodyHtml(final String bodyHtml) {
		this.bodyHtml = bodyHtml;
		return this;
	}

	public List<MailAttachment> getAttachments() {
		return attachments;
	}

	public Email setAttachments(final List<MailAttachment> attachments) {
		this.attachments = attachments;
		return this;
	}

	public Email addAttachment(final MailAttachment attachment) {
		attachments.add(attachment);
		return this;
	}

	public Email setDkimData(final String domain, final String selector, final RSAPrivateKey privateKey) throws Exception {
		return setDkimData(domain, selector, privateKey, null);
	}

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

	public RSAPrivateKey getDkimPrivateKey() {
		return dkimPrivateKey;
	}

	public String getDkimDomain() {
		return dkimDomain;
	}

	public String getDkimSelector() {
		return dkimSelector;
	}

	public String getDkimIdentity() {
		return dkimIdentity;
	}

	public PrivateKey getSignatureKey() {
		return signatureKey;
	}

	public Email setSignaturePrivateKey(final PrivateKey signatureKey) {
		this.signatureKey = signatureKey;
		return this;
	}

	public Email setSignatureCertificate(final X509Certificate signatureCertificate) {
		this.signatureCertificate = signatureCertificate;
		return this;
	}

	public X509Certificate getSignatureCertificate() {
		return signatureCertificate;
	}

	public X509Certificate getEncryptionCertificate() {
		return encryptionCertificate;
	}

	public Email setEncryptionCertificate(final X509Certificate encryptionCertificate) {
		this.encryptionCertificate = encryptionCertificate;
		return this;
	}

	public CryptoType getCryptoType() {
		return cryptoType;
	}

	public Email setCryptoType(final CryptoType cryptoType) {
		this.cryptoType = cryptoType;
		return this;
	}

	public List<String> checkValidData() throws Exception {
		final List<String> errors = new ArrayList<>();

		if (dkimPrivateKey != null) {
			final DomainKey domainKey = DomainKeyUtil.getDomainKey(dkimDomain, dkimSelector);
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

				String certEmail = null;
				for (final String token : Utilities.parseTokens(signatureCertificate.getSubjectDN().toString(), ',')) {
					final String[] keyValueParts = token.trim().split("=");
					if (keyValueParts.length >= 2 && ("E".equals(keyValueParts[0]) || "EMAILADDRESS".equals(keyValueParts[0]))) {
						certEmail = keyValueParts[1];
						break;
					}
				}

				if (certEmail == null || !certEmail.equals(fromAddress.toString())) {
					errors.add("SignatureCertficates emailaddress '" + certEmail + "' does not match from-emailaddress '" + fromAddress.toString() + "'");
				}

				if (signatureCertificate != null && signatureCertificate.getNotBefore() != null && signatureCertificate.getNotBefore().after(new Date())) {
					errors.add("SignatureCertficates of emailaddress '" + certEmail + "' may not be used before: " + new SimpleDateFormat(DateUtilities.DD_MM_YYYY_HH_MM_SS).format(signatureCertificate.getNotBefore()));
				}
				if (signatureCertificate != null && signatureCertificate.getNotAfter() != null && signatureCertificate.getNotAfter().before(new Date())) {
					errors.add("SignatureCertficates of emailaddress '" + certEmail + "' may not be used after: " + new SimpleDateFormat(DateUtilities.DD_MM_YYYY_HH_MM_SS).format(signatureCertificate.getNotAfter()));
				}

				if (!CryptographicUtilities.checkPrivateKeyFitsPublicKey(signatureKey, signatureCertificate.getPublicKey())) {
					errors.add("SignatureCertficate of emailaddress '" + certEmail + "' does not fit to signatureKey");
				}
			}

			if (encryptionCertificate != null) {
				String certEmail = null;
				for (final String token : Utilities.parseTokens(encryptionCertificate.getSubjectDN().toString(), ',')) {
					final String[] keyValueParts = token.trim().split("=");
					if (keyValueParts.length >= 2 && ("E".equals(keyValueParts[0]) || "EMAILADDRESS".equals(keyValueParts[0]))) {
						certEmail = keyValueParts[1];
						break;
					}
				}

				if (toAddressList.size() != 1) {
					errors.add("To many to-address recipients for single encryption certificate");
				} else if (certEmail == null || !certEmail.equals(toAddressList.get(0).toString())) {
					errors.add("EncryptionCertficates emailaddress '" + certEmail + "' does not match to-emailaddress '" + toAddressList.get(0).toString() + "'");
				}

				if (encryptionCertificate != null && encryptionCertificate.getNotBefore() != null && encryptionCertificate.getNotBefore().after(new Date())) {
					errors.add("EncryptionCertficates of emailaddress '" + certEmail + "' may not be used before: " + new SimpleDateFormat(DateUtilities.DD_MM_YYYY_HH_MM_SS).format(encryptionCertificate.getNotBefore()));
				}
				if (encryptionCertificate != null && encryptionCertificate.getNotAfter() != null && encryptionCertificate.getNotAfter().before(new Date())) {
					errors.add("EncrytionCertficates of emailaddress '" + certEmail + "' may not be used after: " + new SimpleDateFormat(DateUtilities.DD_MM_YYYY_HH_MM_SS).format(encryptionCertificate.getNotAfter()));
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

	public String getSignatureMethodName() {
		return signatureMethodName;
	}

	public Email setSignatureMethodName(final String signatureMethodName) {
		this.signatureMethodName = signatureMethodName;
		return this;
	}

	public String getEncryptionMethodName() {
		return encryptionMethodName;
	}

	public Email setEncryptionMethodName(final String encryptionMethodName) {
		this.encryptionMethodName = encryptionMethodName;
		return this;
	}

	public PGPSecretKey getPgpSecretKey() {
		return pgpSecretKey;
	}

	public Email setPgpSecretKey(final PGPSecretKey pgpSecretKey) {
		this.pgpSecretKey = pgpSecretKey;
		return this;
	}

	public char[] getPgpSecretKeyPassword() {
		return pgpSecretKeyPassword;
	}

	public Email setPgpSecretKeyPassword(final char[] pgpSecretKeyPassword) {
		this.pgpSecretKeyPassword = pgpSecretKeyPassword;
		return this;
	}

	public PGPPublicKey getPgpPublicKey() {
		return pgpPublicKey;
	}

	public Email setPgpPublicKey(final PGPPublicKey pgpPublicKey) {
		this.pgpPublicKey = pgpPublicKey;
		return this;
	}
}
