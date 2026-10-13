package de.soderer.mailer;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.eclipse.angus.mail.smtp.SMTPAddressFailedException;
import org.eclipse.angus.mail.util.CRLFOutputStream;

import de.soderer.crypto.CryptographicUtilities;
import de.soderer.crypto.PGPFileEncryptionWorker;
import de.soderer.crypto.PGPUtilities;
import de.soderer.crypto.PGPUtilities.PgpHashMethod;
import de.soderer.network.HttpUtilities;
import de.soderer.utilities.DateUtilities;
import de.soderer.utilities.Utilities;
import de.soderer.utilities.mail.dkim.DkimSignedMessage;
import jakarta.activation.DataHandler;
import jakarta.mail.Address;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.SendFailedException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.ContentDisposition;
import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimePart;
import jakarta.mail.internet.MimeUtility;
import jakarta.mail.util.ByteArrayDataSource;

/**
 * Sends {@link Email} objects via SMTP, optionally signed and/or encrypted with S/MIME or PGP.
 * Configuration methods return this instance for method chaining.
 */
public class Mailer {
	/**
	 * Return value of stream read methods at the end of the stream.
	 */
	public static final int EOF = -1;

	private String smtpMailRelayHostname = "localhost";
	private int smtpMailRelayPort = 0;

	private String smtpUsername = null;
	private char[] smtpPassword = null;

	private MailerConnectionSecurity connectionSecurity = MailerConnectionSecurity.None;

	/**
	 * Create a mailer for an SMTP relay on "localhost" with the default port and without authentication and encryption.
	 */
	public Mailer() {
		// Configuration is done by the setters
	}

	/**
	 * Get the hostname of the SMTP server.
	 *
	 * @return hostname
	 */
	public String getSmtpMailRelayHostname() {
		return smtpMailRelayHostname;
	}

	/**
	 * Set the hostname of the SMTP server.
	 *
	 * @param smtpMailRelayHostname hostname
	 * @return this mailer
	 */
	public Mailer setSmtpMailRelayHostname(final String smtpMailRelayHostname) {
		this.smtpMailRelayHostname = smtpMailRelayHostname;
		return this;
	}

	/**
	 * Get the port of the SMTP server.
	 *
	 * @return port, 0 or less for the default port of the connection security
	 */
	public int getSmtpMailRelayPort() {
		return smtpMailRelayPort;
	}

	/**
	 * Set the port of the SMTP server.
	 *
	 * @param smtpMailRelayPort port, 0 or less for the default port of the connection security
	 * @return this mailer
	 */
	public Mailer setSmtpMailRelayPort(final int smtpMailRelayPort) {
		this.smtpMailRelayPort = smtpMailRelayPort;
		return this;
	}

	/**
	 * Get the username for SMTP authentication.
	 *
	 * @return username, null for no authentication
	 */
	public String getSmtpUsername() {
		return smtpUsername;
	}

	/**
	 * Set the username for SMTP authentication.
	 *
	 * @param smtpUsername username, null for no authentication
	 * @return this mailer
	 */
	public Mailer setSmtpUsername(final String smtpUsername) {
		this.smtpUsername = smtpUsername;
		return this;
	}

	/**
	 * Get the password for SMTP authentication.
	 *
	 * @return password (not copied)
	 */
	public char[] getSmtpPassword() {
		return smtpPassword;
	}

	/**
	 * Set the password for SMTP authentication.
	 *
	 * @param smtpPassword password (not copied)
	 * @return this mailer
	 */
	public Mailer setSmtpPassword(final char[] smtpPassword) {
		this.smtpPassword = smtpPassword;
		return this;
	}

	/**
	 * Get the transport security of the connection to the SMTP server.
	 *
	 * @return connection security
	 */
	public MailerConnectionSecurity getConnectionSecurity() {
		return connectionSecurity;
	}

	/**
	 * Set the transport security of the connection to the SMTP server.
	 *
	 * @param connectionSecurity connection security
	 * @return this mailer
	 */
	public Mailer setConnectionSecurity(final MailerConnectionSecurity connectionSecurity) {
		this.connectionSecurity = connectionSecurity;
		return this;
	}

	/**
	 * Send an email. The email is checked for valid data first.
	 *
	 * @param email email to send
	 * @return this mailer
	 * @throws Exception if the email is invalid or cannot be built, signed, encrypted or sent
	 */
	public Mailer send(final Email email) throws Exception {
		if (Utilities.isBlank(smtpMailRelayHostname)) {
			smtpMailRelayHostname = "localhost";
		}

		final Properties mailProps = new Properties();

		// Email header "Return-Path"
		if (email.getBounceAddress() != null) {
			// The envelope sender (SMTP "MAIL FROM") is the plain address without display name
			mailProps.put("mail.smtp.from", email.getBounceAddress().getAddress());
		} else {
			mailProps.put("mail.smtp.from", email.getFromAddress().getAddress());
		}

		mailProps.put("mail.smtp.host", smtpMailRelayHostname);
		// Port 0 (not set) means the default port of the protocol
		if (smtpMailRelayPort > 0) {
			mailProps.put("mail.smtp.port", Integer.toString(smtpMailRelayPort));
		}

		if (connectionSecurity == MailerConnectionSecurity.SSL_TLS) {
			mailProps.put("mail.smtp.ssl.enable", "true");
			mailProps.put("mail.smtp.ssl.checkserveridentity", "true");
		} else if (connectionSecurity == MailerConnectionSecurity.STARTTLS) {
			mailProps.put("mail.smtp.starttls.enable", "true");
			// Without "required" the mail (and the SMTP password) is sent unencrypted, if the server or an attacker in between does not offer STARTTLS
			mailProps.put("mail.smtp.starttls.required", "true");
			mailProps.put("mail.smtp.ssl.checkserveridentity", "true");
		}

		final Session session;
		if (smtpUsername != null) {
			mailProps.put("mail.smtp.auth", true);
			final Authenticator authenticator = new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(smtpUsername, smtpPassword == null ? "" : new String(smtpPassword));
				}
			};
			// A new session per send: Session.getDefaultInstance() returns one JVM wide session, which keeps the settings of the first call
			session = Session.getInstance(mailProps, authenticator);
		} else {
			mailProps.put("mail.smtp.auth", false);
			session = Session.getInstance(mailProps);
		}

		// create a message
		final String messageID = Utilities.generateUUID();
		final MimeMessage mimeMessage;
		if (email.getDkimPrivateKey() != null) {
			mimeMessage = new DkimSignedMessage(session, messageID);
			((DkimSignedMessage) mimeMessage).setDkimKeyData(email.getDkimDomain(), email.getDkimSelector(), email.getDkimPrivateKey(), email.getDkimIdentity());
		} else {
			mimeMessage = new MimeMessageWithId(session, messageID);
		}

		mimeMessage.setFrom(email.getFromAddress());
		mimeMessage.setSubject(email.getSubject(), email.getCharset().name());
		mimeMessage.setSentDate(DateUtilities.getDateForLocalDateTime(LocalDateTime.now()));

		// Set reply-to address
		if (email.getReplyToAddressList().size() > 0) {
			mimeMessage.setReplyTo(email.getReplyToAddressList().toArray(new InternetAddress[0]));
		} else {
			// Use fromAddress as fallback
			mimeMessage.setReplyTo(new Address[] { email.getFromAddress() });
		}

		// Set to-recipient email addresses
		if (email.getToAddressList().size() > 0) {
			mimeMessage.setRecipients(Message.RecipientType.TO, email.getToAddressList().toArray(new InternetAddress[0]));
		}

		// Set cc-recipient email addresses
		if (email.getCcAddressList().size() > 0) {
			mimeMessage.setRecipients(Message.RecipientType.CC, email.getCcAddressList().toArray(new InternetAddress[0]));
		}

		// Set bcc-recipient email addresses
		if (email.getBccAddressList().size() > 0) {
			mimeMessage.setRecipients(Message.RecipientType.BCC, email.getBccAddressList().toArray(new InternetAddress[0]));
		}

		if (email.getNotificationAddress() != null) {
			// InternetAddress.toString() encodes non ASCII display names as required in mail headers
			mimeMessage.setHeader("Disposition-Notification-To", email.getNotificationAddress().toString());
		}

		Multipart rootMultipart = null;

		if ((email.getAttachments() == null || email.getAttachments().size() == 0)
				&& (email.getEventInvitations() == null || email.getEventInvitations().size() == 0)
				&& email.getCryptoType() != CryptoType.PGP) {
			if (Utilities.isBlank(email.getBodyText()) && Utilities.isBlank(email.getBodyHtml())) {
				// Use a simple text email with only text content
				mimeMessage.setText("", email.getCharset().name());
			} else if (Utilities.isBlank(email.getBodyHtml())) {
				// Use a simple text email with only text content
				mimeMessage.setText(email.getBodyText(), email.getCharset().name());
			} else if (Utilities.isBlank(email.getBodyText())) {
				// Use a simple html email with only html content
				mimeMessage.setContent(email.getBodyHtml(), "text/html; charset=" + email.getCharset().name());
			} else {
				// Use a multipart email with text and html content
				rootMultipart = new de.soderer.mailer.MimeMultipart("alternative", HttpUtilities.generateBoundary());

				final MimeBodyPart textMimeBodyPart = new MimeBodyPart();
				textMimeBodyPart.setContent(email.getBodyText(), "text/plain; charset=" + email.getCharset().name());

				final MimeBodyPart htmlMimeBodyPart = new MimeBodyPart();
				htmlMimeBodyPart.setContent(email.getBodyHtml(), "text/html; charset=" + email.getCharset().name());

				rootMultipart.addBodyPart(textMimeBodyPart);
				rootMultipart.addBodyPart(htmlMimeBodyPart);
			}
		} else {
			rootMultipart = new de.soderer.mailer.MimeMultipart("mixed", HttpUtilities.generateBoundary());

			if (Utilities.isBlank(email.getBodyText()) && Utilities.isBlank(email.getBodyHtml())) {
				// Use a multipart text email with only text content and attachements
				final MimeBodyPart textMimeBodyPart = new MimeBodyPart();
				textMimeBodyPart.setText("", email.getCharset().name());
				rootMultipart.addBodyPart(textMimeBodyPart);
			} else if (Utilities.isBlank(email.getBodyHtml())) {
				final MimeBodyPart textMimeBodyPart = new MimeBodyPart();
				// Use a multipart text email with only text content and attachements
				textMimeBodyPart.setContent(email.getBodyText(), "text/plain; charset=" + email.getCharset().name());
				rootMultipart.addBodyPart(textMimeBodyPart);
			} else if (Utilities.isBlank(email.getBodyText())) {
				final MimeBodyPart textMimeBodyPart = new MimeBodyPart();
				// Use a multipart html email with only html content and attachements
				textMimeBodyPart.setContent(email.getBodyHtml(), "text/html; charset=" + email.getCharset().name());
				rootMultipart.addBodyPart(textMimeBodyPart);
			} else {
				// Use a multipart html email with text and html content and attachements
				final Multipart multipartTextContent = new de.soderer.mailer.MimeMultipart("alternative", HttpUtilities.generateBoundary());

				final MimeBodyPart textMimeBodyPart = new MimeBodyPart();
				textMimeBodyPart.setText(email.getBodyText(), email.getCharset().name());
				multipartTextContent.addBodyPart(textMimeBodyPart);

				final MimeBodyPart htmlMimeBodyPart = new MimeBodyPart();
				htmlMimeBodyPart.setContent(email.getBodyHtml(), "text/html; charset=" + email.getCharset().name());
				multipartTextContent.addBodyPart(htmlMimeBodyPart);

				final MimeBodyPart alternativeMimeBodyPart = new MimeBodyPart();
				rootMultipart.addBodyPart(alternativeMimeBodyPart);
				alternativeMimeBodyPart.setContent(multipartTextContent);
			}

			for (final MailAttachment attachment : email.getAttachments()) {
				final MimeBodyPart attachmentMimeBodyPart = new MimeBodyPart();
				attachmentMimeBodyPart.setFileName(MimeUtility.encodeText(attachment.getName(), StandardCharsets.UTF_8.name(), null));
				if (attachment.getData() == null) {
					throw new Exception("Invalid empty mail attachment");
				} else {
					final ByteArrayDataSource bds = new ByteArrayDataSource(attachment.getData(), attachment.getMimeType());
					attachmentMimeBodyPart.setDataHandler(new DataHandler(bds));
					rootMultipart.addBodyPart(attachmentMimeBodyPart);
				}
			}

			if (email.getEventInvitations() != null) {
				int count = 0;
				for (final String eventInvitation : email.getEventInvitations()) {
					if (Utilities.isBlank(eventInvitation)) {
						throw new Exception("Invalid empty event invitation");
					} else {
						final MimeBodyPart invitation = new MimeBodyPart();
						invitation.setHeader("Content-ID", "calendar_message_" + (++count));
						invitation.setHeader("Content-Disposition", "inline");
						invitation.setContent(eventInvitation, "text/calendar; method=REQUEST");
						rootMultipart.addBodyPart(invitation);
					}
				}
			}
		}

		if (email.getCryptoType() == CryptoType.S_MIME) {
			if (rootMultipart != null) {
				mimeMessage.setContent(rootMultipart, rootMultipart.getContentType());
			}

			if (email.getSignatureKey() != null) {
				if (email.getSignatureCertificate() == null) {
					throw new Exception("Signature certificate is missing");
				}
				signMessageWithSmime(mimeMessage, email.getSignatureKey(), email.getSignatureCertificate(), email.getSignatureMethodName());
			}

			if (email.getEncryptionCertificate() != null) {
				encryptMessageWithSmime(mimeMessage, email.getEncryptionCertificate(), email.getEncryptionMethodName());
			}
		} else if (email.getCryptoType() == CryptoType.PGP) {
			if (email.getPgpSecretKey() != null) {
				rootMultipart = signMessageWithPgp(mimeMessage, rootMultipart, email.getPgpSecretKey(), email.getPgpSecretKeyPassword(), email.getSignatureMethodName());
			}

			if (email.getPgpPublicKey() != null) {
				encryptMessageWithPgp(mimeMessage, rootMultipart, email.getPgpPublicKey(), email.getEncryptionMethodName());
			}
		} else {
			if (rootMultipart != null) {
				mimeMessage.setContent(rootMultipart, rootMultipart.getContentType());
			}
		}

		try {
			Transport.send(mimeMessage);
		} catch (final SendFailedException e) {
			if (e.getCause() != null && e.getCause() instanceof SMTPAddressFailedException && e.getCause().getMessage() != null) {
				if (e.getCause().getMessage().contains("Relay access denied")) {
					throw new Exception("Server '" + smtpMailRelayHostname + "' denied relay of this email", e);
				} else if (e.getCause().getMessage().contains("Client host rejected")) {
					throw new Exception("Server '" + smtpMailRelayHostname + "' denied relay of this email. Your host is not allowed to send emails.", e);
				} else if (e.getCause().getMessage().contains("Access denied")) {
					throw new Exception("Server '" + smtpMailRelayHostname + "' denied relay of this email. Maybe authentification is needed.", e);
				} else {
					throw e;
				}
			} else {
				throw e;
			}
		}

		return this;
	}

	private static MimeMessage signMessageWithSmime(final MimeMessage mimeMessage, final PrivateKey privateKey, final X509Certificate signingCertificate, final String signatureMethodName) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
		capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
		capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
		capabilities.addCapability(SMIMECapability.dES_CBC);
		capabilities.addCapability(SMIMECapability.aES256_CBC);

		final ASN1EncodableVector attributes = new ASN1EncodableVector();
		attributes.add(new SMIMECapabilitiesAttribute(capabilities));

		final SMIMESignedGenerator signer = new SMIMESignedGenerator();

		signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.setSignedAttributeGenerator(new AttributeTable(attributes))
				.build(Utilities.isBlank(signatureMethodName) ? "SHA512withRSA" : signatureMethodName, privateKey, signingCertificate));

		final List<X509Certificate> certList = new ArrayList<>();
		certList.add(signingCertificate);
		signer.addCertificates(new JcaCertStore(certList));

		final de.soderer.mailer.MimeMultipart mimeMultipart = new de.soderer.mailer.MimeMultipart(signer.generate(mimeMessage));

		mimeMessage.setContent(mimeMultipart, mimeMultipart.getContentType());
		mimeMessage.saveChanges();

		return mimeMessage;
	}

	private static MimeMessage encryptMessageWithSmime(final MimeMessage mimeMessage, final X509Certificate recipientCert, final String encryptionMethodName) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final SMIMEEnvelopedGenerator envelopedGenerator = new SMIMEEnvelopedGenerator();
		envelopedGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider(BouncyCastleProvider.PROVIDER_NAME));

		final MimeBodyPart mimeBodyPart = new MimeBodyPart();
		mimeBodyPart.setContent(mimeMessage.getContent(), mimeMessage.getContentType());
		final ASN1ObjectIdentifier encryptionAlgorithmIdentifier = Utilities.isBlank(encryptionMethodName) ? CMSAlgorithm.AES256_CBC : CryptographicUtilities.getASN1ObjectIdentifierByEncryptionMethodName(encryptionMethodName);
		final MimeBodyPart encryptedMimeBodyPart = envelopedGenerator.generate(mimeBodyPart, new JceCMSContentEncryptorBuilder(encryptionAlgorithmIdentifier).setProvider(BouncyCastleProvider.PROVIDER_NAME).build());
		mimeMessage.setContent(encryptedMimeBodyPart.getContent(), encryptedMimeBodyPart.getContentType());
		mimeMessage.saveChanges();

		return mimeMessage;
	}

	private static Multipart signMessageWithPgp(final MimeMessage mimeMessage, final Multipart rootMultipart, final PGPSecretKey privateKey, final char[] password, final String signatureMethodNameParameter) throws Exception {
		final String signatureMethodName = Utilities.isBlank(signatureMethodNameParameter) ? PgpHashMethod.SHA256.name() : signatureMethodNameParameter;
		final MimeBodyPart bodyPart = new MimeBodyPart();
		bodyPart.setContent(rootMultipart);

		updateHeaders(bodyPart);

		final ByteArrayOutputStream messageToSignBuffer = new ByteArrayOutputStream();
		try (CRLFOutputStream canonicalLinebreakOutputStream = new CRLFOutputStream(messageToSignBuffer)) {
			bodyPart.writeTo(canonicalLinebreakOutputStream);
		}
		final byte[] messageToSign = messageToSignBuffer.toByteArray();

		final JcePBESecretKeyDecryptorBuilder jcePBESecretKeyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider());
		final PBESecretKeyDecryptor pbeSecretKeyDecryptor = jcePBESecretKeyDecryptorBuilder.build(password);
		final PGPPrivateKey pgpPrivKey = privateKey.extractPrivateKey(pbeSecretKeyDecryptor);
		final PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(privateKey.getPublicKey().getAlgorithm(), PgpHashMethod.getByName(signatureMethodName).getId()).setProvider(new BouncyCastleProvider()), privateKey.getPublicKey());

		pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

		final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		try (ArmoredOutputStream armoredOutput = new ArmoredOutputStream(byteOut);
				final InputStream inputStream = new BufferedInputStream(new ByteArrayInputStream(messageToSign))) {
			int readBuffer = 0;
			final byte[] buffer = new byte[4096];
			while ((readBuffer = inputStream.read(buffer)) != EOF) {
				pgpSignatureGenerator.update(buffer, 0, readBuffer);
			}
			Utilities.clear(buffer);

			armoredOutput.endClearText();
			pgpSignatureGenerator.generate().encode(armoredOutput);
		}

		final String signature = PGPUtilities.removeVersionFromArmoredData(new String(byteOut.toByteArray(), StandardCharsets.UTF_8));

		final Multipart multipartSigned = new de.soderer.mailer.MimeMultipart("signed", HttpUtilities.generateBoundary(), Utilities.createMap("micalg", "pgp-" + signatureMethodName.toLowerCase(Locale.ROOT).replace("_", "").replace("-", ""), "protocol", "application/pgp-signature"));

		final MimeBodyPart mimeBodyPart = new MimeBodyPart();

		mimeBodyPart.setContent(rootMultipart, rootMultipart.getContentType());

		multipartSigned.addBodyPart(mimeBodyPart);

		final MimeBodyPart signatureMimeBodyPart = new MimeBodyPart();
		signatureMimeBodyPart.addHeader("Content-Description", "OpenPGP digital signature");
		signatureMimeBodyPart.addHeader("Content-Disposition", "attachment; filename=\"OpenPGP_signature\"");

		signatureMimeBodyPart.setContent(signature, "application/pgp-signature; name=\"OpenPGP_signature.asc\"");

		multipartSigned.addBodyPart(signatureMimeBodyPart);

		mimeMessage.setContent(multipartSigned);

		return multipartSigned;
	}

	private static MimeMessage encryptMessageWithPgp(final MimeMessage mimeMessage, final Multipart rootMultipart, final PGPPublicKey publicKey, final String encryptionMethodName) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final MimeBodyPart contentPart = new MimeBodyPart();
		contentPart.setContent(rootMultipart);

		final MimeBodyPart controlPart = new MimeBodyPart();
		controlPart.setContent("Version: 1\n", "application/pgp-encrypted");

		updateHeaders(contentPart);

		final ByteArrayOutputStream messageToEncryptBuffer = new ByteArrayOutputStream();
		try (CRLFOutputStream canonicalLinebreakOutputStream = new CRLFOutputStream(messageToEncryptBuffer)) {
			contentPart.writeTo(canonicalLinebreakOutputStream);
		}

		final ByteArrayOutputStream encryptedMessageBuffer = new ByteArrayOutputStream();
		final PGPFileEncryptionWorker pgpFileEncryptionWorker = new PGPFileEncryptionWorker(null, new ByteArrayInputStream(messageToEncryptBuffer.toByteArray()), encryptedMessageBuffer, publicKey);
		if (encryptionMethodName != null) {
			pgpFileEncryptionWorker.setPgpSymmetricEncryptionMethod(encryptionMethodName);
		}
		if (!pgpFileEncryptionWorker.work()) {
			throw new Exception("Error while encrypting data", pgpFileEncryptionWorker.getError());
		}

		final String encryptedMessage = PGPUtilities.removeVersionFromArmoredData(new String(encryptedMessageBuffer.toByteArray(), StandardCharsets.UTF_8));

		final MimeBodyPart encryptedPart = new MimeBodyPart();
		encryptedPart.setDataHandler(new DataHandler(new ByteArrayDataSource(encryptedMessage, "application/pgp-encrypted")));
		updateHeaders(encryptedPart);
		final String contentType = encryptedPart.getContentType();
		encryptedPart.setHeader("Content-Type", contentType + "; name=encrypted.asc");

		final de.soderer.mailer.MimeMultipart newEncryptedMultipart = new de.soderer.mailer.MimeMultipart("encrypted", HttpUtilities.generateBoundary(), Utilities.createMap("protocol", "application/pgp-encrypted"));

		newEncryptedMultipart.addBodyPart(controlPart, 0);
		newEncryptedMultipart.addBodyPart(encryptedPart, 1);

		mimeMessage.setContent(newEncryptedMultipart);

		return mimeMessage;
	}

	private static void updateHeaders(final Object part) throws MessagingException {
		if (part instanceof MimeMultipart) {
			final MimeMultipart mimeMultipart = (MimeMultipart) part;
			for (int i = 0; i < mimeMultipart.getCount(); i++) {
				updateHeaders(mimeMultipart.getBodyPart(i));
			}
		} else if (part instanceof MimePart) {
			final MimePart mimePart = (MimePart) part;
			final DataHandler dataHandler = mimePart.getDataHandler();
			if (dataHandler != null) {
				try {
					String contentTypeString = dataHandler.getContentType();
					boolean composite = false;
					final ContentType contentType = new ContentType(contentTypeString);
					if (contentType.match("multipart/*")) {
						composite = true;
						updateHeaders(dataHandler.getContent());
					} else if (contentType.match("message/rfc822")) {
						composite = true;
					}

					if (mimePart.getHeader("Content-Type") == null) {
						final String contentDispositionString = mimePart.getHeader("Content-Disposition", null);
						if (contentDispositionString != null) {
							final ContentDisposition contentDisposition = new ContentDisposition(contentDispositionString);
							final String filename = contentDisposition.getParameter("filename");
							if (filename != null) {
								contentType.setParameter("name", filename);
								contentTypeString = contentType.toString();
							}
						}
						mimePart.setHeader("Content-Type", contentTypeString);
					}

					if (!composite && (mimePart.getHeader("Content-Transfer-Encoding") == null)) {
						mimePart.setHeader("Content-Transfer-Encoding", MimeUtility.getEncoding(dataHandler));
					}
				} catch (final IOException ex) {
					throw new MessagingException("IOException updating headers", ex);
				}
			}
		}
	}
}
