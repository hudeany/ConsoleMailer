package de.soderer.utilities.mail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.mail.Address;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.SendFailedException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.ContentDisposition;
import javax.mail.internet.ContentType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;
import javax.mail.internet.MimeUtility;
import javax.mail.util.ByteArrayDataSource;

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

import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.util.CRLFOutputStream;

import de.soderer.utilities.Utilities;
import de.soderer.utilities.crypto.CryptographicUtilities;
import de.soderer.utilities.crypto.PGPFileEncryptionWorker;
import de.soderer.utilities.crypto.PGPUtilities;
import de.soderer.utilities.crypto.PGPUtilities.PgpHashMethod;
import de.soderer.utilities.http.HttpUtilities;
import de.soderer.utilities.mail.dkim.DkimSignedMessage;

public class Mailer {
	private String smtpMailRelayHostname = "localhost";
	private int smtpMailRelayPort = 0;

	private String smtpUsername = null;
	private char[] smtpPassword = null;

	private MailerConnectionSecurity connectionSecurity = MailerConnectionSecurity.None;

	public String getSmtpMailRelayHostname() {
		return smtpMailRelayHostname;
	}

	public Mailer setSmtpMailRelayHostname(final String smtpMailRelayHostname) {
		this.smtpMailRelayHostname = smtpMailRelayHostname;
		return this;
	}

	public int getSmtpMailRelayPort() {
		return smtpMailRelayPort;
	}

	public Mailer setSmtpMailRelayPort(final int smtpMailRelayPort) {
		this.smtpMailRelayPort = smtpMailRelayPort;
		return this;
	}

	public String getSmtpUsername() {
		return smtpUsername;
	}

	public Mailer setSmtpUsername(final String smtpUsername) {
		this.smtpUsername = smtpUsername;
		return this;
	}

	public char[] getSmtpPassword() {
		return smtpPassword;
	}

	public Mailer setSmtpPassword(final char[] smtpPassword) {
		this.smtpPassword = smtpPassword;
		return this;
	}

	public MailerConnectionSecurity getConnectionSecurity() {
		return connectionSecurity;
	}

	public Mailer setConnectionSecurity(final MailerConnectionSecurity connectionSecurity) {
		this.connectionSecurity = connectionSecurity;
		return this;
	}

	public Mailer send(final Email email) throws Exception {
		if (Utilities.isBlank(smtpMailRelayHostname)) {
			smtpMailRelayHostname = "localhost";
		}

		final Properties mailProps = new Properties();
		mailProps.put("mail.smtp.from", email.getFromAddress().getAddress());
		mailProps.put("mail.smtp.host", smtpMailRelayHostname);
		mailProps.put("mail.smtp.port", smtpMailRelayPort);

		if (connectionSecurity == MailerConnectionSecurity.SSL_TLS) {
			mailProps.put("mail.smtp.socketFactory.port", smtpMailRelayPort);
			mailProps.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
			mailProps.put("mail.smtp.socketFactory.fallback", "false");
		} else if (connectionSecurity == MailerConnectionSecurity.STARTTLS) {
			mailProps.put("mail.smtp.starttls.enable", "true");
		}

		final Session session;
		if (smtpUsername != null) {
			mailProps.put("mail.smtp.auth", true);
			final Authenticator authenticator = new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(smtpUsername, new String(smtpPassword));
				}
			};
			session = Session.getDefaultInstance(mailProps, authenticator);
		} else {
			mailProps.put("mail.smtp.auth", false);
			session = Session.getDefaultInstance(mailProps);
		}

		// create a message
		final String messageID = Utilities.generateUUID();
		final MimeMessage mimeMessage;
		if (email.getDkimPrivateKey() != null) {
			mimeMessage = new DkimSignedMessage(session, messageID);
			((DkimSignedMessage) mimeMessage).setDkimKeyData(email.getDkimDomain(), email.getDkimSelector(), email.getDkimPrivateKey(), email.getDkimIdentity());
		} else {
			mimeMessage = new de.soderer.utilities.mail.MimeMessage(session, messageID);
		}

		mimeMessage.setFrom(email.getFromAddress().getAddress());
		mimeMessage.setSubject(email.getSubject(), email.getCharset().name());
		mimeMessage.setSentDate(new Date());

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

		Multipart rootMultipart = null;

		if (email.getAttachments() == null || email.getAttachments().size() == 0 && email.getCryptoType() != CryptoType.PGP) {
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
				rootMultipart = new de.soderer.utilities.mail.MimeMultipart("alternative", HttpUtilities.generateBoundary());

				final MimeBodyPart textMimeBodyPart = new MimeBodyPart();
				textMimeBodyPart.setContent(email.getBodyText(), "text/plain; charset=" + email.getCharset().name());

				final MimeBodyPart htmlMimeBodyPart = new MimeBodyPart();
				htmlMimeBodyPart.setContent(email.getBodyHtml(), "text/html; charset=" + email.getCharset().name());

				rootMultipart.addBodyPart(textMimeBodyPart);
				rootMultipart.addBodyPart(htmlMimeBodyPart);
			}
		} else {
			rootMultipart = new de.soderer.utilities.mail.MimeMultipart("mixed", HttpUtilities.generateBoundary());

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
				final Multipart multipartTextContent = new de.soderer.utilities.mail.MimeMultipart("alternative", HttpUtilities.generateBoundary());

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
				}
				final ByteArrayDataSource bds = new ByteArrayDataSource(attachment.getData(), attachment.getMimeType());
				attachmentMimeBodyPart.setDataHandler(new DataHandler(bds));
				rootMultipart.addBodyPart(attachmentMimeBodyPart);
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

		signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
				.setSignedAttributeGenerator(new AttributeTable(attributes))
				.build(Utilities.isBlank(signatureMethodName) ? "SHA512withRSA" : signatureMethodName, privateKey, signingCertificate));

		final List<X509Certificate> certList = new ArrayList<>();
		certList.add(signingCertificate);
		signer.addCertificates(new JcaCertStore(certList));

		final de.soderer.utilities.mail.MimeMultipart mimeMultipart = new de.soderer.utilities.mail.MimeMultipart(signer.generate(mimeMessage));

		mimeMessage.setContent(mimeMultipart, mimeMultipart.getContentType());
		mimeMessage.saveChanges();

		return mimeMessage;
	}

	private static MimeMessage encryptMessageWithSmime(final MimeMessage mimeMessage, final X509Certificate recipientCert, final String encryptionMethodName) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final SMIMEEnvelopedGenerator envelopedGenerator = new SMIMEEnvelopedGenerator();
		envelopedGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));

		final MimeBodyPart mimeBodyPart = new MimeBodyPart();
		mimeBodyPart.setContent(mimeMessage.getContent(), mimeMessage.getContentType());
		final ASN1ObjectIdentifier encryptionAlgorithmIdentifier = Utilities.isBlank(encryptionMethodName) ? CMSAlgorithm.AES256_CBC : CryptographicUtilities.getASN1ObjectIdentifierByEncryptionMethodName(encryptionMethodName);
		final MimeBodyPart encryptedMimeBodyPart = envelopedGenerator.generate(mimeBodyPart, new JceCMSContentEncryptorBuilder(encryptionAlgorithmIdentifier).setProvider("BC").build());
		mimeMessage.setContent(encryptedMimeBodyPart.getContent(), encryptedMimeBodyPart.getContentType());
		mimeMessage.saveChanges();

		return mimeMessage;
	}

	private static Multipart signMessageWithPgp(final MimeMessage mimeMessage, final Multipart rootMultipart, final PGPSecretKey privateKey, final char[] password, final String signatureMethodName) throws Exception {
		final MimeBodyPart bodyPart = new MimeBodyPart();
		bodyPart.setContent(rootMultipart);

		updateHeaders(bodyPart);

		final ByteArrayOutputStream messageToSignBuffer = new ByteArrayOutputStream();
		try (final CRLFOutputStream canonicalLinebreakOutputStream = new CRLFOutputStream(messageToSignBuffer)) {
			bodyPart.writeTo(canonicalLinebreakOutputStream);
		}
		final byte[] messageToSign = messageToSignBuffer.toByteArray();

		final JcePBESecretKeyDecryptorBuilder jcePBESecretKeyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider());
		final PBESecretKeyDecryptor pbeSecretKeyDecryptor = jcePBESecretKeyDecryptorBuilder.build(password);
		final PGPPrivateKey pgpPrivKey = privateKey.extractPrivateKey(pbeSecretKeyDecryptor);
		final PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(privateKey.getPublicKey().getAlgorithm(), PgpHashMethod.getByName(signatureMethodName).getId()).setProvider(new BouncyCastleProvider()));

		pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

		final ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		try (final ArmoredOutputStream armoredOutput = new ArmoredOutputStream(byteOut);
				final InputStream inputStream = new BufferedInputStream(new ByteArrayInputStream(messageToSign))) {
			int readBuffer = 0;
			final byte[] buffer = new byte[4096];
			while ((readBuffer = inputStream.read(buffer)) != -1) {
				pgpSignatureGenerator.update(buffer, 0, readBuffer);
			}

			armoredOutput.endClearText();
			pgpSignatureGenerator.generate().encode(armoredOutput);
		}

		final String signature = PGPUtilities.removeVersionFromArmoredData(new String(byteOut.toByteArray(), StandardCharsets.UTF_8));

		final Multipart multipartSigned = new de.soderer.utilities.mail.MimeMultipart("signed", HttpUtilities.generateBoundary(), Utilities.createMap("micalg", "pgp-" + signatureMethodName.toLowerCase().replace("_", "").replace("-", ""), "protocol", "application/pgp-signature"));

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
		try (final CRLFOutputStream canonicalLinebreakOutputStream = new CRLFOutputStream(messageToEncryptBuffer)) {
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

		final de.soderer.utilities.mail.MimeMultipart newEncryptedMultipart = new de.soderer.utilities.mail.MimeMultipart("encrypted", HttpUtilities.generateBoundary(), Utilities.createMap("protocol", "application/pgp-encrypted"));

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
