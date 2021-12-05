package de.soderer.mailer;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.FileNameMap;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.mail.internet.InternetAddress;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import de.soderer.utilities.FileUtilities;
import de.soderer.utilities.IoUtilities;
import de.soderer.utilities.ParameterException;
import de.soderer.utilities.UpdateableConsoleApplication;
import de.soderer.utilities.Utilities;
import de.soderer.utilities.Version;
import de.soderer.utilities.appupdate.ApplicationUpdateUtilities;
import de.soderer.utilities.crypto.CryptographicUtilities;
import de.soderer.utilities.crypto.PGPUtilities;
import de.soderer.utilities.crypto.PGPUtilities.PgpHashMethod;
import de.soderer.utilities.crypto.PGPUtilities.PgpSymmetricEncryptionMethod;
import de.soderer.utilities.mail.CryptoType;
import de.soderer.utilities.mail.Email;
import de.soderer.utilities.mail.MailAttachment;
import de.soderer.utilities.mail.MailUtilities;
import de.soderer.utilities.mail.Mailer;
import de.soderer.utilities.mail.MailerConnectionSecurity;

/**
 * The Main-Class of ConsoleMailer<br />
 */
public class ConsoleMailer extends UpdateableConsoleApplication {
	/** The Constant APPLICATION_NAME */
	public static final String APPLICATION_NAME = "ConsoleMailer";

	/** The Constant VERSION_RESOURCE_FILE, which contains version number and versioninfo download url */
	public static final String VERSION_RESOURCE_FILE = "/version.txt";

	public static final String HELP_RESOURCE_FILE = "/help.txt";

	/** The version is filled in at application start from the version.txt file */
	public static Version VERSION = null;

	/** The versioninfo download url is filled in at application start from the version.txt file */
	public static String VERSIONINFO_DOWNLOAD_URL = null;

	/** Trusted CA certificate for updates **/
	public static String TRUSTED_UPDATE_CA_CERTIFICATE = null;

	/** The usage message */
	private static String getUsageMessage() {
		try (InputStream helpInputStream = ConsoleMailer.class.getResourceAsStream(HELP_RESOURCE_FILE)) {
			return "ConsoleMailer (by Andreas Soderer, mail: consolemailer@soderer.de)\n"
					+ "VERSION: " + VERSION + "\n\n"
					+ new String(IoUtilities.toByteArray(helpInputStream), StandardCharsets.UTF_8);
		} catch (@SuppressWarnings("unused") final Exception e) {
			return "Help info is missing";
		}
	}

	/**
	 * The main method.
	 *
	 * @param arguments the arguments
	 */
	public static void main(final String[] arguments) {
		final int returnCode = _main(arguments);
		if (returnCode >= 0) {
			System.exit(returnCode);
		}
	}

	/**
	 * Method used for main but with no System.exit call to make it junit testable
	 *
	 * @param arguments
	 * @return
	 */
	protected static int _main(final String[] args) {
		try (InputStream resourceStream = ConsoleMailer.class.getResourceAsStream(VERSION_RESOURCE_FILE)) {
			// Try to fill the version and versioninfo download url
			final List<String> versionInfoLines = Utilities.readLines(resourceStream, StandardCharsets.UTF_8);
			VERSION = new Version(versionInfoLines.get(0));
			if (versionInfoLines.size() >= 2) {
				VERSIONINFO_DOWNLOAD_URL = versionInfoLines.get(1);
			}
			if (versionInfoLines.size() >= 3) {
				TRUSTED_UPDATE_CA_CERTIFICATE = versionInfoLines.get(2);
			}
		} catch (@SuppressWarnings("unused") final Exception e) {
			// Without the version.txt file we may not go on
			System.err.println("Invalid version.txt");
			return 1;
		}

		final List<String> arguments = new ArrayList<>(Arrays.asList(args));
		final List<File> configFiles = new ArrayList<>();

		try {
			if (arguments.size() == 0) {
				System.out.println(getUsageMessage());
				return 1;
			} else {
				for (int i = 0; i < arguments.size(); i++) {
					if ("help".equalsIgnoreCase(arguments.get(i)) || "-help".equalsIgnoreCase(arguments.get(i)) || "--help".equalsIgnoreCase(arguments.get(i)) || "-h".equalsIgnoreCase(arguments.get(i)) || "--h".equalsIgnoreCase(arguments.get(i))
							|| "-?".equalsIgnoreCase(arguments.get(i)) || "--?".equalsIgnoreCase(arguments.get(i))) {
						System.out.println(getUsageMessage());
						return 1;
					} else if ("version".equalsIgnoreCase(arguments.get(i))) {
						System.out.println(VERSION.toString());
						return 1;
					} else if ("update".equalsIgnoreCase(arguments.get(i))) {
						if (arguments.size() > i + 2) {
							final ConsoleMailer consoleMailer = new ConsoleMailer();
							ApplicationUpdateUtilities.executeUpdate(consoleMailer, ConsoleMailer.VERSIONINFO_DOWNLOAD_URL, ConsoleMailer.APPLICATION_NAME, ConsoleMailer.VERSION, ConsoleMailer.TRUSTED_UPDATE_CA_CERTIFICATE, arguments.get(i + 1), arguments.get(i + 2).toCharArray(), null, false);
						} else if (arguments.size() > i + 1) {
							final ConsoleMailer consoleMailer = new ConsoleMailer();
							ApplicationUpdateUtilities.executeUpdate(consoleMailer, ConsoleMailer.VERSIONINFO_DOWNLOAD_URL, ConsoleMailer.APPLICATION_NAME, ConsoleMailer.VERSION, ConsoleMailer.TRUSTED_UPDATE_CA_CERTIFICATE, arguments.get(i + 1), null, null, false);
						} else {
							final ConsoleMailer consoleMailer = new ConsoleMailer();
							ApplicationUpdateUtilities.executeUpdate(consoleMailer, ConsoleMailer.VERSIONINFO_DOWNLOAD_URL, ConsoleMailer.APPLICATION_NAME, ConsoleMailer.VERSION, ConsoleMailer.TRUSTED_UPDATE_CA_CERTIFICATE, null, null, null, false);
						}
						return 1;
					} else if ("-cfg".equalsIgnoreCase(arguments.get(i)) || "-config".equalsIgnoreCase(arguments.get(i))) {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter configfile");
						} else {
							final String configFilePath = arguments.get(i);
							if (Utilities.isBlank(configFilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter configfile");
							}
							final File configFile = new File(configFilePath);
							if (!configFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "Configfile does not exist: " + configFilePath);
							}
							configFiles.add(configFile);
						}
					}
				}
			}

			for (final File configFile : configFiles) {
				try {
					arguments.addAll(Utilities.parseArguments(FileUtilities.readFileToString(configFile, Charset.defaultCharset())));
				} catch (@SuppressWarnings("unused") final Exception e) {
					throw new ParameterException("Configfile is invalid: " + configFile.getAbsolutePath());
				}
			}

			String host = null;
			Integer port = null;
			String user = null;
			char[] password = null;
			MailerConnectionSecurity connectionSecurity = null;

			InternetAddress fromAddress = null;
			String subject = null;
			Charset charset = null;
			final List<InternetAddress> replyToAddressList = new ArrayList<>();
			final List<InternetAddress> toAddressList = new ArrayList<>();
			final List<InternetAddress> ccAddressList = new ArrayList<>();
			final List<InternetAddress> bccAddressList = new ArrayList<>();
			String bodyText = null;
			String bodyHtml = null;
			CryptoType cryptoType = null;
			File signatureKeyFile = null;
			char[] signatureKeyPassword = null;
			File signatureCertificateFile = null;
			String signatureMethodName = null;
			File encryptionCertificateFile = null;
			String encryptionMethodName = null;
			final List<MailAttachment> attachments = new ArrayList<>();
			RSAPrivateKey dkimPrivateKey = null;
			String dkimDomain = null;
			String dkimSelector = null;
			String dkimIdentity = null;
			boolean test = false;
			boolean force = false;
			boolean silent = false;

			// Read the parameters
			for (int i = 0; i < arguments.size(); i++) {
				if (Utilities.isBlank(arguments.get(i))) {
					throw new ParameterException(arguments.get(i), "Invalid parameter");
				} else if ("-cfg".equalsIgnoreCase(arguments.get(i)) || "-config".equalsIgnoreCase(arguments.get(i))) {
					// Configfiles have already been processed
					i++;
				} else if ("-h".equalsIgnoreCase(arguments.get(i)) || "-host".equalsIgnoreCase(arguments.get(i))) {
					if (host != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter host");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter host");
						} else {
							host = arguments.get(i);
							if (host.contains(":")) {
								if (port != null) {
									throw new ParameterException(arguments.get(i - 1), "Multiple parameter port");
								} else {
									try {
										port = Integer.parseInt(host.substring(host.indexOf(":") + 1));
									} catch (@SuppressWarnings("unused") final NumberFormatException e) {
										throw new ParameterException("Invalid value for parameter port");
									}
									host = host.substring(0, host.indexOf(":"));
								}
							}
						}
					}
				} else if ("-port".equalsIgnoreCase(arguments.get(i))) {
					if (port != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter port");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter port");
						} else {
							try {
								port = Integer.parseInt(arguments.get(i));
							} catch (@SuppressWarnings("unused") final NumberFormatException e) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter port");
							}
						}
					}
				} else if ("-starttls".equalsIgnoreCase(arguments.get(i))) {
					if (connectionSecurity != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter connectionSecurity");
					} else {
						connectionSecurity = MailerConnectionSecurity.STARTTLS;
					}
				} else if ("-ssl".equalsIgnoreCase(arguments.get(i)) || "-tls".equalsIgnoreCase(arguments.get(i)) || "-ssltls".equalsIgnoreCase(arguments.get(i).replace("_", ""))) {
					if (connectionSecurity != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter connectionSecurity");
					} else {
						connectionSecurity = MailerConnectionSecurity.SSL_TLS;
					}
				} else if ("-u".equalsIgnoreCase(arguments.get(i)) || "-user".equalsIgnoreCase(arguments.get(i))) {
					if (user != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter user");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter user");
						} else {
							user = arguments.get(i);
						}
					}
				} else if ("-p".equalsIgnoreCase(arguments.get(i)) || "-password".equalsIgnoreCase(arguments.get(i))) {
					if (password != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter password");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter password");
						} else {
							password = arguments.get(i).toCharArray();
						}
					}
				} else if ("-from".equalsIgnoreCase(arguments.get(i))) {
					if (fromAddress != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter from-address");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter from-address");
						} else {
							final InternetAddress[] fromAddresses = MailUtilities.getEmailAddressesFromList(arguments.get(i));
							if (fromAddresses.length != 1) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter from-address");
							} else {
								fromAddress = fromAddresses[0];
							}
						}
					}
				} else if ("-s".equalsIgnoreCase(arguments.get(i)) || "-subject".equalsIgnoreCase(arguments.get(i))) {
					if (subject != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter subject");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter subject");
						} else {
							if (Utilities.isBlank(arguments.get(i))) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter subject");
							} else {
								subject = arguments.get(i);
							}
						}
					}
				} else if ("-c".equalsIgnoreCase(arguments.get(i)) || "-charset".equalsIgnoreCase(arguments.get(i))) {
					if (charset != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter charset");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter charset");
						} else {
							if (Utilities.isBlank(arguments.get(i))) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter charset");
							} else {
								try {
									charset = Charset.forName(arguments.get(i));
								} catch (@SuppressWarnings("unused") final Exception e) {
									throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter charset");
								}
							}
						}
					}
				} else if ("-replyto".equalsIgnoreCase(arguments.get(i))) {
					i++;
					if (i >= arguments.size()) {
						throw new ParameterException(arguments.get(i - 1), "Missing value for parameter replyTo-address");
					} else {
						InternetAddress[] replyToAddresses;
						try {
							replyToAddresses = MailUtilities.getEmailAddressesFromList(arguments.get(i));
						} catch (@SuppressWarnings("unused") final Exception e) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter replyTo-address");
						}
						if (replyToAddresses.length == 0) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter replyTo-address");
						} else {
							for (final InternetAddress replyToAddress : replyToAddresses) {
								replyToAddressList.add(replyToAddress);
							}
						}
					}
				} else if ("-to".equalsIgnoreCase(arguments.get(i))) {
					i++;
					if (i >= arguments.size()) {
						throw new ParameterException(arguments.get(i - 1), "Missing value for parameter to-address");
					} else {
						InternetAddress[] toAddresses;
						try {
							toAddresses = MailUtilities.getEmailAddressesFromList(arguments.get(i));
						} catch (@SuppressWarnings("unused") final Exception e) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter to-address");
						}
						if (toAddresses.length == 0) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter to-address");
						} else {
							for (final InternetAddress toAddress : toAddresses) {
								toAddressList.add(toAddress);
							}
						}
					}
				} else if ("-cc".equalsIgnoreCase(arguments.get(i))) {
					i++;
					if (i >= arguments.size()) {
						throw new ParameterException(arguments.get(i - 1), "Missing value for parameter cc-address");
					} else {
						InternetAddress[] ccAddresses;
						try {
							ccAddresses = MailUtilities.getEmailAddressesFromList(arguments.get(i));
						} catch (@SuppressWarnings("unused") final Exception e) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter cc-address");
						}
						if (ccAddresses.length == 0) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter cc-address");
						} else {
							for (final InternetAddress ccAddress : ccAddresses) {
								ccAddressList.add(ccAddress);
							}
						}
					}
				} else if ("-bcc".equalsIgnoreCase(arguments.get(i))) {
					i++;
					if (i >= arguments.size()) {
						throw new ParameterException(arguments.get(i - 1), "Missing value for parameter bcc-address");
					} else {
						InternetAddress[] bccAddresses;
						try {
							bccAddresses = MailUtilities.getEmailAddressesFromList(arguments.get(i));
						} catch (@SuppressWarnings("unused") final Exception e) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter bcc-address");
						}
						if (bccAddresses.length == 0) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter bcc-address");
						} else {
							for (final InternetAddress bccAddress : bccAddresses) {
								bccAddressList.add(bccAddress);
							}
						}
					}
				} else if ("-text".equalsIgnoreCase(arguments.get(i))) {
					if (bodyText != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter text");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter text");
						} else {
							bodyText = arguments.get(i);
						}
					}
				} else if ("-textfile".equalsIgnoreCase(arguments.get(i))) {
					if (bodyText != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter text");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter text-file");
						} else {
							final String textFilePath = arguments.get(i);
							if (Utilities.isBlank(textFilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter text-file");
							}
							final File textFile = new File(textFilePath);
							if (!textFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "Text file does not exist: " + textFilePath);
							}
							bodyText = FileUtilities.readFileToString(textFile, charset == null ? StandardCharsets.UTF_8 : charset);
						}
					}
				} else if ("-html".equalsIgnoreCase(arguments.get(i))) {
					if (bodyHtml != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter html");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter html");
						} else {
							bodyHtml = arguments.get(i);
						}
					}
				} else if ("-htmlfile".equalsIgnoreCase(arguments.get(i))) {
					if (bodyHtml != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter html");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter html-file");
						} else {
							final String htmlFilePath = arguments.get(i);
							if (Utilities.isBlank(htmlFilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter html-file");
							}
							final File htmlFile = new File(htmlFilePath);
							if (!htmlFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "Html file does not exist: " + htmlFilePath);
							}
							bodyHtml = FileUtilities.readFileToString(htmlFile, charset == null ? StandardCharsets.UTF_8 : charset);
						}
					}
				} else if ("-crypto".equalsIgnoreCase(arguments.get(i)) || "-cryptotype".equalsIgnoreCase(arguments.get(i))) {
					if (cryptoType != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter crypto");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter crypto");
						} else {
							final String cryptoTypeString = arguments.get(i);
							if (Utilities.isBlank(cryptoTypeString)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter crypto");
							}
							if ("smime".equalsIgnoreCase(cryptoTypeString.replace("/", "").replace("_", "").replace(" ", ""))) {
								cryptoType = CryptoType.S_MIME;
							} else if ("pgp".equalsIgnoreCase(cryptoTypeString.replace("/", "").replace("_", "").replace(" ", "")) || "gpg".equalsIgnoreCase(cryptoTypeString.replace("/", "").replace("_", "").replace(" ", ""))) {
								cryptoType = CryptoType.PGP;
							} else {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter crypto");
							}
						}
					}
				} else if ("-signaturekeyfile".equalsIgnoreCase(arguments.get(i))) {
					if (signatureKeyFile != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter signatureKeyfile");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter signatureKeyfile");
						} else {
							final String signatureKeyfilePath = arguments.get(i);
							if (Utilities.isBlank(signatureKeyfilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter signatureKeyfile");
							}
							signatureKeyFile = new File(signatureKeyfilePath);
							if (!signatureKeyFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "signatureKeyfile does not exist: " + signatureKeyfilePath);
							}
						}
					}
				} else if ("-signaturekeypassword".equalsIgnoreCase(arguments.get(i))) {
					if (signatureKeyPassword != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter signatureKeypassword");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter signatureKeypassword");
						} else {
							signatureKeyPassword = arguments.get(i).toCharArray();
						}
					}
				} else if ("-signaturecertificatefile".equalsIgnoreCase(arguments.get(i))) {
					if (signatureCertificateFile != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter signatureCertificateFile");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter signatureCertificateFile");
						} else {
							final String signatureCertificateFilePath = arguments.get(i);
							if (Utilities.isBlank(signatureCertificateFilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter signaturecertificatefile");
							}
							signatureCertificateFile = new File(signatureCertificateFilePath);
							if (!signatureCertificateFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "signatureCertificateFile does not exist: " + signatureCertificateFilePath);
							}
						}
					}
				} else if ("-signaturemethodname".equalsIgnoreCase(arguments.get(i))) {
					if (signatureMethodName != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter signatureMethodName");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter signatureMethodName");
						} else {
							signatureMethodName = arguments.get(i);
						}
					}
				} else if ("-encryptioncertificatefile".equalsIgnoreCase(arguments.get(i))) {
					if (encryptionCertificateFile != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter encryptionKeyFile or encryptionCertificateFile");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter encryptionCertificateFile");
						} else {
							final String encryptionCertificateFilePath = arguments.get(i);
							if (Utilities.isBlank(encryptionCertificateFilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter encryptionCertificateFile");
							}
							encryptionCertificateFile = new File(encryptionCertificateFilePath);
							if (!encryptionCertificateFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "encryptionCertificateFile does not exist: " + encryptionCertificateFilePath);
							}
						}
					}
				} else if ("-encryptionkeyfile".equalsIgnoreCase(arguments.get(i))) {
					if (encryptionCertificateFile != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter encryptionKeyFile or encryptionCertificateFile");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter encryptionKeyFile");
						} else {
							final String encryptionCertificateFilePath = arguments.get(i);
							if (Utilities.isBlank(encryptionCertificateFilePath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter encryptionKeyFile");
							}
							encryptionCertificateFile = new File(encryptionCertificateFilePath);
							if (!encryptionCertificateFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "encryptionKeyFile does not exist: " + encryptionCertificateFilePath);
							}
						}
					}
				} else if ("-encryptionmethodname".equalsIgnoreCase(arguments.get(i))) {
					if (encryptionMethodName != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter encryptionMethodName");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter encryptionMethodName");
						} else {
							encryptionMethodName = arguments.get(i);
						}
					}
				} else if ("-dkimkeyfile".equalsIgnoreCase(arguments.get(i))) {
					if (dkimPrivateKey != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter dkimkeyfile");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter dkimkeyfile");
						} else {
							final String dkimPrivateKeyPath = arguments.get(i);
							if (Utilities.isBlank(dkimPrivateKeyPath)) {
								throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter dkimkeyfile");
							}
							final File dkimPrivateKeyFile = new File(dkimPrivateKeyPath);
							if (!dkimPrivateKeyFile.exists()) {
								throw new ParameterException(arguments.get(i - 1), "Dkimkeyfile does not exist: " + dkimPrivateKeyPath);
							}
							try {
								dkimPrivateKey = (RSAPrivateKey) CryptographicUtilities.getPrivateKeyFromString(FileUtilities.readFileToString(dkimPrivateKeyFile, charset == null ? StandardCharsets.UTF_8 : charset), null);
							} catch (@SuppressWarnings("unused") final Exception e) {
								throw new ParameterException(arguments.get(i - 1), "Dkimkeyfile is invalid");
							}
						}
					}
				} else if ("-dkimdomain".equalsIgnoreCase(arguments.get(i))) {
					if (dkimDomain != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter dkimdomain");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter dkimdomain");
						} else {
							dkimDomain = arguments.get(i);
						}
					}
				} else if ("-dkimselector".equalsIgnoreCase(arguments.get(i))) {
					if (dkimSelector != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter dkimselector");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter dkimselector");
						} else {
							dkimSelector = arguments.get(i);
						}
					}
				} else if ("-dkimidentity".equalsIgnoreCase(arguments.get(i))) {
					if (dkimIdentity != null) {
						throw new ParameterException(arguments.get(i - 1), "Multiple value for parameter dkimidentity");
					} else {
						i++;
						if (i >= arguments.size()) {
							throw new ParameterException(arguments.get(i - 1), "Missing value for parameter dkimidentity");
						} else {
							dkimIdentity = arguments.get(i);
						}
					}
				} else if ("-attachment".equalsIgnoreCase(arguments.get(i))) {
					i++;
					if (i >= arguments.size()) {
						throw new ParameterException(arguments.get(i - 1), "Missing value for parameter attachment");
					} else {
						final String attachmentPath = arguments.get(i);
						if (Utilities.isBlank(attachmentPath)) {
							throw new ParameterException(arguments.get(i - 1), "Invalid value for parameter attachment");
						}
						final File attachmentFile = new File(attachmentPath);
						if (!attachmentFile.exists()) {
							throw new ParameterException(arguments.get(i - 1), "Attachment file does not exist: " + attachmentPath);
						}
						final FileNameMap fileNameMap = URLConnection.getFileNameMap();
						final String mimeType = fileNameMap.getContentTypeFor(attachmentFile.getName());
						attachments.add(new MailAttachment(attachmentFile.getName(), FileUtilities.readFileToByteArray(attachmentFile), mimeType));
					}
				} else if ("-test".equalsIgnoreCase(arguments.get(i))) {
					if (test) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter test");
					} else {
						test = true;
					}
				} else if ("-f".equalsIgnoreCase(arguments.get(i)) || "-force".equalsIgnoreCase(arguments.get(i))) {
					if (force) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter force");
					} else {
						force = true;
					}
				} else if ("-silent".equalsIgnoreCase(arguments.get(i))) {
					if (silent) {
						throw new ParameterException(arguments.get(i - 1), "Multiple parameter silent");
					} else {
						silent = true;
					}
				} else {
					throw new ParameterException(arguments.get(i), "Invalid parameter");
				}
			}

			// Mandatory parameters
			if (Utilities.isBlank(host)) {
				throw new ParameterException("Missing parameter host");
			} else if (Utilities.isNotBlank(user) && Utilities.isBlank(password)) {
				throw new ParameterException("Missing parameter password, because parameter user is set");
			} else if (fromAddress == null) {
				throw new ParameterException("Missing parameter from-address");
			} else if (subject == null) {
				throw new ParameterException("Missing parameter subject");
			} else if (toAddressList.size() == 0 && ccAddressList.size() == 0 && bccAddressList.size() == 0) {
				throw new ParameterException("No email recipient (to/cc/bcc)");
			} else {
				// Default parameters
				if (port == null) {
					port = 25;
				}
				if (connectionSecurity == null) {
					connectionSecurity = MailerConnectionSecurity.None;
				}
				if (charset == null) {
					charset = StandardCharsets.UTF_8;
				}

				final Mailer mailer = new Mailer();
				mailer.setSmtpMailRelayHostname(host);
				mailer.setSmtpMailRelayPort(port);
				mailer.setConnectionSecurity(connectionSecurity);
				mailer.setSmtpUsername(user);
				mailer.setSmtpPassword(password);

				final Email email = new Email(fromAddress, subject, charset);
				for (final InternetAddress replyToAddress : replyToAddressList) {
					email.addReplyToAddress(replyToAddress);
				}
				for (final InternetAddress toAddress : toAddressList) {
					email.addToAddress(toAddress);
				}
				for (final InternetAddress ccAddress : ccAddressList) {
					email.addCcAddress(ccAddress);
				}
				for (final InternetAddress bccAddress : bccAddressList) {
					email.addBccAddress(bccAddress);
				}
				email.setBodyText(bodyText);
				email.setBodyHtml(bodyHtml);
				email.setAttachments(attachments);

				if (dkimPrivateKey != null) {
					if (dkimSelector == null) {
						throw new ParameterException("Missing parameter dkimSelector");
					}
					if (dkimDomain == null) {
						dkimDomain = MailUtilities.getDomainFromEmail(fromAddress.getAddress());
					}
					email.setDkimData(dkimDomain, dkimSelector, dkimPrivateKey, dkimIdentity);
				}

				if (signatureKeyFile != null) {
					email.setCryptoType(cryptoType);
					if (cryptoType == CryptoType.PGP) {
						final PGPSecretKey signaturePrivateKey;
						try (InputStream signatureKeyFileInputStream = new FileInputStream(signatureKeyFile)) {
							signaturePrivateKey = PGPUtilities.readPGPSecretKey(signatureKeyFileInputStream);
						}
						if (signaturePrivateKey == null) {
							throw new ParameterException("Invalid PGP signature private key in file '" + signatureKeyFile.getAbsolutePath() + "'");
						}
						email.setPgpSecretKey(signaturePrivateKey);
						if (signatureKeyPassword != null) {
							email.setPgpSecretKeyPassword(signatureKeyPassword);
						}

						if (signatureMethodName != null) {
							try {
								PgpHashMethod.getByName(signatureMethodName);
							} catch (@SuppressWarnings("unused") final Exception e) {
								throw new ParameterException(signatureMethodName, "Invalid value for parameter signatureMethodName");
							}

							email.setSignatureMethodName(signatureMethodName);
						}
					} else if (cryptoType == CryptoType.S_MIME) {
						final PrivateKey signaturePrivateKey = CryptographicUtilities.getPrivateKeyFromString(FileUtilities.readFileToString(signatureKeyFile, StandardCharsets.UTF_8), signatureKeyPassword);
						if (signaturePrivateKey == null) {
							throw new ParameterException("Invalid S/MIME signature private key in file '" + signatureKeyFile.getAbsolutePath() + "'");
						}
						email.setSignaturePrivateKey(signaturePrivateKey);
						if (signatureCertificateFile != null) {
							final List<X509Certificate> signatureCertificates = CryptographicUtilities.getCertificatesFromString(FileUtilities.readFileToString(signatureCertificateFile, StandardCharsets.UTF_8));
							if (signatureCertificates == null || signatureCertificates.size() != 1) {
								throw new ParameterException("Invalid S/MIME signature certificate in file '" + signatureCertificateFile.getAbsolutePath() + "'");
							}
							email.setSignatureCertificate(signatureCertificates.get(0));
						}

						if (signatureMethodName != null) {
							if (Utilities.isBlank(CryptographicUtilities.checkSignatureMethodName(signatureMethodName))) {
								throw new ParameterException(signatureMethodName, "Invalid value for parameter signatureMethodName");
							}

							email.setSignatureMethodName(signatureMethodName);
						}
					} else {
						throw new ParameterException("Missing parameter crypto");
					}
				}

				if (encryptionCertificateFile != null) {
					email.setCryptoType(cryptoType);
					if (cryptoType == CryptoType.PGP) {
						final PGPPublicKey encryptionPublicKey;
						try (InputStream encryptionCertificateFileInputStream = new FileInputStream(encryptionCertificateFile)) {
							encryptionPublicKey = PGPUtilities.readPGPPublicKey(encryptionCertificateFileInputStream);
						}
						if (encryptionPublicKey == null) {
							throw new ParameterException("Invalid PGP encryption public key in file '" + encryptionCertificateFile.getAbsolutePath() + "'");
						}
						email.setPgpPublicKey(encryptionPublicKey);
						if (encryptionMethodName != null) {
							try {
								PgpSymmetricEncryptionMethod.getByName(encryptionMethodName);
							} catch (@SuppressWarnings("unused") final Exception e) {
								throw new ParameterException("-encryptionMethodName", "Invalid value for parameter encryptionMethodName with PGP");
							}
							email.setEncryptionMethodName(encryptionMethodName);
						}
					} else if (cryptoType == CryptoType.S_MIME) {
						final List<X509Certificate> encryptionCertificates = CryptographicUtilities.getCertificatesFromString(FileUtilities.readFileToString(encryptionCertificateFile, StandardCharsets.UTF_8));
						if (encryptionCertificates == null || encryptionCertificates.size() != 1) {
							throw new ParameterException("Invalid S/MIME encryption certificate in file '" + encryptionCertificateFile.getAbsolutePath() + "'");
						}
						email.setEncryptionCertificate(encryptionCertificates.get(0));
						if (encryptionMethodName != null) {
							if (Utilities.isBlank(CryptographicUtilities.checkEncryptionMethodName(encryptionMethodName))) {
								throw new ParameterException("-encryptionMethodName", "Invalid value for parameter encryptionMethodName with S/MIME");
							}
							email.setEncryptionMethodName(encryptionMethodName);
						}
					} else {
						throw new ParameterException("Missing parameter crypto");
					}
				}

				final List<String> errors = email.checkValidData();
				if (errors.size() > 0) {
					if (force) {
						if (!silent) {
							final StringBuilder warningText = new StringBuilder("Warning: \n");
							for (final String error : errors) {
								warningText.append("\t- ").append(error).append("\n");
							}
							System.err.println(warningText);
						}
					} else {
						final StringBuilder errorText = new StringBuilder("There were errors (use parameter '-force' to send anyway): \n");
						for (final String error : errors) {
							errorText.append("\t- ").append(error).append("\n");
						}
						throw new Exception(errorText.toString());
					}
				}

				if (!test) {
					mailer.send(email);

					if (!silent) {
						System.out.println("Email was sent");
					}
				} else {
					System.out.println("Email was NOT sent due to test configuration");
				}
				return 0;
			}
		} catch (final ParameterException e) {
			System.err.println(e.getMessage());
			System.err.println();
			System.err.println("For help information use parameter \"help\"");
			return 1;
		} catch (final Exception e) {
			System.err.println(e.getMessage());

			return 1;
		}
	}

	/**
	 * Instantiates a new ConsoleMailer
	 *
	 * @throws Exception the exception
	 */
	public ConsoleMailer() throws Exception {
		super(APPLICATION_NAME, VERSION);
	}
}
