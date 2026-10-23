package de.soderer.mailer;

import java.awt.Desktop;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.soderer.network.HttpUtilities;
import de.soderer.utilities.StringUtilities;
import de.soderer.utilities.SystemUtilities;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;

/**
 * Utilities for email addresses and opening emails in the standard email client.
 */
public class MailUtilities {
	private static final String SPECIAL_CHARS_REGEXP = "\\p{Cntrl}\\(\\)<>@,;:'\\\\\\\"\\.\\[\\]";
	private static final String VALID_CHARS_REGEXP = "[^\\s" + SPECIAL_CHARS_REGEXP + "]";
	private static final String QUOTED_USER_REGEXP = "(\"[^\"]*\")";
	private static final String WORD_REGEXP = "((" + VALID_CHARS_REGEXP + "|')+|" + QUOTED_USER_REGEXP + ")";

	private static final String DOMAIN_PART_REGEX = "\\p{Alnum}(?>[\\p{Alnum}-]*\\p{Alnum})*";
	private static final String TOP_DOMAIN_PART_REGEX = "\\p{Alpha}{2,}";
	private static final String DOMAIN_NAME_REGEX = "^(?:" + DOMAIN_PART_REGEX + "\\.)+" + "(" + TOP_DOMAIN_PART_REGEX + ")$";

	/**
	 * Regular expression for parsing email addresses.
	 *
	 * Taken from Apache Commons Validator.
	 * If this is not working, shame on Apache ;)
	 */
	private static final String EMAIL_REGEX = "^\\s*?(.+)@(.+?)\\s*$";

	private static final String USER_REGEX = "^\\s*" + WORD_REGEXP + "(\\." + WORD_REGEXP + ")*$";

	/** Regular expression pattern for parsing email addresses. */
	private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

	private static final Pattern USER_PATTERN = Pattern.compile(USER_REGEX);

	private static final Pattern DOMAIN_NAME_PATTERN = Pattern.compile(DOMAIN_NAME_REGEX);

	/** Time to wait for a launcher process to detect an immediate failure (e.g. no mail handler configured) */
	private static final long LAUNCHER_EXIT_CHECK_SECONDS = 3;

	private MailUtilities() {
		// Utility class
	}

	/**
	 * Check the syntax of an email address (local part and domain). The ".local" top level domain is not allowed.
	 *
	 * @param emailAddress email address to check
	 * @return true if the email address is valid, false for invalid addresses and null
	 */
	public static boolean isEmailValid(final String emailAddress) {
		if (emailAddress == null) {
			return false;
		}

		final Matcher m = EMAIL_PATTERN.matcher(emailAddress);

		// Check, if email address matches outline structure
		if (!m.matches()) {
			return false;
		}

		// Check if user-part is valid
		if (!isValidUser(m.group(1))) {
			return false;
		}

		// Check if domain-part is valid
		if (!isValidDomain(m.group(2))) {
			return false;
		}

		return true;
	}

	/**
	 * Get the domain part of an email address.
	 *
	 * @param emailAddress email address
	 * @return domain part
	 * @throws Exception if the email address is invalid
	 */
	public static String getDomainFromEmail(final String emailAddress) throws Exception {
		final Matcher m = EMAIL_PATTERN.matcher(emailAddress);

		// Check, if email address matches outline structure
		if (!m.matches()) {
			throw new Exception("Invalid email address");
		}

		// Check if user-part is valid
		if (!isValidUser(m.group(1))) {
			throw new Exception("Invalid email address");
		}

		// Check if domain-part is valid
		if (!isValidDomain(m.group(2))) {
			throw new Exception("Invalid email address");
		}

		return m.group(2);
	}

	/**
	 * Check the syntax of the local part of an email address.
	 *
	 * @param user local part
	 * @return true if the local part is valid
	 */
	public static boolean isValidUser(final String user) {
		return USER_PATTERN.matcher(user).matches();
	}

	/**
	 * Check the syntax of the domain part of an email address (also internationalized domain names).
	 * The ".local" top level domain is not allowed.
	 *
	 * @param domain domain part
	 * @return true if the domain part is valid
	 */
	public static boolean isValidDomain(final String domain) {
		String asciiDomainName;
		try {
			asciiDomainName = java.net.IDN.toASCII(domain);
		} catch (@SuppressWarnings("unused") final Exception e) {
			// invalid domain name like abc@.ch
			return false;
		}

		// Do not allow ".local" top level domain
		if (asciiDomainName.toLowerCase(Locale.ROOT).endsWith(".local")) {
			return false;
		}

		return DOMAIN_NAME_PATTERN.matcher(asciiDomainName).matches();
	}

	/**
	 * Check if a given e-mail address is valid.
	 * Notice that a {@code null} value is invalid address.
	 *
	 * @param email an e-mail address to check.
	 * @return {@code true} if address is valid or {@code false} otherwise.
	 */
	public static boolean isEmailValidAndNormalized(final String email) {
		return email != null && isEmailValid(email) && email.equals(normalizeEmail(email));
	}

	/**
	 * Parse a list of email addresses separated by ";", "," or blanks.
	 * Entries may contain display names in the form {@code Name <address>}, then the separators are ";" and ",".
	 * The addresses are normalized (lowercase, trimmed).
	 *
	 * @param emailAddressesListString list of email addresses
	 * @return parsed addresses, empty for a blank list
	 * @throws Exception if an address is invalid
	 */
	public static InternetAddress[] getEmailAddressesFromList(final String emailAddressesListString) throws Exception {
		if (StringUtilities.isBlank(emailAddressesListString)) {
			return new InternetAddress[0];
		} else {
			final List<InternetAddress> emailAddresses = new ArrayList<>();

			if (!emailAddressesListString.contains(">")) {
				for (final String emailAddressString : emailAddressesListString.split(";|,| ")) {
					if (StringUtilities.isNotBlank(emailAddressString)) {
						final String normalizedEmailAddressString = normalizeEmail(emailAddressString);
						if (MailUtilities.isEmailValid(normalizedEmailAddressString)) {
							try {
								final InternetAddress nextAddress = new InternetAddress(normalizedEmailAddressString);
								nextAddress.validate();
								emailAddresses.add(nextAddress);
							} catch (final AddressException e) {
								throw new Exception("Invalid emailaddress found: " + emailAddressString, e);
							}
						} else {
							throw new Exception("Invalid emailaddress found: " + emailAddressString);
						}
					}
				}
			} else {
				for (final String nameWithEmailAddressString : emailAddressesListString.split(";|,|>")) {
					if (StringUtilities.isNotBlank(nameWithEmailAddressString)) {
						String name;
						String normalizedEmailAddressString;
						if (nameWithEmailAddressString.contains("<")) {
							name = nameWithEmailAddressString.substring(0, nameWithEmailAddressString.indexOf("<")).trim();
							normalizedEmailAddressString = normalizeEmail(nameWithEmailAddressString.substring(nameWithEmailAddressString.indexOf("<") + 1).trim());
						} else {
							name = null;
							normalizedEmailAddressString = normalizeEmail(nameWithEmailAddressString);
						}

						if (MailUtilities.isEmailValid(normalizedEmailAddressString)) {
							try {
								final InternetAddress nextAddress;
								if (StringUtilities.isBlank(name)) {
									nextAddress = new InternetAddress(normalizedEmailAddressString);
								} else {
									nextAddress = new InternetAddress(normalizedEmailAddressString, name);
								}
								nextAddress.validate();
								emailAddresses.add(nextAddress);
							} catch (final AddressException e) {
								throw new Exception("Invalid emailaddress found: " + nameWithEmailAddressString, e);
							}
						} else {
							throw new Exception("Invalid emailaddress found: " + nameWithEmailAddressString);
						}
					}
				}
			}

			return emailAddresses.toArray(new InternetAddress[0]);
		}
	}

	/**
	 * Call lowercase and trim on email address. Watch out: apostrophe and other
	 * special characters {@code !#$%&'*+-/=?^_`{|}~} are allowed in local parts of
	 * emailaddresses
	 *
	 * @param email email address
	 * @return normalized email address, null for a blank email address
	 */
	public static String normalizeEmail(final String email) {
		if (StringUtilities.isBlank(email)) {
			return null;
		} else {
			return email.toLowerCase(Locale.ROOT).trim();
		}
	}

	/**
	 * Try to open an email in the standard email client
	 *
	 * @param toAdress recipient address(es)
	 * @param subject subject, may be null
	 * @param body body text, may be null
	 * @return true if some launcher accepted the mailto link
	 */
	public static boolean openMailInStandardClient(final String toAdress, final String subject, final String body) {
		return openMailInStandardClient(toAdress, null, null, subject, body);
	}

	/**
	 * Try to open an email in the standard email client.
	 * Uses only JDK means (java.awt.Desktop) and OS specific launchers, no SWT.
	 *
	 * @param toAdress recipient address(es)
	 * @param ccAdress cc address(es), may be null
	 * @param bccAdress bcc address(es), may be null
	 * @param subject subject, may be null
	 * @param body body text, may be null
	 * @return true if some launcher accepted the mailto link
	 */
	public static boolean openMailInStandardClient(final String toAdress, final String ccAdress, final String bccAdress, final String subject, final String body) {
		final String mailtoString;
		try {
			mailtoString = createMailtoLink(toAdress, ccAdress, bccAdress, subject, body);
		} catch (final Exception e) {
			e.printStackTrace();
			return false;
		}

		if (SystemUtilities.isWindowsSystem()) {
			if (openViaDesktopApi(mailtoString)) {
				return true;
			}
			// Replacement for SWT Program.launch(): let the Windows shell resolve the mailto handler
			if (launchProcess("rundll32", "url.dll,FileProtocolHandler", mailtoString)) {
				return true;
			}
		} else if (isMacOsSystem()) {
			if (openViaDesktopApi(mailtoString)) {
				return true;
			}
			if (launchProcess("open", mailtoString)) {
				return true;
			}
		} else {
			// Linux / Unix: xdg-open respects the desktop environment's configured mail client
			if (launchProcess("xdg-open", mailtoString)) {
				return true;
			}
			// Desktop API only works on some Linux desktops (GNOME/GTK based)
			if (openViaDesktopApi(mailtoString)) {
				return true;
			}
			// Last resort: Thunderbird accepts a mailto URL as command line argument
			// See http://kb.mozillazine.org/Command_line_arguments_%28Thunderbird%29
			if (launchProcess("thunderbird", mailtoString)) {
				return true;
			}
		}

		new Exception("Cannot create mail in standard mailclient").printStackTrace();
		return false;
	}

	/**
	 * Open the mailto link via java.awt.Desktop, if supported on this system
	 */
	private static boolean openViaDesktopApi(final String mailtoString) {
		try {
			if (Desktop.isDesktopSupported()) {
				final Desktop desktop = Desktop.getDesktop();
				if (desktop.isSupported(Desktop.Action.MAIL)) {
					desktop.mail(new URI(mailtoString));
					return true;
				}
			}
		} catch (@SuppressWarnings("unused") final Exception e) {
			// Headless environment, unsupported desktop or no mail handler configured
		}
		return false;
	}

	/**
	 * Start an external launcher process.
	 * Waits briefly to detect an immediate failure (non-zero exit code).
	 * A process still running after the wait time is considered successful (e.g. the mail client itself).
	 */
	private static boolean launchProcess(final String... command) {
		try {
			final Process process = new ProcessBuilder(command)
					.redirectOutput(ProcessBuilder.Redirect.DISCARD)
					.redirectError(ProcessBuilder.Redirect.DISCARD)
					.start();
			if (process.waitFor(LAUNCHER_EXIT_CHECK_SECONDS, TimeUnit.SECONDS)) {
				return process.exitValue() == 0;
			} else {
				return true;
			}
		} catch (@SuppressWarnings("unused") final InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		} catch (@SuppressWarnings("unused") final Exception e) {
			// Executable not found or not startable
			return false;
		}
	}

	private static boolean isMacOsSystem() {
		final String osName = System.getProperty("os.name", "");
		return osName.toLowerCase(Locale.ROOT).startsWith("mac");
	}

	/**
	 * Create a "mailto:" link (RFC 6068) with URL encoded parameters.
	 *
	 * @param toAdress recipient address(es)
	 * @param ccAdress cc address(es), may be null
	 * @param bccAdress bcc address(es), may be null
	 * @param subject subject, may be null
	 * @param body body text, may be null
	 * @return mailto link
	 * @throws Exception if the to-address is missing
	 */
	public static String createMailtoLink(final String toAdress, final String ccAdress, final String bccAdress, final String subject, final String body) throws Exception {
		if (StringUtilities.isBlank(toAdress)) {
			throw new Exception("TO address is missing or empty");
		}

		final StringBuilder mailtoString = new StringBuilder("mailto:").append(HttpUtilities.urlEncode(toAdress, StandardCharsets.UTF_8));

		boolean isFirstParameter = true;

		if (StringUtilities.isNotBlank(bccAdress)) {
			mailtoString.append(isFirstParameter ? "?" : "&");
			mailtoString.append("bcc=").append(HttpUtilities.urlEncode(bccAdress, StandardCharsets.UTF_8));
			isFirstParameter = false;
		}

		if (StringUtilities.isNotBlank(ccAdress)) {
			mailtoString.append(isFirstParameter ? "?" : "&");
			mailtoString.append("cc=").append(HttpUtilities.urlEncode(ccAdress, StandardCharsets.UTF_8));
			isFirstParameter = false;
		}

		if (StringUtilities.isNotBlank(subject)) {
			mailtoString.append(isFirstParameter ? "?" : "&");
			mailtoString.append("subject=").append(HttpUtilities.urlEncode(subject, StandardCharsets.UTF_8).replace("+", "%20"));
			isFirstParameter = false;
		}

		if (StringUtilities.isNotBlank(body)) {
			mailtoString.append(isFirstParameter ? "?" : "&");
			mailtoString.append("body=").append(HttpUtilities.urlEncode(body, StandardCharsets.UTF_8).replace("+", "%20"));
			isFirstParameter = false;
		}
		// Attachments are not part of the mailto standard (RFC 6068) and are ignored by most clients

		return mailtoString.toString();
	}
}
