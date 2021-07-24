package de.soderer.utilities.mail;

import java.awt.Desktop;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.eclipse.swt.program.Program;

import de.soderer.utilities.SystemUtilities;
import de.soderer.utilities.Utilities;
import de.soderer.utilities.http.HttpUtilities;

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

	public static boolean isEmailValid(final String emailAddress) {
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

	public static boolean isValidUser(final String user) {
		return USER_PATTERN.matcher(user).matches();
	}

	public static boolean isValidDomain(final String domain) {
		String asciiDomainName;
		try {
			asciiDomainName = java.net.IDN.toASCII(domain);
		} catch (@SuppressWarnings("unused") final Exception e) {
			// invalid domain name like abc@.ch
			return false;
		}

		// Do not allow ".local" top level domain
		if (asciiDomainName.toLowerCase().endsWith(".local")) {
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

	public static InternetAddress[] getEmailAddressesFromList(final String listString) throws Exception {
		final List<InternetAddress> emailAddresses = new ArrayList<>();

		if (Utilities.isNotBlank(listString)) {
			for (String address : splitAndNormalizeEmails(listString)) {
				address = address == null ? "" : Utilities.trim(address);
				if (Utilities.isNotBlank(address) && MailUtilities.isEmailValid(address)) {
					try {
						final InternetAddress nextAddress = new InternetAddress(address.trim());
						nextAddress.validate();
						emailAddresses.add(nextAddress);
					} catch (final AddressException e) {
						throw new Exception("Invalid Emailaddress found: " + address, e);
					}
				}
			}
		}

		return emailAddresses.toArray(new InternetAddress[0]);
	}

	public static Set<String> splitAndNormalizeEmails(final String emails) {
		if (Utilities.isBlank(emails)) {
			return Collections.emptySet();
		}

		final Set<String> addresses = new LinkedHashSet<>();

		for (final String part : emails.split(";|,| ")) {
			final String address = normalizeEmail(part);

			if (Utilities.isNotEmpty(address)) {
				addresses.add(address);
			}
		}

		return addresses;
	}

	/**
	 * Call lowercase and trim on email address. Watch out: apostrophe and other
	 * special characters !#$%&'*+-/=?^_`{|}~ are allowed in local parts of
	 * emailaddresses
	 *
	 * @param email
	 * @return
	 */
	public static String normalizeEmail(final String email) {
		if (Utilities.isBlank(email)) {
			return null;
		} else {
			return email.toLowerCase().trim();
		}
	}

	/**
	 * Try to open an email in the standard email client
	 *
	 * @param toAdress
	 * @param subject
	 * @param body
	 * @return
	 */
	public static boolean openMailInStandardClient(final String toAdress, final String subject, final String body) {
		return openMailInStandardClient(toAdress, null, null, subject, body);
	}

	/**
	 * Try to open an email in the standard email client
	 *
	 * @param toAdress
	 * @param ccAdress
	 * @param subject
	 * @param body
	 * @return
	 */
	public static boolean openMailInStandardClient(final String toAdress, final String ccAdress, final String bccAdress, final String subject, final String body) {
		try {
			final String mailtoString = createMailtoLink(toAdress, ccAdress, bccAdress, subject, body);

			if (SystemUtilities.isWindowsSystem()) {
				if (Desktop.isDesktopSupported()) {
					final Desktop desktop = Desktop.getDesktop();
					if (desktop.isSupported(Desktop.Action.MAIL)) {
						desktop.mail(new URI(mailtoString));
						return true;
					}
				}

				try {
					if (Program.launch(mailtoString)) {
						return true;
					}
				} catch (@SuppressWarnings("unused") final Exception e) {
					// Try some other method of mail creation
				}
			} else {
				try {
					Runtime.getRuntime().exec("xdg-open " + mailtoString);
					return true;
				} catch (@SuppressWarnings("unused") final Exception e) {
					// Try some other method of mail creation
				}

				try {
					// For using the parameters check the following description
					// http://kb.mozillazine.org/Command_line_arguments_%28Thunderbird%29
					Runtime.getRuntime().exec("thunderbird -compose");
					if (Program.launch(mailtoString)) {
						return true;
					}
				} catch (@SuppressWarnings("unused") final Exception e) {
					// Try some other method of mail creation
				}
			}

			throw new Exception("Cannot create mail in standard mailclient");
		} catch (final Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static String createMailtoLink(final String toAdress, final String ccAdress, final String bccAdress, final String subject, final String body) throws Exception {
		if (Utilities.isBlank(toAdress)) {
			throw new Exception("TO address is missing or empty");
		}

		String mailtoString = "mailto:" + HttpUtilities.urlEncode(toAdress, StandardCharsets.UTF_8);

		boolean isFirstParameter = true;

		if (Utilities.isNotBlank(bccAdress)) {
			if (isFirstParameter) {
				mailtoString += "?";
			} else {
				mailtoString += "&";
			}
			mailtoString += "bcc=" + HttpUtilities.urlEncode(bccAdress, StandardCharsets.UTF_8);
			isFirstParameter = false;
		}

		if (Utilities.isNotBlank(ccAdress)) {
			if (isFirstParameter) {
				mailtoString += "?";
			} else {
				mailtoString += "&";
			}
			mailtoString += "cc=" + HttpUtilities.urlEncode(ccAdress, StandardCharsets.UTF_8);
			isFirstParameter = false;
		}

		if (Utilities.isNotBlank(subject)) {
			if (isFirstParameter) {
				mailtoString += "?";
			} else {
				mailtoString += "&";
			}
			mailtoString += "subject=" + HttpUtilities.urlEncode(subject, StandardCharsets.UTF_8).replace("+", "%20");
			isFirstParameter = false;
		}

		if (Utilities.isNotBlank(body)) {
			if (isFirstParameter) {
				mailtoString += "?";
			} else {
				mailtoString += "&";
			}
			mailtoString += "body=" + HttpUtilities.urlEncode(body, StandardCharsets.UTF_8).replace("+", "%20");
			isFirstParameter = false;
		}
		// + (attachmentFile != null ? "&attachment=" + urlEncode(attachmentFile.getAbsolutePath(), StandardCharsets.UTF_8) : ""); // maybe it is "&attach="

		return mailtoString;
	}
}
