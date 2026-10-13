package de.soderer.mailer;

/**
 * Transport security of the connection to the SMTP server.
 */
public enum MailerConnectionSecurity {
	/**
	 * Unencrypted connection.
	 */
	None,
	/**
	 * Plain connection that is upgraded to TLS with the STARTTLS command (the upgrade is required).
	 */
	STARTTLS,
	/**
	 * Connection that is encrypted with SSL/TLS right from the start (implicit TLS, SMTPS).
	 */
	SSL_TLS;

	/**
	 * Get the connection security by its name, ignoring case and underscores (e.g. "ssltls" for {@link #SSL_TLS}).
	 *
	 * @param mailerConnectionSecurityString name of the connection security
	 * @return the matching connection security
	 * @throws Exception if the name is null or unknown
	 */
	public static MailerConnectionSecurity getMailerConnectionSecurityByName(final String mailerConnectionSecurityString) throws Exception {
		if (mailerConnectionSecurityString != null) {
			for (final MailerConnectionSecurity mailerConnectionSecurity : MailerConnectionSecurity.values()) {
				if (mailerConnectionSecurity.name().replace("_", "").equalsIgnoreCase(mailerConnectionSecurityString.replace("_", ""))) {
					return mailerConnectionSecurity;
				}
			}
		}
		throw new Exception("Unknown MailerConnectionSecurity: '" + mailerConnectionSecurityString + "'");
	}
}
