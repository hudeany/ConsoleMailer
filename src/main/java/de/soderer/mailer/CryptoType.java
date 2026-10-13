package de.soderer.mailer;

/**
 * Cryptographic standard used to sign and/or encrypt an email.
 */
public enum CryptoType {
	/**
	 * S/MIME with X.509 certificates.
	 */
	S_MIME,
	/**
	 * OpenPGP (PGP/MIME) with PGP keys.
	 */
	PGP
}
