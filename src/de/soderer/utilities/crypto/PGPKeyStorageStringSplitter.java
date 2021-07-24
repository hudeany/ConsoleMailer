package de.soderer.utilities.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import de.soderer.utilities.IoUtilities;

public class PGPKeyStorageStringSplitter {
	private static final String PUBLIC_KEY_START = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
	private static final String PUBLIC_KEY_END = "-----END PGP PUBLIC KEY BLOCK-----";
	private static final String PRIVATE_KEY_START = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
	private static final String PRIVATE_KEY_END = "-----END PGP PRIVATE KEY BLOCK-----";

	private final byte[] keyStorageData;
	private String publicKeyStorageString = null;
	private String privateKeyStorageString = null;

	public InputStream getPublicKeyInputStream() throws Exception {
		if (publicKeyStorageString != null) {
			return new ByteArrayInputStream(publicKeyStorageString.getBytes(StandardCharsets.UTF_8));
		} else {
			return new ByteArrayInputStream(keyStorageData);
		}
	}

	public InputStream getPrivateKeyInputStream() throws Exception {
		if (privateKeyStorageString != null) {
			return new ByteArrayInputStream(privateKeyStorageString.getBytes(StandardCharsets.UTF_8));
		} else {
			return new ByteArrayInputStream(keyStorageData);
		}
	}

	public PGPKeyStorageStringSplitter(final InputStream inputStream) throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		IoUtilities.copy(inputStream, outputStream);
		keyStorageData = outputStream.toByteArray();
		final String keyStorageString = new String(outputStream.toByteArray(), StandardCharsets.UTF_8);

		if (keyStorageString.contains(PUBLIC_KEY_START) && keyStorageString.contains(PUBLIC_KEY_END)) {
			publicKeyStorageString = keyStorageString.substring(keyStorageString.indexOf(PUBLIC_KEY_START), keyStorageString.lastIndexOf(PUBLIC_KEY_END) + PUBLIC_KEY_END.length());
		}

		if (keyStorageString.contains(PRIVATE_KEY_START) && keyStorageString.contains(PRIVATE_KEY_END)) {
			privateKeyStorageString = keyStorageString.substring(keyStorageString.indexOf(PRIVATE_KEY_START), keyStorageString.lastIndexOf(PRIVATE_KEY_END) + PRIVATE_KEY_END.length());
		}

		inputStream.close();
	}
}
