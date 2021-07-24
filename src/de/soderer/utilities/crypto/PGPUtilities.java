package de.soderer.utilities.crypto;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import de.soderer.utilities.LangResources;
import de.soderer.utilities.TextUtilities;
import de.soderer.utilities.UserError;
import de.soderer.utilities.Utilities;

public class PGPUtilities {
	public static final String DEFAULT_SYMMETRIC_ENCRYPTION_METHOD = "AES-256";

	/**
	 * Fermat prime number: F4 = 65537
	 */
	public static final BigInteger FERMAT_PRIME_F4 = BigInteger.valueOf(0x10001);

	public enum PgpSymmetricEncryptionMethod {
		IDEA(SymmetricKeyAlgorithmTags.IDEA),
		TRIPLE_DES(SymmetricKeyAlgorithmTags.TRIPLE_DES),
		CAST5(SymmetricKeyAlgorithmTags.CAST5),
		BLOWFISH(SymmetricKeyAlgorithmTags.BLOWFISH),
		SAFER(SymmetricKeyAlgorithmTags.SAFER),
		DES(SymmetricKeyAlgorithmTags.DES),
		AES_128(SymmetricKeyAlgorithmTags.AES_128),
		AES_192(SymmetricKeyAlgorithmTags.AES_192),
		AES_256(SymmetricKeyAlgorithmTags.AES_256),
		TWOFISH(SymmetricKeyAlgorithmTags.TWOFISH);

		private final int id;

		PgpSymmetricEncryptionMethod(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static String[] names() {
			final String[] names = new String[PgpSymmetricEncryptionMethod.values().length];
			for (int i = 0; i < PgpSymmetricEncryptionMethod.values().length; i++) {
				names[i] = PgpSymmetricEncryptionMethod.values()[i].name();
			}
			return names;
		}

		public static PgpSymmetricEncryptionMethod getByName(final String methodName) throws Exception {
			final String searchMethodName = methodName.replace("-", "").replace("_", "");
			for (final PgpSymmetricEncryptionMethod encryptionMethod : PgpSymmetricEncryptionMethod.values()) {
				if (encryptionMethod.toString().replace("-", "").replace("_", "").equalsIgnoreCase(searchMethodName)) {
					return encryptionMethod;
				}
			}
			throw new Exception("Invalid PgpEncryptionMethod name: " + methodName);
		}

		public static PgpSymmetricEncryptionMethod getById(final int id) throws Exception {
			for (final PgpSymmetricEncryptionMethod encryptionMethod : PgpSymmetricEncryptionMethod.values()) {
				if (encryptionMethod.getId() == id) {
					return encryptionMethod;
				}
			}
			throw new Exception("Invalid PgpEncryptionMethod id: " + id);
		}
	}

	public static final String DEFAULT_PUBLIC_ENCRYPTION_METHOD = "RSA-GENERAL";

	public enum PgpPublicEncryptionMethod {
		RSA_GENERAL(PublicKeyAlgorithmTags.RSA_GENERAL),
		RSA_ENCRYPT(PublicKeyAlgorithmTags.RSA_ENCRYPT),
		RSA_SIGN(PublicKeyAlgorithmTags.RSA_SIGN),

		ELGAMAL_GENERAL(PublicKeyAlgorithmTags.ELGAMAL_GENERAL),
		ELGAMAL_ENCRYPT(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT),

		DSA(PublicKeyAlgorithmTags.DSA),
		/**
		 * @Deprecated use ECDH
		 */
		@SuppressWarnings("deprecation")
		EC(PublicKeyAlgorithmTags.EC),
		ECDH(PublicKeyAlgorithmTags.ECDH),
		ECDSA(PublicKeyAlgorithmTags.ECDSA),
		DIFFIE_HELLMAN(PublicKeyAlgorithmTags.DIFFIE_HELLMAN);

		private final int id;

		PgpPublicEncryptionMethod(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static String[] names() {
			final String[] names = new String[PgpPublicEncryptionMethod.values().length];
			for (int i = 0; i < PgpPublicEncryptionMethod.values().length; i++) {
				names[i] = PgpPublicEncryptionMethod.values()[i].name();
			}
			return names;
		}

		public static PgpPublicEncryptionMethod getByName(final String methodName) throws Exception {
			final String searchMethodName = methodName.replace("-", "").replace("_", "");
			for (final PgpPublicEncryptionMethod encryptionMethod : PgpPublicEncryptionMethod.values()) {
				if (encryptionMethod.toString().replace("-", "").replace("_", "").equalsIgnoreCase(searchMethodName)) {
					return encryptionMethod;
				}
			}
			throw new Exception("Invalid PgpPublicEncryptionMethod name: " + methodName);
		}

		public static PgpPublicEncryptionMethod getById(final int id) throws Exception {
			for (final PgpPublicEncryptionMethod encryptionMethod : PgpPublicEncryptionMethod.values()) {
				if (encryptionMethod.getId() == id) {
					return encryptionMethod;
				}
			}
			throw new Exception("Invalid PgpPublicEncryptionMethod id: " + id);
		}
	}

	public static final String DEFAULT_HASHING_METHOD = "SHA256";

	public enum PgpHashMethod {
		MD5(HashAlgorithmTags.MD5),
		SHA1(HashAlgorithmTags.SHA1),
		RIPEMD160(HashAlgorithmTags.RIPEMD160),
		DOUBLE_SHA(HashAlgorithmTags.DOUBLE_SHA),
		MD2(HashAlgorithmTags.MD2),
		TIGER_192(HashAlgorithmTags.TIGER_192),
		HAVAL_5_160(HashAlgorithmTags.HAVAL_5_160),
		SHA256(HashAlgorithmTags.SHA256),
		SHA384(HashAlgorithmTags.SHA384),
		SHA512(HashAlgorithmTags.SHA512),
		SHA224(HashAlgorithmTags.SHA224);

		private final int id;

		PgpHashMethod(final int id) {
			this.id = id;
		}

		public int getId() {
			return id;
		}

		public static String[] names() {
			final String[] names = new String[PgpHashMethod.values().length];
			for (int i = 0; i < PgpHashMethod.values().length; i++) {
				names[i] = PgpHashMethod.values()[i].name();
			}
			return names;
		}

		public static PgpHashMethod getByName(final String methodName) throws Exception {
			final String searchMethodName = methodName.replace("-", "").replace("_", "");
			for (final PgpHashMethod encryptionMethod : PgpHashMethod.values()) {
				if (encryptionMethod.toString().replace("-", "").replace("_", "").equalsIgnoreCase(searchMethodName)) {
					return encryptionMethod;
				}
			}
			throw new Exception("Invalid PgpHashMethod name: " + methodName);
		}

		public static PgpHashMethod getById(final int id) throws Exception {
			for (final PgpHashMethod encryptionMethod : PgpHashMethod.values()) {
				if (encryptionMethod.getId() == id) {
					return encryptionMethod;
				}
			}
			throw new Exception("Invalid PgpHashMethod id: " + id);
		}
	}

	public static PGPSecretKey generatePGPSecretKey(final int keyStrength, final PgpPublicEncryptionMethod keyType, final String identity, final char[] password, final Date validity) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PGPKeyPair masterKeyPair;
		PGPKeyPair subKeyPair = null;
		if (keyType == PgpPublicEncryptionMethod.RSA_GENERAL
				|| keyType == PgpPublicEncryptionMethod.RSA_ENCRYPT
				|| keyType == PgpPublicEncryptionMethod.RSA_SIGN) {
			masterKeyPair = new JcaPGPKeyPair(keyType.getId(), CryptographicUtilities.generateRsaKeyPair(keyStrength), new Date());
		} else if (keyType == PgpPublicEncryptionMethod.ELGAMAL_GENERAL
				|| keyType == PgpPublicEncryptionMethod.ELGAMAL_ENCRYPT) {
			masterKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.DSA, CryptographicUtilities.generateDsaKeyPair(keyStrength), new Date());
			subKeyPair = new JcaPGPKeyPair(PgpPublicEncryptionMethod.ELGAMAL_GENERAL.getId(), CryptographicUtilities.generateElGamalKeyPair(keyStrength), new Date());
		} else if (keyType == PgpPublicEncryptionMethod.DSA) {
			masterKeyPair = new JcaPGPKeyPair(keyType.getId(), CryptographicUtilities.generateDsaKeyPair(keyStrength), new Date());
		} else {
			throw new Exception("Unsupported keytype: " + keyType.name());
		}

		final PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

		// Add signed metadata on the signature.
		// Declare its purpose
		subpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
		// Set preferences for secondary crypto algorithms to use when sending messages to this key.
		subpacketGenerator.setPreferredSymmetricAlgorithms
		(false, new int[] {
				SymmetricKeyAlgorithmTags.AES_256,
				SymmetricKeyAlgorithmTags.AES_192,
				SymmetricKeyAlgorithmTags.AES_128
		});
		subpacketGenerator.setPreferredHashAlgorithms
		(false, new int[] {
				HashAlgorithmTags.SHA256,
				HashAlgorithmTags.SHA1,
				HashAlgorithmTags.SHA384,
				HashAlgorithmTags.SHA512,
				HashAlgorithmTags.SHA224,
		});
		// Request senders add additional checksums to the message (useful when verifying unsigned messages.)
		subpacketGenerator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

		final long secondsUntilExpiration = (validity.getTime() - new Date().getTime()) / 1000L + 1;
		subpacketGenerator.setKeyExpirationTime(true, secondsUntilExpiration);

		subpacketGenerator.addNotationData(false, true, "identity", identity);

		// Objects used to encrypt the secret key
		final JcaPGPDigestCalculatorProviderBuilder builder = new JcaPGPDigestCalculatorProviderBuilder();
		final PGPDigestCalculatorProvider pgpDigestCalculatorProvider = builder.build();

		final PGPDigestCalculator sha1Calc = pgpDigestCalculatorProvider.get(HashAlgorithmTags.SHA1);
		final PGPDigestCalculator sha256Calc = pgpDigestCalculatorProvider.get(HashAlgorithmTags.SHA256);

		final PBESecretKeyEncryptor pbeSecretKeyEncryptor = (new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha256Calc, 0xc0)).build(password);

		final PGPKeyRingGenerator pgpKeyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, masterKeyPair, identity, sha1Calc, subpacketGenerator.generate(), null, new JcaPGPContentSignerBuilder(masterKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pbeSecretKeyEncryptor);
		if (subKeyPair != null) {
			pgpKeyRingGenerator.addSubKey(subKeyPair);
		}

		final PGPSecretKeyRing pgpSecretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();

		final Iterator<PGPSecretKey> secretKeys = pgpSecretKeyRing.getSecretKeys();
		PGPSecretKey secretKey = null;
		while (secretKeys.hasNext()) {
			// if available only export the subkey. For ElGamal this is the wanted key, but it cannot be used for signatures
			secretKey = secretKeys.next();
		}
		return secretKey;
	}

	public static PGPSecretKey generateDualKeyPGPSecretKey(final int keyStrength, final String identity, final char[] password, final Date validity) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final KeyPair keyPair1 = CryptographicUtilities.generateRsaKeyPair(keyStrength);
		final KeyPair keyPair2 = CryptographicUtilities.generateRsaKeyPair(keyStrength);

		// First create the master (signing) key with the generator.
		final PGPKeyPair rsakp_sign = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN, keyPair1, new Date());
		// Then an encryption subkey.
		final PGPKeyPair rsakp_enc = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_ENCRYPT, keyPair2, new Date());

		// Add a self-signature on the id
		final PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

		// Add signed metadata on the signature.
		// 1) Declare its purpose
		subpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
		// 2) Set preferences for secondary crypto algorithms to use when sending messages to this key.
		subpacketGenerator.setPreferredSymmetricAlgorithms
		(false, new int[] {
				SymmetricKeyAlgorithmTags.AES_256,
				SymmetricKeyAlgorithmTags.AES_192,
				SymmetricKeyAlgorithmTags.AES_128
		});
		subpacketGenerator.setPreferredHashAlgorithms
		(false, new int[] {
				HashAlgorithmTags.SHA256,
				HashAlgorithmTags.SHA1,
				HashAlgorithmTags.SHA384,
				HashAlgorithmTags.SHA512,
				HashAlgorithmTags.SHA224,
		});
		// 3) Request senders add additional checksums to the message (useful when verifying unsigned messages.)
		subpacketGenerator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

		final long secondsUntilExpiration = (validity.getTime() - new Date().getTime()) / 1000L + 1;
		subpacketGenerator.setKeyExpirationTime(true, secondsUntilExpiration);

		subpacketGenerator.addNotationData(true, true, "identity", identity);

		// Create a signature on the encryption subkey
		final PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
		// Add metadata to declare its purpose
		enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

		// Objects used to encrypt the secret key
		final JcaPGPDigestCalculatorProviderBuilder builder = new JcaPGPDigestCalculatorProviderBuilder();
		final PGPDigestCalculatorProvider pgpDigestCalculatorProvider = builder.build();
		final PGPDigestCalculator sha1Calc = pgpDigestCalculatorProvider.get(HashAlgorithmTags.SHA1);
		final PGPDigestCalculator sha256Calc = pgpDigestCalculatorProvider.get(HashAlgorithmTags.SHA256);

		// bcpg 1.48 exposes this API that includes s2kcount. Earlier versions use a default of 0x60.
		final PBESecretKeyEncryptor pske = (new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha256Calc, 0xc0)).build(password);

		// Finally, create the keyring itself. The constructor takes parameters that allow it to generate the self signature.
		final PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign, identity, sha1Calc, subpacketGenerator.generate(), null, new JcaPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pske);

		// Add our encryption subkey, together with its signature.
		keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null);

		final PGPSecretKeyRing skr = keyRingGen.generateSecretKeyRing();

		final Iterator<PGPSecretKey> secretKeys = skr.getSecretKeys();
		PGPSecretKey secretKey = null;
		while (secretKeys.hasNext()) {
			secretKey = secretKeys.next();
		}
		return secretKey;
	}

	public static byte[] exportPGPSecretKey(final PGPSecretKey pgpSecretKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (ByteArrayOutputStream secretKeyStream = new ByteArrayOutputStream()) {
			try (OutputStream outputStream = new ArmoredOutputStream(secretKeyStream)) {
				pgpSecretKey.encode(outputStream);
			}
			return secretKeyStream.toByteArray();
		} catch (final Exception e) {
			throw new Exception("Cannot export PGP key", e);
		}
	}

	public static byte[] exportPGPPublicKey(final PGPPublicKey pgpPublicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (ByteArrayOutputStream secretKeyStream = new ByteArrayOutputStream()) {
			try (OutputStream outputStream = new ArmoredOutputStream(secretKeyStream)) {
				pgpPublicKey.encode(outputStream);
			}
			return secretKeyStream.toByteArray();
		} catch (final Exception e) {
			throw new Exception("Cannot export PGP key", e);
		}
	}

	public static PGPPublicKey readPGPPublicKey(final InputStream inputStream) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (InputStream decoderStream = PGPUtil.getDecoderStream(new PGPKeyStorageStringSplitter(inputStream).getPublicKeyInputStream())) {
			final PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
			@SuppressWarnings("rawtypes")
			final
			Iterator keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
			while (keyRingIterator.hasNext()) {
				final PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIterator.next();
				@SuppressWarnings("rawtypes")
				final
				Iterator publicKeyIterator = keyRing.getPublicKeys();
				while (publicKeyIterator.hasNext()) {
					final PGPPublicKey nextPGPPublicKey = (PGPPublicKey) publicKeyIterator.next();
					if (nextPGPPublicKey.isEncryptionKey()) {
						return nextPGPPublicKey;
					}
				}
			}

			// key not found
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static PGPSecretKey readPGPSecretKey(final InputStream inputStream) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (InputStream decoderStream = PGPUtil.getDecoderStream(new PGPKeyStorageStringSplitter(inputStream).getPrivateKeyInputStream())) {
			final PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(decoderStream, new JcaKeyFingerprintCalculator());
			@SuppressWarnings("rawtypes")
			final
			Iterator keyRingIterator = pgpSecretKeyRingCollection.getKeyRings();
			while (keyRingIterator.hasNext()) {
				final PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIterator.next();
				@SuppressWarnings("rawtypes")
				final
				Iterator privateKeyIterator = keyRing.getSecretKeys();
				while (privateKeyIterator.hasNext()) {
					final PGPSecretKey nextPGPSecretKey = (PGPSecretKey) privateKeyIterator.next();
					if (nextPGPSecretKey.isMasterKey()) {
						return nextPGPSecretKey;
					}
				}
			}

			// key not found
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static PGPPrivateKey readPGPPrivateKey(final PGPSecretKey secretKey, final char[] password) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			if (secretKey == null) {
				return null;
			} else {
				final PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().build(password);
				return secretKey.extractPrivateKey(decryptor);
			}
		} catch (final PGPException e) {
			if (e.getUnderlyingException() != null && e.getUnderlyingException().getMessage().contains("Illegal key size")) {
				throw new UserError("keystrengthExceedsAllowedJCE", e);
			} else {
				throw new UserError("cannotReadPrivateKey", e);
			}
		} catch (final Exception e) {
			throw new UserError("cannotReadPrivateKey", e);
		}
	}

	public static PGPPublicKey readPGPPublicKey(final PGPSecretKey pgpSecretKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		if (pgpSecretKey == null) {
			return null;
		} else {
			return pgpSecretKey.getPublicKey();
		}
	}

	public static PGPPublicKey signPublicKey(final PGPSecretKey pgpSecretKey, final char[] password, final PGPPublicKey publicKeyToBeSigned) throws Exception {
		return signPublicKey(pgpSecretKey, password, publicKeyToBeSigned, null);
	}

	public static PGPPublicKey signPublicKey(final PGPSecretKey pgpSecretKey, final char[] password, final PGPPublicKey publicKeyToBeSigned, final Map<String, String> notationData) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PGPPrivateKey pgpPrivKey = readPGPPrivateKey(pgpSecretKey, password);
		final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PgpPublicEncryptionMethod.RSA_GENERAL.getId(), PgpHashMethod.getByName(DEFAULT_HASHING_METHOD).getId()));
		signatureGenerator.init(PGPSignature.DIRECT_KEY, pgpPrivKey);

		if (notationData == null) {
			final PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
			pgpSignatureSubpacketGenerator.addNotationData(true, true, "identity", PGPUtilities.getIdentityFromPgpPublicKey(pgpSecretKey.getPublicKey()));
			final PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
			signatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
		} else if (!notationData.isEmpty()) {
			final PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
			for (final Entry<String, String> notation : notationData.entrySet()) {
				pgpSignatureSubpacketGenerator.addNotationData(true, true, notation.getKey(), notation.getValue());
				final PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
				signatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
			}
		}

		final PGPSignature certification = signatureGenerator.generateCertification(publicKeyToBeSigned);
		return PGPPublicKey.addCertification(publicKeyToBeSigned, certification);
	}

	public static PGPPublicKey signPublicKey(final PGPPrivateKey pgpPrivKey, final PGPPublicKey pgpPublicKey, final PGPPublicKey publicKeyToBeSigned) throws Exception {
		return signPublicKey(pgpPrivKey, pgpPublicKey, publicKeyToBeSigned, null);
	}

	public static PGPPublicKey signPublicKey(final PGPPrivateKey pgpPrivKey, final PGPPublicKey pgpPublicKey, final PGPPublicKey publicKeyToBeSigned, final Map<String, String> notationData) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PgpPublicEncryptionMethod.RSA_GENERAL.getId(), PgpHashMethod.getByName(DEFAULT_HASHING_METHOD).getId()));
		signatureGenerator.init(PGPSignature.DIRECT_KEY, pgpPrivKey);

		if (notationData == null) {
			final PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
			pgpSignatureSubpacketGenerator.addNotationData(true, true, "identity", PGPUtilities.getIdentityFromPgpPublicKey(pgpPublicKey));
			final PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
			signatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
		} else if (!notationData.isEmpty()) {
			final PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
			for (final Entry<String, String> notation : notationData.entrySet()) {
				pgpSignatureSubpacketGenerator.addNotationData(true, true, notation.getKey(), notation.getValue());
				final PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
				signatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
			}
		}

		final PGPSignature certification = signatureGenerator.generateCertification(publicKeyToBeSigned);
		return PGPPublicKey.addCertification(publicKeyToBeSigned, certification);
	}

	public static String getIdentityFromPgpPublicKey(final PGPPublicKey publicKey) {
		Security.addProvider(new BouncyCastleProvider());

		final StringBuilder identities = new StringBuilder();
		final Iterator<String> userIdentities = publicKey.getUserIDs();
		while (userIdentities.hasNext()) {
			if (identities.length() > 0) {
				identities.append(", ");
			}
			identities.append(userIdentities.next());
		}
		return identities.toString();
	}

	public static List<Map<String, Object>> getKeySigners(final PGPPublicKey publicKey) {
		Security.addProvider(new BouncyCastleProvider());

		final List<Map<String, Object>> signersData = new ArrayList<>();
		final Iterator<?> signerIterator = publicKey.getSignatures();
		while (signerIterator.hasNext()) {
			final Map<String, Object> signatureData = new HashMap<>();
			final PGPSignature signature = (PGPSignature) signerIterator.next();

			final long id = signature.getKeyID();
			signatureData.put("id", id);

			// time = signature.getHashedSubPackets().getSignatureCreationTime();
			signatureData.put("creationtime", signature.getCreationTime());

			String encryptionAlgorithm;
			try {
				encryptionAlgorithm = PgpPublicEncryptionMethod.getById(signature.getKeyAlgorithm()).name();
			} catch (@SuppressWarnings("unused") final Exception e1) {
				encryptionAlgorithm = LangResources.get("Unknown");
			}
			signatureData.put("encryptionalgorithm", encryptionAlgorithm);

			String hashingAlgorithm;
			try {
				hashingAlgorithm = PgpHashMethod.getById(signature.getHashAlgorithm()).name();
			} catch (@SuppressWarnings("unused") final Exception e1) {
				hashingAlgorithm = LangResources.get("Unknown");
			}
			signatureData.put("hashingalgorithm", hashingAlgorithm);

			String identity = "";
			final NotationData[] notationData = signature.getHashedSubPackets().getNotationDataOccurrences();
			for (int i = 0; i < notationData.length; i++) {
				if (identity.length() > 0) {
					identity += ", ";
				}
				if (notationData.length > 1 || Utilities.isBlank(notationData[i].getNotationValue())) {
					identity += notationData[i].getNotationName() + ": ";
				}
				identity += notationData[i].getNotationValue();
			}
			if (id == publicKey.getKeyID()) {
				if (Utilities.isNotBlank(identity)) {
					identity += " ";
				}
				identity += "(Selfsigned)";
			}
			if (Utilities.isBlank(identity)) {
				identity = LangResources.get("Unknown");
			}

			signatureData.put("identity", identity);

			signersData.add(signatureData);
		}

		return signersData;
	}

	public static List<String> getSignerKeyIDs(final PGPPublicKey publicKey) {
		Security.addProvider(new BouncyCastleProvider());

		final List<String> signatureIDs = new ArrayList<>();
		final Iterator<?> signerIterator = publicKey.getSignatures();
		while (signerIterator.hasNext()) {
			final PGPSignature signature = (PGPSignature) signerIterator.next();
			final long id = signature.getKeyID();
			signatureIDs.add(Long.toHexString(id).toUpperCase());
		}
		return signatureIDs;
	}

	public static String removeVersionFromArmoredData(final String armoredData) {
		return TextUtilities.removeLinesContainingText(armoredData, "Version: ");
	}
}
