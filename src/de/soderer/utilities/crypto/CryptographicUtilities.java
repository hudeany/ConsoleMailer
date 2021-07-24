package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ThreadLocalRandom;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.soderer.utilities.BitUtilities;
import de.soderer.utilities.DateUtilities;
import de.soderer.utilities.FileUtilities;
import de.soderer.utilities.IoUtilities;
import de.soderer.utilities.Utilities;

/**
 * May need installed "US_export_policy.jar" and "local_policy.jar" for unlimited key strength Download: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
 */
public class CryptographicUtilities {
	public static byte[] DEFAULT_SALT = new byte[] { 48, 57, 56, 107, 108, 102, 114, 113, 54, 64, 108, 107 };
	public static byte[] DEFAULT_SYMMETRIC_INITALIZATION_VECTOR = new byte[] { 48, 57, 56, 107, 108, 102, 114, 113, 54, 64, 108, 107, 48, 57, 56, 107 };

	public static final String[] SYMMETRIC_CIPHERS = {
			// Block chiffre
			"AES", "AESWrap", "Blowfish	", "Camellia", "CamelliaWrap", "CAST5", "CAST6", "DES", "DESede", "TripleDES", "3DES", "DESedeWrap", "GOST28147", "IDEA", "Noekeon", "RC2", "RC5", "RC5-64", "RC6", "Rijndael",
			"SEED", "SEEDWrap", "Serpent", "Skipjack", "TEA", "Twofish", "XTEA",

			// Stream chiffre
			"RC4", "HC128", "HC256", "Salsa20", "VMPC", "Grainv1", "Grain128" };

	public static String DEFAULT_SYMMETRIC_ENCRYPTION_METHOD = "AES/CBC/PKCS7Padding";
	public static final String[] KNOWN_SYMMETRIC_ENCRYPTION_METHODS = new String[] { DEFAULT_SYMMETRIC_ENCRYPTION_METHOD, "DES/CBC/PKCS5Padding", "DES/CBC/X9.23Padding", "DES/OFB8/NoPadding",
			"DES/ECB/WithCTS", "IDEA/CBC/ISO10126Padding", "IDEA/CBC/ISO7816-4Padding", "SKIPJACK/ECB/PKCS7Padding" };

	public static String DEFAULT_SIGNATURE_METHOD = "SHA256WithRSA";
	public static final String[] KNOWN_SIGNATURE_METHODS = new String[] { DEFAULT_SIGNATURE_METHOD, "DSTU4145", "GOST3411withGOST3410", "GOST3411withGOST3410-94", "GOST3411withECGOST3410",
			"GOST3411withGOST3410-2001", "MD2withRSA", "MD5withRSA", "SHA1withRSA", "RIPEMD128withRSA", "RIPEMD160withRSA", "RIPEMD160withECDSA", "RIPEMD256withRSA", "SHA1withDSA", "NONEwithDSA",
			"SHA1withECDSA", "NONEwithECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA256withRSA", "SHA384withECDSA", "SHA512withECDSA", "SHA1withECNR", "SHA224withECNR", "SHA256withECNR", "SHA384withECNR",
			"SHA512withECNR", "SHA224withRSA", "SHA384withRSA", "SHA512withRSA", "SHA1withRSAandMGF1", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1" };

	public static final String[] ASYMMETRIC_CIPHERS = new String[] { "RSA", "ElGamal" };
	public static String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD = "RSA/ECB/PKCS1Padding";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_RSA = new String[] {
			"RSA/NONE/PKCS1Padding",
			"RSA/NONE/OAEPPadding",
			"RSA/NONE/NoPadding",
			"RSA/NONE/PKCS1Padding",
			"RSA/NONE/OAEPWithMD5AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA1AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA224AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA256AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA384AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA512AndMGF1Padding",
			"RSA/NONE/ISO9796-1Padding"
	};

	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_ELGAMAL = new String[] {
			"ELGAMAL/NONE/NoPadding",
			"ELGAMAL/NONE/PKCS1PADDING",
	};

	public static KeyPair generateRsaKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateDsaKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateDhKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateEcDsaKeyPair(final String ecCurveName) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
			final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecCurveName);
			keyGen.initialize(ecGenParameterSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create ECDSA keypair", e);
		}
	}

	public static KeyPair generateElGamalKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static X509Certificate generateRsaCertificate(final KeyPair keyPair, final String issuerName, final Date validFrom, final Date validUntil) throws Exception {
		return generateRsaCertificate(keyPair, issuerName, validFrom, validUntil, DEFAULT_SIGNATURE_METHOD);
	}

	public static X509Certificate generateRsaCertificate(final KeyPair keyPair, final String issuerName, final Date validFrom, final Date validUntil, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
			builder.addRDN(BCStyle.CN, issuerName);
			final X500Name x500Name = builder.build();

			final ContentSigner sigGen = new JcaContentSignerBuilder(signatureMethod).build(keyPair.getPrivate());
			final X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(x500Name, BigInteger.ONE, validFrom, validUntil, x500Name, keyPair.getPublic());
			return new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA certificate", e);
		}
	}

	public static X509Certificate generateRsaCertificate(final AsymmetricCipherKeyPair keyPair, final String issuerName, final Date validFrom, final Date validUntil) throws Exception {
		return generateRsaCertificate(keyPair, issuerName, validFrom, validUntil, DEFAULT_SIGNATURE_METHOD);
	}

	public static X509Certificate generateRsaCertificate(final AsymmetricCipherKeyPair keyPair, final String issuerName, final Date validFrom, final Date validUntil, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
			builder.addRDN(BCStyle.CN, issuerName);
			final X500Name x500Name = builder.build();

			final ContentSigner sigGen = new JcaContentSignerBuilder(signatureMethod).build(getPrivateKeyFromAsymmetricCipherKeyPair(keyPair));
			final X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(x500Name, BigInteger.ONE, validFrom, validUntil, x500Name, getPublicKeyFromAsymmetricCipherKeyPair(keyPair));
			return new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA certificate", e);
		}
	}

	public static String getStringFromX509Certificate(final X509Certificate certificate) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (StringWriter stringWriter = new StringWriter();
				JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(certificate);
			pemWriter.close();
			return stringWriter.toString();
		} catch (final Exception e) {
			throw new Exception("Cannot create certificate string: " + e.getMessage(), e);
		}
	}

	public static void encryptAsymmetric(final InputStream dataStream, final OutputStream encryptedOutputStream, final PublicKey publicKey) throws Exception {
		encryptAsymmetric(dataStream, encryptedOutputStream, publicKey, DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD);
	}

	public static void encryptAsymmetric(final InputStream dataStream, final OutputStream encryptedOutputStream, final PublicKey publicKey, String encryptionMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			if (Utilities.isBlank(encryptionMethod)) {
				throw new Exception("Empty asymmetric encryption method");
			}
			encryptionMethod = encryptionMethod.toLowerCase();
			AsymmetricBlockCipher encryptCipher;
			if (encryptionMethod.startsWith("rsa")) {
				encryptCipher = new RSAEngine();
			} else if (encryptionMethod.startsWith("elgamal")) {
				encryptCipher = new ElGamalEngine();
			} else {
				throw new Exception("Unknown asymmetric encryption cipher method: " + encryptionMethod);
			}
			if (encryptionMethod.contains("pkcs1")) {
				encryptCipher = new PKCS1Encoding(encryptCipher);
			} else if (encryptionMethod.contains("oaep")) {
				encryptCipher = new OAEPEncoding(encryptCipher);
			} else if (encryptionMethod.contains("iso9796")) {
				encryptCipher = new ISO9796d1Encoding(encryptCipher);
			} else if (encryptionMethod.contains("nopadding")) {
				// do no padding
			} else {
				throw new Exception("Unknown asymmetric encryption padding method: " + encryptionMethod);
			}
			encryptCipher.init(true, PublicKeyFactory.createKey(publicKey.getEncoded()));

			final byte[] buffer = new byte[encryptCipher.getInputBlockSize()];
			int readBytes;
			while ((readBytes = dataStream.read(buffer)) > -1) {
				encryptedOutputStream.write(encryptCipher.processBlock(buffer, 0, readBytes));
			}
		} catch (final Exception e) {
			throw new Exception("Error while encrypting: " + e.getMessage(), e);
		}
	}

	public static void decryptAsymmetric(final InputStream encryptedDataStream, final OutputStream dataOutputStream, final PrivateKey privateKey) throws Exception {
		decryptAsymmetric(encryptedDataStream, dataOutputStream, privateKey, DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD);
	}

	public static void decryptAsymmetric(final InputStream encryptedDataStream, final OutputStream dataOutputStream, final PrivateKey privateKey, String encryptionMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			if (encryptionMethod == null || "".equals(encryptionMethod.trim())) {
				throw new Exception("Empty asymmetric encryption method");
			}
			encryptionMethod = encryptionMethod.toLowerCase();
			AsymmetricBlockCipher decryptCipher;
			if (encryptionMethod.startsWith("rsa")) {
				decryptCipher = new RSAEngine();
			} else if (encryptionMethod.startsWith("elgamal")) {
				decryptCipher = new ElGamalEngine();
			} else {
				throw new Exception("Unknown asymmetric encryption cipher method: " + encryptionMethod);
			}
			if (encryptionMethod.contains("pkcs1")) {
				decryptCipher = new PKCS1Encoding(decryptCipher);
			} else if (encryptionMethod.contains("oaep")) {
				decryptCipher = new OAEPEncoding(decryptCipher);
			} else if (encryptionMethod.contains("iso9796")) {
				decryptCipher = new ISO9796d1Encoding(decryptCipher);
			} else if (encryptionMethod.contains("nopadding")) {
				// do no padding
			} else {
				throw new Exception("Unknown asymmetric encryption padding method: " + encryptionMethod);
			}

			decryptCipher.init(false, PrivateKeyFactory.createKey(privateKey.getEncoded()));

			final byte[] buffer = new byte[decryptCipher.getInputBlockSize()];
			int readBytes;
			while ((readBytes = encryptedDataStream.read(buffer)) > -1) {
				dataOutputStream.write(decryptCipher.processBlock(buffer, 0, readBytes));
			}
		} catch (final Exception e) {
			throw new Exception("Error while encrypting: " + e.getMessage(), e);
		}
	}

	public static String getStringFromKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		final PublicKey publicKey = getPublicKeyFromAsymmetricCipherKeyPair(keyPair);
		final PrivateKey privateKey = getPrivateKeyFromAsymmetricCipherKeyPair(keyPair);

		return getStringFromKeyPair(privateKey, publicKey);
	}

	public static String getStringFromKeyPair(final KeyPair keyPair) throws Exception {
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		return getStringFromKeyPair(privateKey, publicKey);
	}

	public static String getStringFromKeyPair(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (StringWriter stringWriter = new StringWriter();
				JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(privateKey);
			pemWriter.writeObject(publicKey);
			pemWriter.close();
			return stringWriter.toString();
		} catch (final Exception e) {
			throw new Exception("Cannot create key string: " + e.getMessage(), e);
		}
	}

	public static AsymmetricCipherKeyPair getAsymmetricCipherKeyPair(final InputStream inputStream) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(IoUtilities.toString(inputStream, StandardCharsets.UTF_8));
		AsymmetricKeyParameter privateAsymmetricKeyParameter;
		if (keyPair.getPrivateKeyInfo() != null) {
			privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		} else {
			privateAsymmetricKeyParameter = null;
		}
		final AsymmetricKeyParameter publicAsymmetricKeyParameter;
		if (keyPair.getPublicKeyInfo() != null) {
			publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());
		} else {
			publicAsymmetricKeyParameter = null;
		}

		return new AsymmetricCipherKeyPair(publicAsymmetricKeyParameter, privateAsymmetricKeyParameter);
	}

	public static KeyPair getKeyPair(final InputStream inputStream) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(IoUtilities.toString(inputStream, StandardCharsets.UTF_8));
		AsymmetricKeyParameter privateAsymmetricKeyParameter;
		if (keyPair.getPrivateKeyInfo() != null) {
			privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		} else {
			privateAsymmetricKeyParameter = null;
		}
		final AsymmetricKeyParameter publicAsymmetricKeyParameter;
		if (keyPair.getPublicKeyInfo() != null) {
			publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());
		} else {
			publicAsymmetricKeyParameter = null;
		}

		final AsymmetricCipherKeyPair asymmetricCipherKeyPair = new AsymmetricCipherKeyPair(publicAsymmetricKeyParameter, privateAsymmetricKeyParameter);

		return new KeyPair(getPublicKeyFromAsymmetricCipherKeyPair(asymmetricCipherKeyPair), getPrivateKeyFromAsymmetricCipherKeyPair(asymmetricCipherKeyPair));
	}

	/**
	 * not tested yet
	 */
	public static KeyPair getKeyPairFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair asymmetricCipherKeyPair) throws Exception {
		final byte[] pkcs8Encoded = PrivateKeyInfoFactory.createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate()).getEncoded();
		final PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8Encoded);
		final byte[] spkiEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic()).getEncoded();
		final X509EncodedKeySpec spkiKeySpec = new X509EncodedKeySpec(spkiEncoded);
		final KeyFactory keyFac = KeyFactory.getInstance("RSA");
		return new KeyPair(keyFac.generatePublic(spkiKeySpec), keyFac.generatePrivate(pkcs8KeySpec));
	}

	public static AsymmetricCipherKeyPair getAsymmetricCipherKeyPair(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(getStringFromKeyPair(privateKey, publicKey));
		final AsymmetricKeyParameter privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		final AsymmetricKeyParameter publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());

		return new AsymmetricCipherKeyPair(privateAsymmetricKeyParameter, publicAsymmetricKeyParameter);
	}

	public static PublicKey getPublicKeyFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
	}

	public static PublicKey getPublicKeyFromKeyPair(final KeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
	}

	public static PrivateKey getPrivateKeyFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
		final BigInteger exponent = ((RSAPrivateCrtKeyParameters) keyPair.getPrivate()).getExponent();
		//		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		//		BigInteger exponent = publicKey.getExponent();
		return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(privateKey.getModulus(), exponent, privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
				privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
	}

	/**
	 * Generates Private Key from BASE64 encoded string
	 */
	public static PEMKeyPair getPEMKeyPairFromString(final String keyString) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (PEMParser pemReader = new PEMParser(new StringReader(keyString))) {
			final Object readObject = pemReader.readObject();
			pemReader.close();
			//			if (readObject instanceof PEMEncryptedKeyPair) {
			//                PEMEncryptedKeyPair pemEncryptedKeyPairKeyPair = (PEMEncryptedKeyPair) readObject;
			//                JcePEMDecryptorProviderBuilder jcePEMDecryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();
			//                PEMKeyPair pemKeyPair = pemEncryptedKeyPairKeyPair.decryptKeyPair(jcePEMDecryptorProviderBuilder.build(keyPassword.toCharArray()));
			//            } else
			if (readObject instanceof PEMKeyPair) {
				final PEMKeyPair keyPair = (PEMKeyPair) readObject;
				return keyPair;
			} else if (readObject instanceof PrivateKeyInfo) {
				final PEMKeyPair keyPair = new PEMKeyPair(null, (PrivateKeyInfo) readObject);
				return keyPair;
			} else {
				return null;
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read private key", e);
		}
	}

	/**
	 * Generates X509Certificate from BASE64 encoded string
	 */
	public static X509Certificate getCertificateFromString(final String certificateString) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (PEMParser pemReader = new PEMParser(new StringReader(certificateString))) {
			final Object readObject = pemReader.readObject();
			pemReader.close();
			if (readObject instanceof X509Certificate) {
				return (X509Certificate) readObject;
			} else if (readObject instanceof X509CertificateHolder) {
				return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) readObject);
			} else {
				return null;
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read certificate", e);
		}
	}

	/**
	 * Read a certificate file
	 */
	public static X509Certificate getCertificateFromFile(final File certificateFile) throws Exception {
		final String certificateFileString = FileUtilities.readFileToString(certificateFile, StandardCharsets.UTF_8);
		return getCertificateFromString(certificateFileString);
	}

	public static void encryptSymmetric(final InputStream dataStream, final OutputStream encryptedOutputStream, final char[] password) throws Exception {
		encryptSymmetric(dataStream, encryptedOutputStream, password, DEFAULT_SALT, DEFAULT_SYMMETRIC_INITALIZATION_VECTOR, DEFAULT_SYMMETRIC_ENCRYPTION_METHOD);
	}

	public static void encryptSymmetric(final InputStream dataStream, final OutputStream encryptedOutputStream, final char[] password, final byte[] salt, final byte[] initializationVector, String encryptionMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			if ("TripleDES".equalsIgnoreCase(encryptionMethod) || "3DES".equalsIgnoreCase(encryptionMethod)) {
				encryptionMethod = "DESede";
			}

			final byte[] keyBytes = stretchPassword(password, 128, salt);
			final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
			final Cipher encryptCipher = Cipher.getInstance(encryptionMethod, BouncyCastleProvider.PROVIDER_NAME);
			encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(initializationVector));
			try (CipherOutputStream cipherOutputStream = new CipherOutputStream(encryptedOutputStream, encryptCipher)) {
				IoUtilities.copy(dataStream, cipherOutputStream);
			}
		} catch (final Exception e) {
			throw new Exception("Error while encrypting: " + e.getMessage(), e);
		}
	}

	public static void decryptSymmetric(final InputStream encryptedDataStream, final OutputStream dataOutputStream, final char[] password) throws Exception {
		decryptSymmetric(encryptedDataStream, dataOutputStream, password, DEFAULT_SALT, DEFAULT_SYMMETRIC_INITALIZATION_VECTOR, DEFAULT_SYMMETRIC_ENCRYPTION_METHOD);
	}

	public static void decryptSymmetric(final InputStream encryptedDataStream, final OutputStream dataOutputStream, final char[] password, final byte[] salt, final byte[] initializationVector, final String encryptionMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final byte[] keyBytes = stretchPassword(password, 128, salt);
			final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
			final Cipher decryptCipher = Cipher.getInstance(encryptionMethod, BouncyCastleProvider.PROVIDER_NAME);
			decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(initializationVector));
			try (CipherInputStream cipherInputStream = new CipherInputStream(encryptedDataStream, decryptCipher)) {
				IoUtilities.copy(cipherInputStream, dataOutputStream);
			}
		} catch (final Exception e) {
			throw new Exception("Error while decrypting: " + e.getMessage(), e);
		}
	}

	public static byte[] stretchPassword(final char[] password, final int keyLength, final byte[] salt) {
		Security.addProvider(new BouncyCastleProvider());

		final PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
		generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, 1000);
		final KeyParameter params = (KeyParameter) generator.generateDerivedParameters(keyLength);
		return params.getKey();
	}

	public static byte[] signData(final byte[] data, final PrivateKey privateKey) throws Exception {
		return signData(data, privateKey, DEFAULT_SIGNATURE_METHOD);
	}

	public static byte[] signData(final byte[] data, final PrivateKey privateKey, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final Signature signature = Signature.getInstance(signatureMethod, BouncyCastleProvider.PROVIDER_NAME);
			signature.initSign(privateKey);
			signature.update(data);
			return signature.sign();
		} catch (final Exception e) {
			throw new Exception("Cannot create signature", e);
		}
	}

	public static byte[] signStream(final InputStream dataStream, final PrivateKey privateKey) throws Exception {
		return signStream(dataStream, privateKey, DEFAULT_SIGNATURE_METHOD);
	}

	public static byte[] signStream(final InputStream dataStream, final PrivateKey privateKey, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final Signature signature = Signature.getInstance(signatureMethod, BouncyCastleProvider.PROVIDER_NAME);
			signature.initSign(privateKey);
			final byte[] buffer = new byte[4096];
			int bytesRead = dataStream.read(buffer);
			while (bytesRead >= 0) {
				signature.update(buffer, 0, bytesRead);
				bytesRead = dataStream.read(buffer);
			}
			return signature.sign();
		} catch (final Exception e) {
			throw new Exception("Cannot create signature", e);
		}
	}

	public static boolean verifyData(final byte[] data, final PublicKey publicKey, final byte[] signatureData) throws Exception {
		return verifyData(data, publicKey, signatureData, DEFAULT_SIGNATURE_METHOD);
	}

	public static boolean verifyData(final byte[] data, final PublicKey publicKey, final byte[] signatureData, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final Signature signature = Signature.getInstance(signatureMethod, BouncyCastleProvider.PROVIDER_NAME);
			signature.initVerify(publicKey);
			signature.update(data);
			return signature.verify(signatureData);
		} catch (final Exception e) {
			throw new Exception("Cannot verify signature", e);
		}
	}

	public static boolean verifyStream(final InputStream dataStream, final PublicKey publicKey, final byte[] signatureData) throws Exception {
		return verifyStream(dataStream, publicKey, signatureData, DEFAULT_SIGNATURE_METHOD);
	}

	public static boolean verifyStream(final InputStream dataStream, final PublicKey publicKey, final byte[] signatureData, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final Signature signature = Signature.getInstance(signatureMethod, BouncyCastleProvider.PROVIDER_NAME);
			signature.initVerify(publicKey);
			final byte[] buffer = new byte[4096];
			int bytesRead = dataStream.read(buffer);
			while (bytesRead >= 0) {
				signature.update(buffer, 0, bytesRead);
				bytesRead = dataStream.read(buffer);
			}
			return signature.verify(signatureData);
		} catch (final Exception e) {
			throw new Exception("Cannot verify signature", e);
		}
	}

	public static void otpWork(final byte[][] immutableData, final byte[][] mutableData) {
		for (int i = 0; i < mutableData.length - 1; i++) {
			Utilities.getRandomByteArray(mutableData[i]);
		}
		final byte[] lastArray = mutableData[mutableData.length - 1];
		for (int i = 0; i < immutableData[0].length; i++) {
			lastArray[i] = 0;
			for (final byte[] element : immutableData) {
				lastArray[i] = (byte) (lastArray[i] ^ element[i]);
			}
			for (int j = 0; j < mutableData.length - 1; j++) {
				lastArray[i] = (byte) (lastArray[i] ^ mutableData[j][i]);
			}
		}
	}

	public static Set<String> getJarSignatureNames(final File jarFile) throws Exception {
		final Set<String> returnData = new HashSet<>();
		try (JarFile jar = new JarFile(jarFile)) {
			final Manifest manifest = jar.getManifest();
			if (manifest == null) {
				returnData.add("Has no MANIFEST.MF file");
				return returnData;
			}

			final byte[] buffer = new byte[4096];
			final Enumeration<JarEntry> jarEntriesEnumerator = jar.entries();
			final List<JarEntry> jarEntries = new ArrayList<>();

			while (jarEntriesEnumerator.hasMoreElements()) {
				final JarEntry jarEntry = jarEntriesEnumerator.nextElement();
				jarEntries.add(jarEntry);

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry)) {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// just read it
					}
				}
			}

			for (final JarEntry jarEntry : jarEntries) {
				if (!jarEntry.isDirectory()) {
					// Every file must be signed, except for files in META-INF
					final Certificate[] certs = jarEntry.getCertificates();
					if ((certs == null) || (certs.length == 0)) {
						if (!jarEntry.getName().startsWith("META-INF")) {
							returnData.add("Contains unsigned files");
						}
					} else {
						for (final Certificate cert : certs) {
							if (cert instanceof X509Certificate) {
								final X509Certificate certificate = (X509Certificate) cert;
								if (certificate.getBasicConstraints() == -1) {
									// Certificate is not a CA certificate
									returnData.add(getCnFromCertificate(certificate));
								} else {
									// Certificate is a CA certificate
									returnData.add("CA: " + getCnFromCertificate(certificate));
								}
							} else {
								returnData.add("Unknown type of certificate");
							}
						}
					}
				}
			}

			return returnData;
		}
	}

	public static boolean verifyJarSignature(final File jarFile, final Collection<? extends Certificate> trustedCerts) throws Exception {
		if (trustedCerts == null || trustedCerts.size() == 0) {
			return false;
		}

		try (JarFile jar = new JarFile(jarFile)) {
			final Manifest manifest = jar.getManifest();
			if (manifest == null) {
				throw new SecurityException("The jar file has no manifest, which contains the file signatures");
			}

			final byte[] buffer = new byte[4096];
			final Enumeration<JarEntry> jarEntriesEnumerator = jar.entries();
			final List<JarEntry> jarEntries = new ArrayList<>();

			while (jarEntriesEnumerator.hasMoreElements()) {
				final JarEntry jarEntry = jarEntriesEnumerator.nextElement();
				jarEntries.add(jarEntry);

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry)) {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// just read it
					}
				}
			}

			for (final JarEntry jarEntry : jarEntries) {
				if (!jarEntry.isDirectory()) {
					// Every file must be signed, except for files in META-INF
					final Certificate[] certs = jarEntry.getCertificates();
					if ((certs == null) || (certs.length == 0)) {
						if (!jarEntry.getName().startsWith("META-INF")) {
							throw new SecurityException("The jar file contains unsigned files.");
						}
					} else {
						boolean isSignedByTrustedCert = false;

						for (final Certificate chainRootCertificate : certs) {
							if (chainRootCertificate instanceof X509Certificate && verifyChainOfTrust((X509Certificate) chainRootCertificate, trustedCerts)) {
								isSignedByTrustedCert = true;
								break;
							}
						}

						if (!isSignedByTrustedCert) {
							throw new SecurityException("The jar file contains untrusted signed files");
						}
					}
				}
			}

			return true;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	public static boolean verifyChainOfTrust(final X509Certificate cert, final Collection<? extends Certificate> trustedCerts) throws Exception {
		final CertPathBuilder certifier = CertPathBuilder.getInstance("PKIX");
		final X509CertSelector targetConstraints = new X509CertSelector();
		targetConstraints.setCertificate(cert);

		final Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (final Certificate trustedRootCert : trustedCerts) {
			trustAnchors.add(new TrustAnchor((X509Certificate) trustedRootCert, null));
		}

		final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetConstraints);
		params.setRevocationEnabled(false);
		try {
			final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) certifier.build(params);
			return result != null;
		} catch (@SuppressWarnings("unused") final Exception cpbe) {
			return false;
		}
	}

	public static X509Certificate[] getChainRootCertificates(final Certificate[] certs) {
		final Vector<X509Certificate> result = new Vector<>();
		for (int i = 0; i < certs.length - 1; i++) {
			if (!((X509Certificate) certs[i + 1]).getSubjectDN().equals(((X509Certificate) certs[i]).getIssuerDN())) {
				result.addElement((X509Certificate) certs[i]);
			}
		}
		// The final entry in the certs array is always a root certificate
		result.addElement((X509Certificate) certs[certs.length - 1]);
		final X509Certificate[] returnValue = new X509Certificate[result.size()];
		result.copyInto(returnValue);
		return returnValue;
	}

	public static X509Certificate[] loadCertificatesFromPemFile(final File pemFile) throws Exception {
		try (PEMParser pemReader = new PEMParser(new FileReader(pemFile))) {
			final List<X509Certificate> certificateList = new ArrayList<>();
			Object readObject;
			while ((readObject = pemReader.readObject()) != null) {
				if (readObject instanceof X509Certificate) {
					certificateList.add((X509Certificate) readObject);
				} else if (readObject instanceof X509CertificateHolder) {
					certificateList.add(new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) readObject));
				} else {
					throw new Exception("Unknown certificate type");
				}
			}
			return certificateList.toArray(new X509Certificate[0]);
		}
	}

	public static Collection<? extends Certificate> loadCertificatesFromPemStream(final InputStream pemInputStream) throws Exception {
		return CertificateFactory.getInstance("X.509").generateCertificates(new BufferedInputStream(pemInputStream));

		//		Security.addProvider(new BouncyCastleProvider());
		//
		//		try (PEMParser pemReader = new PEMParser(new InputStreamReader(pemInputStream))) {
		//			List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
		//			Object pemReaderObject;
		//			while ((pemReaderObject = pemReader.readObject()) != null) {
		//				if (pemReaderObject instanceof X509Certificate) {
		//					// Old BouncyCastle API
		//					certificateList.add((X509Certificate) pemReaderObject);
		//				} else if (pemReaderObject instanceof X509CertificateHolder) {
		//					X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) pemReaderObject);
		//					certificateList.add(certificate);
		//				}
		//			}
		//			return certificateList.toArray(new X509Certificate[0]);
		//		}
	}

	public static String getCnFromCertificate(final X509Certificate certificate) throws InvalidNameException {
		final Principal principal = certificate.getSubjectDN();
		final String dn = principal.getName();
		final LdapName ln = new LdapName(dn);

		for (final Rdn rdn : ln.getRdns()) {
			if ("CN".equalsIgnoreCase(rdn.getType())) {
				return (String) rdn.getValue();
			}
		}

		return null;
	}

	public static boolean checkForCaCertificate(final X509Certificate certificate) {
		return certificate.getBasicConstraints() != 1;
	}

	public static String getMd5FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha1FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha256FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(certificate.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getMd5FingerPrint(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha1FingerPrint(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static String getSha256FingerPrint(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(key.getEncoded());
		return BitUtilities.toHexString(md.digest());
	}

	public static int getKeySize(final X509Certificate certificate) {
		final RSAKey rsaKey = (RSAKey) certificate.getPublicKey();
		return rsaKey.getModulus().bitLength();
	}

	public static KeyPair convertPEMKeyPairToKeyPair(final PEMKeyPair keyPair) throws PEMException {
		try {
			String algorithm = keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm().getAlgorithm().getId();
			if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm)) {
				algorithm = "ECDSA";
			}

			final KeyFactory keyFactory = new DefaultJcaJceHelper().createKeyFactory(algorithm);

			return new KeyPair(
					keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublicKeyInfo().getEncoded())),
					keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivateKeyInfo().getEncoded())));
		} catch (final Exception e) {
			throw new PEMException("Unable to convert key pair: " + e.getMessage(), e);
		}
	}

	public static RSAPrivateKey getRsaPrivateKeyFromString(final String key) throws Exception {
		try {
			Security.addProvider(new BouncyCastleProvider());

			String privateKeyPEM = key.trim();
			final String pemRsaBegin = "-----BEGIN RSA PRIVATE KEY-----";
			final String pemRsaEnd = "-----END RSA PRIVATE KEY-----";

			final String pemBegin = "-----BEGIN PRIVATE KEY-----";
			final String pemEnd = "-----END PRIVATE KEY-----";

			if (privateKeyPEM.contains(pemRsaBegin) && privateKeyPEM.contains(pemRsaEnd) && privateKeyPEM.indexOf(pemRsaBegin) < privateKeyPEM.indexOf(pemRsaEnd)) {
				privateKeyPEM = privateKeyPEM.substring(privateKeyPEM.indexOf(pemRsaBegin) + pemRsaBegin.length(), privateKeyPEM.indexOf(pemRsaEnd)).trim();
			} else if (privateKeyPEM.contains(pemBegin) && privateKeyPEM.contains(pemEnd) && privateKeyPEM.indexOf(pemBegin) < privateKeyPEM.indexOf(pemEnd)) {
				privateKeyPEM = privateKeyPEM.substring(privateKeyPEM.indexOf(pemBegin) + pemBegin.length(), privateKeyPEM.indexOf(pemEnd)).trim();
			}

			privateKeyPEM = privateKeyPEM.replace("\r", "").replace("\n", "");
			final byte[] privateKeyData = Base64.getDecoder().decode(privateKeyPEM);
			final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyData));
			return (RSAPrivateKey) privateKey;
		} catch (final Exception e) {
			throw new Exception("Cannot read private key", e);
		}
	}

	public static PrivateKey getPrivateKeyFromString(final String key, final char[] password) throws Exception {
		try {
			Security.addProvider(new BouncyCastleProvider());

			final PEMParser pemParser = new PEMParser(new StringReader(key));
			final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			final Object object = pemParser.readObject();
			if (password == null) {
				if (object instanceof PEMEncryptedKeyPair) {
					throw new Exception("Encrypted private key found. Password is needed.");
				} else {
					final KeyPair keyPair = converter.getKeyPair((PEMKeyPair) object);
					return keyPair.getPrivate();
				}
			} else {
				if (!(object instanceof PEMEncryptedKeyPair)) {
					throw new Exception("Unencrypted private key found. Password is obsolete.");
				} else {
					final PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);
					final KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
					return keyPair.getPrivate();
				}
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read private key", e);
		}
	}

	public static String getX509CertificateInfo(final X509Certificate certificate) throws Exception {
		String dataOutput = "";
		dataOutput += "CN: " + CryptographicUtilities.getCnFromCertificate(certificate);
		dataOutput += "\n";
		dataOutput += "Subject: " + certificate.getSubjectDN();
		dataOutput += "\n";
		dataOutput += "Issuer: " + certificate.getIssuerDN();
		dataOutput += "\n";
		dataOutput += "is CA-certificate: " + (CryptographicUtilities.checkForCaCertificate(certificate) ? "true" : "false");
		dataOutput += "\n";
		dataOutput += "Valid from: " + new SimpleDateFormat(DateUtilities.YYYY_MM_DD_HHMMSS).format(certificate.getNotBefore());
		dataOutput += "\n";
		dataOutput += "Valid until: " + new SimpleDateFormat(DateUtilities.YYYY_MM_DD_HHMMSS).format(certificate.getNotAfter());
		dataOutput += "\n";
		dataOutput += "Signature algorithm: " + certificate.getSigAlgName();
		dataOutput += "\n";
		dataOutput += "Type: " + certificate.getType();
		dataOutput += "\n";
		dataOutput += "Version: " + certificate.getVersion();
		dataOutput += "\n";
		dataOutput += "Serial: " + certificate.getSerialNumber();
		dataOutput += "\n";
		dataOutput += "Key length: " + CryptographicUtilities.getKeySize(certificate);
		dataOutput += "\n";
		dataOutput += "MD5 fingerprint: " + CryptographicUtilities.getMd5FingerPrint(certificate);
		dataOutput += "\n";
		dataOutput += "SHA1 fingerprint: " + CryptographicUtilities.getSha1FingerPrint(certificate);
		dataOutput += "\n";
		dataOutput += "SHA256 fingerprint: " + CryptographicUtilities.getSha256FingerPrint(certificate);
		dataOutput += "\n";
		return dataOutput;
	}

	public static String getKeyInfo(final Key key) {
		String dataOutput = "";
		dataOutput += "Algorithm: " + key.getAlgorithm();
		dataOutput += "\n";

		if (key instanceof RSAKey) {
			dataOutput += "Key length: " + ((RSAKey) key).getModulus().bitLength();
			dataOutput += "\n";
		}

		try {
			dataOutput += "MD5 fingerprint: " + CryptographicUtilities.getMd5FingerPrint(key);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "MD5 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA1 fingerprint: " + CryptographicUtilities.getSha1FingerPrint(key);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA1 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA256 fingerprint: " + CryptographicUtilities.getSha256FingerPrint(key);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA256 fingerprint: Unknown";
		}
		dataOutput += "\n";

		return dataOutput;
	}

	public static Certificate generateSelfsignedCertificate(final KeyPair keyPair, final int validityInDays, final String signatureAlgorithm, final String subjectDN) throws OperatorCreationException, CertificateException, IOException {
		final Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		final long now = System.currentTimeMillis();
		final Date startDate = new Date(now);
		final X500Name dnName = new X500Name(subjectDN);
		final BigInteger certSerialNumber = new BigInteger(Long.toString(now));
		final Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.DAY_OF_YEAR, validityInDays);
		final Date endDate = calendar.getTime();
		final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
		final JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());
		final BasicConstraints basicConstraints = new BasicConstraints(true);
		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
		return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}

	public static boolean checkPrivateKeyFitsPublicKey(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		final byte[] challenge = new byte[1024];
		ThreadLocalRandom.current().nextBytes(challenge);

		final Signature challengeSignature = Signature.getInstance("SHA512withRSA");
		challengeSignature.initSign(privateKey);
		challengeSignature.update(challenge);
		final byte[] signature = challengeSignature.sign();

		challengeSignature.initVerify(publicKey);
		challengeSignature.update(challenge);

		return challengeSignature.verify(signature);
	}

	public static String checkSignatureMethodName(final String signatureMethodName) {
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		return null;
	}

	public static ASN1ObjectIdentifier getASN1ObjectIdentifierByEncryptionMethodName(final String encryptionMethodName) {
		try {
			for (final Field field : CMSAlgorithm.class.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) && field.getName().replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(encryptionMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
					return (ASN1ObjectIdentifier) field.get(encryptionMethodName);
				}
			}
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static String checkEncryptionMethodName(final String encryptionMethodName) {
		try {
			for (final Field field : CMSAlgorithm.class.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) && field.getName().replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(encryptionMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
					return encryptionMethodName;
				}
			}
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	// TODO: Read TLS CA Cert (CA Chain file with multiple CA Certs)
	// TODO: Read TLS Key Cert
}
