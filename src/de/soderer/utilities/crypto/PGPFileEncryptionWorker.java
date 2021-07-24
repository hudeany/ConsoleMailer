package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import de.soderer.utilities.Utilities;
import de.soderer.utilities.crypto.PGPUtilities.PgpSymmetricEncryptionMethod;
import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.worker.WorkerSimple;

/**
 * May need installed "US_export_policy.jar" and "local_policy.jar" for unlimited key strength Download: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
 */
public class PGPFileEncryptionWorker extends WorkerSimple<Boolean> {
	private InputStream dataToEncrypt = null;
	private OutputStream encryptedData = null;
	private PGPPublicKey publicKey = null;
	private boolean useIntegrityPacket = true;
	private PgpSymmetricEncryptionMethod pgpSymmetricEncryptionMethod = PgpSymmetricEncryptionMethod.AES_256;

	public boolean isUseIntegrityPacket() {
		return useIntegrityPacket;
	}

	public PGPFileEncryptionWorker setUseIntegrityPacket(final boolean useIntegrityPacket) {
		this.useIntegrityPacket = useIntegrityPacket;
		return this;
	}

	public PGPFileEncryptionWorker(final WorkerParentSimple parent, final InputStream dataToEncrypt, final OutputStream encryptedData, final PGPPublicKey publicKey) {
		super(parent);
		this.dataToEncrypt = dataToEncrypt;
		this.encryptedData = encryptedData;
		this.publicKey = publicKey;
	}

	public PGPFileEncryptionWorker setPgpSymmetricEncryptionMethod(final String pgpSymmetricEncryptionMethod) throws Exception {
		this.pgpSymmetricEncryptionMethod = PgpSymmetricEncryptionMethod.getByName(pgpSymmetricEncryptionMethod);
		return this;
	}

	public PGPFileEncryptionWorker setPgpSymmetricEncryptionMethod(final PgpSymmetricEncryptionMethod pgpSymmetricEncryptionMethod) {
		this.pgpSymmetricEncryptionMethod = pgpSymmetricEncryptionMethod;
		return this;
	}

	public PgpSymmetricEncryptionMethod getPgpSymmetricEncryptionMethod() {
		return pgpSymmetricEncryptionMethod;
	}

	@SuppressWarnings("resource")
	@Override
	public Boolean work() throws Exception {
		showProgress();

		final boolean armor = true;

		PGPEncryptedDataGenerator encryptedDataGenerator = null;
		OutputStream encryptedDataGeneratorStream = null;
		PGPCompressedDataGenerator compressedDataGenerator = null;
		OutputStream compressedDataGeneratorStream = null;
		PGPLiteralDataGenerator literalDataGenerator = null;
		OutputStream literalDataGeneratorStream = null;
		try {
			itemsToDo = dataToEncrypt.available();

			Security.addProvider(new BouncyCastleProvider());

			dataToEncrypt = new BufferedInputStream(dataToEncrypt);

			if (armor) {
				encryptedData = new ArmoredOutputStream(encryptedData);
			}

			final JcePGPDataEncryptorBuilder builder = new JcePGPDataEncryptorBuilder(pgpSymmetricEncryptionMethod.getId()).setWithIntegrityPacket(useIntegrityPacket);
			encryptedDataGenerator = new PGPEncryptedDataGenerator(builder);
			final JcePublicKeyKeyEncryptionMethodGenerator encryptionMethodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(publicKey);
			encryptedDataGenerator.addMethod(encryptionMethodGenerator);
			encryptedDataGeneratorStream = encryptedDataGenerator.open(encryptedData, new byte[4096]);

			compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
			compressedDataGeneratorStream = compressedDataGenerator.open(encryptedDataGeneratorStream);

			literalDataGenerator = new PGPLiteralDataGenerator();
			literalDataGeneratorStream = literalDataGenerator.open(compressedDataGeneratorStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, dataToEncrypt.available(), new Date());

			final byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = dataToEncrypt.read(buffer)) >= 0) {
				if (cancel) {
					break;
				} else {
					literalDataGeneratorStream.write(buffer, 0, bytesRead);

					itemsDone += bytesRead;
					showProgress();
				}
			}

			literalDataGenerator.close();
			compressedDataGenerator.close();
			encryptedDataGenerator.close();

			return true;
		} catch (final Exception e) {
			throw new Exception("Error while encrypting", e);
		} finally {
			if (literalDataGenerator != null) {
				literalDataGenerator.close();
			}
			if (compressedDataGenerator != null) {
				compressedDataGenerator.close();
			}
			if (encryptedDataGenerator != null) {
				encryptedDataGenerator.close();
			}
			Utilities.closeQuietly(literalDataGeneratorStream);
			Utilities.closeQuietly(compressedDataGeneratorStream);
			Utilities.closeQuietly(encryptedDataGeneratorStream);
			if (armor) {
				Utilities.closeQuietly(encryptedData);
			}
		}
	}
}
