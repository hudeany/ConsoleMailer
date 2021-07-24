package de.soderer.utilities;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import de.soderer.utilities.UserError.Reason;
import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.xml.XmlUtilities;

public class ApplicationUpdateHelper implements WorkerParentSimple {
	private final String applicationName;
	private final Version applicationVersion;
	private final String versionIndexFileLocation;
	private final UpdateParent updateParent;
	private FileDownloadWorker fileDownloadWorker;
	private String updateFileLocation;
	private String updateFileMd5Checksum = null;
	private final String restartParameter;
	private String trustedCaCertificateFileName = null;
	private String username;
	private char[] password;

	/**
	 * @param versionIndexFileLocation
	 *            may include placeholders:<br />
	 *            &lt;system> : replaced by "windows" or "linux"<br />
	 *            &lt;bitmode> : replaced by "32" or "64"<br />
	 *            &lt;username> : interactive username dialog<br />
	 *            &lt;password> : interactive password dialog
	 *            &lt;time_seconds> : current timestamp in seconds (used by sourceforge.net)
	 * @throws Exception
	 */
	public ApplicationUpdateHelper(final String applicationName, final String applicationVersion, final String versionIndexFileLocation, final UpdateParent updateParent, final String restartParameter, final String trustedCaCertificateFileName) throws Exception {
		if (Utilities.isEmpty(versionIndexFileLocation)) {
			throw new Exception("Invalid version index location");
		}

		this.applicationName = applicationName;
		this.applicationVersion = new Version(applicationVersion);
		this.versionIndexFileLocation = replacePlaceholders(versionIndexFileLocation);
		this.updateParent = updateParent;
		this.restartParameter = restartParameter;
		this.trustedCaCertificateFileName = trustedCaCertificateFileName;
	}

	public void executeUpdate() {
		final String newVersionAvailable = checkForNewVersionAvailable();
		if (askForUpdate(newVersionAvailable)) {
			updateApplication();
		}
	}

	private String checkForNewVersionAvailable() {
		try {
			if (!NetworkUtilities.checkForNetworkConnection()) {
				throw new Exception("error.missingNetworkConnection");
			} else if (!NetworkUtilities.ping(versionIndexFileLocation)) {
				throw new Exception("error.missingInternetConnection");
			}

			Document versionsDocument = null;
			if (versionIndexFileLocation.toLowerCase().startsWith("http")) {
				versionsDocument = XmlUtilities.downloadAndParseXmlFile(versionIndexFileLocation);
			} else if (new File(versionIndexFileLocation).exists()) {
				versionsDocument = XmlUtilities.parseXmlFile(new File(versionIndexFileLocation));
			}

			if (versionsDocument == null) {
				throw new Exception("Version index not found at location '" + versionIndexFileLocation + "'");
			}

			final Node startFileNameNode = XmlUtilities.getSingleXPathNode(versionsDocument, "ApplicationVersions/" + applicationName);
			if (startFileNameNode == null) {
				throw new Exception("error.cannotFindUpdateVersionData");
			}
			final Node versionNode = startFileNameNode.getAttributes().getNamedItem("version");
			final String version = versionNode.getNodeValue();

			final Node md5ChecksumNode = startFileNameNode.getAttributes().getNamedItem("md5CheckSum");
			if (md5ChecksumNode != null) {
				updateFileMd5Checksum = md5ChecksumNode.getNodeValue();
			}

			updateFileLocation = startFileNameNode.getFirstChild().getNodeValue();

			final Version availableVersion = new Version(version);
			if (applicationVersion.compareTo(availableVersion) < 0 && updateFileLocation != null && updateFileLocation.trim().length() > 0) {
				updateFileLocation = replacePlaceholders(updateFileLocation);
				return version;
			} else {
				updateFileLocation = null;
				return null;
			}
		} catch (final Exception e) {
			showUpdateError("Update error while checking for new version:\n" + e.getMessage());
			return null;
		}
	}

	private boolean askForUpdate(final String availableNewVersion) {
		if (updateParent != null) {
			try {
				return updateParent.askForUpdate(availableNewVersion);
			} catch (final Exception e) {
				updateParent.showUpdateError("Update error :\n" + e.getMessage());
				return false;
			}
		} else {
			return false;
		}
	}

	private void updateApplication() {
		try {
			String jarFilePath = System.getProperty(SystemUtilities.SYSTEM_PARAMETER_NAME_CURRENT_RUNNING_JAR);

			if (jarFilePath == null) {
				jarFilePath = System.getenv(SystemUtilities.SYSTEM_PARAMETER_NAME_CURRENT_RUNNING_JAR);
			}

			if (jarFilePath == null) {
				try {
					final String currentJarUrlPath = getClass().getResource(getClass().getSimpleName() + ".class").toString();
					jarFilePath = currentJarUrlPath.substring(0, currentJarUrlPath.lastIndexOf("!")).replaceFirst("jar:file:", "");
				} catch (@SuppressWarnings("unused") final Exception e) {
					jarFilePath = null;
				}
			}

			jarFilePath = Utilities.replaceUsersHome(jarFilePath);

			if (jarFilePath == null || !new File(jarFilePath).exists()) {
				throw new Exception("Current running jar file was not found");
			}

			final File downloadTempFile = new File(new File(jarFilePath).getParent() + File.separator + "temp_" + new File(jarFilePath).getName());

			final boolean downloadSuccess = getNewApplicationVersionFile(downloadTempFile);
			if (downloadSuccess) {
				if (Utilities.isNotEmpty(trustedCaCertificateFileName)) {
					Collection<? extends Certificate> trustedCerts = null;
					final ClassLoader applicationClassLoader = getClass().getClassLoader();
					if (applicationClassLoader == null) {
						showUpdateError("Update error:\n" + "Applications classloader is not readable");
						return;
					}
					try (InputStream trustedUpdateCertificatesStream = applicationClassLoader.getResourceAsStream(trustedCaCertificateFileName)) {
						trustedCerts = CertificateFactory.getInstance("X.509").generateCertificates(trustedUpdateCertificatesStream);
					} catch (final Exception e) {
						showUpdateError("Update error:\n" + "Trusted CA certificate '" + trustedCaCertificateFileName + "' is not readable: " + e.getMessage());
						return;
					}
					if (trustedCerts == null || trustedCerts.size() == 0) {
						showUpdateError("Update error:\n" + "Trusted CA certificate is missing");
						return;
					} else if (!verifyJarSignature(downloadTempFile, trustedCerts)) {
						showUpdateError("Update error:\n" + "Signature of updatefile is invalid");
						return;
					}
				} else if (Utilities.isNotEmpty(updateFileMd5Checksum) && !"NONE".equalsIgnoreCase(updateFileMd5Checksum)) {
					final String downloadTempFileMd5Checksum = createMd5Checksum(downloadTempFile);
					if (!updateFileMd5Checksum.equalsIgnoreCase(downloadTempFileMd5Checksum)) {
						showUpdateError("Update error:\n" + "MD5-Checksum of updatefile is invalid (expected: " + updateFileMd5Checksum + ", actual: " + downloadTempFileMd5Checksum + ")");
						return;
					}
				}

				final String restartCommand = createUpdateBatchFile(jarFilePath, downloadTempFile);

				if (updateParent != null) {
					updateParent.showUpdateDone();
				}

				if (restartCommand != null) {
					Runtime.getRuntime().exec(restartCommand);
					Runtime.getRuntime().exit(0);
				}
			}
		} catch (final Exception e) {
			showUpdateError("Update error while updating to new version:\n" + e.getMessage());
			return;
		}
	}

	private boolean getNewApplicationVersionFile(final File downloadTempFile) throws Exception {
		if (updateFileLocation.toLowerCase().startsWith("http")) {
			// Download file
			boolean retryDownload = true;
			while (retryDownload) {
				String downloadUrlWithCredentials = updateFileLocation;

				if (username != null) {
					downloadUrlWithCredentials = downloadUrlWithCredentials.replace("<username>", username);
					// Only use preconfigured username in first try
					username = null;
				}
				if (password != null) {
					downloadUrlWithCredentials = downloadUrlWithCredentials.replace("<password>", new String(password));
					// Only use preconfigured password in first try
					password = null;
				}

				if (downloadUrlWithCredentials.contains("<username>") && downloadUrlWithCredentials.contains("<password>")) {
					if (updateParent != null) {
						final Credentials credentials = updateParent.aquireCredentials("Please enter update credentials", true, true);
						if (credentials == null || Utilities.isEmpty(credentials.getUsername()) || Utilities.isEmpty(credentials.getPassword())) {
							updateParent.showUpdateError("Update error:\nusername and password required");
							return false;
						} else {
							downloadUrlWithCredentials = downloadUrlWithCredentials.replace("<username>", credentials.getUsername());
							downloadUrlWithCredentials = downloadUrlWithCredentials.replace("<password>", new String(credentials.getPassword()));
						}
					} else {
						showUpdateError("Update error:\n" + "username required");
						return false;
					}
				} else if (downloadUrlWithCredentials.contains("<username>")) {
					if (updateParent != null) {
						final Credentials credentials = updateParent.aquireCredentials("Please enter update credentials", true, false);
						if (credentials == null || Utilities.isEmpty(credentials.getUsername())) {
							updateParent.showUpdateError("Update error:\nusername required");
							return false;
						} else {
							downloadUrlWithCredentials = downloadUrlWithCredentials.replace("<username>", credentials.getUsername());
						}
					} else {
						showUpdateError("Update error:\n" + "username required");
						return false;
					}
				} else if (downloadUrlWithCredentials.contains("<password>")) {
					if (updateParent != null) {
						final Credentials credentials = updateParent.aquireCredentials("Please enter update credentials", false, true);
						if (credentials == null || Utilities.isEmpty(credentials.getPassword())) {
							updateParent.showUpdateError("Update error:\npassword required");
							return false;
						} else {
							downloadUrlWithCredentials = downloadUrlWithCredentials.replace("<password>", new String(credentials.getPassword()));
						}
					} else {
						showUpdateError("Update error:\n" + "password required");
						return false;
					}
				}

				retryDownload = false;
				try {
					if (downloadTempFile.exists()) {
						downloadTempFile.delete();
					}
					final boolean success = downloadUpdateFile(downloadTempFile, downloadUrlWithCredentials);
					if (!success) {
						// download stopped by user
						updateParent.showUpdateError("Canceled by user");
						return false;
					}
				} catch (final UserError e) {
					if (updateParent != null) {
						updateParent.showUpdateError("Update error:\n" + e.getMessage());

						if (e.getReason() == Reason.UnauthenticatedOrUnauthorized) {
							if (updateFileLocation.contains("<username>") || updateFileLocation.contains("<password>")) {
								retryDownload = true;
							} else {
								System.err.println("Update error:\nAuthentication error");
								return false;
							}
						} else {
							return false;
						}
					} else {
						System.err.println("Update error while downloading new version:\n" + e.getMessage());
						return false;
					}
				} catch (final Exception e) {
					if (e instanceof ExecutionException && e.getCause() instanceof UserError) {
						if (updateParent != null) {
							updateParent.showUpdateError("Update error:\n" + ((UserError) e.getCause()).getMessage());

							if (((UserError) e.getCause()).getReason() == Reason.UnauthenticatedOrUnauthorized) {
								if (updateFileLocation.contains("<username>") || updateFileLocation.contains("<password>")) {
									retryDownload = true;
								} else {
									System.err.println("Update error:\nAuthentication error");
									return false;
								}
							} else {
								return false;
							}
						} else {
							System.err.println("Update error while downloading new version:\n" + ((UserError) e.getCause()).getMessage());
							return false;
						}
					} else {
						showUpdateError("Update error:\n" + e.getMessage());
						return false;
					}
				}
			}
		} else {
			// Copy file
			Files.copy(new File(updateFileLocation).toPath(), downloadTempFile.toPath());
		}

		return downloadTempFile.exists();
	}

	private String createUpdateBatchFile(final String jarFilePath, final File downloadTempFile) throws Exception {
		String javaBinPath = SystemUtilities.getJavaBinPath();
		if (Utilities.isBlank(javaBinPath)) {
			javaBinPath = "java";
		}
		if (SystemUtilities.isWindowsSystem()) {
			final File batchFile = new File(new File(jarFilePath).getParent() + File.separator + "batchUpdate_" + new File(jarFilePath).getName() + ".cmd");
			writeFile(batchFile,
					"@echo off\r\n"
							+ "del \"" + jarFilePath + "\"\r\n"
							+ "if exist \"" + jarFilePath + "\" (\r\n"
							+ "ping -n 3 127.0.0.1 >nul\r\n"
							+ "del \"" + jarFilePath + "\"\r\n"
							+ "if exist \"" + jarFilePath + "\" (\r\n"
							+ "ping -n 3 127.0.0.1 >nul\r\n"
							+ "del \"" + jarFilePath + "\"\r\n"
							+ "if exist \"" + jarFilePath + "\" (\r\n"
							+ "ping -n 3 127.0.0.1 >nul\r\n"
							+ "del \"" + jarFilePath + "\"\r\n"
							+ ")\r\n"
							+ ")\r\n"
							+ ")\r\n"
							+ "ren \"" + downloadTempFile.getAbsolutePath() + "\" \"" + new File(jarFilePath).getName() + "\"\r\n"
							+ "if not exist \"" + downloadTempFile.getAbsolutePath() + "\" (\r\n"
							+ "\"" + javaBinPath + "\" -jar \"" + jarFilePath + "\"" + (restartParameter != null ? " " + restartParameter : "") + "\r\n"
							+ "del \"" + batchFile.getAbsolutePath() + "\"\r\n"
							+ ")\r\n");

			return "cmd /c start /B " + batchFile.getAbsolutePath();
		} else if (SystemUtilities.isLinuxSystem()) {
			final File batchFile = new File(new File(jarFilePath).getParent() + File.separator + "batchUpdate_" + new File(jarFilePath).getName() + ".sh");
			writeFile(batchFile,
					"#!/bin/bash\n"
							+ "rm \"" + jarFilePath + "\"\n"
							+ "if [ -f \"" + jarFilePath + "\" ]; then\n"
							+ "sleep 3\n"
							+ "rm \"" + jarFilePath + "\"\n"
							+ "if [ -f \"" + jarFilePath + "\" ]; then\n"
							+ "sleep 3\n"
							+ "rm \"" + jarFilePath + "\"\n"
							+ "if [ -f \"" + jarFilePath + "\" ]; then\n"
							+ "sleep 3\n"
							+ "rm \"" + jarFilePath + "\"\n"
							+ "fi\n"
							+ "fi\n"
							+ "fi\n"
							+ "mv \"" + downloadTempFile.getAbsolutePath() + "\" \"" + jarFilePath + "\"\n"
							+ "if ! [ -f \"" + downloadTempFile.getAbsolutePath() + "\" ]; then\n"
							+ "\"" + javaBinPath + "\" -jar \"" + jarFilePath + "\"" + (restartParameter != null ? " " + restartParameter : "") + "\n"
							+ "rm \"" + batchFile.getAbsolutePath() + "\"\n"
							+ "fi\n");

			return "sh " + batchFile.getAbsolutePath();
		} else {
			return null;
		}
	}

	private static String replacePlaceholders(String value) {
		if (value == null) {
			return null;
		} else {
			if (value.contains("<system>")) {
				if (SystemUtilities.isWindowsSystem()) {
					value = value.replace("<system>", "windows");
				} else if (SystemUtilities.isLinuxSystem()) {
					value = value.replace("<system>", "linux");
				}
			}

			if (value.contains("<bitmode>")) {
				if (System.getProperty("os.arch") != null && System.getProperty("os.arch").contains("64")) {
					value = value.replace("<bitmode>", "64");
				} else if (SystemUtilities.isLinuxSystem()) {
					value = value.replace("<bitmode>", "32");
				}
			}

			if (value.contains("<time_seconds>")) {
				value = value.replace("<time_seconds>", "" + (new Date().getTime() / 1000));
			}

			return value;
		}
	}

	private static void writeFile(final File file, final String string) throws Exception {
		try (FileOutputStream out = new FileOutputStream(file)) {
			out.write(string.getBytes(StandardCharsets.UTF_8));
		} catch (final Exception e) {
			throw new Exception("Cannot write file " + file.getAbsolutePath(), e);
		}
	}

	private boolean downloadUpdateFile(final File downloadTempFile, final String downloadUrl) throws Exception {
		try {
			fileDownloadWorker = new FileDownloadWorker(this, downloadUrl, downloadTempFile);
			new Thread(fileDownloadWorker).start();

			if (updateParent != null) {
				updateParent.showUpdateDownloadStart();
			}

			while (!fileDownloadWorker.isDone()) {
				// Wait for download process
				Thread.sleep(1000);
			}

			if (!fileDownloadWorker.get()) {
				throw new Exception("Download was not successful");
			}

			return !fileDownloadWorker.isCancelled();
		} catch (final Exception e) {
			if (e instanceof ExecutionException && e.getCause() instanceof UserError) {
				throw (UserError) e.getCause();
			} else {
				throw e;
			}
		}
	}

	private static String createMd5Checksum(final File file) {
		try {
			final MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			try (InputStream inputStream = new FileInputStream(file)) {
				final byte[] buffer = new byte[4096];
				int bytesRead;
				while ((bytesRead = inputStream.read(buffer)) >= 0) {
					messageDigest.update(buffer, 0, bytesRead);
				}
			}
			return bytesToHexString(messageDigest.digest());
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	private static String bytesToHexString(final byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();

		final char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			final int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	@Override
	public void showUnlimitedProgress() {
		// Do nothing
	}

	@Override
	public void showProgress(final Date start, final long itemsToDo, final long itemsDone) {
		if (updateParent != null) {
			updateParent.showUpdateProgress(start, itemsToDo, itemsDone);
		}
	}

	@Override
	public void showDone(final Date start, final Date end, final long itemsDone) {
		if (updateParent != null) {
			updateParent.showUpdateDownloadEnd();
		}
	}

	@Override
	public void cancel() {
		// Do nothing
	}

	private void showUpdateError(final String errorMessage) {
		if (updateParent != null) {
			updateParent.showUpdateError(errorMessage);
		} else {
			// Linebreak to end progress display
			System.err.println("");
			System.err.println(errorMessage);
		}
	}

	public void setUsername(final String username) {
		this.username = username;
	}

	public void setPassword(final char[] password) {
		this.password = password;
	}

	@Override
	public void changeTitle(final String text) {
		// do nothing
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

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry))  {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// Do nothing
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
}
