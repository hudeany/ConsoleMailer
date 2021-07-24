package de.soderer.utilities.mail.dkim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeUtility;

import de.soderer.utilities.IoUtilities;
import de.soderer.utilities.QuotedPrintableCodec;
import de.soderer.utilities.TextUtilities;
import de.soderer.utilities.TextUtilities.LineBreakType;
import de.soderer.utilities.Utilities;

public class DkimSignedMessage extends de.soderer.utilities.mail.MimeMessage {
	private static final int MAXIMUM_MESSAGE_HEADER_LENGTH = 67;
	private static final String DKIM_SIGNATURE_HEADER_NAME = "DKIM-Signature";

	private String domain;
	private String selector;
	private RSAPrivateKey privateRsaKey;
	private String identity;
	private boolean useRelaxedHeaderCanonicalization = true;
	private boolean useRelaxedBodyCanonicalization = true;
	private Set<String> excludedHeaderNames = null;

	public DkimSignedMessage(final Session session, final String messageID) {
		super(session, messageID);
	}

	public DkimSignedMessage setDkimKeyData(final String domain, final String selector, final RSAPrivateKey privateRsaKey, final String identity) throws Exception {
		if (Utilities.isBlank(domain)) {
			throw new Exception("DKIM domain may not be empty");
		} else if (Utilities.isBlank(selector)) {
			throw new Exception("DKIM key selector may not be empty");
		} else if (privateRsaKey == null) {
			throw new Exception("DKIM private key may not be empty");
		}

		this.domain = domain;
		this.selector = selector;
		this.privateRsaKey = privateRsaKey;
		this.identity = identity;

		return this;
	}

	public DkimSignedMessage setCanonicalization(final boolean useRelaxedHeaderCanonicalization, final boolean useRelaxedBodyCanonicalization) {
		this.useRelaxedHeaderCanonicalization = useRelaxedHeaderCanonicalization;
		this.useRelaxedBodyCanonicalization = useRelaxedBodyCanonicalization;

		return this;
	}

	public DkimSignedMessage setExcludedHeaders(final String... headerNames) {
		excludedHeaderNames = new HashSet<>();
		excludedHeaderNames.addAll(Arrays.asList(headerNames));

		return this;
	}

	@Override
	public void writeTo(final OutputStream outputStream, final String[] ignoreList) throws IOException, MessagingException {
		if (privateRsaKey != null) {
			if (!saved) {
				saveChanges();
			}

			// Get the encoded message body
			final String encodedMessageBody = getEncodedMessageBody();

			// Write dkim signature
			outputStream.write(createDkimSignature(encodedMessageBody).getBytes(StandardCharsets.UTF_8));
			outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));

			// Write other headers
			final Enumeration<String> headerLines = getNonMatchingHeaderLines(ignoreList);
			while (headerLines.hasMoreElements()) {
				outputStream.write(headerLines.nextElement().getBytes(StandardCharsets.UTF_8));
				outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
			}
			outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));

			// Write the encoded message body
			outputStream.write(encodedMessageBody.getBytes(StandardCharsets.UTF_8));
			outputStream.flush();
		} else {
			super.writeTo(outputStream, ignoreList);
		}
	}

	private String getEncodedMessageBody() throws IOException, MessagingException {
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			if (modified) {
				try (OutputStream outputStream = MimeUtility.encode(buffer, getEncoding())) {
					getDataHandler().writeTo(outputStream);
				}
			} else if (content == null) {
				try (InputStream inputStream = getContentStream()) {
					IoUtilities.copy(inputStream, buffer);
				}
			} else {
				buffer.write(content);
			}
			buffer.flush();
			buffer.close();
			return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
		}
	}

	private String createDkimSignature(final String encodedMessageBody) throws MessagingException {
		Date sentDate = getSentDate();
		if (sentDate == null) {
			sentDate = new Date();
			setSentDate(sentDate);
		}

		final Map<String, String> signatureData = new LinkedHashMap<>();
		signatureData.put("v", "1");
		signatureData.put("a", "rsa-sha256");
		signatureData.put("c", (useRelaxedHeaderCanonicalization ? "relaxed" : "simple") + "/" + (useRelaxedBodyCanonicalization ? "relaxed" : "simple"));
		signatureData.put("d", domain);
		signatureData.put("s", selector);
		signatureData.put("t", Long.toString(sentDate.getTime() / 1000l));
		if (identity != null) {
			final String data = identity;
			signatureData.put("i", QuotedPrintableCodec.encode(data, StandardCharsets.UTF_8));
		}

		boolean fromHeaderIsIncluded = false;
		final List<Header> headersToIncludeInDkimSignature = new LinkedList<>();
		for (final Header header : Collections.list(getAllHeaders())) {
			if ((excludedHeaderNames == null || !excludedHeaderNames.contains(header.getName())) && !DKIM_SIGNATURE_HEADER_NAME.equalsIgnoreCase(header.getName())) {
				headersToIncludeInDkimSignature.add(header);
				if ("from".equalsIgnoreCase(header.getName())) {
					fromHeaderIsIncluded = true;
				}
			}
		}

		if (!fromHeaderIsIncluded) {
			throw new MessagingException("Mandatory header 'from' is not included in headers for dkim signature");
		}

		final List<String> headerNames = new ArrayList<>();
		final StringBuilder serializedHeaderData = new StringBuilder();
		for (final Header header : headersToIncludeInDkimSignature) {
			final String headerName = header.getName();
			final String headerValue = header.getValue();
			headerNames.add(headerName);
			serializedHeaderData.append(canonicalizeHeader(useRelaxedHeaderCanonicalization, headerName, headerValue));
			serializedHeaderData.append("\r\n");
		}

		MessageDigest bodyHashingMessageDigest;
		try {
			bodyHashingMessageDigest = MessageDigest.getInstance("sha-256");
		} catch (final NoSuchAlgorithmException e) {
			throw new MessagingException("Unknown hashing algorithm: sha-256", e);
		}
		final String canonicalBody = canonicalizeBody(useRelaxedBodyCanonicalization, encodedMessageBody);
		final byte[] bodyHashBytes = bodyHashingMessageDigest.digest(canonicalBody.getBytes(StandardCharsets.UTF_8));
		final String bodyHashBase64String = Base64.getEncoder().encodeToString(bodyHashBytes).replace("\r", "").replace("\n", "");
		signatureData.put("bh", bodyHashBase64String);

		signatureData.put("h", serializeHeaderNames(headerNames, 3, MAXIMUM_MESSAGE_HEADER_LENGTH));

		final String serializedSignature = serializeDkimSignatureData(signatureData, DKIM_SIGNATURE_HEADER_NAME.length() + 2, MAXIMUM_MESSAGE_HEADER_LENGTH);
		serializedHeaderData.append(canonicalizeHeader(useRelaxedHeaderCanonicalization, DKIM_SIGNATURE_HEADER_NAME, serializedSignature));

		Signature signature;
		try {
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateRsaKey);
		} catch (final NoSuchAlgorithmException e) {
			throw new MessagingException("Unknown signing algorithm SHA256withRSA", e);
		} catch (final InvalidKeyException e) {
			throw new MessagingException("Invalid private key", e);
		}
		byte[] signatureBytes;
		try {
			signature.update(serializedHeaderData.toString().getBytes(StandardCharsets.UTF_8));
			signatureBytes = signature.sign();
		} catch (final SignatureException e) {
			throw new MessagingException("Faild to create signature", e);
		}
		final String signatureBase64String = Base64.getEncoder().encodeToString(signatureBytes).replace("\r", "").replace("\n", "");

		return DKIM_SIGNATURE_HEADER_NAME + ": " + serializedSignature + serializeBase64String(signatureBase64String, 3, MAXIMUM_MESSAGE_HEADER_LENGTH);
	}

	private static String canonicalizeHeader(final boolean useRelaxedCanonicalization, final String headerName, final String headerValue) {
		if (useRelaxedCanonicalization) {
			return headerName.trim().toLowerCase() + ":" + headerValue.replaceAll("\\s+", " ").trim();
		} else {
			return headerName + ": " + headerValue;
		}
	}

	private static String canonicalizeBody(final boolean useRelaxedCanonicalization, String body) {
		body = TextUtilities.normalizeLineBreaks(body, LineBreakType.Windows);

		if (useRelaxedCanonicalization) {
			if (body == null) {
				return "";
			} else {
				if (!body.endsWith("\r\n")) {
					body += "\r\n";
				}
				body = body.replaceAll("[ \\t]+\r\n", "\r\n");
				body = body.replaceAll("[ \\t]+", " ");

				while (body.endsWith("\r\n\r\n")) {
					body = body.substring(0, body.length() - 2);
				}

				if ("\r\n".equals(body)) {
					body = "";
				}

				return body;
			}
		} else {
			if (body == null) {
				return "\r\n";
			} else {
				if (!body.endsWith("\r\n")) {
					return body + "\r\n";
				} else {
					while (body.endsWith("\r\n\r\n")) {
						body = body.substring(0, body.length() - 2);
					}

					return body;
				}
			}
		}
	}

	private static String serializeHeaderNames(final List<String> headerNames, final int prefixLength, final int maxHeaderLength) {
		final StringBuilder headerNamesSerialized = new StringBuilder();
		int currentLinePosition = prefixLength;
		for (int i = 0; i < headerNames.size(); i++) {
			final String headerName = headerNames.get(i);
			final boolean isLastHeaderName = ((i + 1) >= headerNames.size());
			if (headerNamesSerialized.length() == 0) {
				// first header without leading separator
				headerNamesSerialized.append(headerName);
				currentLinePosition += headerName.length();
			} else if (currentLinePosition + 1 + headerName.length() + (isLastHeaderName ? 0 : 1) > maxHeaderLength) {
				// header content would exceed limit, so linebreak is added
				headerNamesSerialized.append(":");
				headerNamesSerialized.append("\r\n\t ");
				headerNamesSerialized.append(headerName);
				currentLinePosition = 2 + headerName.length();
			} else {
				// simply adding separator and headername
				headerNamesSerialized.append(":");
				headerNamesSerialized.append(headerName);
				currentLinePosition += 1 + headerName.length();
			}
		}
		return headerNamesSerialized.toString();
	}

	private static String serializeDkimSignatureData(final Map<String, String> signatureData, int prefixLength, final int maxHeaderLength) {
		int position = 0;
		final StringBuilder builder = new StringBuilder();

		for (final Entry<String, String> entry : signatureData.entrySet()) {
			final StringBuilder entryBuilder = new StringBuilder();
			entryBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append(";");

			if (position + entryBuilder.length() + 1 + prefixLength > maxHeaderLength) {
				position = entryBuilder.length();
				builder.append("\r\n\t").append(entryBuilder);
				prefixLength = 0;
			} else {
				builder.append(" ").append(entryBuilder);
				position += 1 + entryBuilder.length();
			}
		}

		// "b=" must be included in serialized signature data
		builder.append("\r\n\t" + "b=");

		return builder.toString().trim();
	}

	private static String serializeBase64String(final String base64String, int prefixLength, final int maxHeaderLength) {
		int base64StringReadIndex = 0;
		final StringBuilder builder = new StringBuilder();

		while (true) {
			if (prefixLength > 0 && (base64String.substring(base64StringReadIndex).length() + prefixLength) > maxHeaderLength) {
				builder.append(base64String.substring(base64StringReadIndex, base64StringReadIndex + maxHeaderLength - prefixLength));
				base64StringReadIndex += maxHeaderLength - prefixLength;
				prefixLength = 0;
			} else if (2 + base64String.substring(base64StringReadIndex).length() > maxHeaderLength) {
				builder.append("\r\n\t ").append(base64String.substring(base64StringReadIndex, base64StringReadIndex + maxHeaderLength - 2));
				base64StringReadIndex += maxHeaderLength -2;
			} else {
				builder.append("\r\n\t ").append(base64String.substring(base64StringReadIndex));
				break;
			}
		}

		return builder.toString();
	}
}
