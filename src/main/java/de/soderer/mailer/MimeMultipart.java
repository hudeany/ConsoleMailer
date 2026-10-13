package de.soderer.mailer;

import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import de.soderer.network.HttpUtilities;
import de.soderer.utilities.Utilities;
import jakarta.mail.internet.ContentType;

/**
 * MIME multipart that allows a predefined boundary and additional content type parameters.
 */
public class MimeMultipart extends jakarta.mail.internet.MimeMultipart {
	/**
	 * Create an empty multipart.
	 *
	 * @param multipartSubtype multipart subtype, e.g. "mixed" or "alternative"
	 * @param boundary boundary to use, or null/blank for a generated one
	 * @throws Exception if the content type cannot be created
	 */
	public MimeMultipart(final String multipartSubtype, final String boundary) throws Exception {
		this(multipartSubtype, boundary, null);
	}

	/**
	 * Create a copy of a multipart with the same subtype and body parts, but with a newly generated boundary.
	 *
	 * @param mimeMultipart multipart to copy
	 * @throws Exception if the content type of the given multipart is no multipart content type or cannot be read
	 */
	public MimeMultipart(final jakarta.mail.internet.MimeMultipart mimeMultipart) throws Exception {
		super(getMultipartSubtypeFromContentType(mimeMultipart.getContentType()));

		final ContentType newContentType = new ContentType(mimeMultipart.getContentType());

		newContentType.setParameter("boundary", HttpUtilities.generateBoundary());

		contentType = newContentType.toString();

		for (int i = 0; i < mimeMultipart.getCount(); i++) {
			addBodyPart(mimeMultipart.getBodyPart(i));
		}
	}

	/**
	 * Create an empty multipart with additional content type parameters (e.g. "protocol" for signed or encrypted multiparts).
	 *
	 * @param multipartSubtype multipart subtype, e.g. "mixed" or "signed"
	 * @param boundary boundary to use, or null/blank for a generated one
	 * @param additionalContentParameters additional content type parameters, may be null
	 * @throws Exception if the content type cannot be created
	 */
	public MimeMultipart(final String multipartSubtype, final String boundary, final Map<String, String> additionalContentParameters) throws Exception {
		super(multipartSubtype);

		final ContentType newContentType = new ContentType(contentType);

		if (additionalContentParameters != null) {
			for (final Entry<String, String> entry : additionalContentParameters.entrySet()) {
				newContentType.setParameter(entry.getKey(), entry.getValue());
			}
		}

		if (!Utilities.isBlank(boundary)) {
			newContentType.setParameter("boundary", boundary);
		}

		contentType = newContentType.toString();
	}

	private static String getMultipartSubtypeFromContentType(final String contentType) throws Exception {
		if (contentType.toLowerCase(Locale.ROOT).startsWith("multipart/")) {
			String subtype = contentType.substring(10);
			if (subtype.contains(";")) {
				subtype = subtype.substring(0, subtype.indexOf(";"));
			}
			subtype = subtype.trim();
			return subtype;
		} else {
			throw new Exception("Invalid multipart contenttype: " + contentType);
		}
	}
}
