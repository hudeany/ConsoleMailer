package de.soderer.utilities.mail;

import java.util.Map;
import java.util.Map.Entry;

import javax.mail.internet.ContentType;

import de.soderer.utilities.Utilities;
import de.soderer.utilities.http.HttpUtilities;

public class MimeMultipart extends javax.mail.internet.MimeMultipart {
	public MimeMultipart(final String multipartSubtype, final String boundary) throws Exception {
		this(multipartSubtype, boundary, null);
	}

	public MimeMultipart(final javax.mail.internet.MimeMultipart mimeMultipart) throws Exception {
		super(getMultipartSubtypeFromContentType(mimeMultipart.getContentType()));

		final ContentType newContentType = new ContentType(mimeMultipart.getContentType());

		newContentType.setParameter("boundary", HttpUtilities.generateBoundary());

		contentType = newContentType.toString();

		for (int i = 0; i < mimeMultipart.getCount(); i++) {
			addBodyPart(mimeMultipart.getBodyPart(i));
		}
	}

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
		if (contentType.startsWith("multipart/")) {
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
