package de.soderer.mailer;

import java.net.FileNameMap;
import java.net.URLConnection;

import de.soderer.utilities.Utilities;

/**
 * Attachment of an {@link Email}.
 */
public class MailAttachment {
	private final String name;
	private final byte[] data;
	private final String mimeType;

	/**
	 * Create an attachment.
	 *
	 * @param name file name of the attachment
	 * @param data content of the attachment
	 * @param mimeType MIME type of the attachment, or null/blank to detect it from the file name extension
	 * 	("application/octet-stream" for unknown extensions)
	 * @throws Exception if name or data are missing
	 */
	public MailAttachment(final String name, final byte[] data, final String mimeType) throws Exception {
		if (Utilities.isBlank(name)) {
			throw new Exception("Invalid empty mail attachment");
		} else {
			this.name = name;
		}

		if (data == null) {
			throw new Exception("Invalid empty mail attachment");
		} else {
			this.data = data;
		}

		if (Utilities.isBlank(mimeType)) {
			final FileNameMap fileNameMap = URLConnection.getFileNameMap();
			final String detectedMimeType = fileNameMap.getContentTypeFor(name);
			// Unknown file name extensions are sent as generic binary data
			this.mimeType = detectedMimeType == null ? "application/octet-stream" : detectedMimeType;
		} else {
			this.mimeType = mimeType;
		}
	}

	/**
	 * Get the file name of the attachment.
	 *
	 * @return file name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the content of the attachment.
	 *
	 * @return content (not copied)
	 */
	public byte[] getData() {
		return data;
	}

	/**
	 * Get the MIME type of the attachment.
	 *
	 * @return MIME type
	 */
	public String getMimeType() {
		return mimeType;
	}
}
