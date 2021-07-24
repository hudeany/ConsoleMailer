package de.soderer.utilities.mail;

import java.net.FileNameMap;
import java.net.URLConnection;

import de.soderer.utilities.Utilities;

public class MailAttachment {
	private final String name;
	private final byte[] data;
	private final String mimeType;

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
			this.mimeType = fileNameMap.getContentTypeFor(name);
		} else {
			this.mimeType = mimeType;
		}
	}

	public String getName() {
		return name;
	}

	public byte[] getData() {
		return data;
	}

	public String getMimeType() {
		return mimeType;
	}
}
