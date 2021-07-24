package de.soderer.utilities.mail;

import javax.mail.MessagingException;
import javax.mail.Session;

public class MimeMessage extends javax.mail.internet.MimeMessage {
	private String messageID = null;

	public MimeMessage(final Session session, final String messageID) {
		super(session);

		this.messageID = messageID;
	}

	@Override
	protected void updateMessageID() throws MessagingException {
		if (messageID != null) {
			setHeader("Message-ID", messageID);
		}
	}
}
