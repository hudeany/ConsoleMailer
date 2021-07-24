package de.soderer.utilities.mail.dkim;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public final class DomainKeyUtil {
	private static final Map<String, DomainKey> DOMAINKEY_CACHE = new HashMap<>();
	private static final Pattern RECORD_PATTERN = Pattern
			.compile("(?:\"(.*?)\"(?: |$))|(?:'(.*?)'(?: |$))|(?:(.*?)(?: |$))");
	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;
	private static long cacheTtl = DEFAULT_CACHE_TTL;

	public static synchronized long getCacheTtl() {
		return cacheTtl;
	}

	public static synchronized void setCacheTtl(long cacheTtl) {
		if (cacheTtl < 0) {
			cacheTtl = DEFAULT_CACHE_TTL;
		}
		DomainKeyUtil.cacheTtl = cacheTtl;
	}

	/**
	 * Retrieves the DomainKey for the given signing domain and selector
	 */
	public static synchronized DomainKey getDomainKey(final String signingDomain, final String selector)
			throws Exception {
		return getDomainKey(getRecordName(signingDomain, selector));
	}

	private static synchronized DomainKey getDomainKey(final String recordName) throws Exception {
		DomainKey domainKey = DOMAINKEY_CACHE.get(recordName);
		if (null != domainKey && 0 != cacheTtl && isRecent(domainKey)) {
			return domainKey;
		} else {
			domainKey = new DomainKey(getTags(recordName));
			DOMAINKEY_CACHE.put(recordName, domainKey);
			return domainKey;
		}
	}

	private static boolean isRecent(final DomainKey domainKey) {
		return domainKey.getTimestamp() + cacheTtl > System.currentTimeMillis();
	}

	private static Map<Character, String> getTags(final String recordName) throws Exception {
		final Map<Character, String> tags = new HashMap<>();

		final String recordValue = getValue(recordName);

		for (String tag : recordValue.split(";")) {
			try {
				tag = tag.trim();
				final String[] tagKeyValueParts = tag.split("=", 2);
				if (tagKeyValueParts.length == 2 && tagKeyValueParts[0].length() == 1) {
					tags.put(tagKeyValueParts[0].charAt(0), tagKeyValueParts[1]);
				} else {
					throw new Exception("Invalid tag found in recordValue: " + recordValue);
				}
			} catch (final IndexOutOfBoundsException e) {
				throw new Exception("The tag " + tag + " in RR " + recordName + " couldn't be decoded.", e);
			}
		}
		return tags;
	}

	private static String getValue(final String recordName) throws Exception {
		try {
			final DirContext dnsContext = new InitialDirContext(getEnvironment());

			final Attributes attributes = dnsContext.getAttributes(recordName, new String[] { "TXT" });
			final Attribute txtRecord = attributes.get("txt");

			if (txtRecord == null) {
				throw new Exception("There is no TXT record available for " + recordName);
			}

			final StringBuilder builder = new StringBuilder();
			final NamingEnumeration<?> e = txtRecord.getAll();
			while (e.hasMore()) {
				if (builder.length() > 0) {
					builder.append(";");
				}
				builder.append((String) e.next());
			}

			final String value = builder.toString();
			if (value.isEmpty()) {
				throw new Exception("Value of RR " + recordName + " couldn't be retrieved");
			}

			return unquoteRecordValue(value);
		} catch (final NamingException ne) {
			throw new Exception("Selector lookup failed", ne);
		}
	}

	private static String unquoteRecordValue(final String recordValue) throws Exception {
		final Matcher recordMatcher = RECORD_PATTERN.matcher(recordValue);

		final StringBuilder builder = new StringBuilder();
		while (recordMatcher.find()) {
			for (int i = 1; i <= recordMatcher.groupCount(); i++) {
				final String match = recordMatcher.group(i);
				if (null != match) {
					builder.append(match);
				}
			}
		}

		final String unquotedRecordValue = builder.toString();
		if (null == unquotedRecordValue || 0 == unquotedRecordValue.length()) {
			throw new Exception("Unable to parse DKIM record: " + recordValue);
		}

		return unquotedRecordValue;
	}

	private static String getRecordName(final String signingDomain, final String selector) {
		return selector + "._domainkey." + signingDomain;
	}

	private static Hashtable<String, String> getEnvironment() {
		final Hashtable<String, String> environment = new Hashtable<>();
		environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		return environment;
	}
}
