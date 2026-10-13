package de.soderer.mailer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import jakarta.mail.internet.InternetAddress;

@SuppressWarnings("static-method")
public class MailUtilitiesTest {
	@Test
	public void testEmailAddressListParsing() {
		try {
			final InternetAddress[] addressList = MailUtilities.getEmailAddressesFromList("Test1@example.com Test2@example.com");

			assertEquals(2, addressList.length);

			assertEquals(null, addressList[0].getPersonal());
			assertEquals("test1@example.com", addressList[0].getAddress());

			assertEquals(null, addressList[1].getPersonal());
			assertEquals("test2@example.com", addressList[1].getAddress());

			final InternetAddress[] addressList1 = MailUtilities.getEmailAddressesFromList("First Test <Test1@example.com> Second Test <Test2@example.com>");
			assertEquals(2, addressList1.length);

			assertEquals("First Test", addressList1[0].getPersonal());
			assertEquals("test1@example.com", addressList1[0].getAddress());

			assertEquals("Second Test", addressList1[1].getPersonal());
			assertEquals("test2@example.com", addressList1[1].getAddress());

			final InternetAddress[] addressList2 = MailUtilities.getEmailAddressesFromList("First Test<Test1@example.com>,Second Test<Test2@example.com>");
			assertEquals(2, addressList2.length);

			assertEquals("First Test", addressList2[0].getPersonal());
			assertEquals("test1@example.com", addressList2[0].getAddress());

			assertEquals("Second Test", addressList2[1].getPersonal());
			assertEquals("test2@example.com", addressList2[1].getAddress());

			final InternetAddress[] addressList3 = MailUtilities.getEmailAddressesFromList("First Test<Test1@example.com>;Second Test<Test2@example.com>");
			assertEquals(2, addressList3.length);

			assertEquals("First Test", addressList3[0].getPersonal());
			assertEquals("test1@example.com", addressList3[0].getAddress());

			assertEquals("Second Test", addressList3[1].getPersonal());
			assertEquals("test2@example.com", addressList3[1].getAddress());
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}
}
