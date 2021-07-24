package de.soderer.utilities.console;

import java.io.IOException;
import java.io.InputStream;
import java.text.NumberFormat;
import java.util.Date;
import java.util.Locale;

import de.soderer.utilities.DateUtilities;
import de.soderer.utilities.SystemUtilities;
import de.soderer.utilities.Utilities;

public class ConsoleUtilities {
	private static Boolean consoleSupportsAnsiCodes = null;
	private static boolean linuxConsoleActivatedRawMode = false;

	/**
	 * Detection of Ctrl-C only works on Windows systems, because it ends Linux Java VM immediatelly
	 */
	public static final int KeyCode_CtrlC = 3;
	public static final int KeyCode_CtrlV = 22;
	public static final int KeyCode_CtrlX = 24;

	/**
	 * Detection of contextmenu insert. Only works on Linux systems
	 */
	public static final int KeyCode_ContextMenu_Insert = 6513249;

	public static final int KeyCode_Enter;
	public static final int KeyCode_Backspace;
	public static final int KeyCode_Tab = 9;
	public static final int KeyCode_Escape = 27;

	public static final int KeyCode_Home;
	public static final int KeyCode_PageUp;
	public static final int KeyCode_End;
	public static final int KeyCode_Insert;
	public static final int KeyCode_Delete;
	public static final int KeyCode_PageDown;

	public static final int KeyCode_Up;
	public static final int KeyCode_Left;
	public static final int KeyCode_Right;
	public static final int KeyCode_Down;

	public static final int KeyCode_AUml_Lower;
	public static final int KeyCode_AUml_Upper;
	public static final int KeyCode_OUml_Lower;
	public static final int KeyCode_OUml_Upper;
	public static final int KeyCode_UUml_Lower;
	public static final int KeyCode_UUml_Upper;

	static {
		if (SystemUtilities.isWindowsSystem()) {
			KeyCode_Enter = 13;
			KeyCode_Backspace = 8;

			KeyCode_Insert = 57426;
			KeyCode_Home = 57415;
			KeyCode_PageUp = 57417;
			KeyCode_End = 57423;
			KeyCode_Delete = 57427;
			KeyCode_PageDown = 57425;

			KeyCode_Up = 57416;
			KeyCode_Left = 57419;
			KeyCode_Right = 57421;
			KeyCode_Down = 57424;

			KeyCode_AUml_Lower = 228;
			KeyCode_AUml_Upper = 196;
			KeyCode_OUml_Lower = 246;
			KeyCode_OUml_Upper = 214;
			KeyCode_UUml_Lower = 252;
			KeyCode_UUml_Upper = 220;
		} else {
			KeyCode_Enter = 10;
			KeyCode_Backspace = 127;

			KeyCode_Insert = 2117229339;
			KeyCode_Home = 4741915;
			KeyCode_PageUp = 2117425947;
			KeyCode_Delete = 2117294875;
			KeyCode_End = 4610843;
			KeyCode_PageDown = 2117491483;

			KeyCode_Up = 4283163;
			KeyCode_Left = 4479771;
			KeyCode_Right = 4414235;
			KeyCode_Down = 4348699;

			KeyCode_AUml_Lower = 42179;
			KeyCode_AUml_Upper = 33987;
			KeyCode_OUml_Lower = 46787;
			KeyCode_OUml_Upper = 38595;
			KeyCode_UUml_Lower = 48323;
			KeyCode_UUml_Upper = 40131;
		}
	}

	/**
	 * Additional attributes
		Bold 1
		Underline 4
		No underline 24
		Negative(reverse the foreground and background) 7
		Positive(no negative) 27
		Default 0
	 */
	public enum TextColor {
		Black(30, 40),
		Red(31, 41),
		Green(32, 42),
		Yellow(33, 43),
		Blue(34, 44),
		Magenta(35, 45),
		Cyan(36, 46),
		Light_gray(37, 47),
		Dark_gray(90, 100),
		Light_red(91, 101),
		Light_green(92, 102),
		Light_yellow(93, 103),
		Light_blue(94, 104),
		Light_magenta(95, 105),
		Light_cyan(96, 106),
		White(97, 107);

		private final int foreGroundColorCode;
		private final int backGroundColorCode;

		TextColor(final int foreGroundColorCode, final int backGroundColorCode) {
			this.foreGroundColorCode = foreGroundColorCode;
			this.backGroundColorCode = backGroundColorCode;
		}

		public int getForeGroundColorCode() {
			return foreGroundColorCode;
		}

		public int getBackGroundColorCode() {
			return backGroundColorCode;
		}
	}

	public enum TextAttribute {
		/**
		 * Reset Text decoration
		 */
		RESET("\033[0m"),

		HIGH_INTENSITY("\033[1m"),

		/**
		 * Not supported by Windows console
		 */
		LOW_INTENSITY("\033[2m"),

		/**
		 * Not supported by Windows console
		 */
		ITALIC("\033[3m"),

		UNDERLINE("\033[4m"),

		/**
		 * Not supported by Windows console
		 */
		BLINK("\033[5m"),

		/**
		 * Not supported by Windows console
		 */
		RAPID_BLINK("\033[6m"),

		REVERSE_VIDEO("\033[7m"),

		INVISIBLE_TEXT("\033[8m");

		private final String ansiCode;

		TextAttribute(final String ansiCode) {
			this.ansiCode = ansiCode;
		}

		public String getAnsiCode() {
			return ansiCode;
		}
	}

	public static boolean consoleSupportsAnsiCodes() {
		if (consoleSupportsAnsiCodes == null) {
			consoleSupportsAnsiCodes = SystemUtilities.isWindowsSystem() || (System.console() != null && System.getenv().get("TERM") != null);
		}
		return consoleSupportsAnsiCodes;
	}

	public static boolean activateLinuxConsoleRawMode() throws Exception {
		if (!linuxConsoleActivatedRawMode) {
			Runtime.getRuntime().exec(new String[] { "/bin/sh", "-c", "stty raw -echo < /dev/tty" }).waitFor();
			linuxConsoleActivatedRawMode = true;
			registerShutdownHook();
			return true;
		} else {
			return false;
		}
	}

	public static void deactivateLinuxConsoleRawMode() throws Exception {
		if (linuxConsoleActivatedRawMode) {
			Runtime.getRuntime().exec(new String[] { "/bin/sh", "-c", "stty -raw echo </dev/tty" }).waitFor();
			linuxConsoleActivatedRawMode = false;
		}
	}

	private static void registerShutdownHook() {
		Runtime.getRuntime().addShutdownHook(new Thread() {
			@Override
			public void run() {
				try {
					deactivateLinuxConsoleRawMode();
				} catch (@SuppressWarnings("unused") final Exception e) {
					// do nothing
				}
			}
		});
	}

	/**
	 * Create a progress string for terminal output e.g.: "65% [=================================>                   ] 103.234 200/s eta 5m"
	 *
	 * @param start
	 * @param itemsToDo
	 * @param itemsDone
	 * @return
	 */
	public static String getConsoleProgressString(final int lineLength, final Date start, final long itemsToDo, final long itemsDone) {
		final Date now = new Date();
		String itemsToDoString = "??";
		String percentageString = " 0%";
		String speedString = "???/s";
		String etaString = "eta ???";
		int percentageDone = 0;
		if (itemsToDo > 0 && itemsDone > 0) {
			itemsToDoString = NumberFormat.getNumberInstance(Locale.getDefault()).format(itemsToDo);
			percentageDone = (int) (itemsDone * 100 / itemsToDo);
			percentageString = Utilities.leftPad(percentageDone + "%", 3);
			long elapsedSeconds = (now.getTime() - start.getTime()) / 1000;
			// Prevent division by zero, when start is fast
			if (elapsedSeconds == 0) {
				elapsedSeconds = 1;
			}
			final int speed = (int) (itemsDone / elapsedSeconds);
			speedString = Utilities.getHumanReadableNumber(speed, "", true, 5, true, Locale.ENGLISH) + "/s";
			final Date estimatedEnd = DateUtilities.calculateETA(start, itemsToDo, itemsDone);
			etaString = "eta " + DateUtilities.getShortHumanReadableTimespan(estimatedEnd.getTime() - now.getTime(), false, true);
		} else if (itemsToDo > 0) {
			itemsToDoString = NumberFormat.getNumberInstance(Locale.getDefault()).format(itemsToDo);
		}

		final String leftPart = percentageString + " [";
		final String rightPart = "] " + itemsToDoString + " " + speedString + " " + etaString;
		final int barWith = lineLength - (leftPart.length() + rightPart.length());
		int barDone = barWith * percentageDone / 100;
		if (barDone < 1) {
			barDone = 1;
		} else if (barDone >= barWith) {
			barDone = barWith;
		}
		return leftPart + Utilities.repeat("=", barDone - 1) + ">" + Utilities.repeat(" ", barWith - barDone) + rightPart;
	}

	public static void printBoxed(final String text) {
		printBoxed(text, '*');
	}

	public static void printBoxed(final String text, final char boxChar) {
		if (text != null) {
			System.out.println(Utilities.repeat(boxChar, text.length() + 4));
			System.out.println(boxChar + " " + text + " " + boxChar);
			System.out.println(Utilities.repeat(boxChar, text.length() + 4));
		}
	}

	public static void clearScreen() {
		if (SystemUtilities.isWindowsSystem()) {
			try {
				new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
			} catch (@SuppressWarnings("unused") final Exception e) {
				System.err.println("Cannot clear Windows console");
			}
		} else {
			System.out.print("\033[H\033[2J");
			System.out.flush();
		}
	}

	public static String getAnsiColoredText(final String text, final TextColor foreGroundColor) {
		return getAnsiFormattedText(text, foreGroundColor, null);
	}

	public static String getAnsiColoredText(final TextColor foreGroundColor, final TextColor backGroundColor, final String text) {
		return getAnsiFormattedText(text, foreGroundColor, backGroundColor);
	}

	public static String getAnsiFormattedText(final String text, final TextColor foreGroundColor, final TextColor backGroundColor, final TextAttribute... attributes) {
		final StringBuilder builder = new StringBuilder();
		if (foreGroundColor != null) {
			builder.append("\033[" + foreGroundColor.getForeGroundColorCode() + "m");
		}
		if (backGroundColor != null) {
			builder.append("\033[" + backGroundColor.getBackGroundColorCode() + "m");
		}
		if (attributes != null) {
			for (final TextAttribute attribute : attributes) {
				builder.append(attribute.getAnsiCode());
			}
		}
		builder.append(text);
		builder.append(TextAttribute.RESET.getAnsiCode());
		return builder.toString();
	}

	public static void saveCurrentCursorPosition() {
		System.out.print("\033[s");
	}

	public static void moveCursorToPosition(final int line, final int column) {
		System.out.print("\033[" + line + ";" + column + "H");
	}

	public static void moveCursorToSavedPosition() {
		System.out.print("\033[u");
	}

	public static void clearLineContentAfterCursor() {
		System.out.print("\033[K");
	}

	public static void hideCursor() {
		System.out.print("\033[?25l");
	}

	public static void showCursor() {
		System.out.print("\033[?25h");
	}

	public static Size getUnixTerminalSizeByTput() throws Exception {
		try {
			return new Size(Integer.parseInt(executeTputCommand("lines").trim()), Integer.parseInt(executeTputCommand("cols").trim()));
		} catch (final Exception e) {
			throw new Exception("Cannot detect terminal size", e);
		}
	}

	private static String executeTputCommand(final String command) throws IOException {
		final ProcessBuilder processBuilder = new ProcessBuilder("tput", command);
		try (InputStream inputStream = processBuilder.start().getInputStream()) {
			int readBuffer = 0;
			final StringBuffer buffer = new StringBuffer();
			while ((readBuffer = inputStream.read()) != -1) {
				buffer.append((char) readBuffer);
			}
			return buffer.toString();
		}
	}
}
