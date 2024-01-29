/**
 * Copyright © 2023 LogonBox Limited (support@logonbox.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the “Software”), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.logonbox.vpn.drivers.lib.util;

import java.net.InetAddress;
import java.security.MessageDigest;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.ArrayList; 
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sshtools.liftlib.OS;

public class Util {
    static Logger log = LoggerFactory.getLogger(Util.class);
    
    public static byte[] toArray(List<Byte> bytes) {
        var b = new byte[bytes.size()];
        for(int i = 0 ; i < bytes.size(); i++)
            b[i] = bytes.get(i);
        return b;
    }
    
    public static boolean isBlank(String str) {
        return str == null || str.isBlank();
    }
    public static boolean isNotBlank(String str) {
        return !isBlank(str);
    }

	public static String getBasename(String name) {
		int idx = name.indexOf('.');
		return idx == -1 ? name : name.substring(0, idx);
	}

	public static String checkEndsWithSlash(String str) {
		if (str.endsWith("/")) {
			return str;
		} else {
			return str + "/";
		}
	}
	
	public static String titleUnderline(int len) {
		return repeat(len, '=');
	}
	
	public static String repeat(int times, char ch) {
		StringBuilder l = new StringBuilder();
		for(int i = 0 ; i < times; i++) {
			l.append('=');
		}
		return l.toString();
	}

	public static String hash(byte[] in) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(in);
			byte[] bytes = md.digest();
			return Base64.getEncoder().encodeToString(bytes);
		} catch (Exception e) {
			throw new IllegalStateException("Failed to hash.", e);
		}
	}
	
	public static String getDeviceName() {
		String hostname = OsUtil.getHostName();
		if (isBlank(hostname)) {
			try {
				hostname = InetAddress.getLocalHost().getHostName();
			} catch (Exception e) {
				hostname = "Unknown Host";
			}
		}
		String os = System.getProperty("os.name");
		if (OS.isWindows()) {
			os = "Windows";
		} else if (OS.isLinux()) {
			os = "Linux";
		} else if (OS.isMacOs()) {
			os = "Mac OSX";
		}
		return os + " " + hostname;
	}
	
	public static byte[] decodeHexString(String hexString) {
		if (hexString.length() % 2 == 1) {
			throw new IllegalArgumentException("Invalid hexadecimal String supplied.");
		}

		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < hexString.length(); i += 2) {
			bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
		}
		return bytes;
	}

	public static byte hexToByte(String hexString) {
		int firstDigit = toDigit(hexString.charAt(0));
		int secondDigit = toDigit(hexString.charAt(1));
		return (byte) ((firstDigit << 4) + secondDigit);
	}

	public static int byteSwap(int a) {
	    return Integer.reverseBytes(a);
//	    var b = ByteBuffer.allocate(4);
//	    b.putInt(a);
//	    b.flip();
//        b.order(ByteOrder.LITTLE_ENDIAN);
//	    return b.get();
	    
//		return ((a & 0xff000000) >>> 24) | ((a & 0x00ff0000) >>> 8) | ((a & 0x0000ff00) << 8)
//				| ((a & 0x000000ff) << 24);
	}
	
	public static Optional<String> stringOr(String str) {
		return str == null || str.length() == 0 ? Optional.empty() : Optional.of(str);
	}

    public static int parseFwMark(String tkn) {
        tkn = tkn.trim();
        if (tkn.equals("off") || tkn.length() == 0)
            return 0;
        else {
            if (tkn.startsWith("0x")) {
                return Integer.parseInt(tkn.substring(2), 16);
            } else {
                return Integer.parseInt(tkn);
            }
        }
    }

	/**
	 * Parse a space separated string into a list, treating portions quotes with
	 * single quotes as a single element. Single quotes themselves and spaces can be
	 * escaped with a backslash.
	 * 
	 * @param command command to parse
	 * @return parsed command
	 */
	public static List<String> parseQuotedString(String command) {
		List<String> args = new ArrayList<String>();
		boolean escaped = false;
		boolean quoted = false;
		StringBuilder word = new StringBuilder();
		for (int i = 0; i < command.length(); i++) {
			char c = command.charAt(i);
			if (c == '"' && !escaped) {
				if (quoted) {
					quoted = false;
				} else {
					quoted = true;
				}
			} else if (c == '\\' && !escaped) {
				escaped = true;
			} else if (c == ' ' && !escaped && !quoted) {
				if (word.length() > 0) {
					args.add(word.toString());
					word.setLength(0);
					;
				}
			} else {
				word.append(c);
			}
		}
		if (word.length() > 0)
			args.add(word.toString());
		return args;
	}

	public static String toHumanSize(long bytes) {
		long absB = bytes == Long.MIN_VALUE ? Long.MAX_VALUE : Math.abs(bytes);
		if (absB < 1024) {
			return bytes + " B";
		}
		long value = absB;
		CharacterIterator ci = new StringCharacterIterator("KMGTPE");
		for (int i = 40; i >= 0 && absB > 0xfffccccccccccccL >> i; i -= 10) {
			value >>= 10;
			ci.next();
		}
		value *= Long.signum(bytes);
		return String.format("%.1f %ciB", value / 1024.0, ci.current());
	}

    private static int toDigit(char hexChar) {
    	int digit = Character.digit(hexChar, 16);
    	if (digit == -1) {
    		throw new IllegalArgumentException("Invalid Hexadecimal Character: " + hexChar);
    	}
    	return digit;
    }
}
