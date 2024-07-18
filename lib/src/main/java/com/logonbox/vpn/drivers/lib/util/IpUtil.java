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

import java.util.ArrayList;
import java.util.List;

import com.github.jgonian.ipmath.AbstractIp;
import com.github.jgonian.ipmath.AbstractIpRange;
import com.github.jgonian.ipmath.Ipv4;
import com.github.jgonian.ipmath.Ipv4Range;
import com.github.jgonian.ipmath.Ipv6;
import com.github.jgonian.ipmath.Ipv6Range;

public class IpUtil {
	
	public static AbstractIp<?, ?> parse(String ip) {
		try {
			return Ipv4.of(ip);
		}
		catch(IllegalArgumentException iae) {
			return Ipv6.of(ip);
		}
	}

	public static AbstractIpRange<?,?> rangeFrom(String range) {
		try {
			return Ipv4Range.parse(range);
		} catch(IllegalArgumentException e) {
			return Ipv6Range.parse(range);
		}
	}

	public static String toIEEE802(byte[] mac) {
		return mac == null ? null
				: String.format("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	
	public static String[] filterIpV4Addresses(String[] address) {
		List<String> l = new ArrayList<>();
		if (address != null) {
			for (String a : address) {
				try {
					Ipv4.of(a);
					l.add(a);
				} catch (IllegalArgumentException iae) {
				}
			}
		}
		return l.toArray(new String[0]);
	}
	
	public static String[] filterIpV6Addresses(String[] address) {
		List<String> l = new ArrayList<>();
		if (address != null) {
			for (String a : address) {
				try {
					Ipv6.of(a);
					l.add(a);
				} catch (IllegalArgumentException iae) {
				}
			}
		}
		return l.toArray(new String[0]);
	}

	public static String[] filterAddresses(String[] address) {
		List<String> l = new ArrayList<>();
		if (address != null) {
			for (String a : address) {
				try {
					Ipv4.of(a);
					l.add(a);
				} catch (IllegalArgumentException iae) {
					try {
						Ipv6.of(a);
						l.add(a);
					} catch (IllegalArgumentException iae2) {

					}
				}
			}
		}
		return l.toArray(new String[0]);
	}

	public static String[] filterNames(String[] address) {
		List<String> l = new ArrayList<>();
		if (address != null) {
			for (String a : address) {
				try {
					Ipv4.of(a);
					continue;
				} catch (IllegalArgumentException iae) {
					try {
						Ipv6.of(a);
						continue;
					} catch (IllegalArgumentException iae2) {

					}
				}
				l.add(a);
			}
		}
		return l.toArray(new String[0]);
	}

}
