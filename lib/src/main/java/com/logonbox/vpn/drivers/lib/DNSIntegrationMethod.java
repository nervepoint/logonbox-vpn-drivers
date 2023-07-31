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
package com.logonbox.vpn.drivers.lib;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.SystemUtils;

public enum DNSIntegrationMethod {
	AUTO, NETSH, NETWORK_MANAGER, SYSTEMD, RESOLVCONF, RAW, NETWORKSETUP, SCUTIL_COMPATIBLE, SCUTIL_SPLIT, NONE;
	
	public boolean isForOS() {
		switch(this) {
		case NETWORKSETUP:
		case SCUTIL_COMPATIBLE:
		case SCUTIL_SPLIT:
			return SystemUtils.IS_OS_MAC_OSX;
		case NETWORK_MANAGER:
		case SYSTEMD:
		case RAW:
		case RESOLVCONF:
			return SystemUtils.IS_OS_LINUX;
		case NETSH:
			return SystemUtils.IS_OS_WINDOWS;
		case AUTO:
		case NONE:
			return true;
		default:
			return false;
		}
	}
	
	public static DNSIntegrationMethod[] valuesForOs() {
		List<DNSIntegrationMethod> l = new ArrayList<>();
		for(DNSIntegrationMethod m : values()) {
			if(m.isForOS())
				l.add(m);
		}
		return l.toArray(new DNSIntegrationMethod[0]);
	}
	
}
