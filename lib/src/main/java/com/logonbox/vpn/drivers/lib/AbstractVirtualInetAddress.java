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

public abstract class AbstractVirtualInetAddress<P extends PlatformService<?>> implements VpnAddress {

	public final static String TABLE_AUTO = "auto";
	public final static String TABLE_OFF = "off";
	
	private int mtu;
	private String name;
	private String peer;
	private String table = TABLE_AUTO;
	protected P platform;
    protected final SystemCommands commands;

	public AbstractVirtualInetAddress(P platform) {
		super();
		this.platform = platform;
	    commands = platform.commands();
	}

	public AbstractVirtualInetAddress(P platform, String name) {
		super();
		this.name = name;
		this.platform = platform;
	    commands = platform.commands();
	}

	@Override
	public final int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public final boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AbstractVirtualInetAddress<?> other = (AbstractVirtualInetAddress<?>) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		return true;
	}

	@Override
	public final int getMtu() {
		return mtu;
	}

	@Override
	public final String name() {
		return name;
	}

	@Override
	public final String peer() {
		return peer;
	}

	@Override
	public final String table() {
		return table;
	}

	@Override
	public final void mtu(int mtu) {
		this.mtu = mtu;
	}

	@Override
	public final DNSIntegrationMethod calcDnsMethod() {
	    var method = platform.context().configuration().dnsIntegrationMethod();
		if (method == DNSIntegrationMethod.AUTO) {
			return platform.dnsMethod();
		} else
			return method;
	}
}