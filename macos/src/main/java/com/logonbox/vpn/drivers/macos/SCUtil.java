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
package com.logonbox.vpn.drivers.macos;

import com.logonbox.vpn.drivers.lib.SystemCommands;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;

public class SCUtil implements Closeable {
	final static Logger LOG = LoggerFactory.getLogger(SCUtil.class);

	private String iface;
	private PrintWriter out;

	public SCUtil(SystemCommands commands, String iface) throws IOException {
		this.iface = iface;
		LOG.info("Running scutil");
		out = commands.privileged().logged().pipe(line -> {
            LOG.info("SCUTIL: {}", line);    
		}, "scutil");
	}
	
	public void compatible(String dnsServers[], String[] domains) {
		LOG.info("Creating compatible resolver");
		out.println(String.format("d.add ServerAddresses * %s", String.join(" ", dnsServers)));
		out.println(String.format("d.add SearchDomains %s", String.join(" ", domains)));
		out.println(String.format("set State:/Network/Service/%s/DNS", iface));
	}
	
	public void split(String dnsServers[], String[] domains) {
		LOG.info("Creating split resolver");
		out.println(String.format("d.add ServerAddresses * %s", String.join(" ", dnsServers)));
		out.println(String.format("d.add SupplementalMatchDomains * %s", String.join(" ", domains)));
		out.println(String.format("set State:/Network/Service/%s/DNS", iface));
	}
	
	public void remove() {
		LOG.info("Removing resolver");
		out.println(String.format("remove State:/Network/Service/%s/DNS", iface));
	}

	@Override
	public void close() throws IOException {
		out.println("quit");
		try {
		    out.close();
		}
		catch(UncheckedIOException uoe) {
		    throw uoe.getCause();
		}
	}

}
