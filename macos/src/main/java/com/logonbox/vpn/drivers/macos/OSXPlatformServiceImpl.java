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

import com.logonbox.vpn.drivers.lib.AbstractDesktopPlatformServiceImpl;
import com.logonbox.vpn.drivers.lib.ActiveSession;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.WireguardConfiguration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.NetworkInterface;
import java.util.Arrays;
import java.util.List;

public class OSXPlatformServiceImpl extends AbstractDesktopPlatformServiceImpl<OSXIP> {

	final static Logger LOG = LoggerFactory.getLogger(OSXPlatformServiceImpl.class);

	private static final String INTERFACE_PREFIX = "wg";

	public OSXPlatformServiceImpl() {
		super(INTERFACE_PREFIX);
	}

	@Override
	public String[] getMissingPackages() {
		return new String[0];
	}

    @Override
    protected void addRouteAll(WireguardConfiguration connection) throws IOException {
        LOG.info("Routing traffic all through VPN");
        String gw = getDefaultGateway();
        LOG.info(String.join(" ", Arrays.asList("route", "add", connection.getEndpointAddress(), "gw", gw)));
        commands().privileged().run("route", "add", connection.getEndpointAddress(), "gw", gw);
    }

    @Override
    protected void removeRouteAll(ActiveSession<OSXIP> session) throws IOException {
        LOG.info("Removing routing of all traffic through VPN");
        String gw = getDefaultGateway();
        LOG.info(String.join(" ", Arrays.asList("route", "del", session.connection().getEndpointAddress(), "gw", gw)));
        commands().privileged().run("route", "del", session.connection().getEndpointAddress(), "gw", gw);
    }

	@Override
	protected String getDefaultGateway() throws IOException {
		for(String line : commands().privileged().withOutput("route", "-n", "get", "default")) {
			line = line.trim();
			if(line.startsWith("gateway:")) {
				String[] args = line.split(":");
				if(args.length > 1)
					return args[1].trim();
			}
		}
		throw new IOException("Could not get default gateway.");
	}

	@Override
	protected OSXIP createVirtualInetAddress(NetworkInterface nif) {
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	protected OSXIP onConnect(ActiveSession<OSXIP> logonBoxVPNSession)
			throws IOException {
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public DNSIntegrationMethod dnsMethod() {
		return DNSIntegrationMethod.SCUTIL_COMPATIBLE;
	}

    @Override
    protected void runCommand(List<String> commands) throws IOException {
        commands().privileged().run(commands.toArray(new String[0]));
    }

}
