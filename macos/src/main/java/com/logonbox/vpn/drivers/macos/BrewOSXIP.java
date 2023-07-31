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

import com.logonbox.vpn.drivers.lib.AbstractVirtualInetAddress;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.macos.OSXNetworksetupDNS.InterfaceDNS;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class BrewOSXIP extends AbstractVirtualInetAddress<BrewOSXPlatformServiceImpl> {
	enum IpAddressState {
		HEADER, IP, MAC
	}

	public final static String TABLE_AUTO = "auto";
	public final static String TABLE_MAIN = "main";
	public final static String TABLE_OFF = "off";

	private final static Logger LOG = LoggerFactory.getLogger(BrewOSXIP.class);

	private Set<String> addresses = new LinkedHashSet<>();
	private boolean autoRoute4;
	private boolean autoRoute6;
    private OSXNetworksetupDNS osxDns;

	public BrewOSXIP(String name, BrewOSXPlatformServiceImpl platform) throws IOException {
		super(platform, name);
	}

	public void addAddress(String address) throws IOException {
		if (addresses.contains(address))
			throw new IllegalStateException(String.format("Interface %s already has address %s", getName(), address));
		if (addresses.size() > 0 && StringUtils.isNotBlank(getPeer()))
			throw new IllegalStateException(String.format(
					"Interface %s is configured to have a single peer %s, so cannot add a second address %s", getName(),
					getPeer(), address));

		if (address.matches(".*:.*"))
			commands.privileged().withResult(OsUtil.debugCommandArgs("ifconfig", getName(), "inet6", address, "alias"));
		else
			commands.privileged().withResult(OsUtil.debugCommandArgs("ifconfig", getName(), "inet", address,
					address.replace("/*", ""), "alias"));
		addresses.add(address);
	}

	@Override
	public void delete() throws IOException {
		commands.privileged().withResult(OsUtil.debugCommandArgs("rm", "-f", getSocketFile().getAbsolutePath()));
	}

	protected File getSocketFile() {
		return new File("/var/run/wireguard/" + getName() + ".sock");
	}

	public void dns(String[] dns) throws IOException {
		if (dns == null || dns.length == 0) {
			unsetDns();
		} else {
			DNSIntegrationMethod method = calcDnsMethod();
			try {
				LOG.info(String.format("Setting DNS for %s to %s using %s", getName(), String.join(", ", dns), method));
				switch (method) {
				case NETWORKSETUP:
				    OSXNetworksetupDNS.get().changeDns(new InterfaceDNS(getName(), dns));
					break;
				case SCUTIL_COMPATIBLE:
					try (SCUtil scutil = new SCUtil(commands, getName())) {
						scutil.compatible(IpUtil.filterAddresses(dns), IpUtil.filterNames(dns));
					}
					break;
				case SCUTIL_SPLIT:
					try (SCUtil scutil = new SCUtil(commands,getName())) {
						scutil.split(IpUtil.filterAddresses(dns), IpUtil.filterNames(dns));
					}
					break;
				case NONE:
					break;
				default:
					throw new UnsupportedOperationException(
							String.format("DNS integration method %s not supported.", method));
				}
			} finally {
				LOG.info("Done setting DNS");
			}
		}
	}

    @Override
	public void down() throws IOException {
		unsetDns();
		/*
		 * TODO
		 * 
		 * [[ $HAVE_SET_FIREWALL -eq 0 ]] || remove_firewall
		 * 
		 * TODO
		 * 
		 * if [[ -z $TABLE || $TABLE == auto ]] && get_fwmark table && [[ $(wg show
		 * "$INTERFACE" allowed-ips) =~ /0(\ |$'\n'|$) ]]; then while [[ $(ip -4 rule
		 * show 2>/dev/null) == *"lookup $table"* ]]; do cmd ip -4 rule delete table
		 * $table done while [[ $(ip -4 rule show 2>/dev/null) ==
		 * *"from all lookup main suppress_prefixlength 0"* ]]; do cmd ip -4 rule delete
		 * table main suppress_prefixlength 0 done while [[ $(ip -6 rule show
		 * 2>/dev/null) == *"lookup $table"* ]]; do cmd ip -6 rule delete table $table
		 * done while [[ $(ip -6 rule show 2>/dev/null) ==
		 * *"from all lookup main suppress_prefixlength 0"* ]]; do cmd ip -6 rule delete
		 * table main suppress_prefixlength 0 done fi cmd ip link delete dev
		 * "$INTERFACE"
		 */
		setRoutes(new ArrayList<>());
	}

	public Set<String> getAddresses() {
		return addresses;
	}

	@Override
	public String getDisplayName() {
		try {
			NetworkInterface iface = getByName(getName());
			return iface == null ? "Unknown" : iface.getDisplayName();
		} catch (IOException ioe) {
			return "Unknown";
		}
	}

	@Override
	public String getMac() {
		try {
			NetworkInterface iface = getByName(getName());
			return iface == null ? null : IpUtil.toIEEE802(iface.getHardwareAddress());
		} catch (IOException ioe) {
			return null;
		}
	}

	public boolean hasAddress(String address) {
		return addresses.contains(address);
	}

	public boolean isAutoRoute4() {
		return autoRoute4;
	}

	public boolean isAutoRoute6() {
		return autoRoute6;
	}

	@Override
	public boolean isUp() {
		return getSocketFile().exists();
	}

	public void removeAddress(String address) throws IOException {
		if (!addresses.contains(address))
			throw new IllegalStateException(String.format("Interface %s not not have address %s", getName(), address));
		if (addresses.size() > 0 && StringUtils.isNotBlank(getPeer()))
			throw new IllegalStateException(String.format(
					"Interface %s is configured to have a single peer %s, so cannot add a second address %s", getName(),
					getPeer(), address));

		commands.privileged().withResult(OsUtil.debugCommandArgs("ifconfig", getName(), "-alias", address));
		addresses.remove(address);
	}

	public void setAddresses(String... addresses) {
		List<String> addr = Arrays.asList(addresses);
		List<Exception> exceptions = new ArrayList<>();
		for (String a : addresses) {
			if (!hasAddress(a)) {
				try {
					addAddress(a);
				} catch (Exception e) {
					exceptions.add(e);
				}
			}
		}

		for (String a : new ArrayList<>(this.addresses)) {
			if (!addr.contains(a)) {
				try {
					removeAddress(a);
				} catch (Exception e) {
					exceptions.add(e);
				}
			}
		}

		if (!exceptions.isEmpty()) {
			Exception e = exceptions.get(0);
			if (e instanceof RuntimeException)
				throw (RuntimeException) e;
			else
				throw new IllegalArgumentException("Failed to set addresses.", e);
		}
	}

	public void setEndpointDirectRoute() {
		// TODO
		LOG.warn("TODO: setEndpointDirectRoute() not implemented.");
	}

	@Override
	public void setPeer(String peer) {
		if (!Objects.equals(peer, this.getPeer())) {
			if (StringUtils.isNotBlank(peer) && addresses.size() > 1)
				throw new IllegalStateException(String.format(
						"Interface %s is already configured to have multiple addresses, so cannot have a single peer %s",
						getName(), peer));
			super.setPeer(peer);
		}
	}

	public void setRoutes(Collection<String> allows) throws IOException {

		/* Remove all the current routes for this interface */
		boolean ipv6 = false;
		for (String row : commands.privileged().withOutput(OsUtil.debugCommandArgs("netstat", "-nr"))) {
			String[] l = row.trim().split("\\s+");
			if (l[0].equals("Destination") || l[0].equals("Routing"))
				continue;
			if (l.length > 0 && l[0].equals("Internet6:")) {
				ipv6 = true;
			} else if (l.length > 3 && l[3].equals(getName())) {
				String gateway = l[1];
				if (gateway.equals(getName())) {
					if (getAddresses().isEmpty())
						continue;
					else
						gateway = getAddresses().iterator().next();
				}
				LOG.info(String.format("Removing route %s %s for %s", l[0], gateway, getName()));
				if (ipv6) {
					commands.privileged().withResult(OsUtil.debugCommandArgs("route", "-qn", "delete", "-inet6", "-ifp",
							getName(), l[0], gateway));
				} else {
					commands.privileged().withResult(
							OsUtil.debugCommandArgs("route", "-qn", "delete", "-ifp", getName(), l[0], gateway));
				}
			}
		}

		for (String route : allows) {
			addRoute(route);
		}
	}

	@Override
	public String toString() {
		return "Ip [name=" + getName() + ", addresses=" + addresses + ", peer=" + getPeer() + "]";
	}

	@Override
	public void up() throws IOException {
		setMtu();

		commands.privileged().withResult(OsUtil.debugCommandArgs("ifconfig", getName(), "up"));
	}

	protected void setMtu() throws IOException {

		int currentMtu = 0;
		for (String line : commands.withOutput(OsUtil.debugCommandArgs("ifconfig", getName()))) {
			List<String> parts = Arrays.asList(line.split("\\s+"));
			int idx = parts.indexOf("mtu");
			if (idx == -1 && idx < parts.size() - 1)
				LOG.warn("Could not find MTU on vpn interface");
			else
				currentMtu = Integer.parseInt(parts.get(idx + 1));
			break;
		}

		int tmtu = 0;
		if (getMtu() > 0) {
			tmtu = getMtu();
		} else {
			String defaultIf = null;
			for (String line : commands.withOutput(OsUtil.debugCommandArgs("netstat", "-nr", "-f", "inet"))) {
				String[] arr = line.split("\\s+");
				if (arr[0].equals("default")) {
					defaultIf = arr[3];
					break;
				}
			}
			if (StringUtils.isBlank(defaultIf))
				LOG.warn("Could not determine default interface to get MTU from.");
			else {
				for (String line : commands.withOutput(OsUtil.debugCommandArgs("ifconfig", defaultIf))) {
					List<String> parts = Arrays.asList(line.split("\\s+"));
					int idx = parts.indexOf("mtu");
					if (idx == -1 && idx < parts.size() - 1)
						LOG.warn("Could not find MTU on default interface");
					else
						tmtu = Integer.parseInt(parts.get(idx + 1));
					break;
				}
			}

			/* Still not found, use generic default */
			if (tmtu == 0)
				tmtu = 1500;

			/* Subtract 80, because .. */
			tmtu -= 80;
		}

		/* Bring it up! */
		if (currentMtu > 0 && tmtu != currentMtu) {
			LOG.info(String.format("Setting MTU to %d", tmtu));
			commands.privileged().withResult(OsUtil.debugCommandArgs("ifconfig", getName(), "mtu", String.valueOf(tmtu)));
		} else
			LOG.info(String.format("MTU already set to %d", tmtu));
	}

	private void addRoute(String route) throws IOException {
		String proto = "inet";
		if (route.matches(".*:.*"))
			proto = "inet6";
		if (TABLE_OFF.equals(getTable()))
			return;

		if (route.endsWith("/0") && (StringUtils.isBlank(getTable()) || TABLE_AUTO.equals(getTable()))) {
			if (route.matches(".*:.*")) {
				autoRoute6 = true;
				commands.privileged().withResult(OsUtil.debugCommandArgs("route", "-q", "-n", "add", "-inet6", "::/1:",
						"-interface", getName()));
				commands.privileged().withResult(OsUtil.debugCommandArgs("route", "-q", "-m", "add", "-inet6", "8000::/1",
						"-interface", getName()));
			} else {
				autoRoute4 = true;
				commands.privileged().withResult(OsUtil.debugCommandArgs("route", "-q", "-n", "add", "-inet", "0.0.0.0/1",
						"-interface", getName()));
				commands.privileged().withResult(OsUtil.debugCommandArgs("route", "-q", "-m", "add", "-inet", "128.0.0.1/1",
						"-interface", getName()));
			}
		} else {
			if (!TABLE_MAIN.equals(getTable()) && !TABLE_AUTO.equals(getTable()) && !StringUtils.isBlank(getTable())) {
				throw new IOException("Darwin only supports TABLE=auto|main|off");
			}

			for (String line : commands.withOutput(OsUtil.debugCommandArgs("route", "-n", "get", "-" + proto, route))) {
				line = line.trim();
				String[] args = line.split(":");
				if (args.length > 1 && args[0].equals("interface:") && args[1].equals(getName())) {
					// Already have route
					return;
				}
			}

			LOG.info(String.format("Adding route %s to %s for %s", route, getName(), proto));
			commands.privileged().withResult(
					OsUtil.debugCommandArgs("route", "-q", "-n", "add", "-" + proto, route, "-interface", getName()));
		}

	}

	private void unsetDns() throws IOException {
		LOG.info(String.format("unsetting DNS for %s (iface prefix %s)", getName(),
				getPlatform().resolvconfIfacePrefix()));
		switch (calcDnsMethod()) {
		case NETWORKSETUP:
			if (OSXNetworksetupDNS.get().isSet(getName())) {
			    OSXNetworksetupDNS.get().popDns(getName());
			}
			break;
		case SCUTIL_SPLIT:
		case SCUTIL_COMPATIBLE:
			try (SCUtil scutil = new SCUtil(commands, getName())) {
				scutil.remove();
			}
			break;
		case NONE:
			break;
		default:
			throw new UnsupportedOperationException();
		}
	}
}
