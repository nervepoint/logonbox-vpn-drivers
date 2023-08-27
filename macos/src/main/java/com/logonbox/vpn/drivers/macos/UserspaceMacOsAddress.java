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
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.lib.util.Util;

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
import java.util.Set;

public class UserspaceMacOsAddress extends AbstractVirtualInetAddress<UserspaceMacOsPlatformService> {
	enum IpAddressState {
		HEADER, IP, MAC
	}

	public final static String TABLE_AUTO = "auto";
	public final static String TABLE_MAIN = "main";
	public final static String TABLE_OFF = "off";

	private final static Logger LOG = LoggerFactory.getLogger(UserspaceMacOsAddress.class);

	private Set<String> addresses = new LinkedHashSet<>();
	private boolean autoRoute4;
	private boolean autoRoute6;

	UserspaceMacOsAddress(String name, UserspaceMacOsPlatformService platform) throws IOException {
		super(platform, name);
	}

	public void addAddress(String address) throws IOException {
		if (addresses.contains(address))
			throw new IllegalStateException(String.format("Interface %s already has address %s", name(), address));
		if (addresses.size() > 0 && Util.isNotBlank(peer()))
			throw new IllegalStateException(String.format(
					"Interface %s is configured to have a single peer %s, so cannot add a second address %s", name(),
					peer(), address));

		if (address.matches(".*:.*"))
			commands.privileged().logged().result(OsUtil.debugCommandArgs("ifconfig", name(), "inet6", address, "alias"));
		else
			commands.privileged().logged().result(OsUtil.debugCommandArgs("ifconfig", name(), "inet", address,
					address.replace("/*", ""), "alias"));
		addresses.add(address);
	}

	@Override
	public void delete() throws IOException {
		commands.privileged().logged().result(OsUtil.debugCommandArgs("rm", "-f", getSocketFile().getAbsolutePath()));
	}

	@Override
	public void down() throws IOException {
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
	public String displayName() {
		try {
			NetworkInterface iface = getByName(name());
			return iface == null ? "Unknown" : iface.getDisplayName();
		} catch (IOException ioe) {
			return "Unknown";
		}
	}

	@Override
	public String getMac() {
		try {
			NetworkInterface iface = getByName(name());
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
			throw new IllegalStateException(String.format("Interface %s not not have address %s", name(), address));
		if (addresses.size() > 0 && Util.isNotBlank(peer()))
			throw new IllegalStateException(String.format(
					"Interface %s is configured to have a single peer %s, so cannot add a second address %s", name(),
					peer(), address));

		commands.privileged().logged().result(OsUtil.debugCommandArgs("ifconfig", name(), "-alias", address));
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
//
//	@Override
//	public void setPeer(String peer) {
//		if (!Objects.equals(peer, this.peer())) {
//			if (Util.isNotBlank(peer) && addresses.size() > 1)
//				throw new IllegalStateException(String.format(
//						"Interface %s is already configured to have multiple addresses, so cannot have a single peer %s",
//						name(), peer));
//			super.setPeer(peer);
//		}
//	}

	public void setRoutes(Collection<String> allows) throws IOException {

		/* Remove all the current routes for this interface */
		var ipv6 = false;
		for (var row : commands.privileged().output(OsUtil.debugCommandArgs("netstat", "-nr"))) {
			var l = row.trim().split("\\s+");
			if (l[0].equals("Destination") || l[0].equals("Routing"))
				continue;
			if (l.length > 0 && l[0].equals("Internet6:")) {
				ipv6 = true;
			} else if (l.length > 3 && l[3].equals(name())) {
				var gateway = l[1];
				if (gateway.equals(name())) {
					if (getAddresses().isEmpty())
						continue;
					else
						gateway = getAddresses().iterator().next();
				}
				LOG.info("Removing route {} {} for {}", l[0], gateway, name());
				if (ipv6) {
					commands.privileged().logged().result(OsUtil.debugCommandArgs("route", "-qn", "delete", "-inet6", "-ifp",
							name(), l[0], gateway));
				} else {
					commands.privileged().logged().result(
							OsUtil.debugCommandArgs("route", "-qn", "delete", "-ifp", name(), l[0], gateway));
				}
			}
		}

		for (String route : allows) {
			addRoute(route);
		}
	}

	@Override
	public String toString() {
		return "Ip [name=" + name() + ", addresses=" + addresses + ", peer=" + peer() + "]";
	}

	@Override
	public void up() throws IOException {
		setMtu();

		commands.privileged().logged().result(OsUtil.debugCommandArgs("ifconfig", name(), "up"));
	}

	protected File getSocketFile() {
		return new File("/var/run/wireguard/" + name() + ".sock");
	}

	protected void setMtu() throws IOException {

		int currentMtu = 0;
		for (var line : commands.output(OsUtil.debugCommandArgs("ifconfig", name()))) {
			var parts = Arrays.asList(line.split("\\s+"));
			var idx = parts.indexOf("mtu");
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
			for (var line : commands.output(OsUtil.debugCommandArgs("netstat", "-nr", "-f", "inet"))) {
			    var arr = line.split("\\s+");
				if (arr[0].equals("default")) {
					defaultIf = arr[3];
					break;
				}
			}
			if (Util.isBlank(defaultIf))
				LOG.warn("Could not determine default interface to get MTU from.");
			else {
				for (var line : commands.output(OsUtil.debugCommandArgs("ifconfig", defaultIf))) {
				    var parts = Arrays.asList(line.split("\\s+"));
				    var idx = parts.indexOf("mtu");
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
			LOG.info("Setting MTU to {}", tmtu);
			commands.privileged().logged().result(OsUtil.debugCommandArgs("ifconfig", name(), "mtu", String.valueOf(tmtu)));
		} else
			LOG.info("MTU already set to {}", tmtu);
	}

	private void addRoute(String route) throws IOException {
		var proto = "inet";
		if (route.matches(".*:.*"))
			proto = "inet6";
		if (TABLE_OFF.equals(table()))
			return;

		if (route.endsWith("/0") && (Util.isBlank(table()) || TABLE_AUTO.equals(table()))) {
			if (route.matches(".*:.*")) {
				autoRoute6 = true;
				commands.privileged().logged().result(OsUtil.debugCommandArgs("route", "-q", "-n", "add", "-inet6", "::/1:",
						"-interface", name()));
				commands.privileged().logged().result(OsUtil.debugCommandArgs("route", "-q", "-m", "add", "-inet6", "8000::/1",
						"-interface", name()));
			} else {
				autoRoute4 = true;
				commands.privileged().logged().result(OsUtil.debugCommandArgs("route", "-q", "-n", "add", "-inet", "0.0.0.0/1",
						"-interface", name()));
				commands.privileged().logged().result(OsUtil.debugCommandArgs("route", "-q", "-m", "add", "-inet", "128.0.0.1/1",
						"-interface", name()));
			}
		} else {
			if (!TABLE_MAIN.equals(table()) && !TABLE_AUTO.equals(table()) && !Util.isBlank(table())) {
				throw new IOException("Darwin only supports TABLE=auto|main|off");
			}

			for (var line : commands.output(OsUtil.debugCommandArgs("route", "-n", "get", "-" + proto, route))) {
				line = line.trim();
				String[] args = line.split(":");
				if (args.length > 1 && args[0].equals("interface:") && args[1].equals(name())) {
					// Already have route
					return;
				}
			}

			LOG.info(String.format("Adding route %s to %s for %s", route, name(), proto));
			commands.privileged().logged().result(
					OsUtil.debugCommandArgs("route", "-q", "-n", "add", "-" + proto, route, "-interface", name()));
		}

	}
}
