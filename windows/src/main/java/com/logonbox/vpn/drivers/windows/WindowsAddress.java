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
package com.logonbox.vpn.drivers.windows;

import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.logonbox.vpn.drivers.lib.AbstractVirtualInetAddress;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.lib.util.Util;
import com.sshtools.liftlib.ElevatedClosure;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;

import uk.co.bithatch.nativeimage.annotations.Serialization;

public class WindowsAddress extends AbstractVirtualInetAddress<WindowsPlatformService> {
	enum IpAddressState {
		HEADER, IP, MAC
	}

	final static Logger LOG = LoggerFactory.getLogger(WindowsAddress.class);

	private Object lock = new Object();
	private String displayName;
	private Set<String> domainsAdded = new LinkedHashSet<String>();
	private final SystemCommands commands;

	public WindowsAddress(String name, String displayName, WindowsPlatformService platform) {
		super(platform, name);
		this.displayName = displayName;
		commands = platform.commands();
	}

	@Override
	public void delete() throws IOException {
		synchronized (lock) {
			if (isUp()) {
				down();
			}
			try {
				commands.privileged().logged().task(new Uninstall(getServiceName()));
			} catch (IOException ioe) {
				throw ioe;
			} catch (Exception e) {
				throw new IllegalStateException("Failed to delete.", e);
			}
		}
	}

	@Override
	public void down() throws IOException {
		synchronized (lock) {
			try {
				unsetDns();
				commands.privileged().logged().task(new Stop(getServiceName()));
			} catch (IOException ioe) {
				throw ioe;
			} catch (Exception e) {
				throw new IllegalStateException("Failed to delete.", e);
			}
		}
	}

	@Override
	public boolean isUp() {
		synchronized (lock) {
			try {
				return commands.privileged().logged().task(new IsRunning(getServiceName()));
			} catch (Exception e) {
				return false;
			}
		}
	}

	protected String getServiceName() {
		return WindowsPlatformService.TUNNEL_SERVICE_NAME_PREFIX + "$" + name();
	}

	@Override
	public String toString() {
		return "Ip [name=" + name() + ", peer=" + peer() + "]";
	}

	@Override
	public void up() throws IOException {
		synchronized (lock) {
			try {
				commands.privileged().logged().task(new Start(getServiceName()));

				var tmtu = this.getMtu();

				if (tmtu == 0) {
					/* TODO detect */

					/* Still not found, use generic default */
					if (tmtu == 0)
						tmtu = 1500;

					/* Subtract 80, because .. */
					tmtu -= 80;
				}

				commands.privileged().logged().result("netsh", "interface", "ipv4", "set", "subinterface", name(),
						"mtu=" + String.valueOf(tmtu), "store=persistent");
			} catch (IOException e) {
				throw e;
			} catch (Exception e) {
				throw new IOException("Failed to bring up interface service.", e);
			}
		}
	}

	@Override
	public String getMac() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String displayName() {
		return displayName;
	}

	@Override
	public void dns(String[] dns) throws IOException {
		if (dns == null || dns.length == 0) {
			unsetDns();
		} else {
			var method = platform.calcDnsMethod();
			try {
				LOG.info("Setting DNS for {} to {} using {}", name(), String.join(", ", dns), method);
				switch (method) {
				case NETSH:
					/* Ipv4 */
					var dnsAddresses = IpUtil.filterIpV4Addresses(dns);
					if (dnsAddresses.length > 2) {
						LOG.warn(
								"Windows only supports a maximum of 2 DNS servers. {} were supplied, the last {} will be ignored.",
								dnsAddresses.length, dnsAddresses.length - 2);
					}

					commands.privileged().logged().result(OsUtil.debugCommandArgs("netsh", "interface", "ipv4",
							"delete", "dnsservers", name(), "all"));
					if (dnsAddresses.length > 0) {
						commands.privileged().logged().result(OsUtil.debugCommandArgs("netsh", "interface", "ipv4",
								"add", "dnsserver", name(), dnsAddresses[0], "index=1", "no"));
					}
					if (dnsAddresses.length > 1) {
						commands.privileged().logged().result(OsUtil.debugCommandArgs("netsh", "interface", "ipv4",
								"add", "dnsserver", name(), dnsAddresses[1], "index=2", "no"));
					}

					/* Ipv6 */
					dnsAddresses = IpUtil.filterIpV6Addresses(dns);
					if (dnsAddresses.length > 2) {
						LOG.warn(
								"Windows only supports a maximum of 2 DNS servers. {} were supplied, the last {} will be ignored.",
								dnsAddresses.length, dnsAddresses.length - 2);
					}

					commands.privileged().logged().result(OsUtil.debugCommandArgs("netsh", "interface", "ipv6",
							"delete", "dnsservers", name(), "all"));
					if (dnsAddresses.length > 0) {
						commands.privileged().logged().result(OsUtil.debugCommandArgs("netsh", "interface", "ipv6",
								"add", "dnsserver", name(), dnsAddresses[0], "index=1", "no"));
					}
					if (dnsAddresses.length > 1) {
						commands.privileged().logged().result(OsUtil.debugCommandArgs("netsh", "interface", "ipv6",
								"add", "dnsserver", name(), dnsAddresses[1], "index=2", "no"));
					}

					var dnsNames = IpUtil.filterNames(dns);
					String currentDomains = null;
					try {
						currentDomains = Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE,
								"System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList");
					} catch (Exception e) {
						//
					}
					var newDomainList = new LinkedHashSet<String>(Util.isBlank(currentDomains) ? Collections.emptySet()
							: Arrays.asList(currentDomains.split(",")));
					for (var dnsName : dnsNames) {
						if (!newDomainList.contains(dnsName)) {
							LOG.info("Adding domain {} to search", dnsName);
							newDomainList.add(dnsName);
						}
					}
					var newDomains = String.join(",", newDomainList);
					if (!Objects.equals(currentDomains, newDomains)) {
						domainsAdded.clear();
						domainsAdded.addAll(newDomainList);
						LOG.info("Final domain search {}", newDomains);
						Advapi32Util.registrySetStringValue(WinReg.HKEY_LOCAL_MACHINE,
								"System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList", newDomains);
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

	private void unsetDns() {
		var currentDomains = Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE,
				"System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList");
		var currentDomainList = new LinkedHashSet<String>(
				Util.isBlank(currentDomains) ? Collections.emptySet() : Arrays.asList(currentDomains));
		for (var dnsName : domainsAdded) {
			LOG.info(String.format("Removing domain %s from search", dnsName));
			currentDomainList.remove(dnsName);
		}
		var newDomains = String.join(",", currentDomainList);
		if (!Objects.equals(currentDomains, newDomains)) {
			LOG.info("Final domain search {}", newDomains);
			Advapi32Util.registrySetStringValue(WinReg.HKEY_LOCAL_MACHINE,
					"System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList", newDomains);
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class Uninstall implements ElevatedClosure<Serializable, Serializable> {

		private String name;

		public Uninstall() {
		}

		private Uninstall(String name) {
			this.name = name;
		}

		@Override
		public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
			try (var srvs = new WindowsSystemServices()) {
				srvs.getService(name).uninstall();
			}
			return null;
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class Stop implements ElevatedClosure<Serializable, Serializable> {

		private String name;

		public Stop() {
		}

		private Stop(String name) {
			this.name = name;
		}

		@Override
		public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
			try (var srvs = new WindowsSystemServices()) {
				srvs.getService(name).stop();
			}
			return null;
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class Start implements ElevatedClosure<Serializable, Serializable> {

		private String name;

		public Start() {
		}

		private Start(String name) {
			this.name = name;
		}

		@Override
		public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
			try (var srvs = new WindowsSystemServices()) {
				srvs.getService(name).start();
			}
			return null;
		}
	}
	@SuppressWarnings("serial")
	@Serialization
	public final static class IsRunning implements ElevatedClosure<Boolean, Serializable> {

		private String name;

		public IsRunning() {
		}

		private IsRunning(String name) {
			this.name = name;
		}

		@Override
		public Boolean call(ElevatedClosure<Boolean, Serializable> proxy) throws Exception {
			try (var srvs = new WindowsSystemServices()) {
				return srvs.getService(name).getStatus().isRunning();
			}
		}
	}
}
