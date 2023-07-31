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

import com.logonbox.vpn.drivers.lib.AbstractVirtualInetAddress;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.sshtools.forker.services.Service;
import com.sshtools.forker.services.Services;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public class WindowsIP extends AbstractVirtualInetAddress<WindowsPlatformServiceImpl> {
	enum IpAddressState {
		HEADER, IP, MAC
	}

	final static Logger LOG = LoggerFactory.getLogger(WindowsIP.class);

	private Object lock = new Object();
	private String displayName;
	private Set<String> domainsAdded = new LinkedHashSet<String>();
	private final SystemCommands commands;
	
	public WindowsIP(String name, String displayName, WindowsPlatformServiceImpl platform) {
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
			getPlatform().uninstall(getServiceName());
		}
	}

	@Override
	public void down() throws IOException {
		synchronized (lock) {
			try {
				unsetDns();
				Services.get().stopService(getService());
			} catch (IOException ioe) {
				throw ioe;
			} catch (Exception e) {
				throw new IOException("Failed to take interface down.", e);
			}
		}
	}

	@Override
	public boolean isUp() {
		synchronized (lock) {
			try {
				return getService().getStatus().isRunning();
			} catch (IOException e) {
				return false;
			}
		}
	}

	protected Service getService() throws IOException {
		Service service = Services.get().getService(getServiceName());
		if (service == null)
			throw new IOException(String.format("No service for interface %s.", getName()));
		return service;
	}

	protected String getServiceName() {
		return WindowsPlatformServiceImpl.TUNNEL_SERVICE_NAME_PREFIX + "$" + getName();
	}

	public boolean isInstalled() {
		synchronized (lock) {
			try {
				getService();
				return true;
			} catch (IOException ioe) {
				return false;
			}
		}
	}

	@Override
	public String toString() {
		return "Ip [name=" + getName() + ", peer=" + getPeer() + "]";
	}

	@Override
	public void up() throws IOException {
		synchronized (lock) {
			try {
				Services.get().startService(getService());

				var tmtu = this.getMtu(); 
				
				if(tmtu == 0) {
					/* TODO detect */
						
					/* Still not found, use generic default */
					if (tmtu == 0)
						tmtu = 1500;
	
					/* Subtract 80, because .. */
					tmtu -= 80;
				}

				commands.privileged().withResult("netsh", "interface", "ipv4", "set", "subinterface", getName(), "mtu=" + String.valueOf(tmtu), "store=persistent");
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
	public String getDisplayName() {
		return displayName;
	}

	@Override
	public void dns(String[] dns) throws IOException {
		if (dns == null || dns.length == 0) {
			unsetDns();
		} else {
			DNSIntegrationMethod method = calcDnsMethod();
			try {
				LOG.info(String.format("Setting DNS for %s to %s using %s", getName(),
						String.join(", ", dns), method));
				switch (method) {
				case NETSH:
					/* Ipv4 */
					String[] dnsAddresses = IpUtil.filterIpV4Addresses(dns);
					if(dnsAddresses.length > 2) {
						LOG.warn("Windows only supports a maximum of 2 DNS servers. {} were supplied, the last {} will be ignored.", dnsAddresses.length, dnsAddresses.length - 2);
					}

					commands.privileged().withResult(OsUtil.debugCommandArgs("netsh", "interface", "ipv4", "delete", "dnsservers", getName(), "all"));
					if(dnsAddresses.length > 0) {
					    commands.privileged().withResult(OsUtil.debugCommandArgs("netsh", "interface", "ipv4", "add", "dnsserver", getName(), dnsAddresses[0], "index=1", "no"));	
					} 
					if(dnsAddresses.length > 1) {
					    commands.privileged().withResult(OsUtil.debugCommandArgs("netsh", "interface", "ipv4", "add", "dnsserver", getName(), dnsAddresses[1], "index=2", "no"));	
					} 

					/* Ipv6 */
					dnsAddresses = IpUtil.filterIpV6Addresses(dns);
					if(dnsAddresses.length > 2) {
						LOG.warn("Windows only supports a maximum of 2 DNS servers. {} were supplied, the last {} will be ignored.", dnsAddresses.length, dnsAddresses.length - 2);
					}

					commands.privileged().withResult(OsUtil.debugCommandArgs("netsh", "interface", "ipv6", "delete", "dnsservers", getName(), "all"));
					if(dnsAddresses.length > 0) {
					    commands.privileged().withResult(OsUtil.debugCommandArgs("netsh", "interface", "ipv6", "add", "dnsserver", getName(), dnsAddresses[0], "index=1", "no"));	
					} 
					if(dnsAddresses.length > 1) {
					    commands.privileged().withResult(OsUtil.debugCommandArgs("netsh", "interface", "ipv6", "add", "dnsserver", getName(), dnsAddresses[1], "index=2", "no"));	
					} 

					String[] dnsNames = IpUtil.filterNames(dns);
					String currentDomains = null;
					try {
						currentDomains = Advapi32Util.registryGetStringValue
				                (WinReg.HKEY_LOCAL_MACHINE,
				                        "System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList");
					}
					catch(Exception e) {
						//
					}
					Set<String> newDomainList = new LinkedHashSet<>(StringUtils.isBlank(currentDomains) ? Collections.emptySet() : Arrays.asList(currentDomains.split(",")));
					for(String dnsName : dnsNames) {
						if(!newDomainList.contains(dnsName)) {
							LOG.info(String.format("Adding domain %s to search", dnsName));
							newDomainList.add(dnsName);
						}
					}
					String newDomains = String.join(",", newDomainList);
					if(!Objects.equals(currentDomains, newDomains)) {
						domainsAdded.clear();
						domainsAdded.addAll(newDomainList);
						LOG.info(String.format("Final domain search %s", newDomains));
						Advapi32Util.registrySetStringValue
			            (WinReg.HKEY_LOCAL_MACHINE,
			                    "System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList", newDomains);
					}
					break;
				case NONE:
					break;
				default:
					throw new UnsupportedOperationException(String.format("DNS integration method %s not supported.", method));
				}
			}
			finally {
				LOG.info("Done setting DNS");
			}
		}
		
	}

	private void unsetDns() {
		String currentDomains = Advapi32Util.registryGetStringValue
                (WinReg.HKEY_LOCAL_MACHINE,
                        "System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList");
		Set<String> currentDomainList = new LinkedHashSet<>(StringUtils.isBlank(currentDomains) ? Collections.emptySet() : Arrays.asList(currentDomains));
		for(String dnsName : domainsAdded) {
			LOG.info(String.format("Removing domain %s from search", dnsName));
			currentDomainList.remove(dnsName);
		}
		String newDomains = String.join(",", currentDomainList);
		if(!Objects.equals(currentDomains, newDomains)) {
			LOG.info(String.format("Final domain search %s", newDomains));
			Advapi32Util.registrySetStringValue
            (WinReg.HKEY_LOCAL_MACHINE,
                    "System\\CurrentControlSet\\Services\\TCPIP\\Parameters", "SearchList", newDomains);
		}		
	}
}
