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
package com.logonbox.vpn.drivers.linux;

import com.github.jgonian.ipmath.Ipv4;
import com.logonbox.vpn.drivers.lib.AbstractVirtualInetAddress;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.lib.util.Util;
import com.logonbox.vpn.drivers.linux.dbus.NetworkManager;
import com.logonbox.vpn.drivers.linux.dbus.NetworkManager.Ipv6Address;
import com.logonbox.vpn.drivers.linux.dbus.Resolve1Manager;

import org.apache.commons.lang3.StringUtils;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.Properties;
import org.freedesktop.dbus.types.UInt32;
import org.freedesktop.dbus.types.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class LinuxIP extends AbstractVirtualInetAddress<LinuxPlatformServiceImpl> {
	private static final String TABLE_PREFIX = "logonbox-vpn-";
	private static final String NETWORK_MANAGER_BUS_NAME = "org.freedesktop.NetworkManager";

	enum IpAddressState {
		HEADER, IP, MAC
	}

	public final static String TABLE_AUTO = "auto";
	public final static String TABLE_OFF = "off";

	final static Logger LOG = LoggerFactory.getLogger(LinuxIP.class);

	private static final String END_HYPERSOCKET_WIREGUARD_RESOLVCONF = "###### END-HYPERSOCKET-WIREGUARD ######";
	private static final String START_HYPERSOCKET_WIREGUARD_RESOLVECONF = "###### START-HYPERSOCKET-WIREGUARD ######";

	private Set<String> addresses = new LinkedHashSet<>();
	private boolean haveSetFirewall;
	private boolean dnsSet;

	public LinuxIP(String name, LinuxPlatformServiceImpl platform) {
		super(platform, name);
	}

	public void addAddress(String address) throws IOException {
		if (addresses.contains(address))
			throw new IllegalStateException(String.format("Interface %s already has address %s", getName(), address));
		if (addresses.size() > 0 && StringUtils.isNotBlank(getPeer()))
			throw new IllegalStateException(String.format(
					"Interface %s is configured to have a single peer %s, so cannot add a second address %s", getName(),
					getPeer(), address));

		if (StringUtils.isNotBlank(getPeer())) {
            commands.privileged().withResult("ip", "address", "add", "dev", getName(), address, "peer", getPeer());
        } else
            commands.privileged().withResult("ip", "address", "add", "dev", getName(), address);
		addresses.add(address);
	}

	@Override
	public void delete() throws IOException {
		if(dnsSet) {
			unsetDns();
		}
		if(haveSetFirewall) {
			removeFirewall();
		}
		String table = getTable();
		int fwmark = getFWMark("table");
		if((StringUtils.isBlank(table) || table.equals(TABLE_AUTO)) && fwmark > -1 /* && [[ $(wg show "$INTERFACE" allowed-ips) =~ /0(\ |$'\n'|$) ]] */) {
			while(commandOutputMatches(".*lookup " + fwmark + ".*", "ip", "-4", "rule", "show")) {
				commands.privileged().withResult("ip", "-4", "rule", "delete", "table", String.valueOf(fwmark));
			}
			while(commandOutputMatches(".*from all lookup main suppress_prefixlength 0.*", "ip", "-4", "rule", "show")) {
			    commands.privileged().withResult("ip", "-4", "rule", "delete", "table", "main", "suppress_prefixlength", "0");
			}
			while(commandOutputMatches(".*lookup " + fwmark + ".*", "ip", "-6", "rule", "show")) {
			    commands.privileged().withResult("ip", "-6", "rule", "delete", "table", String.valueOf(fwmark));
			}
			while(commandOutputMatches(".*from all lookup main suppress_prefixlength 0.*", "ip", "-6", "rule", "show")) {
			    commands.privileged().withResult("ip", "-6", "rule", "delete", "table", "main", "suppress_prefixlength", "0");
			}	
		}

		commands.privileged().withResult("ip", "link", "del", "dev", getName());
	}
	
	private boolean commandOutputMatches(String pattern, String... args) throws IOException {
		for(String line : commands.privileged().withOutput(args)) {
			if(line.matches(pattern))
				return true;
		}
		return false;
	}

	public void dns(String[] dns) throws IOException {
		if (dns == null || dns.length == 0) {
			if (dnsSet)
				unsetDns();
		} else {
			DNSIntegrationMethod method = calcDnsMethod();
			LOG.info(String.format("Setting DNS for %s (iface prefix %s) to %s using %s", getName(),
					getPlatform().resolvconfIfacePrefix(), String.join(", ", dns), method));
			switch (method) {
			case NETWORK_MANAGER:
				updateNetworkManager(dns);
				break;
			case RESOLVCONF:
				updateResolvConf(dns);
				break;
			case SYSTEMD:
				updateSystemd(dns);
				break;
			case RAW:
				updateResolvDotConf(dns);
				break;
			case NONE:
				break;
			default:
				/* TODO */
				throw new UnsupportedOperationException();
			}

			dnsSet = true;
		}
	}

	@Override
	public void down() throws IOException {
		if (dnsSet) {
			unsetDns();
		}
		
		if(haveSetFirewall) {
			removeFirewall();
		}

		setRoutes(new ArrayList<>());
	}

	public boolean hasAddress(String address) {
		return addresses.contains(address);
	}

	@Override
	public boolean isUp() {
		return true;
	}

	public void removeAddress(String address) throws IOException {
		if (!addresses.contains(address))
			throw new IllegalStateException(String.format("Interface %s not not have address %s", getName(), address));
		if (addresses.size() > 0 && StringUtils.isNotBlank(getPeer()))
			throw new IllegalStateException(String.format(
					"Interface %s is configured to have a single peer %s, so cannot add a second address %s", getName(),
					getPeer(), address));

		commands.privileged().withResult("ip", "address", "del", address, "dev", getName());
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
		var have = new HashSet<>();
		for (String row : commands.privileged().withOutput("ip", "route", "show", "dev", getName())) {
			String[] l = row.split("\\s+");
			if (l.length > 0) {
				have.add(l[0]);
				if(!allows.contains(l[0])) {
					LOG.info(String.format("Removing route %s for %s", l[0], getName()));
					commands.privileged().withResult("ip", "route", "del", l[0], "dev", getName());
				}
			}
		}

		for (String route : allows) {
			if(!have.contains(route))
				addRoute(route);
		}
	}

	@Override
	public String toString() {
		return "Ip [name=" + getName() + ", addresses=" + addresses + ", peer=" + getPeer() + "]";
	}

	@Override
	public void up() throws IOException {
		if (getMtu() > 0) {
		    commands.privileged().withResult("ip", "link", "set", "mtu", String.valueOf(getMtu()), "up", "dev", getName());
		} else {
			/*
			 * First detect MTU, then bring up. First try from existing Wireguard
			 * connections?
			 */
			int tmtu = 0;
			// TODO
//				for (String line : OSCommand.runCommandAndCaptureOutput("wg", "show", name, "endpoints")) {
//				 [[ $endpoint =~ ^\[?([a-z0-9:.]+)\]?:[0-9]+$ ]] || continue
//	                output="$(ip route get "${BASH_REMATCH[1]}" || true)"
//	                [[ ( $output =~ mtu\ ([0-9]+) || ( $output =~ dev\ ([^ ]+) && $(ip link show dev "${BASH_REMATCH[1]}") =~ mtu\ ([0-9]+) ) ) && ${BASH_REMATCH[1]} -gt $mtu ]] && mtu="${BASH_REMATCH[1]}"
			// TODO
//				}

			if (tmtu == 0) {
				/* Not found, try the default route */
				for (String line : commands.privileged().withOutput("ip", "route", "show", "default")) {
					StringTokenizer t = new StringTokenizer(line);
					while (t.hasMoreTokens()) {
						String tk = t.nextToken();
						if (tk.equals("dev")) {
							for (String iline : commands.privileged().withOutput("ip", "link", "show", "dev",
									t.nextToken())) {
								StringTokenizer it = new StringTokenizer(iline);
								while (it.hasMoreTokens()) {
									String itk = it.nextToken();
									if (itk.equals("mtu")) {
										tmtu = Integer.parseInt(it.nextToken());
										break;
									}
								}
								break;
							}
							break;
						}
					}
					break;
				}
			}

			/* Still not found, use generic default */
			if (tmtu == 0)
				tmtu = 1500;

			/* Subtract 80, because .. */
			tmtu -= 80;

			/* Bring it up! */
			commands.privileged().withResult("ip", "link", "set", "mtu", String.valueOf(tmtu), "up", "dev", getName());
		}
	}
	
	private void removeFirewall() throws IOException {
		if(OsUtil.doesCommandExist("nft")) {
			StringBuilder nftcmd = new StringBuilder();
			for(String table : commands.privileged().withOutput("nft", "list", "tables")) {
				if(table.contains(TABLE_PREFIX)) {
					nftcmd.append(String.format("%s\n", table));
				}	
			}
			if(nftcmd.length() > 0) {
			    commands.privileged().pipeTo(nftcmd.toString(), "nft", "-f");
			}
		}
		if(OsUtil.doesCommandExist("iptables")) {
			for(String iptables : new String[] {"iptables", "ip6tables"}) {
				StringBuilder restore = new StringBuilder();
				boolean found = false;
				for(String line : commands.privileged().withOutput(iptables + "-save")) {
					if(line.startsWith("*") || line.equals("COMMIT") || line.matches("-A .*-m comment --comment \"LogonBoxVPN rule for " + getName() + ".*"))
						continue;
					if(line.startsWith("-A"))
						found = true;
					restore.append(String.format("%s\n", line.replace("#-A", "-D"))); // TODO is this really #-A?
				}
				if(found) {
				    commands.privileged().pipeTo(restore.toString(), iptables + "-restore", "-n");
				}
			}
		}

		
	}

	private int getIndexForName() throws IOException {
		for (String line : commands.withOutput("ip", "addr")) {
			line = line.trim();
			String[] args = line.split(":");
			if (args.length > 1) {
				try {
					int idx = Integer.parseInt(args[0].trim());
					if (args[1].trim().equals(getName()))
						return idx;
				} catch (Exception e) {
				}
			}
		}
		throw new IOException(String.format("Could not find interface index for %s", getName()));
	}
	
	private int getFWMark(String table) {
		try {
			Collection<String> lines = commands.privileged().withOutput(getPlatform().getWGCommand(), "show", getName(), "fwmark");
			if(lines.isEmpty())
				throw new IOException();
			else {
				String fwmark = lines.iterator().next();
				if(fwmark.length() > 0 && !fwmark.equals("off"))
					return -1;
				fwmark = fwmark.substring(2); // 0x...
				return Integer.parseInt(fwmark, 16);
			}
		}
		catch(IOException ioe) {
			return -1;
		}
	}

	private void addDefault(String route) throws IOException {
		int table = getFWMark("table");
		if(table == -1) {
			table = 51820;
			while(!commands.privileged().withOutput("ip", "-4", "route", "show", "table", String.valueOf(table)).isEmpty() ||
					   !commands.privileged().withOutput("ip", "-6", "route", "show", "table", String.valueOf(table)).isEmpty()) {
				table++;
			}
			commands.privileged().withResult(getPlatform().getWGCommand(), "set", getName(), "fwmark", String.valueOf(table));
		}
		String proto = "-4";
		String iptables = "iptables";
		String pf = "ip";

		if (route.matches(".*:.*")) {
			proto = "-6";
			iptables = "ip6tables";
			pf = "ip6";
		}

		commands.privileged().withResult("ip", proto, "route", "add", route, "dev", getName(), "table", String.valueOf(table));
		commands.privileged().withResult("ip", proto, "rule", "add", "not", "fwmark", String.valueOf("table"), "table", String.valueOf(table));
		commands.privileged().withResult("ip", proto, "rule", "add", "table", "main", "suppress_prefixlength", "0");
		
		String marker = String.format("-m comment --comment \"LogonBoxVPN rule for %s\"", getName());
		String restore = "*raw\n";
		String nftable = TABLE_PREFIX + getName();
		
		StringBuilder nftcmd = new StringBuilder();
		nftcmd.append(String.format("add table %s %s\n", pf, nftable));
		nftcmd.append(String.format("add chain %s %s preraw { type filter hook prerouting priority -300; }\n", pf, nftable));
		nftcmd.append(String.format("add chain %s %s premangle { type filter hook prerouting priority -150; }\n", pf, nftable));
		nftcmd.append(String.format("add chain %s %s postmangle { type filter hook postrouting priority -150; }\n", pf, nftable));
		
		Pattern pattern = Pattern.compile(".*inet6?\\ ([0-9a-f:.]+)/[0-9]+.*");
		for(String line : commands.privileged().withOutput("ip", "-o", proto, "addr", "show", "dev", getName())) {
			Matcher m = pattern.matcher(line); 
			if(!m.matches()) {
				continue;
			}
			
			restore += String.format("-I PREROUTING ! -i %s -d %s -m addrtype ! --src-type LOCAL -j DROP %s\n", getName(), m.group(1), marker);
			nftcmd.append(String.format("add rule %s %s postmangle meta l4proto udp mark %s ct mark set mark \n", pf, nftable, getName(), pf, m.group(1)));
		}

		
		restore += String.format("COMMIT\n*mangle\n-I POSTROUTING -m mark --mark %d -p udp -j CONNMARK --save-mark %s\n-I PREROUTING -p udp -j CONNMARK --restore-mark %s\nCOMMIT\n", table, marker, marker);
		nftcmd.append(String.format("add rule %s %s postmangle meta l4proto udp mark %d ct mark set mark \n", pf, nftable, table));
		nftcmd.append(String.format("add rule %s %s premangle meta l4proto udp meta mark set ct mark \n", pf, nftable));
		
		if(proto.equals("-4")) {
		    commands.privileged().withResult("sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1");
		}
		
		if(OsUtil.doesCommandExist("nft")) {
			LOG.info("Updating firewall: " + nftcmd.toString());
			commands.privileged().pipeTo(nftcmd.toString(), "nft", "-f");
		}
		else {
			LOG.info("Updating firewall: " + restore);
			commands.privileged().pipeTo(restore, iptables + "-restore", "-n");
		}
		haveSetFirewall = true;
	}
	
	private void addRoute(String route) throws IOException {
		String proto = "-4";
		if (route.matches(".*:.*"))
			proto = "-6";
		if (TABLE_OFF.equals(getTable()))
			return;
		if (!TABLE_AUTO.equals(getTable())) {
		    commands.privileged().withResult("ip", proto, "route", "add", route, "dev", getName(), "table", getTable());
		} else if (route.endsWith("/0")) {
			addDefault(route);
		} else {
			try {
				String res = commands.privileged().withOutput("ip", proto, "route", "show", "dev", getName(), "match", route)
						.iterator().next();
				if (StringUtils.isNotBlank(res)) {
					// Already have
					return;
				}
			} catch (Exception e) {
			}
			LOG.info(String.format("Adding route %s to %s for %s", route, getName(), proto));
			commands.privileged().withResult("ip", proto, "route", "add", route, "dev", getName());
		}
	}

	private void unsetDns() throws IOException {
		try {
			if (dnsSet) {
				LOG.info(String.format("unsetting DNS for %s (iface prefix %s)", getName(),
						getPlatform().resolvconfIfacePrefix()));
				switch (calcDnsMethod()) {
				case NETWORK_MANAGER:
					updateNetworkManager(null);
					break;
				case RESOLVCONF:
				    commands.privileged().withResult("resolvconf", "-d", getPlatform().resolvconfIfacePrefix() + getName(), "-f");
					break;
				case SYSTEMD:
					updateSystemd(null);
					break;
				case RAW:
					updateResolvDotConf(null);
					break;
				case NONE:
					break;
				default:
					throw new UnsupportedOperationException();
				}
			}
		} finally {
			dnsSet = false;
		}
	}

	private void updateNetworkManager(String[] dns) throws IOException {
		
		/* This will be using split DNS if the backend is systemd or dnsmasq, or
		 * compatible for default backend.
		 * 
		 * TODO we need to check the backend in use if NetworkManager is chosen
		 * to know if we can do split DNS. 
		 * 
		 * https://wiki.gnome.org/Projects/NetworkManager/DNS
		 */
		try (DBusConnection conn = DBusConnectionBuilder.forSystemBus().build()) {
			LOG.info("Updating DNS via NetworkManager");
			NetworkManager mgr = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, "/org/freedesktop/NetworkManager",
					NetworkManager.class);
			DBusPath path = mgr.GetDeviceByIpIface(getName());
			if (path == null)
				throw new IOException(String.format("No interface %s", getName()));

			LOG.info(String.format("DBus device path is %s", path.getPath()));

			Properties props = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, path.getPath(), Properties.class);
			Map<String, Variant<?>> propsMap = props.GetAll("org.freedesktop.NetworkManager.Device");
			@SuppressWarnings("unchecked")
			List<DBusPath> availableConnections = (List<DBusPath>) propsMap.get("AvailableConnections").getValue();
			for (DBusPath availableConnectionPath : availableConnections) {
				NetworkManager.Settings.Connection settings = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME,
						availableConnectionPath.getPath(), NetworkManager.Settings.Connection.class);
				Map<String, Map<String, Variant<?>>> settingsMap = settings.GetSettings();

				if(LOG.isDebugEnabled()) {
					for (Map.Entry<String, Map<String, Variant<?>>> en : settingsMap.entrySet()) {
						LOG.debug("  " + en.getKey());
						for (Map.Entry<String, Variant<?>> en2 : en.getValue().entrySet()) {
							LOG.debug("    " + en2.getKey() + " = " + en2.getValue().getValue());
						}
					}
				}
				
				Map<String, Map<String, Variant<?>>> newSettingsMap = new HashMap<>(settingsMap);

				if (settingsMap.containsKey("ipv4")
						&& "manual".equals(settingsMap.get("ipv4").get("method").getValue())) {
					Map<String, Variant<?>> ipv4Map = new HashMap<>(settingsMap.get("ipv4"));
					ipv4Map.put("dns-search", new Variant<String[]>(IpUtil.filterNames(dns)));
					ipv4Map.put("dns",
							new Variant<UInt32[]>(Arrays.asList(IpUtil.filterIpV4Addresses(dns)).stream()
									.map((addr) -> ipv4AddressToUInt32(addr)).collect(Collectors.toList())
									.toArray(new UInt32[0])));
					newSettingsMap.put("ipv4", ipv4Map);
				}
				if (settingsMap.containsKey("ipv6")
						&& "manual".equals(settingsMap.get("ipv6").get("method").getValue())) {
					Map<String, Variant<?>> ipv6Map = new HashMap<>(settingsMap.get("ipv6"));
					ipv6Map.put("dns-search", new Variant<String[]>(IpUtil.filterNames(dns)));
					ipv6Map.put("dns",
							new Variant<Ipv6Address[]>(Arrays.asList(IpUtil.filterIpV6Addresses(dns)).stream()
									.map((addr) -> ipv6AddressToStruct(addr)).collect(Collectors.toList())
									.toArray(new Ipv6Address[0])));
					newSettingsMap.put("ipv6", ipv6Map);
				}

				settings.Update(newSettingsMap);
				settings.Save();
			}
		} catch (DBusException dbe) {
			throw new IOException("Failed to connect to system bus.", dbe);
		}
	}

	private UInt32 ipv4AddressToUInt32(String address) {
		Ipv4 ipv4 = Ipv4.of(address);
		int ipv4val = ipv4.asBigInteger().intValue();
		return new UInt32(Util.byteSwap(ipv4val));
	}

	private Ipv6Address ipv6AddressToStruct(String address) {
		/* TODO */
		throw new UnsupportedOperationException("TODO");
	}

	private void updateSystemd(String[] dns) throws IOException {
		try (DBusConnection conn = DBusConnectionBuilder.forSystemBus().build()) {
			Resolve1Manager mgr = conn.getRemoteObject("org.freedesktop.resolve1", "/org/freedesktop/resolve1",
					Resolve1Manager.class);
			int index = getIndexForName(); // TODO
			if (dns == null) {
				LOG.info(String.format("Reverting DNS via SystemD. Index is %d", index));
				mgr.RevertLink(index);
			} else {
				LOG.info(String.format("Setting DNS via SystemD. Index is %d", index));
				mgr.SetLinkDNS(index, Arrays.asList(IpUtil.filterAddresses(dns)).stream()
						.map((addr) -> new Resolve1Manager.SetLinkDNSStruct(addr)).collect(Collectors.toList()));
				mgr.SetLinkDomains(index,
						Arrays.asList(IpUtil.filterNames(dns)).stream()
								.map((addr) -> new Resolve1Manager.SetLinkDomainsStruct(addr, false))
								.collect(Collectors.toList()));
			}

		} catch (DBusException dbe) {
			throw new IOException("Failed to connect to system bus.", dbe);
		}
	}

	private void updateResolvConf(String[] dns) throws IOException {

	    var sw =  new StringWriter();
        try (var pw = new PrintWriter(sw)) {
            pw.println(String.format("nameserver %s", String.join(" ", dns)));
        }
	    commands.privileged().pipeTo(sw.toString(), "resolvconf", "-a", getPlatform().resolvconfIfacePrefix() + getName(), "-m",
                "0", "-x");
	}

	private void updateResolvDotConf(String[] dns) {
		synchronized (LinuxPlatformServiceImpl.lock) {
			List<String> headlines = new ArrayList<>();
			List<String> bodylines = new ArrayList<>();
			List<String> taillines = new ArrayList<>();
			List<String> dnslist = new ArrayList<>();
			File file = new File("/etc/resolv.conf");
			String line;
			int sidx = -1;
			int eidx = -1;
			Set<String> rowdns = new HashSet<>();
			try (BufferedReader r = new BufferedReader(new FileReader(file))) {
				int lineNo = 0;
				while ((line = r.readLine()) != null) {
					if (line.startsWith(START_HYPERSOCKET_WIREGUARD_RESOLVECONF)) {
						sidx = lineNo;
					} else if (line.startsWith(END_HYPERSOCKET_WIREGUARD_RESOLVCONF)) {
						eidx = lineNo;
					} else {
						line = line.trim();
						if (line.startsWith("nameserver")) {
							List<String> l = Arrays.asList(line.split("\\s+"));
							rowdns.addAll(l.subList(1, l.size()));
						}
						dnslist.addAll(rowdns);
						if (sidx != -1 && eidx == -1)
							bodylines.add(line);
						else {
							if (sidx == -1 && eidx == -1)
								headlines.add(line);
							else
								taillines.add(line);
						}
					}
					lineNo++;
				}
			} catch (IOException ioe) {
				throw new IllegalStateException("Failed to read resolv.conf", ioe);
			}

			File oldfile = new File("/etc/resolv.conf");
			oldfile.delete();

			if (file.renameTo(oldfile)) {
				LOG.info(String.format("Failed to backup resolv.conf by moving %s to %s", file, oldfile));
			}

			try (PrintWriter pw = new PrintWriter(new FileWriter(file, true))) {
				for (String l : headlines) {
					pw.println(l);
				}
				if (dns != null && dns.length > 0) {
					pw.println(START_HYPERSOCKET_WIREGUARD_RESOLVECONF);
					for (String d : dns) {
						if (!rowdns.contains(d))
							pw.println(String.format("nameserver %s", d));
					}
					pw.println(END_HYPERSOCKET_WIREGUARD_RESOLVCONF);
				}
				for (String l : taillines) {
					pw.println(l);
				}
			} catch (IOException ioe) {
				throw new IllegalStateException("Failed to write resolv.conf", ioe);
			}
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

	@Override
	public String getDisplayName() {
		try {
			NetworkInterface iface = getByName(getName());
			return iface == null ? "Unknown" : iface.getDisplayName();
		} catch (IOException ioe) {
			return "Unknown";
		}
	}

	public Set<String> getAddresses() {
		return addresses;
	}
}
