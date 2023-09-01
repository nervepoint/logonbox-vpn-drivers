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

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.logonbox.vpn.drivers.lib.AbstractUnixDesktopPlatformService;
import com.logonbox.vpn.drivers.lib.NativeComponents.Tool;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnPeer;
import com.logonbox.vpn.drivers.lib.util.OsUtil;

public class UserspaceMacOsPlatformService extends AbstractUnixDesktopPlatformService<UserspaceMacOsAddress> {

	static Logger log = LoggerFactory.getLogger(UserspaceMacOsPlatformService.class);

	private static final String INTERFACE_PREFIX = "utun";
	final static Logger LOG = LoggerFactory.getLogger(UserspaceMacOsPlatformService.class);

	enum IpAddressState {
		HEADER, IP, MAC
	}

	static Object lock = new Object();

	public UserspaceMacOsPlatformService(SystemContext context) {
		super(INTERFACE_PREFIX, context);
	}

	@Override
	protected UserspaceMacOsAddress add(String name, String type) throws IOException {
		var priv = context().commands().privileged();
		priv.result("mkdir", "/var/run/wireguard");
		var tool = context().nativeComponents().tool(Tool.WIREGUARD_GO);
		priv.logged().env(Map.of("WG_TUN_NAME_FILE", String.format("/var/run/wireguard/%s.name", name))).result(tool, "utun");
        var addr = UserspaceMacOsAddress.ofName(name, this);
        if(!addr.nativeName().startsWith("utun")) {
        	throw new IOException(MessageFormat.format("Native network interface name should start with 'utun', but it is ''{0}''", addr.nativeName()));
        }
        context.alert("Interface for {0} is {1]", addr.name(), addr.nativeName());
		return addr;
	}

	@Override
	protected String getDefaultGateway() throws IOException {
		String gw = null;
		for (var line : context().commands().output("route", "get", "default")) {
			line = line.trim();
			if (gw == null && line.startsWith("gateway:")) {
				gw = InetAddress.getByName(line.substring(9)).getHostAddress();
			}
		}
		if (gw == null)
			throw new IOException("Could not get default gateway.");
		else
			return gw;
	}

	@Override
	public List<UserspaceMacOsAddress> addresses() {
		var l = new ArrayList<UserspaceMacOsAddress>();
		UserspaceMacOsAddress lastLink = null;
		try {
			var state = IpAddressState.HEADER;
			for (var r : context().commands().output("ifconfig")) {
				if (!r.startsWith(" ")) {
					var a = r.split(":");
					var name = a[0].trim();
					l.add(lastLink = UserspaceMacOsAddress.ofNativeName(name, this));
					state = IpAddressState.MAC;
				} else if (lastLink != null) {
					r = r.trim();
					if (state == IpAddressState.MAC) {
						if (r.startsWith("ether ")) {
							var a = r.split("\\s+");
							if (a.length > 1) {
								String mac = lastLink.getMac();
								if (mac != null && !mac.equals(a[1]))
									throw new IllegalStateException("Unexpected MAC.");
							}
							state = IpAddressState.IP;
						}
					} else if (state == IpAddressState.IP) {
						if (r.startsWith("inet ")) {
							var a = r.split("\\s+");
							if (a.length > 1) {
								lastLink.getAddresses().add(a[1]);
							}
							state = IpAddressState.HEADER;
						}
					}
				}
			}
		} catch (IOException ioe) {
			if (!Boolean.getBoolean("hypersocket.development")) {
				throw new IllegalStateException("Failed to get network devices.", ioe);
			}
		}
		return l;
	}

	@Override
	protected UserspaceMacOsAddress createVirtualInetAddress(NetworkInterface nif) throws IOException {
		var ip = UserspaceMacOsAddress.ofNativeName(nif.getName(), this);
		for (var addr : nif.getInterfaceAddresses()) {
			ip.getAddresses().add(addr.getAddress().toString());
		}
		return ip;
	}

	@Override
	protected void onStart(Optional<String> interfaceName, VpnConfiguration configuration, VpnAdapter session,
			Optional<VpnPeer> peer) throws IOException {
		var ip = findAddress(interfaceName, configuration, true);

		var tempFile = Files.createTempFile("wg", "cfg");
		try {
			try (var writer = Files.newBufferedWriter(tempFile)) {
				transform(configuration).write(writer);
			}
			log.info("Activating Wireguard configuration for {} (in {})", ip.shortName(), tempFile);
			context().commands().privileged().logged().result(context().nativeComponents().tool(Tool.WG), "setconf",
					ip.nativeName(), tempFile.toString());
			log.info("Activated Wireguard configuration for {}", ip.shortName());
		} finally {
			Files.delete(tempFile);
		}

		/*
		 * About to start connection. The "last handshake" should be this value or later
		 * if we get a valid connection
		 */
		var connectionStarted = Instant.ofEpochMilli(((System.currentTimeMillis() / 1000l) - 1) * 1000l);

		/* Set the address reserved */
		if (configuration.addresses().size() > 0) {
			var addr = configuration.addresses().get(0);
			log.info("Setting address {} on {}", addr, ip.shortName());
			ip.setAddresses(addr);
		}

		/* Bring up the interface (will set the given MTU) */
		ip.mtu(configuration.mtu().or(() -> context.configuration().defaultMTU()).orElse(0));
		log.info("Bringing up {}", ip.shortName());
		ip.up();
		session.attachToInterface(ip);

		/*
		 * Wait for the first handshake. As soon as we have it, we are 'connected'. If
		 * we don't get a handshake in that time, then consider this a failed
		 * connection. We don't know WHY, just it has failed
		 */
		if (peer.isPresent() && context.configuration().connectTimeout().isPresent()) {
			waitForFirstHandshake(configuration, session, connectionStarted, peer,
					context.configuration().connectTimeout().get());
		}

		/* Set the routes */
		try {
			log.info("Setting routes for {}", ip.shortName());
			addRoutes(session);
		} catch (IOException | RuntimeException ioe) {
			try {
				session.close();
			} catch (Exception e) {
			}
			throw ioe;
		}

		if (ip.isAutoRoute4() || ip.isAutoRoute6()) {
			ip.setEndpointDirectRoute();
		}

		/* DNS */
		try {
			dns(configuration, ip);
		} catch (IOException | RuntimeException ioe) {
			try {
				session.close();
			} catch (Exception e) {
			}
			throw ioe;
		}

//		monitor_daemon
//		execute_hooks "${POST_UP[@]}"

	}

	@Override
	public void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException {
		runHookViaPipeToShell(configuration, session, OsUtil.getPathOfCommandInPathOrFail("bash").toString(), "-c",
				String.join(" ; ", hookScript).trim());
	}

	@Override
	protected void runCommand(List<String> commands) throws IOException {
		context().commands().privileged().logged().run(commands.toArray(new String[0]));
	}
}
