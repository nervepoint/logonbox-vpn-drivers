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
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.logonbox.vpn.drivers.lib.AbstractDesktopPlatformService;
import com.logonbox.vpn.drivers.lib.NativeComponents.Tool;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnInterfaceInformation;
import com.logonbox.vpn.drivers.lib.VpnPeer;
import com.logonbox.vpn.drivers.lib.VpnPeerInformation;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.Status;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.Win32Service;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.XAdvapi32;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.XWinsvc;
import com.sshtools.liftlib.ElevatedClosure;
import com.sun.jna.Native;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.Winsvc;
import com.sun.jna.ptr.PointerByReference;

import uk.co.bithatch.nativeimage.annotations.Resource;
import uk.co.bithatch.nativeimage.annotations.Serialization;

@Resource("win32-x84-64/.*")
public class WindowsPlatformService extends AbstractDesktopPlatformService<WindowsAddress> {

	public final static String SID_ADMINISTRATORS_GROUP = "S-1-5-32-544";
	public final static String SID_WORLD = "S-1-1-0";
	public final static String SID_USERS = "S-1-5-32-545";
	public final static String SID_SYSTEM = "S-1-5-18";

	public static final String TUNNEL_SERVICE_NAME_PREFIX = "LogonBoxVPNTunnel";

	private static final String INTERFACE_PREFIX = "net";

	final static Logger LOG = LoggerFactory.getLogger(WindowsPlatformService.class);

	private static final int SERVICE_INSTALL_TIMEOUT = Integer
			.parseInt(System.getProperty("logonbox.vpn.serviceInstallTimeout", "10"));

	private static Preferences PREFS = null;

	public static Preferences getInterfaceNode(String name) {
		return getInterfacesNode().node(name);
	}

	public static Preferences getInterfacesNode() {
		return getPreferences().node("interfaces");
	}

	public static String getBestRealName(String sid, String name) {
		try {
			if (sid == null)
				throw new NullPointerException();
			var acc = Advapi32Util.getAccountBySid(sid);
			return acc.name;
		} catch (Exception e) {
			/* Fallback to i18n */
			LOG.warn("Falling back to I18N strings to determine best real group name for {}", name);
			return WindowsFileSecurity.BUNDLE.getString(name);
		}
	}

	public static Preferences getPreferences() {
		if (PREFS == null) {
			/* Test whether we can write to system preferences */
			try {
				PREFS = Preferences.systemRoot();
				PREFS.put("test", "true");
				PREFS.flush();
				PREFS.remove("test");
				PREFS.flush();
			} catch (Exception bse) {
				System.out.println("Fallback to usering user preferences for public key -> interface mapping.");
				PREFS = Preferences.userRoot();
			}
		}
		return PREFS;
	}

	public WindowsPlatformService(SystemContext context) {
		super(INTERFACE_PREFIX, context);
	}

	@FunctionalInterface
	public interface ServiceCall<R> {
		R accept(Win32Service srv) throws IOException;
	}

	@FunctionalInterface
	public interface ServiceRun {
		void accept(Win32Service srv) throws IOException;
	}

	@Override
	public void openToEveryone(Path path) throws IOException {
		WindowsFileSecurity.openToEveryone(path);
	}

	@Override
	public void restrictToUser(Path path) throws IOException {
		WindowsFileSecurity.restrictToUser(path);
	}

	@Override
	public List<WindowsAddress> addresses() {
		return ips(false);
	}

	@Override
	public List<VpnAdapter> adapters() {
		return ips(true).stream().map(addr -> configureExistingSession(addr)).collect(Collectors.toList());
	}

	private List<WindowsAddress> ips(boolean wireguardInterface) {
		Set<WindowsAddress> ips = new LinkedHashSet<>();

		/* netsh first */
		try {
			for (var line : context().commands().privileged().output("netsh", "interface", "ip", "show", "interfaces")) {
				line = line.trim();
				if (line.equals("") || line.startsWith("Idx") || line.startsWith("---"))
					continue;
				var s = new StringTokenizer(line);
				s.nextToken(); // Idx
				if (s.hasMoreTokens()) {
					s.nextToken(); // Met
					if (s.hasMoreTokens()) {
						s.nextToken(); // MTU
						s.nextToken(); // Status
						var b = new StringBuilder();
						while (s.hasMoreTokens()) {
							if (b.length() > 0)
								b.append(' ');
							b.append(s.nextToken());
						}
						var ifName = b.toString();
						if (isMatchesPrefix(ifName)) {
							WindowsAddress vaddr = new WindowsAddress(ifName.toString(), ifName.toString(), this);
							ips.add(vaddr);
						}
					}

				}
			}
		} catch (Exception e) {
			LOG.error("No netsh?", e);
		}

		try {
			String name = null;

			/*
			 * NOTE: Workaround. NetworkInterface.getNetworkInterfaces() doesn't discover
			 * active WireGuard interfaces for some reason, so use ipconfig /all to create a
			 * merged list.
			 */
			for (var line : context().commands().privileged().output("ipconfig", "/all")) {
				line = line.trim();
				if (line.startsWith("Unknown adapter")) {
					var args = line.split("\\s+");
					if (args.length > 1 && args[2].startsWith(getInterfacePrefix())) {
						name = args[2].split(":")[0];
					}
				} else if (name != null && line.startsWith("Description ")) {
					var args = line.split(":");
					if (args.length > 1) {
						var description = args[1].trim();
						if (description.startsWith("WireGuard Tunnel")) {
							var vaddr = new WindowsAddress(name, description, this);
							ips.add(vaddr);
							break;
						}
					}
				}
			}

		} catch (Exception e) {
			LOG.error("Failed to list interfaces via Java.", e);
		}

		ips.addAll(super.addresses());

		return new ArrayList<WindowsAddress>(ips);
	}

	@Override
	protected void onSetDefaultGateway(VpnPeer peer) throws IOException {
		var gw = getDefaultGateway();
		var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
		LOG.info("Routing traffic all through peer {}", addr);
		context().commands().privileged().logged().run("route", "add", addr, gw);
	}

	@Override
	protected void onResetDefaultGateway(VpnPeer peer) throws IOException {
		var gw = getDefaultGateway();
		var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
		LOG.info("Removing routing of all traffic  through peer {}", addr);
		context().commands().privileged().logged().run("route", "delete", addr, gw);
	}

	@Override
	protected String getDefaultGateway() throws IOException {
		String gw = null;
		for (var line : context().commands().privileged().output("ipconfig")) {
			if (gw == null) {
				line = line.trim();
				if (line.startsWith("Default Gateway ")) {
					int idx = line.indexOf(":");
					if (idx != -1) {
						line = line.substring(idx + 1).trim();
						if (!line.equals("0.0.0.0"))
							gw = line;
					}
				}
			}
		}
		if (gw == null)
			throw new IOException("Could not get default gateway.");
		else
			return gw;
	}

	@Override
	protected Optional<String> getPublicKey(String interfaceName) throws IOException {
		try (var adapter = new WireguardLibrary.Adapter(interfaceName)) {
			var wgIface = adapter.getConfiguration();
			return Optional.of(wgIface.publicKey.toString());
		} catch (IllegalArgumentException iae) {
			return Optional.empty();
		}
	}

	@Override
	protected void onStart(Optional<String> interfaceName, VpnConfiguration configuration, VpnAdapter session,
			Optional<VpnPeer> peer) throws Exception {
		WindowsAddress ip = null;

		/*
		 * Look for wireguard interfaces that are available but not connected. If we
		 * find none, try to create one.
		 */
		int maxIface = -1;

		List<WindowsAddress> ips = ips(false);

		for (int i = 0; i < MAX_INTERFACES; i++) {
			var name = getInterfacePrefix() + i;
			LOG.info("Looking for {}.", name);

			/*
			 * Get ALL the interfaces because on Windows the interface name is netXXX, and
			 * 'net' isn't specific to wireguard, nor even to WinTun.
			 */
			if (exists(name, ips)) {
				LOG.info("    {} exists.", name);
				/* Get if this is actually a Wireguard interface. */
				WindowsAddress nicByName = find(name, ips).orElseThrow(
						() -> new IOException(MessageFormat.format("Could not find network interface {0}", name)));
				;
				if (isWireGuardInterface(nicByName)) {
					/* Interface exists and is wireguard, is it connected? */

					// TODO check service state, we can't rely on the public key
					// as we manage storage of it ourselves (no wg show command)
					LOG.info("    Looking for public key for {}.", name);
					var publicKey = getPublicKey(name);
					if (publicKey.isEmpty()) {
						/* No addresses, wireguard not using it */
						LOG.info("    {} ({}) is free.", name, nicByName.displayName());
						ip = nicByName;
						maxIface = i;
						break;
					} else if (publicKey.get().equals(configuration.publicKey())) {
						LOG.warn("    Peer with public key {} on {} is already active (by {}).", publicKey.get(), name,
								nicByName.displayName());
						session.attachToInterface(nicByName);
						return;
					} else {
						LOG.info("    {} is already in use (by {}).", name, nicByName.displayName());
					}
				} else
					LOG.info("    {} is already in use by something other than WinTun ({}).", name,
							nicByName.displayName());
			} else if (maxIface == -1) {
				/* This one is the next free number */
				maxIface = i;
				LOG.info("    {} is next free interface.", name);
				break;
			}
		}
		if (maxIface == -1)
			throw new IOException(String.format("Exceeds maximum of %d interfaces.", MAX_INTERFACES));

		if (ip == null) {
			var name = getInterfacePrefix() + maxIface;
			LOG.info("No existing unused interfaces, creating new one ({}) for public key .", name,
					configuration.publicKey());
			ip = new WindowsAddress(name, "WireGuard Tunnel", this);
			LOG.info("Created {}", name);
		} else
			LOG.info("Using {}", ip.shortName());

		session.attachToInterface(ip);

		var cwd = context().nativeComponents().binDir();
		var confDir = cwd.resolve("conf").resolve("connections");
		if (!Files.exists(confDir))
			Files.createDirectories(confDir);

		/* Get the driver specific configuration for this platform */
		var transformedConfiguration = transform(configuration);

		/* Install service for the network interface */
		var tool = Paths.get(context().nativeComponents().tool(Tool.NETWORK_CONFIGURATION_SERVICE));
		var install = context().commands().privileged().logged().task(new InstallService(ip.nativeName(), cwd.toAbsolutePath().toString(), confDir.toAbsolutePath().toString(), tool.toAbsolutePath().toString(), transformedConfiguration)).booleanValue();
		/*
		 * About to start connection. The "last handshake" should be this value or later
		 * if we get a valid connection
		 */
		var connectionStarted = Instant.ofEpochMilli(((System.currentTimeMillis() / 1000l) - 1) * 1000l);

		LOG.info("Waiting {} seconds for service to settle.", context.configuration().serviceWait().toSeconds());
		try {
			Thread.sleep(context.configuration().serviceWait().toMillis());
		} catch (InterruptedException e) {
		}
		LOG.info("Service should be settled.");

		if (ip.isUp()) {
			LOG.info("Service for {} is already up.", ip.shortName());
		} else {
			LOG.info("Bringing up {}", ip.shortName());
			try {
				ip.mtu(configuration.mtu().or(() -> context.configuration().defaultMTU()).orElse(0));
				ip.up();
			} catch (IOException | RuntimeException ioe) {
				/* Just installed service failed, clean it up */
				if (install) {
					ip.delete();
				}
				throw ioe;
			}
		}

		/*
		 * Wait for the first handshake. As soon as we have it, we are 'connected'. If
		 * we don't get a handshake in that time, then consider this a failed
		 * connection. We don't know WHY, just it has failed
		 */
		if (context.configuration().connectTimeout().isPresent()) {
			waitForFirstHandshake(configuration, session, connectionStarted, peer,
					context.configuration().connectTimeout().get());
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
	}

	@Override
	protected void onInit(SystemContext ctx) {
		/*
		 * Check for an remove any wireguard interface services that are stopped (they
		 * should either be running or not exist
		 */
		try {
		    context().commands().privileged().task(new CleanUpStaleInterfaces());
		} catch (Exception e) {
			LOG.error("Failed to clean up stale interfaces.", e);
		}
	}

	@Override
	protected WindowsAddress createVirtualInetAddress(NetworkInterface nif) throws IOException {
		return new WindowsAddress(nif.getName(), nif.getDisplayName(), this);
	}

	@Override
	protected boolean isWireGuardInterface(NetworkInterface nif) {
		return super.isWireGuardInterface(nif) &&  nif.getDisplayName().startsWith("WireGuard Tunnel");
	}

	protected boolean isWireGuardInterface(WindowsAddress nif) {
		return isMatchesPrefix(nif) && (
				 nif.displayName().startsWith("WireGuard Tunnel") || isMatchesPrefix(nif.displayName()));
	}

	protected boolean isMatchesPrefix(WindowsAddress nif) {
		return isMatchesPrefix(nif.name());
	}

	protected boolean isMatchesPrefix(String name) {
		return name.startsWith(getInterfacePrefix());
	}

	@Override
	protected void transformInterface(VpnConfiguration configuration, VpnConfiguration.Builder writer) {
		if (!configuration.addresses().isEmpty()) {
			writer.withAddresses(configuration.addresses());
		}
	}

	@Override
	public void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException {
		runHookViaPipeToShell(configuration, session, OsUtil.getPathOfCommandInPathOrFail("cmd.exe").toString(), "/c",
				String.join(" & ", hookScript).trim());
	}

	@Override
	protected void runCommand(List<String> commands) throws IOException {
	    context().commands().privileged().logged().run(commands.toArray(new String[0]));
	}

	@Override
	public VpnInterfaceInformation information(VpnAdapter vpnAdapter) {
		try {
			return context().commands().privileged().logged().task(new GetInformation(vpnAdapter.address().name()));
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public VpnAdapterConfiguration configuration(VpnAdapter vpnAdapter) {
		try {
			return context().commands().privileged().logged().task(new GetConfiguration(vpnAdapter.address().name()));
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class GetConfiguration implements ElevatedClosure<VpnAdapterConfiguration, Serializable> {

		private String name;

		public GetConfiguration() {
		}

		GetConfiguration(String name) {
			this.name = name;
		}

		@Override
		public VpnAdapterConfiguration call(ElevatedClosure<VpnAdapterConfiguration, Serializable> proxy)
				throws Exception {
			var cfgBldr = new VpnAdapterConfiguration.Builder();
			try (var adapter = new WireguardLibrary.Adapter(name)) {
				var wgIface = adapter.getConfiguration();
				cfgBldr.withPrivateKey(wgIface.privateKey.toString());
				cfgBldr.withPublicKey(wgIface.publicKey.toString());
				cfgBldr.withListenPort(wgIface.listenPort);
				for (var peer : wgIface.peers) {
					var peerBldr = new VpnPeer.Builder();
					peerBldr.withPublicKey(peer.publicKey.toString());
					peerBldr.withPersistentKeepalive(peer.PersistentKeepalive);
					if (peer.endpoint != null)
						peerBldr.withEndpoint(peer.endpoint);
					if (peer.presharedKey != null)
						peerBldr.withPresharedKey(peer.presharedKey.toString());
					for (var allowed : peer.allowedIPs) {
						peerBldr.addAllowedIps(allowed.address.getHostAddress() + "/" + allowed.cidr);
					}
					var peerCfg = peerBldr.build();
					cfgBldr.addPeers(peerCfg);
				}
				return cfgBldr.build();
			}
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class GetInformation implements ElevatedClosure<VpnInterfaceInformation, Serializable> {

		private String name;

		public GetInformation() {
		}

		GetInformation(String name) {
			this.name = name;
		}

		@Override
		public VpnInterfaceInformation call(ElevatedClosure<VpnInterfaceInformation, Serializable> proxy)
				throws Exception {
			var lastHandshake = new AtomicLong(0);
			try (var adapter = new WireguardLibrary.Adapter(name)) {
				var wgIface = adapter.getConfiguration();
				var tx = new AtomicLong(0);
				var rx = new AtomicLong(0);
				var peers = new ArrayList<VpnPeerInformation>();
				for (var peer : wgIface.peers) {
					var thisHandshake = peer.lastHandshake.orElse(Instant.ofEpochSecond(0));
					lastHandshake.set(Math.max(lastHandshake.get(), thisHandshake.toEpochMilli()));
					tx.addAndGet(peer.txBytes);
					rx.addAndGet(peer.rxBytes);
					var allowedIps = Arrays.asList(peer.allowedIPs).stream()
							.map(a -> String.format("%s/%d", a.address.getHostAddress(), a.cidr)).collect(Collectors.toList());
					var pTx = peer.txBytes;
					var pRx = peer.rxBytes;
					var peerPublicKey = peer.publicKey.toString();
					var peerPresharedKey = peer.presharedKey;
					peers.add(new VpnPeerInformation() {
						@Override
						public long tx() {
							return pTx;
						}

						@Override
						public long rx() {
							return pRx;
						}

						@Override
						public Instant lastHandshake() {
							return thisHandshake;
						}

						@Override
						public Optional<String> error() {
							return Optional.empty();
						}

						@Override
						public Optional<InetSocketAddress> remoteAddress() {
							/* TODO: Not available? */
							return Optional.empty();
						}

						@Override
						public String publicKey() {
							return peerPublicKey.toString();
						}

						@Override
						public Optional<String> presharedKey() {
							return peerPresharedKey == null ? Optional.empty()
									: Optional.of(peerPresharedKey.toString());
						}

						@Override
						public List<String> allowedIps() {
							return allowedIps;
						}
					});
				}
				
				var ifacePublicKey = wgIface.publicKey.toString();
				var ifacePrivateKey = wgIface.privateKey.toString();
				var ifaceListenPort = wgIface.listenPort;

				return new VpnInterfaceInformation() {

					@Override
					public long tx() {
						return tx.get();
					}

					@Override
					public Optional<String> error() {
						return Optional.empty();
					}

					@Override
					public long rx() {
						return rx.get();
					}

					@Override
					public List<VpnPeerInformation> peers() {
						return peers;
					}

					@Override
					public String interfaceName() {
						return name;
					}

					@Override
					public Instant lastHandshake() {
						return Instant.ofEpochMilli(lastHandshake.get());
					}

					@Override
					public Optional<Integer> listenPort() {
						return Optional.of(ifaceListenPort);
					}

					@Override
					public Optional<Integer> fwmark() {
						return Optional.empty();
					}

					@Override
					public String publicKey() {
						return ifacePublicKey;
					}

					@Override
					public String privateKey() {
						return ifacePrivateKey;
					}
				};
			}
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class CleanUpStaleInterfaces implements ElevatedClosure<Serializable, Serializable> {

		@Override
		public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
			try (var srvs = new WindowsSystemServices()) {
				for (var service : srvs.getServices()) {
					if (service.getNativeName().startsWith(TUNNEL_SERVICE_NAME_PREFIX)
							&& (service.getStatus() == Status.STOPPED || service.getStatus() == Status.PAUSED
									|| service.getStatus() == Status.UNKNOWN)) {
						try {
							service.uninstall();
						} catch (Exception e) {
							LOG.error("Failed to uninstall dead service {}", service.getNativeName(), e);
						}
					}
				}
			}
			return null;
		}
	}

	@SuppressWarnings("serial")
	@Serialization
	public final static class InstallService implements ElevatedClosure<Boolean, Serializable> {

		private String name;
		private String cwd;
		private String exe;
		private String confDir;
		private VpnConfiguration configuration;

		public InstallService() {
		}

		InstallService(String name, String cwd, String confDir, String exe, VpnConfiguration configuration) {
			this.name = name;
			this.cwd = cwd;
			this.exe = exe;
			this.confDir = confDir;
			this.configuration = configuration;
		}

		@Override
		public Boolean call(ElevatedClosure<Boolean, Serializable> proxy) throws Exception {
			/*
			 * We need to set up file descriptors here so that the pipe has correct
			 * 'security descriptor' in windows. It derives this from the permissions on the
			 * folder the configuration file is stored in.
			 * 
			 * This took a lot of finding :\
			 * 
			 */
			var securityDescriptor = new PointerByReference();
			XAdvapi32.INSTANCE.ConvertStringSecurityDescriptorToSecurityDescriptor(
					"O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", 1, securityDescriptor, null);
			if (!Advapi32.INSTANCE.SetFileSecurity(confDir,
					WinNT.OWNER_SECURITY_INFORMATION | WinNT.GROUP_SECURITY_INFORMATION | WinNT.DACL_SECURITY_INFORMATION,
					securityDescriptor.getValue())) {
				var err = Kernel32.INSTANCE.GetLastError();
				throw new IOException(String.format("Failed to set file security on '%s'. %d. %s", confDir, err,
						Kernel32Util.formatMessageFromLastErrorCode(err)));
			}
			
			configuration.write(Paths.get(confDir).resolve(name + ".conf"));

			try (var srvs = new WindowsSystemServices()) {
				var install = false;
				if (!srvs.hasService(TUNNEL_SERVICE_NAME_PREFIX + "$" + name)) {
					install = true;
					install();
				} else
					LOG.info("Service for {} already exists.", name);

				/* The service may take a short while to appear */
				int i = 0;
				for (; i < SERVICE_INSTALL_TIMEOUT; i++) {
					if (srvs.hasService(TUNNEL_SERVICE_NAME_PREFIX + "$" + name))
						break;
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						throw new IOException("Interrupted.", e);
					}
				}
				if (i == 10)
					throw new IOException(String.format(
							"Service for %s cannot be found, suggesting installation failed, please check logs.",
							name));

				return install;
			}
		}

		private void install() throws IOException {
			LOG.info("Installing service for {}", name);
			var cmd = new StringBuilder();

			LOG.info("Using network configuration service at {}", exe);
			cmd.append('"');
			cmd.append(exe);
			cmd.append('"');
			cmd.append(' ');
			cmd.append("/service");
			cmd.append(' ');
			cmd.append('"');
			cmd.append(cwd);
			cmd.append('"');
			cmd.append(' ');
			cmd.append('"');
			cmd.append(name);
			cmd.append('"');

			install(TUNNEL_SERVICE_NAME_PREFIX + "$" + name, "LogonBox VPN Tunnel for " + name,
					"Manage a single tunnel LogonBox VPN (" + name + ")", new String[] { "Nsi", "TcpIp" },
					"LocalSystem", null, cmd.toString(), WinNT.SERVICE_DEMAND_START, false, null, false,
					XWinsvc.SERVICE_SID_TYPE_UNRESTRICTED);

			LOG.info("Installed service for {} ({})", name, cmd);
		}

		void install(String serviceName, String displayName, String description, String[] dependencies, String account,
				String password, String command, int winStartType, boolean interactive,
				Winsvc.SERVICE_FAILURE_ACTIONS failureActions, boolean delayedAutoStart, DWORD sidType)
				throws IOException {

			var advapi32 = XAdvapi32.INSTANCE;

			var desc = new XWinsvc.SERVICE_DESCRIPTION();
			desc.lpDescription = description;

			var serviceManager = WindowsSystemServices.getManager(null, Winsvc.SC_MANAGER_ALL_ACCESS);
			try {

				var dwServiceType = WinNT.SERVICE_WIN32_OWN_PROCESS;
				if (interactive)
					dwServiceType |= WinNT.SERVICE_INTERACTIVE_PROCESS;

				var service = advapi32.CreateService(serviceManager, serviceName, displayName,
						Winsvc.SERVICE_ALL_ACCESS, dwServiceType, winStartType, WinNT.SERVICE_ERROR_NORMAL, command,
						null, null, (dependencies == null ? "" : String.join("\0", dependencies)) + "\0", account,
						password);

				if (service != null) {
					try {
						var success = false;
						if (failureActions != null) {
							success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_FAILURE_ACTIONS,
									failureActions);
							if (!success) {
								var err = Native.getLastError();
								throw new IOException(String.format("Failed to set failure actions. %d. %s", err,
										Kernel32Util.formatMessageFromLastErrorCode(err)));
							}
						}

						success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_DESCRIPTION, desc);
						if (!success) {
							var err = Native.getLastError();
							throw new IOException(String.format("Failed to set description. %d. %s", err,
									Kernel32Util.formatMessageFromLastErrorCode(err)));
						}

						if (delayedAutoStart) {
							var delayedDesc = new XWinsvc.SERVICE_DELAYED_AUTO_START_INFO();
							delayedDesc.fDelayedAutostart = true;
							success = advapi32.ChangeServiceConfig2(service,
									Winsvc.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, delayedDesc);
							if (!success) {
								var err = Native.getLastError();
								throw new IOException(String.format("Failed to set autostart. %d. %s", err,
										Kernel32Util.formatMessageFromLastErrorCode(err)));
							}
						}

						/*
						 * https://github.com/WireGuard/wireguard-windows/tree/master/embeddable-dll-
						 * service
						 */
						if (sidType != null) {
							var info = new XWinsvc.SERVICE_SID_INFO();
							info.dwServiceSidType = sidType;
							success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_SERVICE_SID_INFO,
									info);
							if (!success) {
								var err = Native.getLastError();
								throw new IOException(String.format("Failed to set SERVICE_SID_INFO. %d. %s", err,
										Kernel32Util.formatMessageFromLastErrorCode(err)));
							}
						}

					} finally {
						advapi32.CloseServiceHandle(service);
					}
				} else {
					var err = Kernel32.INSTANCE.GetLastError();
					throw new IOException(String.format("Failed to install. %d. %s", err,
							Kernel32Util.formatMessageFromLastErrorCode(err)));

				}
			} finally {
				advapi32.CloseServiceHandle(serviceManager);
			}
		}
	}
}
