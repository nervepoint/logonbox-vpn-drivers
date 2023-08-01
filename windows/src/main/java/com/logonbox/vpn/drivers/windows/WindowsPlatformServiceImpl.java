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

import com.logonbox.vpn.drivers.lib.AbstractDesktopPlatformServiceImpl;
import com.logonbox.vpn.drivers.lib.ActiveSession;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.StatusDetail;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.WireguardConfiguration;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.Service.Status;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.XAdvapi32;
import com.logonbox.vpn.drivers.windows.WindowsSystemServices.XWinsvc;
import com.sun.jna.Native;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.Winsvc;
import com.sun.jna.platform.win32.Winsvc.SC_HANDLE;
import com.sun.jna.ptr.PointerByReference;

import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.prefs.Preferences;

public class WindowsPlatformServiceImpl extends AbstractDesktopPlatformServiceImpl<WindowsIP> {
	
	public final static String SID_ADMINISTRATORS_GROUP = "S-1-5-32-544";
	public final static String SID_WORLD = "S-1-1-0";
	public final static String SID_USERS = "S-1-5-32-545";
	public final static String SID_SYSTEM = "S-1-5-18";

	public static final String TUNNEL_SERVICE_NAME_PREFIX = "LogonBoxVPNTunnel";

	private static final String INTERFACE_PREFIX = "net";

	final static Logger LOG = LoggerFactory.getLogger(WindowsPlatformServiceImpl.class);

	private static final int SERVICE_INSTALL_TIMEOUT = Integer.parseInt(System.getProperty("logonbox.vpn.serviceInstallTimeout", "10"));

	private static Preferences PREFS = null;
	private Object lock = new Object();

	public static Preferences getInterfaceNode(String name) {
		return getInterfacesNode().node(name);
	}

	public static Preferences getInterfacesNode() {
		return getPreferences().node("interfaces");
	}
	
	public static String getBestRealName(String sid, String name) {
		try {
			if(sid == null)
				throw new NullPointerException();
			var acc = Advapi32Util.getAccountBySid(sid);
			return acc.name;
		}
		catch(Exception e) {
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

	private File wgFile;
    private final WindowsSystemServices services;

	public WindowsPlatformServiceImpl() {
		super(INTERFACE_PREFIX);
		services = new WindowsSystemServices(this);
	}
	
	WindowsSystemServices services() {
	    return services;
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
	public List<WindowsIP> ips(boolean wireguardInterface) {
		Set<WindowsIP> ips = new LinkedHashSet<>();
		

		/* netsh first */
		try {
			for(String line : commands().privileged().output("netsh", "interface", "ip", "show", "interfaces")) {
				line = line.trim();
				if(line.equals("") || line.startsWith("Idx") || line.startsWith("---"))
					continue;
				var s = new StringTokenizer(line);
				s.nextToken(); // Idx
				if(s.hasMoreTokens()) {
					s.nextToken(); // Met
					if(s.hasMoreTokens()) {
						s.nextToken(); // MTU
						s.nextToken(); // Status
						var b = new StringBuilder();
						while(s.hasMoreTokens()) {
							if(b.length() > 0)
								b.append(' ');
							b.append(s.nextToken());
						}
						var ifName = b.toString();
						if(isMatchesPrefix(ifName)) {
							WindowsIP vaddr = new WindowsIP(ifName.toString(), ifName.toString(), this);
							configureVirtualAddress(vaddr);
							ips.add(vaddr);
						}
					}
					
				}
			}
		}
		catch(Exception e) {
			LOG.error("No netsh?", e);
		}
		
		try {
			String name = null;
			
			/* NOTE: Workaround. NetworkInterface.getNetworkInterfaces() doesn't discover 
			 * active WireGuard interfaces for some reason, so use ipconfig /all to 
			 * create a merged list. 
			 */
			for(String line :commands().privileged().output("ipconfig", "/all")) {
				line = line.trim();
				if(line.startsWith("Unknown adapter")) {
					String[] args = line.split("\\s+");
					if(args.length > 1 && args[2].startsWith(getInterfacePrefix())) {
						name = args[2].split(":")[0];
					}
				}
				else if(name != null && line.startsWith("Description ")) {
					String[] args = line.split(":");
					if(args.length > 1) {
						String description = args[1].trim();
						if(description.startsWith("WireGuard Tunnel")) {
							WindowsIP vaddr = new WindowsIP(name, description, this);
							configureVirtualAddress(vaddr);
							ips.add(vaddr);
							break;
						}
					}
				}
			}
			
		}
		catch(Exception e) {
			LOG.error("Failed to list interfaces via Java.", e);
		}

		ips.addAll(super.ips(wireguardInterface));
		
		return new ArrayList<WindowsIP>(ips);
	}
	
	@Override
	protected void addRouteAll(WireguardConfiguration connection) throws IOException {
		LOG.info("Routing traffic all through VPN");
		commands().privileged().run("route", "add", connection.getEndpointAddress(), getDefaultGateway());
	}

	@Override
	protected void removeRouteAll(ActiveSession<WindowsIP> session) throws IOException {
		LOG.info("Removing routing of all traffic through VPN");
		commands().privileged().run("route", "delete", session.connection().getEndpointAddress(), getDefaultGateway());
	}

	@Override
	protected String getDefaultGateway() throws IOException {
		String gw = null;
		for(String line : commands().privileged().output("ipconfig")) {
			if(gw == null) {
				line = line.trim();
				if(line.startsWith("Default Gateway ")) {
					int idx = line.indexOf(":");
					if(idx != -1) {
						line = line.substring(idx + 1).trim();
						if(!line.equals("0.0.0.0"))
							gw = line;
					}
				}
			}
		}
		if(gw == null)
			throw new IOException("Could not get default gateway.");
		else
			return gw;
	}

    @Override
    public StatusDetail status(String iface) throws IOException {
        var lastHandshake = new AtomicLong(0);
        try(var adapter = new WireguardLibrary.Adapter(iface)) {
            var wgIface = adapter.getConfiguration();
            var tx = new AtomicLong(0);
            var rx = new AtomicLong(0);
            for(var peer : wgIface.peers) {
                    var thisHandshake = peer.lastHandshake.map(l -> l.toEpochMilli()).orElse(0l);
                    if(thisHandshake > lastHandshake.get())
                    	lastHandshake.set(thisHandshake);
                    tx.addAndGet(peer.txBytes);
                    rx.addAndGet(peer.rxBytes);
            }

            return new StatusDetail() {
                @Override
                public long getTx() {
                    return tx.get();
                }
                
                @Override
                public long getRx() {
                    return rx.get();
                }
                
                @Override
                public long getLastHandshake() {
                    return lastHandshake.get();
                }
                
                @Override
                public String getInterfaceName() {
                    return iface;
                }
                
                @Override
                public String getError() {
                    return "";
                }
            };
        }
    }

    @Override
    protected String getPublicKey(String interfaceName) throws IOException {
        try(var adapter = new WireguardLibrary.Adapter(interfaceName)) {
            var wgIface = adapter.getConfiguration();
            return wgIface.publicKey.toString();
        }
        catch(IllegalArgumentException iae) {
        	return null;
        }
    }

    @Override
    public long getLatestHandshake(String iface, String publicKey) throws IOException {
        try(var adapter = new WireguardLibrary.Adapter(iface)) {
            var wgIface = adapter.getConfiguration();
            for(var peer : wgIface.peers) {
                if(peer.publicKey != null && peer.publicKey.toString().equals(publicKey)) {
                    return peer.lastHandshake.map(i -> i.toEpochMilli()).orElse(0l);
                }
            }
        }
        return 0;
    }
	
	@Override
	protected WindowsIP onConnect(ActiveSession<WindowsIP> session) throws IOException {
		WindowsIP ip = null;
		var connection = session.connection();

		/*
		 * Look for wireguard interfaces that are available but not connected. If we
		 * find none, try to create one.
		 */
		int maxIface = -1;
		

		List<WindowsIP> ips = ips(false);
		
		for (int i = 0; i < MAX_INTERFACES; i++) {
			String name = getInterfacePrefix() + i;
			LOG.info(String.format("Looking for %s.", name));

			/*
			 * Get ALL the interfaces because on Windows the interface name is netXXX, and
			 * 'net' isn't specific to wireguard, nor even to WinTun.
			 */
			if ( exists(name, ips)) {
				LOG.info(String.format("    %s exists.", name));
				/* Get if this is actually a Wireguard interface. */
				WindowsIP nicByName = find(name, ips);
				if (isWireGuardInterface(nicByName)) {
					/* Interface exists and is wireguard, is it connected? */

					// TODO check service state, we can't rely on the public key
					// as we manage storage of it ourselves (no wg show command)
					LOG.info(String.format("    Looking for public key for %s.", name));
					String publicKey = getPublicKey(name);
					if (publicKey == null) {
						/* No addresses, wireguard not using it */
						LOG.info(String.format("    %s (%s) is free.", name, nicByName.getDisplayName()));
						ip = nicByName;
						maxIface = i;
						break;
					} else if (publicKey.equals(connection.getUserPublicKey())) {
						LOG.warn(
								String.format("    Peer with public key %s on %s is already active (by %s).", publicKey, name, nicByName.getDisplayName()));
						return nicByName;
					} else {
						LOG.info(String.format("    %s is already in use (by %s).", name, nicByName.getDisplayName()));
					}
				} else
					LOG.info(String.format("    %s is already in use by something other than WinTun (%s).", name,
							nicByName.getDisplayName()));
			} else if (maxIface == -1) {
				/* This one is the next free number */
				maxIface = i;
				LOG.info(String.format("    %s is next free interface.", name));
				break;
			}
		}
		if (maxIface == -1)
			throw new IOException(String.format("Exceeds maximum of %d interfaces.", MAX_INTERFACES));

		if (ip == null) {
			String name = getInterfacePrefix() + maxIface;
			LOG.info(String.format("No existing unused interfaces, creating new one (%s) for public key .", name,
					connection.getUserPublicKey()));
			ip = new WindowsIP(name, "Wintun Userspace Tunnel", this);
			configureVirtualAddress(ip);
			LOG.info(String.format("Created %s", name));
		} else
			LOG.info(String.format("Using %s", ip.getName()));

		Path cwd = Paths.get(System.getProperty("user.dir"));
		Path confDir = cwd.resolve("conf").resolve("connections");
		if (!Files.exists(confDir))
			Files.createDirectories(confDir);

		/*
		 * We need to set up file descriptors here so that
		 * the pipe has correct 'security descriptor' in windows. It derives this from
		 * the permissions on the folder the configuration file is stored in.
		 * 
		 * This took a lot of finding :\
		 * 
		 */
		PointerByReference securityDescriptor = new PointerByReference();
		XAdvapi32.INSTANCE.ConvertStringSecurityDescriptorToSecurityDescriptor(
				"O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", 1, securityDescriptor, null);
		if (!Advapi32.INSTANCE.SetFileSecurity(confDir.toFile().getPath(),
				WinNT.OWNER_SECURITY_INFORMATION | WinNT.GROUP_SECURITY_INFORMATION | WinNT.DACL_SECURITY_INFORMATION,
				securityDescriptor.getValue())) {
			int err = Kernel32.INSTANCE.GetLastError();
			throw new IOException(String.format("Failed to set file security on '%s'. %d. %s", confDir, err,
					Kernel32Util.formatMessageFromLastErrorCode(err)));
		}

		Path confFile = confDir.resolve(ip.getName() + ".conf");
		try (Writer writer = Files.newBufferedWriter(confFile)) {
			write(connection, writer);
		}

		/* Install service for the network interface */
		boolean install = false;
		if (!services.hasService(TUNNEL_SERVICE_NAME_PREFIX + "$" + ip.getName())) {
			install = true;
			installService(ip.getName(), cwd);
		} else
			LOG.info(String.format("Service for %s already exists.", ip.getName()));

		/* The service may take a short while to appear */
		int i = 0;
		for (; i < SERVICE_INSTALL_TIMEOUT; i++) {
			if (services.hasService(TUNNEL_SERVICE_NAME_PREFIX + "$" + ip.getName()))
				break;
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				throw new IOException("Interrupted.", e);
			}
		}
		if (i == 10)
			throw new IOException(
					String.format("Service for %s cannot be found, suggesting installation failed, please check logs.",
							ip.getName()));

		/*
		 * About to start connection. The "last handshake" should be this value or later
		 * if we get a valid connection
		 */
		long connectionStarted = ((System.currentTimeMillis() / 1000l) - 1) * 1000l;

		LOG.info(String.format("Waiting %d seconds for service to settle.", context.configuration().serviceWait()));
		try {
			Thread.sleep(context.configuration().serviceWait().toMillis());
		} catch (InterruptedException e) {
		}		
		LOG.info("Service should be settled.");

		if (ip.isUp()) {
			LOG.info(String.format("Service for %s is already up.", ip.getName()));
		} else {
			LOG.info(String.format("Bringing up %s", ip.getName()));
			try {
				ip.setMtu(connection.getMtu() == 0 ? context.configuration().defaultMTU() : connection.getMtu());
				ip.up();
			}
			catch(IOException  | RuntimeException ioe) {
				/* Just installed service failed, clean it up */
				if(install) {
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
		LOG.info(String.format("Waiting for handshake for %d seconds. Hand shake should be after %d", context.configuration().connectTimeout(), connectionStarted));
		ip = waitForFirstHandshake(connection, ip, connectionStarted);
		
		/* DNS */
		try {
			dns(connection, ip);
		}
		catch(IOException | RuntimeException ioe) {
			try {
                session.close();
			}
			catch(Exception e) {
			}
			throw ioe;
		}

		return ip;

	}
	
	@Override
	protected Collection<ActiveSession<WindowsIP>> onStart(SystemContext ctx, List<ActiveSession<WindowsIP>> sessions) {
		/* Check for an remove any wireguard interface services that are stopped (they should
		 * either be running or not exist */
		try {
			for(var service : services.getServices()) {
				if(service.getNativeName().startsWith(TUNNEL_SERVICE_NAME_PREFIX) && ( service.getStatus() == Status.STOPPED || service.getStatus() == Status.PAUSED || service.getStatus() == Status.UNKNOWN)) {
					try {
						uninstall(service.getNativeName());
					}
					catch(Exception e) {
						LOG.error(String.format("Failed to uninstall dead service %s", service.getNativeName()), e);
					}
				}
			}
		}
		catch(Exception e) {
			LOG.error("Failed to remove dead services.", e);
		}
		return sessions;
	}

	@Override
	protected WindowsIP createVirtualInetAddress(NetworkInterface nif) throws IOException {
		return new WindowsIP(nif.getName(), nif.getDisplayName(), this);
	}

	@Override
	public String[] getMissingPackages() {
		return new String[0];
	}

	void install(String serviceName, String displayName, String description, String[] dependencies, String account,
			String password, String command, int winStartType, boolean interactive,
			Winsvc.SERVICE_FAILURE_ACTIONS failureActions, boolean delayedAutoStart, DWORD sidType) throws IOException {

		XAdvapi32 advapi32 = XAdvapi32.INSTANCE;

		XWinsvc.SERVICE_DESCRIPTION desc = new XWinsvc.SERVICE_DESCRIPTION();
		desc.lpDescription = description;

		SC_HANDLE serviceManager = WindowsSystemServices.getManager(null, Winsvc.SC_MANAGER_ALL_ACCESS);
		try {

			int dwServiceType = WinNT.SERVICE_WIN32_OWN_PROCESS;
			if (interactive)
				dwServiceType |= WinNT.SERVICE_INTERACTIVE_PROCESS;

			SC_HANDLE service = advapi32.CreateService(serviceManager, serviceName, displayName,
					Winsvc.SERVICE_ALL_ACCESS, dwServiceType, winStartType, WinNT.SERVICE_ERROR_NORMAL, command, null,
					null, (dependencies == null ? "" : String.join("\0", dependencies)) + "\0", account, password);

			if (service != null) {
				try {
					boolean success = false;
					if (failureActions != null) {
						success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_FAILURE_ACTIONS,
								failureActions);
						if (!success) {
							int err = Native.getLastError();
							throw new IOException(String.format("Failed to set failure actions. %d. %s", err,
									Kernel32Util.formatMessageFromLastErrorCode(err)));
						}
					}

					success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_DESCRIPTION, desc);
					if (!success) {
						int err = Native.getLastError();
						throw new IOException(String.format("Failed to set description. %d. %s", err,
								Kernel32Util.formatMessageFromLastErrorCode(err)));
					}

					if (SystemUtils.IS_OS_WINDOWS_VISTA && delayedAutoStart) {
						XWinsvc.SERVICE_DELAYED_AUTO_START_INFO delayedDesc = new XWinsvc.SERVICE_DELAYED_AUTO_START_INFO();
						delayedDesc.fDelayedAutostart = true;
						success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
								delayedDesc);
						if (!success) {
							int err = Native.getLastError();
							throw new IOException(String.format("Failed to set autostart. %d. %s", err,
									Kernel32Util.formatMessageFromLastErrorCode(err)));
						}
					}

					/*
					 * https://github.com/WireGuard/wireguard-windows/tree/master/embeddable-dll-
					 * service
					 */
					if (sidType != null) {
						XWinsvc.SERVICE_SID_INFO info = new XWinsvc.SERVICE_SID_INFO();
						info.dwServiceSidType = sidType;
						success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_SERVICE_SID_INFO, info);
						if (!success) {
							int err = Native.getLastError();
							throw new IOException(String.format("Failed to set SERVICE_SID_INFO. %d. %s", err,
									Kernel32Util.formatMessageFromLastErrorCode(err)));
						}
					}

				} finally {
					advapi32.CloseServiceHandle(service);
				}
			} else {
				int err = Kernel32.INSTANCE.GetLastError();
				throw new IOException(String.format("Failed to install. %d. %s", err,
						Kernel32Util.formatMessageFromLastErrorCode(err)));

			}
		} finally {
			advapi32.CloseServiceHandle(serviceManager);
		}
	}

	public void installService(String name, Path cwd) throws IOException {
		LOG.info(String.format("Installing service for %s", name));
		StringBuilder cmd = new StringBuilder();
		
		var nativeNCS = Paths.get("network-configuration-service.exe");
		if(Files.exists(nativeNCS)) {
			LOG.info("Using natively compiled network configuration service at {0}", nativeNCS.toAbsolutePath());
			cmd.append('"');
			cmd.append(nativeNCS.toAbsolutePath().toString());
			cmd.append('"');
		}
		else {
		    throw new IOException("No network configuration service executable found for this platform.");
		}
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
				"Manage a single tunnel LogonBox VPN (" + name + ")", new String[] { "Nsi", "TcpIp" }, "LocalSystem",
				null, cmd.toString(), WinNT.SERVICE_DEMAND_START, false, null, false,
				XWinsvc.SERVICE_SID_TYPE_UNRESTRICTED);

		LOG.info(String.format("Installed service for %s (%s)", name, cmd));
	}

	@Override
	protected boolean isWireGuardInterface(NetworkInterface nif) {
		return super.isWireGuardInterface(nif) && nif.getDisplayName().startsWith("Wintun Userspace Tunnel");
	}

	protected boolean isWireGuardInterface(WindowsIP nif) {
		return isMatchesPrefix(nif) && ( nif.getDisplayName().startsWith("Wintun Userspace Tunnel") || nif.getDisplayName().startsWith("WireGuard Tunnel") || isMatchesPrefix(nif.getDisplayName()));
	}

	protected boolean isMatchesPrefix(WindowsIP nif) {
		return isMatchesPrefix(nif.getName());
	}

	protected boolean isMatchesPrefix(String name) {
		return name.startsWith(getInterfacePrefix());
	}

	@Override
	public String getWGCommand() {
		synchronized (lock) {
			if (wgFile == null) {
				try {
					wgFile = File.createTempFile("wgx", ".exe");
					try (InputStream in = WindowsPlatformServiceImpl.class.getResourceAsStream(getWGExeResource())) {
						try (OutputStream out = new FileOutputStream(wgFile)) {
							in.transferTo(out);
						}
					}
				} catch (IOException ioe) {
					throw new IllegalStateException("Failed to get wg.exe.", ioe);
				}
			}
			return wgFile.toString();
		}
	}

	private String getWGExeResource() {
		if (System.getProperty("os.arch").indexOf("64") == -1)
			return "/win32-x86/wg.exe";
		else
			return "/win32-x86-64/wg.exe";
	}

	public void uninstall(String serviceName) throws IOException {
		XAdvapi32 advapi32 = XAdvapi32.INSTANCE;
		SC_HANDLE serviceManager, service;
		serviceManager = WindowsSystemServices.getManager(null, WinNT.GENERIC_ALL);
		try {
			service = advapi32.OpenService(serviceManager, serviceName, WinNT.GENERIC_ALL);
			if (service != null) {
				try {
					if (!advapi32.DeleteService(service)) {
						int err = Kernel32.INSTANCE.GetLastError();
						throw new IOException(String.format("Failed to find service to uninstall '%s'. %d. %s",
								serviceName, err, Kernel32Util.formatMessageFromLastErrorCode(err)));
					}
				} finally {
					advapi32.CloseServiceHandle(service);
				}
			} else {
				int err = Kernel32.INSTANCE.GetLastError();
				throw new IOException(String.format("Failed to find service to uninstall '%s'. %d. %s", serviceName,
						err, Kernel32Util.formatMessageFromLastErrorCode(err)));
			}
		} finally {
			advapi32.CloseServiceHandle(serviceManager);
		}
	}

	@Override
	protected void writeInterface(WireguardConfiguration configuration, Writer writer) {
		PrintWriter pw = new PrintWriter(writer, true);
		pw.println(String.format("Address = %s", configuration.getAddress()));
	}

	@Override
	public void runHook(ActiveSession<WindowsIP> session, String hookScript) throws IOException {
		runHookViaPipeToShell(session, OsUtil.getPathOfCommandInPathOrFail("cmd.exe").toString(), "/c", hookScript);
	}

	@Override
	public DNSIntegrationMethod dnsMethod() {
		return DNSIntegrationMethod.NETSH;
	}

    @Override
    protected void runCommand(List<String> commands) throws IOException {
        commands().privileged().run(commands.toArray(new String[0]));
    }
}
