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

import com.logonbox.vpn.drivers.lib.AbstractDesktopPlatformService;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnInterfaceInformation;
import com.logonbox.vpn.drivers.lib.VpnPeer;
import com.logonbox.vpn.drivers.lib.VpnPeerInformation;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.io.Writer;
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

import uk.co.bithatch.nativeimage.annotations.Resource;

@Resource("win32-x84-64/.*")
public class WindowsPlatformServiceImpl extends AbstractDesktopPlatformService<WindowsIP> {

    public final static String SID_ADMINISTRATORS_GROUP = "S-1-5-32-544";
    public final static String SID_WORLD = "S-1-1-0";
    public final static String SID_USERS = "S-1-5-32-545";
    public final static String SID_SYSTEM = "S-1-5-18";

    public static final String TUNNEL_SERVICE_NAME_PREFIX = "LogonBoxVPNTunnel";

    private static final String INTERFACE_PREFIX = "net";

    final static Logger LOG = LoggerFactory.getLogger(WindowsPlatformServiceImpl.class);

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
    public List<WindowsIP> addresses() {
        return ips(false);
    }


    @Override
    public List<VpnAdapter> adapters() {
        return ips(true).stream().map(addr -> configureExistingSession(addr)).toList();
    }
    
    private List<WindowsIP> ips(boolean wireguardInterface) {
        Set<WindowsIP> ips = new LinkedHashSet<>();

        /* netsh first */
        try {
            for (var line : commands().privileged().output("netsh", "interface", "ip", "show", "interfaces")) {
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
                            WindowsIP vaddr = new WindowsIP(ifName.toString(), ifName.toString(), this);
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
            for (var line : commands().privileged().output("ipconfig", "/all")) {
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
                            var vaddr = new WindowsIP(name, description, this);
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

        return new ArrayList<WindowsIP>(ips);
    }

    @Override
    protected void onSetDefaultGateway(VpnPeer peer) throws IOException {
        var gw = getDefaultGateway();
        var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
        LOG.info("Routing traffic all through peer {}", addr);
        commands().privileged().logged().run("route", "add", addr, gw);
    }

    @Override
    protected void onResetDefaultGateway(VpnPeer peer) throws IOException {
        var gw = getDefaultGateway();
        var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
        LOG.info("Removing routing of all traffic  through peer {}", addr);
        commands().privileged().logged().run("route", "delete", addr, gw);
    }

    @Override
    protected String getDefaultGateway() throws IOException {
        String gw = null;
        for (var line : commands().privileged().output("ipconfig")) {
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
    protected void onStart(Optional<String> interfaceName, VpnConfiguration configuration, VpnAdapter session, Optional<VpnPeer> peer) throws IOException {
        WindowsIP ip = null;

        /*
         * Look for wireguard interfaces that are available but not connected. If we
         * find none, try to create one.
         */
        int maxIface = -1;

        List<WindowsIP> ips = ips(false);

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
                WindowsIP nicByName = find(name, ips).orElseThrow(() -> new IOException(MessageFormat.format("Could not find network interface {0}", name)));;
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
                        LOG.warn("    Peer with public key {} on {} is already active (by {}).",
                                publicKey.get(), name, nicByName.displayName());
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
            ip = new WindowsIP(name, "Wintun Userspace Tunnel", this);
            LOG.info("Created {}", name);
        } else
            LOG.info("Using {}", ip.name());

        session.attachToInterface(ip);

        var cwd = Paths.get(System.getProperty("user.dir"));
        var confDir = cwd.resolve("conf").resolve("connections");
        if (!Files.exists(confDir))
            Files.createDirectories(confDir);

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
        if (!Advapi32.INSTANCE.SetFileSecurity(confDir.toFile().getPath(),
                WinNT.OWNER_SECURITY_INFORMATION | WinNT.GROUP_SECURITY_INFORMATION | WinNT.DACL_SECURITY_INFORMATION,
                securityDescriptor.getValue())) {
            var err = Kernel32.INSTANCE.GetLastError();
            throw new IOException(String.format("Failed to set file security on '%s'. %d. %s", confDir, err,
                    Kernel32Util.formatMessageFromLastErrorCode(err)));
        }

        var confFile = confDir.resolve(ip.name() + ".conf");
        try (var writer = Files.newBufferedWriter(confFile)) {
            write(configuration, writer);
        }

        /* Install service for the network interface */
        var install = false;
        if (!services.hasService(TUNNEL_SERVICE_NAME_PREFIX + "$" + ip.name())) {
            install = true;
            installService(ip.name(), cwd);
        } else
            LOG.info("Service for {} already exists.", ip.name());

        /* The service may take a short while to appear */
        int i = 0;
        for (; i < SERVICE_INSTALL_TIMEOUT; i++) {
            if (services.hasService(TUNNEL_SERVICE_NAME_PREFIX + "$" + ip.name()))
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
                            ip.name()));

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
            LOG.info("Service for {} is already up.", ip.name());
        } else {
            LOG.info("Bringing up {}", ip.name());
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
            waitForFirstHandshake(configuration, session, connectionStarted, peer, context.configuration().connectTimeout().get());
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
            for (var service : services.getServices()) {
                if (service.getNativeName().startsWith(TUNNEL_SERVICE_NAME_PREFIX)
                        && (service.getStatus() == Status.STOPPED || service.getStatus() == Status.PAUSED
                                || service.getStatus() == Status.UNKNOWN)) {
                    try {
                        uninstall(service.getNativeName());
                    } catch (Exception e) {
                        LOG.error("Failed to uninstall dead service {}", service.getNativeName(), e);
                    }
                }
            }
        } catch (Exception e) {
            LOG.error("Failed to remove dead services.", e);
        }
    }

    @Override
    protected WindowsIP createVirtualInetAddress(NetworkInterface nif) throws IOException {
        return new WindowsIP(nif.getName(), nif.getDisplayName(), this);
    }

    void install(String serviceName, String displayName, String description, String[] dependencies, String account,
            String password, String command, int winStartType, boolean interactive,
            Winsvc.SERVICE_FAILURE_ACTIONS failureActions, boolean delayedAutoStart, DWORD sidType) throws IOException {

        var advapi32 = XAdvapi32.INSTANCE;

        var desc = new XWinsvc.SERVICE_DESCRIPTION();
        desc.lpDescription = description;

        var serviceManager = WindowsSystemServices.getManager(null, Winsvc.SC_MANAGER_ALL_ACCESS);
        try {

            var dwServiceType = WinNT.SERVICE_WIN32_OWN_PROCESS;
            if (interactive)
                dwServiceType |= WinNT.SERVICE_INTERACTIVE_PROCESS;

            var service = advapi32.CreateService(serviceManager, serviceName, displayName,
                    Winsvc.SERVICE_ALL_ACCESS, dwServiceType, winStartType, WinNT.SERVICE_ERROR_NORMAL, command, null,
                    null, (dependencies == null ? "" : String.join("\0", dependencies)) + "\0", account, password);

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
                        success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                delayedDesc);
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
                        success = advapi32.ChangeServiceConfig2(service, Winsvc.SERVICE_CONFIG_SERVICE_SID_INFO, info);
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

    public void installService(String name, Path cwd) throws IOException {
        LOG.info("Installing service for {}", name);
        var cmd = new StringBuilder();

        var nativeNCS = Paths.get("network-configuration-service.exe");
        if (Files.exists(nativeNCS)) {
            LOG.info("Using natively compiled network configuration service at {}", nativeNCS.toAbsolutePath());
            cmd.append('"');
            cmd.append(nativeNCS.toAbsolutePath().toString());
            cmd.append('"');
        } else {
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

        LOG.info("Installed service for {} ({})", name, cmd);
    }

    @Override
    protected boolean isWireGuardInterface(NetworkInterface nif) {
        return super.isWireGuardInterface(nif) && nif.getDisplayName().startsWith("Wintun Userspace Tunnel");
    }

    protected boolean isWireGuardInterface(WindowsIP nif) {
        return isMatchesPrefix(nif) && (nif.displayName().startsWith("Wintun Userspace Tunnel")
                || nif.displayName().startsWith("WireGuard Tunnel") || isMatchesPrefix(nif.displayName()));
    }

    protected boolean isMatchesPrefix(WindowsIP nif) {
        return isMatchesPrefix(nif.name());
    }

    protected boolean isMatchesPrefix(String name) {
        return name.startsWith(getInterfacePrefix());
    }

    public void uninstall(String serviceName) throws IOException {
        var advapi32 = XAdvapi32.INSTANCE;
        SC_HANDLE serviceManager, service;
        serviceManager = WindowsSystemServices.getManager(null, WinNT.GENERIC_ALL);
        try {
            service = advapi32.OpenService(serviceManager, serviceName, WinNT.GENERIC_ALL);
            if (service != null) {
                try {
                    if (!advapi32.DeleteService(service)) {
                        var err = Kernel32.INSTANCE.GetLastError();
                        throw new IOException(String.format("Failed to find service to uninstall '%s'. %d. %s",
                                serviceName, err, Kernel32Util.formatMessageFromLastErrorCode(err)));
                    }
                } finally {
                    advapi32.CloseServiceHandle(service);
                }
            } else {
                var err = Kernel32.INSTANCE.GetLastError();
                throw new IOException(String.format("Failed to find service to uninstall '%s'. %d. %s", serviceName,
                        err, Kernel32Util.formatMessageFromLastErrorCode(err)));
            }
        } finally {
            advapi32.CloseServiceHandle(serviceManager);
        }
    }

    @Override
    protected void writeInterface(VpnConfiguration configuration, Writer writer) {
        if (!configuration.addresses().isEmpty()) {
            new PrintWriter(writer, true)
                    .println(String.format("Address = %s", String.join(",", configuration.addresses())));
        }
    }

    @Override
    public void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException {
        runHookViaPipeToShell(configuration, session, OsUtil.getPathOfCommandInPathOrFail("cmd.exe").toString(), "/c",
                String.join(" & ", hookScript).trim());
    }

    @Override
    public DNSIntegrationMethod dnsMethod() {
        return DNSIntegrationMethod.NETSH;
    }

    @Override
    protected void runCommand(List<String> commands) throws IOException {
        commands().privileged().logged().run(commands.toArray(new String[0]));
    }

    @Override
    public VpnInterfaceInformation information(VpnAdapter vpnAdapter) {
        var iface = vpnAdapter.address();
        var lastHandshake = new AtomicLong(0);
        try (var adapter = new WireguardLibrary.Adapter(iface.name())) {
            var wgIface = adapter.getConfiguration();
            var tx = new AtomicLong(0);
            var rx = new AtomicLong(0);
            var peers = new ArrayList<VpnPeerInformation>();
            for (var peer : wgIface.peers) {
                var thisHandshake = peer.lastHandshake.orElse(Instant.ofEpochSecond(0));
                lastHandshake.set(Math.max(lastHandshake.get(), thisHandshake.toEpochMilli()));
                tx.addAndGet(peer.txBytes);
                rx.addAndGet(peer.rxBytes);
                var allowedIps = Arrays.asList(peer.allowedIPs).stream().map(a -> String.format("%s/%d", a.address.getHostAddress(), a.cidr)).toList();
                peers.add(new VpnPeerInformation() {
                    @Override
                    public long tx() {
                        return peer.txBytes;
                    }
                    
                    @Override
                    public long rx() {
                        return peer.rxBytes;
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
                        return peer.publicKey.toString();
                    }

                    @Override
                    public Optional<String> presharedKey() {
                        return peer.presharedKey == null ? Optional.empty() : Optional.of(peer.presharedKey.toString());
                    }

                    @Override
                    public List<String> allowedIps() {
                        return allowedIps;
                    }
                });
            }
            
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
                    return iface.name();
                }
                
                @Override
                public Instant lastHandshake() {
                    return Instant.ofEpochMilli(lastHandshake.get());
                }

                @Override
                public Optional<Integer> listenPort() {
                    return Optional.of(wgIface.listenPort);
                }

                @Override
                public Optional<Integer> fwmark() {
                    return Optional.empty();
                }

                @Override
                public String publicKey() {
                    return wgIface.publicKey.toString();
                }

                @Override
                public String privateKey() {
                    return wgIface.privateKey.toString();
                }
            };
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public VpnAdapterConfiguration configuration(VpnAdapter vpnAdapter) {
        var iface = vpnAdapter.address();
        var cfgBldr = new VpnAdapterConfiguration.Builder();
        try (var adapter = new WireguardLibrary.Adapter(iface.name())) {
            var wgIface = adapter.getConfiguration();
            cfgBldr.withPrivateKey(wgIface.privateKey.toString());
            cfgBldr.withPublicKey(wgIface.publicKey.toString());
            cfgBldr.withListenPort(wgIface.listenPort);
            for (var peer : wgIface.peers) {
                var peerBldr = new VpnPeer.Builder();
                peerBldr.withPublicKey(peer.publicKey.toString());
                peerBldr.withPersistentKeepalive(peer.PersistentKeepalive);
                if(peer.endpoint != null)
                    peerBldr.withEndpoint(peer.endpoint);
                if(peer.presharedKey != null)
                    peerBldr.withPresharedKey(peer.presharedKey.toString());
                for (var allowed : peer.allowedIPs) {
                    peerBldr.addAllowedIps(allowed.address.getHostAddress() + "/" + allowed.cidr);
                }
                var peerCfg = peerBldr.build();
                cfgBldr.addPeers(peerCfg);
            }
            return cfgBldr.build();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
