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

import com.logonbox.vpn.drivers.lib.AbstractUnixDesktopPlatformService;
import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnPeer;
import com.logonbox.vpn.drivers.lib.util.OsUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LinuxPlatformServiceImpl extends AbstractUnixDesktopPlatformService<LinuxIP> {

    enum IpAddressState {
        HEADER, IP, MAC
    }

    static Logger log = LoggerFactory.getLogger(LinuxPlatformServiceImpl.class);
    private static final String INTERFACE_PREFIX = "wg";

    final static Logger LOG = LoggerFactory.getLogger(LinuxPlatformServiceImpl.class);

    static Object lock = new Object();

    public LinuxPlatformServiceImpl() {
        super(INTERFACE_PREFIX);
    }

    @Override
    public List<LinuxIP> addresses() {
        List<LinuxIP> l = new ArrayList<>();
        LinuxIP lastLink = null;
        try {
            IpAddressState state = IpAddressState.HEADER;
            for (String r : commands().output("ip", "address")) {
                if (!r.startsWith(" ")) {
                    String[] a = r.split(":");
                    String name = a[1].trim();
                    l.add(lastLink = new LinuxIP(name, this));
                    state = IpAddressState.MAC;
                } else if (lastLink != null) {
                    r = r.trim();
                    if (state == IpAddressState.MAC) {
                        String[] a = r.split("\\s+");
                        if (a.length > 1) {
                            String mac = lastLink.getMac();
                            if (mac != null && !mac.equals(a[1]))
                                throw new IllegalStateException("Unexpected MAC.");
                        }
                        state = IpAddressState.IP;
                    } else if (state == IpAddressState.IP) {
                        if (r.startsWith("inet ")) {
                            String[] a = r.split("\\s+");
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
    public DNSIntegrationMethod dnsMethod() {
        File f = new File("/etc/resolv.conf");
        try {
            String p = f.getCanonicalFile().getAbsolutePath();
            if (p.equals(f.getAbsolutePath())) {
                return DNSIntegrationMethod.RAW;
            } else if (p.equals("/run/NetworkManager/resolv.conf")) {
                return DNSIntegrationMethod.NETWORK_MANAGER;
            } else if (p.equals("/run/systemd/resolve/stub-resolv.conf")) {
                return DNSIntegrationMethod.SYSTEMD;
            } else if (p.equals("/run/resolvconf/resolv.conf")) {
                return DNSIntegrationMethod.RESOLVCONF;
            }
        } catch (IOException ioe) {
        }
        return DNSIntegrationMethod.RAW;
    }

    @Override
    public String[] getMissingPackages() {
        if (new File("/etc/debian_version").exists()) {
            Set<String> missing = new LinkedHashSet<>(Arrays.asList("wireguard-tools"));
            if (OsUtil.doesCommandExist(getWGCommand()))
                missing.remove("wireguard-tools");
            return missing.toArray(new String[0]);
        } else {
            return new String[0];
        }
    }

    @Override
    public void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException {
        runHookViaPipeToShell(configuration, session, OsUtil.getPathOfCommandInPathOrFail("bash").toString(), "-c", String.join(" ; ", hookScript).trim());
    }

    protected LinuxIP add(String name, String type) throws IOException {
        commands().privileged().logged().result("ip", "link", "add", "dev", name, "type", type);
        return find(name, addresses()).orElseThrow(() -> new IOException(MessageFormat.format("Could not find new network interface {0}", name)));
    }

    @Override
    protected LinuxIP createVirtualInetAddress(NetworkInterface nif) throws IOException {
        LinuxIP ip = new LinuxIP(nif.getName(), this);
        for (InterfaceAddress addr : nif.getInterfaceAddresses()) {
            ip.getAddresses().add(addr.getAddress().toString());
        }
        return ip;
    }

    @Override
    protected String getDefaultGateway() throws IOException {
        String gw = null;
        for (String line : commands().privileged().output("ip", "route")) {
            if (gw == null && line.startsWith("default via")) {
                String[] args = line.split("\\s+");
                if (args.length > 2)
                    gw = args[2];
            }
        }
        if (gw == null)
            throw new IOException("Could not get default gateway.");
        else
            return gw;
    }

    @Override
    protected void onStart(Optional<String> interfaceName, VpnConfiguration configuration, VpnAdapter session, Optional<VpnPeer> peer) throws IOException {
        var ip = findAddress(interfaceName, configuration, true);

        /* Set the address reserved */
        if(configuration.addresses().size() > 0)
            ip.setAddresses(configuration.addresses().get(0));

        Path tempFile = Files.createTempFile(getWGCommand(), ".cfg");
        try {
            try (Writer writer = Files.newBufferedWriter(tempFile)) {
                write(configuration, writer);
            }
            log.info(String.format("Activating Wireguard configuration for %s (in %s)", ip.name(), tempFile));
            commands().privileged().logged().result(getWGCommand(), "setconf", ip.name(), tempFile.toString());
            log.info(String.format("Activated Wireguard configuration for %s", ip.name()));
        } finally {
            Files.delete(tempFile);
        }

        /*
         * About to start connection. The "last handshake" should be this value or later
         * if we get a valid connection
         */
        var connectionStarted = Instant.ofEpochMilli(((System.currentTimeMillis() / 1000l) - 1) * 1000l);

        /* Bring up the interface (will set the given MTU) */
        ip.mtu(configuration.mtu().or(() -> context.configuration().defaultMTU()).orElse(0));
        log.info(String.format("Bringing up %s", ip.name()));
        ip.up();
        session.attachToInterface(ip);

        /*
         * Wait for the first handshake. As soon as we have it, we are 'connected'. If
         * we don't get a handshake in that time, then consider this a failed
         * connection. We don't know WHY, just it has failed
         */
        if(peer.isPresent() && context.configuration().connectTimeout().isPresent()) {
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

        /* Set the routes */
        try {
            log.info(String.format("Setting routes for %s", ip.name()));
            setRoutes(session, ip);
        } catch (IOException | RuntimeException ioe) {
            try {
                session.close();
            } catch (Exception e) {
            }
            throw ioe;
        }

    }

    protected LinuxIP findAddress(Optional<String> interfaceName, VpnConfiguration configuration, boolean failIfInUse) throws IOException {
        LinuxIP ip = null;
        
        var addresses = addresses();
        
        if(interfaceName.isPresent()) {
            String name = interfaceName.get();
            var addr = find(name, addresses);
            if (addr.isEmpty()) {
                log.info(String.format("No existing unused interfaces, creating new one (%s) for public key .", name,
                        configuration.publicKey()));
                ip = add(name, "wireguard");
                if (ip == null)
                    throw new IOException("Failed to create virtual IP address.");
                log.info(String.format("Created %s", name));
            }
            else {
                var publicKey = getPublicKey(name);
                if(failIfInUse && publicKey.isPresent()) {
                    throw new IOException(MessageFormat.format("{0} is alread in use", name));
                }
            }
        }

        /*
         * Look for wireguard interfaces that are available but not connected. If we
         * find none, try to create one.
         */
        if(ip == null) {
            int maxIface = -1;
            for (int i = 0; i < MAX_INTERFACES; i++) {
                String name = getInterfacePrefix() + i;
                log.info(String.format("Looking for %s.", name));
                if (exists(name, addresses)) {
                    /* Interface exists, is it connected? */
                    var publicKey = getPublicKey(name);
                    if (publicKey.isEmpty()) {
                        /* No addresses, wireguard not using it */
                        log.info(String.format("%s is free.", name));
                        ip = address(name);
                        maxIface = i;
                        break;
                    } else if (publicKey.get().equals(configuration.publicKey())) {
                        throw new IllegalStateException(
                                String.format("Peer with public key %s on %s is already active.", publicKey.get(), name));
                    } else {
                        log.info(String.format("%s is already in use.", name));
                    }
                } else if (maxIface == -1) {
                    /* This one is the next free number */
                    maxIface = i;
                    log.info(String.format("%s is next free interface.", name));
                    break;
                }
            }
            if (maxIface == -1)
                throw new IOException(String.format("Exceeds maximum of %d interfaces.", MAX_INTERFACES));

            if (ip == null) {
                String name = getInterfacePrefix() + maxIface;
                log.info(String.format("No existing unused interfaces, creating new one (%s) for public key .", name,
                        configuration.publicKey()));
                ip = add(name, "wireguard");
                if (ip == null)
                    throw new IOException("Failed to create virtual IP address.");
                log.info(String.format("Created %s", name));
            } else
                log.info(String.format("Using %s", ip.name()));
        }
        return ip;
    }

    protected void rebuildAllows(VpnAdapter session, LinuxIP ip) throws IOException {
        session.allows().clear();

        for (String s : commands().privileged().output(getWGCommand(), "show", ip.name(), "allowed-ips")) {
            StringTokenizer t = new StringTokenizer(s);
            if (t.hasMoreTokens()) {
                t.nextToken();
                while (t.hasMoreTokens()) {
                    var r = t.nextToken();
                    if (r.equals("(none)")) {
                        return;
                    }
                    session.allows().add(r);
                }
            }
        }
    }

    @Override
    protected void runCommand(List<String> commands) throws IOException {
        commands().privileged().logged().run(commands.toArray(new String[0]));
    }

    String resolvconfIfacePrefix() {
        File f = new File("/etc/resolvconf/interface-order");
        if (f.exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                String l;
                Pattern p = Pattern.compile("^([A-Za-z0-9-]+)\\*$");
                while ((l = br.readLine()) != null) {
                    Matcher m = p.matcher(l);
                    if (m.matches()) {
                        return m.group(1);
                    }
                }
            }
            catch(IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
        }
        return "";
    }

    void setRoutes(VpnAdapter session, LinuxIP ip) throws IOException {

        /* Set routes from the known allowed-ips supplied by Wireguard. */
        rebuildAllows(session, ip);

        /*
         * Sort by network subnet size (biggest first)
         */
        Collections.sort(session.allows(), (a, b) -> {
            String[] sa = a.split("/");
            String[] sb = b.split("/");
            Integer ia = Integer.parseInt(sa[1]);
            Integer ib = Integer.parseInt(sb[1]);
            int r = ia.compareTo(ib);
            if (r == 0) {
                return a.compareTo(b);
            } else
                return r * -1;
        });
        /* Actually add routes */
        ip.setRoutes(session.allows());
    }
}
