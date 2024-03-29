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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.logonbox.vpn.drivers.lib.AbstractUnixDesktopPlatformService;
import com.logonbox.vpn.drivers.lib.NativeComponents.Tool;
import com.logonbox.vpn.drivers.lib.StartRequest;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.sshtools.liftlib.ElevatedClosure;

import uk.co.bithatch.nativeimage.annotations.Serialization;

public abstract class AbstractLinuxPlatformService extends AbstractUnixDesktopPlatformService<AbstractLinuxAddress> {

    enum IpAddressState {
        HEADER, IP, MAC
    }

    private static final String INTERFACE_PREFIX = "wg";
    private final static Logger LOG = LoggerFactory.getLogger(AbstractLinuxPlatformService.class);

    static Object lock = new Object();

    public AbstractLinuxPlatformService(SystemContext context) {
        super(INTERFACE_PREFIX, context);
    }

	@Override
    public final List<AbstractLinuxAddress> addresses() {
        List<AbstractLinuxAddress> l = new ArrayList<>();
        AbstractLinuxAddress lastLink = null;
        try {
            IpAddressState state = IpAddressState.HEADER;
            for (String r : context().commands().output("ip", "address")) {
                if (!r.startsWith(" ")) {
                    String[] a = r.split(":");
                    String name = a[1].trim();
                    l.add(lastLink = createAddress(nativeNameToInterfaceName(name).orElse(name), name));
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
	public boolean isIpForwardingEnabledOnSystem() {
    	var ipv4 = Paths.get("/proc/sys/ipv4/ip_forward");
    	var ipv6 = Paths.get("/proc/sys/net/ipv6/conf/all/forwarding");
    	return (((Files.exists(ipv4) && isEnabled(ipv4)) || !Files.exists(ipv4)) &&
    			((Files.exists(ipv4) && isEnabled(ipv6)) || !Files.exists(ipv6)));
	}

	@Override
	public boolean isValidNativeInterfaceName(String ifaceName) {
		return ifaceName.length() < 16 && !ifaceName.matches(".*\\s+.*") && !ifaceName.contains(" ") && !ifaceName.contains("/");
	}

	@Override
    public final void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException {
        runHookViaPipeToShell(configuration, session, OsUtil.getPathOfCommandInPathOrFail("bash").toString(), "-c",
                String.join(" ; ", hookScript).trim());
    }

	@Override
	public void setNat(VpnAdapter vpnAdapter, boolean nat) throws IOException {
		var is = isNat(vpnAdapter);
		if(is != nat) {
			if(nat) {
				LOG.info("Turning on NAT masquerade for {}", vpnAdapter.address().nativeName());
				context.commands().privileged().run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", vpnAdapter.address().nativeName(), "-j",
						"MASQUERADE");
			}
			else {
				LOG.info("Turning off NAT masquerade for {}", vpnAdapter.address().nativeName());
				context.commands().privileged().run("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", vpnAdapter.address().nativeName(), "-j",
						"MASQUERADE");
			}
		}
	}

	@Override
	public Optional<String> nativeNameToInterfaceName(String name) {
		return Optional.empty();
	}

	@Override
	public Optional<String> interfaceNameToNativeName(String name) {
		return Optional.empty();
	}

	@Override
	public boolean isNat(VpnAdapter vpnAdapter) throws IOException {
		return getNatInterfaces().contains(vpnAdapter.address().nativeName());
	}

	@Override
	public void setIpForwardingEnabledOnSystem(boolean ipForwarding) {
    	var ipv4 = Paths.get("/proc/sys/ipv4/ip_forward");
    	var ipv6 = Paths.get("/proc/sys/net/ipv6/conf/all/forwarding");
    	var ipv4Exists = Files.exists(ipv4);
		var ipv6Exists = Files.exists(ipv6);
		if(ipv4Exists || ipv6Exists) {
			try {
	    		if(ipv4Exists) {
	    			context.commands().privileged().task(new SetIpForwarding(ipv4.toString(), ipForwarding));
	    		}
	    		if(ipv6Exists) {
	    			context.commands().privileged().task(new SetIpForwarding(ipv6.toString(), ipForwarding));
	    		}
			}
			catch(Exception e) {
				throw new IllegalStateException("Failed to change IP forwarding.", e);
			}
    	}
    	else {
    		super.setIpForwardingEnabledOnSystem(ipForwarding);
    	}
	}

	protected abstract AbstractLinuxAddress createAddress(String name, String nativeName);

    @Override
    protected final AbstractLinuxAddress createVirtualInetAddress(NetworkInterface nif) throws IOException {
        var ip = createAddress(nativeNameToInterfaceName(nif.getName()).orElse(nif.getName()), nif.getName());
        for (var addr : nif.getInterfaceAddresses()) {
            ip.getAddresses().add(addr.getAddress().toString());
        }
        return ip;
    }

    @Override
    protected final String getDefaultGateway() throws IOException {
        String gw = null;
        for (String line : context().commands().privileged().output("ip", "route")) {
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
    protected final void onStart(StartRequest startRequest, VpnAdapter session) throws IOException {
		var configuration  = startRequest.configuration();
		var peer = startRequest.peer();
        var ip = findAddress(startRequest);

        /* Set the address reserved */
        if (configuration.addresses().size() > 0)
            ip.setAddresses(configuration.addresses().get(0));

        Path tempFile = Files.createTempFile("wg", ".cfg");
        try {
            try (Writer writer = Files.newBufferedWriter(tempFile)) {
                transform(configuration).write(writer);
            }
            LOG.info("Activating Wireguard configuration for {} (in {})", ip.shortName(), tempFile);
            context().commands().privileged().logged().result(context().nativeComponents().tool(Tool.WG), "setconf", ip.name(),
                    tempFile.toString());
            LOG.info("Activated Wireguard configuration for {}", ip.shortName());
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
        LOG.info("Bringing up {}", ip.shortName());
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
            LOG.info("Setting routes for {}", ip.shortName());
            addRoutes(session);
        } catch (IOException | RuntimeException ioe) {
            try {
                session.close();
            } catch (Exception e) {
            }
            throw ioe;
        }

    }

    @Override
    protected final void runCommand(List<String> commands) throws IOException {
        context(). commands().privileged().logged().run(commands.toArray(new String[0]));
    }

    String resolvconfIfacePrefix() {
        var f = new File("/etc/resolvconf/interface-order");
        if (f.exists()) {
            try (var br = new BufferedReader(new FileReader(f))) {
                String l;
                var p = Pattern.compile("^([A-Za-z0-9-]+)\\*$");
                while ((l = br.readLine()) != null) {
                    var m = p.matcher(l);
                    if (m.matches()) {
                        return m.group(1);
                    }
                }
            } catch (IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
        }
        return "";
    }

    private boolean isEnabled(Path path) {
		try(var rdr = Files.newBufferedReader(path)) {
    		return rdr.readLine().equals("1");
    	}
    	catch(IOException ioe) {
    		throw new UncheckedIOException(ioe);
    	}
	}

    @SuppressWarnings("serial")
	@Serialization
    public final static class SetIpForwarding implements ElevatedClosure<Serializable, Serializable> {
    	
    	private String path;
		private boolean enable;

		public SetIpForwarding() {} 
    	
		SetIpForwarding(String path, boolean enable) {
    		this.path = path;
    		this.enable = enable;
    	}

		@Override
		public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
			try(var rdr = Files.newBufferedWriter(Paths.get(path))) {
	    		rdr.write(enable ? "1" : "0");
	    	}
	    	catch(IOException ioe) {
	    		throw new UncheckedIOException(ioe);
	    	}
			return null;
		}
    	
    }

	private List<String> getNatInterfaces() throws IOException {
		var s = new ArrayList<String>();
		for (var l : context.commands().privileged().output("iptables", "-t", "nat", "-L", "POSTROUTING", "-v")) {
			var els = l.split("\\s+");
			if(els.length > 6 && els[2].equals("MASQUERADE")) {
				s.add(els[6]);
			}
		}
		Collections.sort(s);
		return s;
	}
}
