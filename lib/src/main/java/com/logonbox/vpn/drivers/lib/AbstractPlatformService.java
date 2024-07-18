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
package com.logonbox.vpn.drivers.lib;

import static java.nio.file.Files.setPosixFilePermissions;

import com.logonbox.vpn.drivers.lib.DNSProvider.DNSEntry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.prefs.Preferences;

public abstract class AbstractPlatformService<I extends VpnAddress> implements PlatformService<I> {
	final static Logger LOG = LoggerFactory.getLogger(AbstractPlatformService.class);
	protected static final int MAX_INTERFACES = Integer.parseInt(System.getProperty("logonbox.vpn.maxInterfaces", "250"));


	private final String interfacePrefix;

    protected SystemContext context;
	private Optional<VpnPeer> defaultGateway = Optional.empty();
	
	protected AbstractPlatformService(String interfacePrefix, SystemContext context) {
		this.interfacePrefix = interfacePrefix;
        LOG.info("Starting platform services {}", getClass().getName());
        this.context = context;
        beforeStart(context);
        onInit(context);
	}
	
	protected void beforeStart(SystemContext ctx) {
	}
	
	protected void onInit(SystemContext ctx) {
	}

	@Override
	public void setNat(String iface, String range, NATMode... nat) throws IOException {
		if(nat.length > 0)
			throw new UnsupportedOperationException("Only routed supported on this platform.");
	}

	@Override
	public NATMode[] getNat(String iface, String range) throws IOException {
		return new NATMode[0];
	}

	@Override
	public boolean isIpForwardingEnabledOnSystem() {
		return true;
	}

	@Override
	public void setIpForwardingEnabledOnSystem(boolean ipForwarding) {
		throw new UnsupportedOperationException();
	}

	@Override
    public void openToEveryone(Path path) throws IOException {
        LOG.info("Setting permissions on {} to {}", path,
                Arrays.asList(PosixFilePermission.values()));
        setPosixFilePermissions(path, new LinkedHashSet<>(Arrays.asList(PosixFilePermission.values())));
    }

    @Override
    public void restrictToUser(Path path) throws IOException {
        var prms = Arrays.asList(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        LOG.info("Setting permissions on {} to {}", path, prms);
        setPosixFilePermissions(path, new LinkedHashSet<>(
                prms));
    }

    @Override
	public Optional<String> nativeNameToInterfaceName(String name) {
    	var map = getNativeNameToNameNode();
    	try {
	    	var pref = context().commands().privileged().task(new Prefs.GetValue(map, name, ""));
			return pref.equals("") ? Optional.empty() : Optional.of(pref);
    	}
    	catch(Exception e) {
    		throw new IllegalStateException(e);
    	}
	}

    @Override
	public Optional<String> interfaceNameToNativeName(String name) {
    	var map = getNameToNativeNameNode();
    	try {
	    	var pref = context().commands().privileged().task(new Prefs.GetValue(map, name, ""));
			return pref.equals("") ? Optional.empty() : Optional.of(pref);
    	}
    	catch(Exception e) {
    		throw new IllegalStateException(e);
    	}
	}

	protected Preferences getNameToNativeNameNode() {
		var sys = Preferences.systemNodeForPackage(AbstractPlatformService.class);
    	var map = sys.node("iface2Native");
		return map;
	}

	protected Preferences getNativeNameToNameNode() {
		var sys = Preferences.systemNodeForPackage(AbstractPlatformService.class);
    	var map = sys.node("native2Iface");
		return map;
	}

	@Override
    public SystemContext context() {
        if(context == null)
            throw new IllegalStateException("Service not started.");
        return context;
    }
	
	@Override
    public Optional<VpnPeer> defaultGateway() {
        return defaultGateway;
    }
	
    @Override
    public final void defaultGateway(VpnPeer peer) throws IOException {
        resetDefaulGateway();
        defaultGateway = Optional.of(peer);
        onSetDefaultGateway(peer);
    }
    
    @Override
    public final void resetDefaulGateway() throws IOException {
        if(defaultGateway.isPresent())  {
            var gw =defaultGateway.get();
            defaultGateway = Optional.empty();
            onResetDefaultGateway(gw); 
        };
    }

    @Override
    public Optional<DNSProvider> dns() {
        return Optional.empty();
    }
    
    @Override
    public final void stop(VpnConfiguration configuration, VpnAdapter session) throws IOException {
        try {

            LOG.info("Stopping VPN for {}", session.address().shortName());
            
            try {
                var dnsOr = dns();
                if(dnsOr.isPresent()) {
                    dnsOr.get().unset(new DNSEntry.Builder().fromConfiguration(configuration).withInterface(session.address().nativeName()).build());
                }
            }
            finally {

                try {
                    if(configuration.preDown().length > 0) {
                        var p = configuration.preDown();
                        LOG.info("Running pre-down commands. {}", String.join(" ; ", p).trim());
                        runHook(configuration, session, p);
                    }
                }
                finally {
                    session.close();
                }
            }
        } finally {
            try {
                onStop(configuration, session);
            } finally {
                if(configuration.postDown().length > 0) {
                    var p = configuration.postDown();
                    LOG.info("Running post-down commands. {}", String.join(" ; ", p).trim());
                    runHook(configuration, session, p);
                }
            }
        }
        
    }

    protected void onStop(VpnConfiguration configuration, VpnAdapter session) {
        
    }

    protected abstract void onResetDefaultGateway(VpnPeer session) throws IOException;

    protected abstract void onSetDefaultGateway(VpnPeer connection) throws IOException;

	protected VpnAdapter configureExistingSession(I ip) {
		return new VpnAdapter(this, Optional.of(ip));
	}
	
	protected Optional<String> getPublicKey(String interfaceName) throws IOException {
		throw new UnsupportedOperationException("Failed to get public key for " + interfaceName);
	}

	protected String getInterfacePrefix() {
		return System.getProperty("logonbox.vpn.interfacePrefix", interfacePrefix);
	}

	protected boolean exists(String nativeName, Iterable<I> links) {
		try {
			return find(nativeName, links).isPresent();
		} catch (IllegalArgumentException iae) {
			return false;
		}
	}

	protected final Optional<I> find(String nativeName, Iterable<I> links) {
		for (var link : links)
			if (Objects.equals(nativeName, link.nativeName()))
				return Optional.of(link);
		return Optional.empty();
	}

    protected final Optional<VpnAdapter> findAdapter(String nativeName, Iterable<VpnAdapter> links) {
        for (var link : links)
            if (Objects.equals(nativeName, link.address().nativeName()))
                return Optional.of(link);
        return Optional.empty();
    }

	@Override
	public boolean isValidNativeInterfaceName(String ifaceName) {
		return ifaceName.startsWith(getInterfacePrefix()) && ifaceName.length() < 17 && ifaceName.matches("[a-z]+[0-9]+");
	}

	@Override
	public final I address(String nativeName) {
		return find(nativeName, addresses()).orElseThrow(() -> new IllegalArgumentException(String.format("No address %s", nativeName)));
	}

    @Override
    public final VpnAdapter adapter(String nativeName) {
        return findAdapter(nativeName, adapters()).orElseThrow(() -> new IllegalArgumentException(String.format("No adapter %s", nativeName)));
    }
}
