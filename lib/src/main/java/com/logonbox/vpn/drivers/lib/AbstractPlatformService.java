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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.prefs.Preferences;

public abstract class AbstractPlatformService<I extends VpnAddress> extends BasePlatformService<I> {
	final static Logger LOG = LoggerFactory.getLogger(AbstractPlatformService.class);
	protected static final int MAX_INTERFACES = Integer.parseInt(System.getProperty("logonbox.vpn.maxInterfaces", "250"));


	private final String interfacePrefix;

    protected SystemContext context;
	private Optional<VpnPeer> defaultGatewayPeer = Optional.empty();
	
	protected AbstractPlatformService(String interfacePrefix, SystemContext context) {
		this.interfacePrefix = interfacePrefix;
        this.context = context;
        beforeStart(context);
        onInit(context);
	}
	
	protected void beforeStart(SystemContext ctx) {
	}
	
	protected void onInit(SystemContext ctx) {
	}

	@Override
	public void setNat(String iface, Optional<NATMode> nat) throws IOException {
		if(nat.isPresent())
			throw new UnsupportedOperationException("Only routed supported on this platform.");
	}

	@Override
	public Optional<NATMode> getNat(String iface) throws IOException {
		return Optional.empty();
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
    public final Optional<VpnPeer> defaultGatewayPeer() {
        return defaultGatewayPeer;
    }
	
    @Override
    public final void defaultGatewayPeer(VpnPeer peer) throws IOException {
    	var gw = defaultGateway().orElseThrow(() -> new IllegalStateException("No default gateway interface is currently set, so cannot set {0} to be it's new address."));
        resetDefaultGatewayPeer();
        defaultGatewayPeer = Optional.of(peer);
        var peerAddr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
		onSetDefaultGateway(new Gateway(gw.nativeIface(), peerAddr));
    }
    
    @Override
    public final void resetDefaultGatewayPeer() throws IOException {
        if(defaultGatewayPeer.isPresent())  {
            var gwOr = defaultGateway();
            var addr = defaultGatewayPeer.get().endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
            defaultGatewayPeer = Optional.empty();
            if(gwOr.isPresent()) {
            	var gw = gwOr.get();
            	if(gw.address().equals(addr)) {
            		onResetDefaultGateway(gw);
            	}
            } 
        };
    }

    @Override
    public Optional<DNSProvider> dns() {
        return Optional.empty();
    }

    @Override
	public final void defaultGateway(Optional<Gateway> addr) {
		defaultGateway().ifPresent(this::onResetDefaultGateway);
		addr.ifPresent(this::onSetDefaultGateway);
	}

	protected abstract void onResetDefaultGateway(Gateway gateway);

    protected abstract void onSetDefaultGateway(Gateway gateway);

	protected VpnAdapter configureExistingSession(I ip) {
		return new VpnAdapter(this, Optional.of(ip));
	}
	
	protected Optional<String> getPublicKey(String interfaceName) throws IOException {
		throw new UnsupportedOperationException("Failed to get public key for " + interfaceName);
	}

	protected String getInterfacePrefix() {
		return System.getProperty("logonbox.vpn.interfacePrefix", interfacePrefix);
	}

	@Override
	public boolean isValidNativeInterfaceName(String ifaceName) {
		return ifaceName.startsWith(getInterfacePrefix()) && ifaceName.length() < 17 && ifaceName.matches("[a-z]+[0-9]+");
	}

	@Override
	public final I address(String nativeName) {
		return find(nativeName, addresses()).orElseThrow(() -> new IllegalArgumentException(String.format("No address %s", nativeName)));
	}
}
