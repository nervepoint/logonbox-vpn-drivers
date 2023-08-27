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

            LOG.info("Stopping VPN for {}", session.address().name());
            
            try {
                var dnsOr = dns();
                if(dnsOr.isPresent()) {
                    dnsOr.get().unset(new DNSEntry.Builder().fromConfiguration(configuration).withInterface(session.address().name()).build());
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

	protected boolean exists(String name, Iterable<I> links) {
		try {
			find(name, links);
			return true;
		} catch (IllegalArgumentException iae) {
			return false;
		}
	}

	protected final Optional<I> find(String name, Iterable<I> links) {
		for (var link : links)
			if (Objects.equals(name, link.name()))
				return Optional.of(link);
		return Optional.empty();
	}

    protected final Optional<VpnAdapter> findAdapter(String name, Iterable<VpnAdapter> links) {
        for (var link : links)
            if (Objects.equals(name, link.address().name()))
                return Optional.of(link);
        return Optional.empty();
    }

	@Override
	public final I address(String name) {
		return find(name, addresses()).orElseThrow(() -> new IllegalArgumentException(String.format("No address %s", name)));
	}

    @Override
    public final VpnAdapter adapter(String name) {
        return findAdapter(name, adapters()).orElseThrow(() -> new IllegalArgumentException(String.format("No adapter %s", name)));
    }
}
