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

import java.io.Closeable;
import java.io.IOException;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class VpnAdapter implements Closeable {
    final static Logger LOG = LoggerFactory.getLogger(VpnAdapter.class);

    private final List<String> allows = new ArrayList<>();
    private final PlatformService<?> service;
    private Optional<VpnAddress> ip;

    VpnAdapter(PlatformService<?> service) {
        this(service, Optional.empty());
    }

    VpnAdapter(PlatformService<?> service, Optional<VpnAddress> ip) {
        this.service = service;
        this.ip = ip;
    }

    /**
     * Get the detailed status of a peer with the given public key in the named
     * interface .
     * 
     * @param interfaceName interface name
     * @param publicKey     public key of peer
     * @return detailed status
     * @throws IOException              on error
     * @throws IllegalArgumentException if no such public key
     */
    public VpnPeerInformation information(String publicKey) throws IOException {
        for (var peer : information().peers()) {
            if (peer.publicKey().equals(publicKey))
                return peer;
        }
        throw new IllegalArgumentException(
                MessageFormat.format("No such peer {0} on interface {1}", publicKey, address().shortName()));
    }

    /**
     * Get the instant of the last handshake for any peer on the specified
     * interface.
     * 
     * @return instant
     */
    public Instant latestHandshake() throws IOException {
        return information().lastHandshake();
    }

    /**
     * Get the instant of the last handshake for a given peer on the specified
     * interface.
     * 
     * @param publicKey public key of peer
     * @return instant
     */
    public Instant latestHandshake(String publicKey) throws IOException {
        return information(publicKey).lastHandshake();
    }

    public VpnAdapterConfiguration configuration() {
        return service.configuration(this);
    }

	public void reconfigure(VpnAdapterConfiguration cfg) throws IOException {
		service.reconfigure(this, cfg);
	}

	public void append(VpnAdapterConfiguration cfg) throws IOException {
		service.append(this, cfg);
	}

	public void sync(VpnAdapterConfiguration cfg) throws IOException {
		service.sync(this, cfg);
	}
	
	public NATMode[] nat(String range) throws IOException {
		return service.getNat(this.address().nativeName(), range);
	}
	
	public void nat(String range, NATMode[] nat) throws IOException {
		service.setNat(this.address().nativeName(), range, nat);
	}

    public VpnInterfaceInformation information() {
        return service.information(this);
    }

    public VpnAddress address() {
        return ip.orElseThrow(() -> new IllegalStateException("No address."));
    }

    public List<String> allows() {
        return allows;
    }

    public void attachToInterface(VpnAddress vpn) {
        this.ip = Optional.of(vpn);
    }

    @Override
    public void close() throws IOException {
        if (ip.isPresent()) {
            VpnAddress ipVal = ip.get();
            LOG.info(String.format("Closing VPN session for %s", ipVal.shortName()));
            try {
                ipVal.down();
            } finally {
                ipVal.delete();
            }
        }
    }

	public void remove(String publicKey) throws IOException {
		service.remove(this, publicKey);
	}
}
