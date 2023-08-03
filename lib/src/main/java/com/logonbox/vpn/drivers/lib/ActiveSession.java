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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class ActiveSession<I extends VpnInterface<?>> implements Closeable {
    final static Logger LOG = LoggerFactory.getLogger(ActiveSession.class);

    private final VpnConfiguration configuration;
    private final List<String> allows = new ArrayList<>();
    private final PlatformService<I> service;
    private final Optional<VpnPeer> peer;
    private Optional<I> ip;

    ActiveSession(VpnConfiguration configuration, PlatformService<I> service, Optional<VpnPeer> peer) {
        this(configuration, service, Optional.empty(), peer);
    }

    ActiveSession(VpnConfiguration configuration, PlatformService<I> service, Optional<I> ip, Optional<VpnPeer> peer) {
        this.configuration = configuration;
        this.service = service;
        this.ip = ip;
        this.peer = peer;
    }

    /**
     * Get the {@link VpnConfiguration} as it was when this session was 
     * created. Note, the configuration may have been externally changed.
     * To get the live configuration, use {@link VpnInterface#configuration()}.
     * 
     * @param <C> type
     * @return configurations
     */
    @SuppressWarnings("unchecked")
    public <C extends VpnConfiguration> C configuration() {
        return (C)configuration;
    }

    public VpnInterfaceInformation information() throws IOException {
        return ip.get().information();
    }

    public Optional<VpnPeer> peer() {
        return peer;
    }

    public Optional<I> ip() {
        return ip;
    }

    public List<String> allows() {
        return allows;
    }

    public void attachToInterface(I vpn) {
        this.ip = Optional.of(vpn);
    }

    /**
     * Get if a session is actually an active connect. If this is acting as a server,
     * then just the interface need be up for this to return <code>true</code>, other
     * wise active {@link  (handshake has occurred and
     * has not timed out).
     * 
     * @return up
     */
    public boolean alive() {
        if(peer.isPresent()) {
            try {
                var ipName = ip.map(VpnInterface::getName).get();
                var lastHandshake = service.getLatestHandshake(ip.get().getName(), peer.get().publicKey());
                var now = Instant.now();
                var alive = !lastHandshake.isBefore(now.minus(service.context().configuration().handshakeTimeout()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                            "Checking if {} ({}) is still alive. Now is {}, Latest Handshake is {}, Timeout secs is {}, Alive is {}",
                            ipName, peer.get().publicKey(), now, lastHandshake,
                            service.context().configuration().handshakeTimeout().toSeconds(), alive);
                }
                return alive;
            } catch (Exception e) {
                LOG.debug("Failed to test if alive, assuming not.", e);
                return false;
            }
        }
        else
            return ip.isPresent() && ip.get().isUp();

    }

    @Override
    public void close() throws IOException {

        try {
            if (ip.isPresent()) {
                I ipVal = ip.get();

                LOG.info(String.format("Closing VPN session for %s", ipVal.getName()));

                if(configuration.preDown().length > 0) {
                    var p = configuration.preDown();
                    LOG.info("Running pre-down commands.", String.join(" ; ", p).trim());
                    service.runHook(this, p);
                }
                
                try {
                    ipVal.down();
                } finally {
                    ipVal.delete();
                }
            }
        } finally {
            try {
                service.cleanUp(this);
            } finally {
                if(configuration.postDown().length > 0) {
                    var p = configuration.postDown();
                    LOG.info("Running post-down commands.", String.join(" ; ", p).trim());
                    service.runHook(this, p);
                }
            }
        }

    }
}
