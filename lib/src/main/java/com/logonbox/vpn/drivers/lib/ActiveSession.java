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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ActiveSession<I extends VirtualInetAddress<?>> implements Closeable {
    final static Logger LOG = LoggerFactory.getLogger(ActiveSession.class);

    private final WireguardConfiguration connection;
    private final List<String> allows = new ArrayList<>();
    private final PlatformService<I> service;
    private Optional<I> ip;

    ActiveSession(WireguardConfiguration connection, PlatformService<I> service) {
        this(connection, service, Optional.empty());
    }

    ActiveSession(WireguardConfiguration connection, PlatformService<I> service, Optional<I> ip) {
        this.connection = connection;
        this.service = service;
        this.ip = ip;
    }

    @SuppressWarnings("unchecked")
    public <C extends WireguardConfiguration> C connection() {
        return (C)connection;
    }

    public Optional<I> ip() {
        return ip;
    }

    public List<String> allows() {
        return allows;
    }

    void attach(I vpn) {
        this.ip = Optional.of(vpn);
    }

    /**
     * Get if a session is actually an active connect (handshake has occurred and
     * has not timed out).
     * 
     * @return up
     */
    public boolean alive() {
        try {
            var ipName = ip.map(VirtualInetAddress::getName).get();
            var lastHandshake = service.getLatestHandshake(ipName, connection.getPublicKey());
            var now = System.currentTimeMillis();
            var alive = lastHandshake >= now - (service.context().configuration().handshakeTimeout().toMillis());
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "Checking if {} ({}) is still alive. Now is {}, Latest Handshake is {}, Timeout secs is {}, Alive is {}",
                        ipName, connection.getPublicKey(), now, lastHandshake,
                        service.context().configuration().handshakeTimeout(), alive);
            }
            return alive;
        } catch (Exception e) {
            LOG.debug("Failed to test if alive, assuming not.", e);
            return false;
        }

    }

    @Override
    public void close() throws IOException {

        try {
            if (ip.isPresent()) {
                I ipVal = ip.get();

                LOG.info(String.format("Closing VPN session for %s", ipVal.getName()));

                if (StringUtils.isNotBlank(connection.getPreDown())) {
                    LOG.info("Running pre-down commands.", connection.getPreDown());
                    service.runHook(this, connection.getPreDown());
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
                if (StringUtils.isNotBlank(connection.getPostDown())) {
                    LOG.info("Running post-down commands.", connection.getPostDown());
                    service.runHook(this, connection.getPostDown());
                }
            }
        }

    }
}
