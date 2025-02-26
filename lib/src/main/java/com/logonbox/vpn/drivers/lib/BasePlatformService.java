package com.logonbox.vpn.drivers.lib;

import com.logonbox.vpn.drivers.lib.DNSProvider.DNSEntry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

public abstract class BasePlatformService<I extends VpnAddress> implements PlatformService<I> {

    final static Logger LOG = LoggerFactory.getLogger(BasePlatformService.class);
    
    @Override
    public final void stop(VpnConfiguration configuration, VpnAdapter session) throws IOException {
        try {

            LOG.info("Stopping VPN for {}", session.address().shortName());
            
            try {
                if(!configuration.addresses().isEmpty()) {
                    var dnsOr = dns();
                    if(dnsOr.isPresent()) {
                        dnsOr.get().unset(new DNSEntry.Builder().fromConfiguration(configuration).withInterface(session.address().nativeName()).build());
                    }
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

    @Override
    public final VpnAdapter adapter(String nativeName) {
        return findAdapter(nativeName, adapters()).orElseThrow(() -> new IllegalArgumentException(String.format("No adapter %s", nativeName)));
    }

    protected void onStop(VpnConfiguration configuration, VpnAdapter session) {
        
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
}
