package com.logonbox.vpn.drivers.lib;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface VpnInterfaceInformation {

    VpnInterfaceInformation EMPTY = new VpnInterfaceInformation() {

        @Override
        public long rx() {
            return 0;
        }

        @Override
        public long tx() {
            return 0;
        }

        @Override
        public String interfaceName() {
            return "";
        }

        @Override
        public List<VpnPeerInformation> peers() {
            return Collections.emptyList();
        }

        @Override
        public Instant lastHandshake() {
            return Instant.ofEpochSecond(0);
        }

        @Override
        public Optional<String> error() {
            return Optional.empty();
        }

        @Override
        public Optional<Integer> listenPort() {
            return Optional.empty();
        }
    };
    
    String interfaceName();

    long tx();

    long rx();
    
    List<VpnPeerInformation> peers();

    Instant lastHandshake();
    
    /**
     * Actual listening port if it can be determined.
     * 
     * @return listening port or empty if cannot be determined
     */
    Optional<Integer> listenPort();

    Optional<String> error();

    default Optional<VpnPeerInformation> peer(String publicKey) {
        for(var peer : peers()) {
            if(peer.publicKey().equals(publicKey))
                return Optional.of(peer);
        }
        return Optional.empty();
    }

}
