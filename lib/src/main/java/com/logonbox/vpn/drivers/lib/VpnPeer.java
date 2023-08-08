package com.logonbox.vpn.drivers.lib;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface VpnPeer {

    public final static class Builder {

        private Optional<Integer> endpointPort = Optional.empty();
        private Optional<String> endpointAddress = Optional.empty();
        private Optional<String> publicKey = Optional.empty();
        private List<String> allowedIps = new ArrayList<>();
        private Optional<Integer> persistentKeepalive = Optional.empty();
        private Optional<String> presharedKey;

        public Builder addAllowedIps(String... allowedIps) {
            return addAllowedIps(Arrays.asList(allowedIps));
        }

        public Builder addAllowedIps(Collection<String> allowedIps) {
            this.allowedIps.addAll(allowedIps);
            return this;
        }

        public Builder withAllowedIps(String... allowedIps) {
            return withAllowedIps(Arrays.asList(allowedIps));
        }

        public Builder withAllowedIps(Collection<String> allowedIps) {
            this.allowedIps.clear();
            return addAllowedIps(allowedIps);
        }

        public Builder withPersistentKeepalive(int persistentKeepalive) {
            return withPersistentKeepalive(Optional.of(persistentKeepalive));
        }

        public Builder withPersistentKeepalive(Optional<Integer> persistentKeepalive) {
            this.persistentKeepalive = persistentKeepalive;
            return this;
        }

        public Builder withEndpointPort(int endpointPort) {
            return withEndpointPort(Optional.of(endpointPort));
        }

        public Builder withEndpointPort(Optional<Integer> endpointPort) {
            this.endpointPort = endpointPort;
            return this;
        }

        public Builder withEndpoint(Optional<String> endpoint) {
            if (endpoint.isEmpty()) {
                withEndpointAddress(Optional.empty());
                withEndpointPort(Optional.empty());
            } else {
                withEndpoint(endpoint.get());
            }
            return this;
        }

        public Builder withEndpoint(String endpoint) {
            var idx = endpoint.indexOf(':');
            withEndpointAddress(idx == -1 ? endpoint : endpoint.substring(0, idx));
            if (idx == -1) {
                withEndpointAddress(endpoint);
                withEndpointPort(Optional.empty());
            } else {
                withEndpointAddress(endpoint.substring(0, idx));
                withEndpointPort(Integer.parseInt(endpoint.substring(idx + 1)));
            }
            return this;
        }

        public Builder withEndpoint(InetSocketAddress endpoint) {
            if (endpoint == null) {
                return withEndpoint(Optional.empty());
            } else {
                return withEndpointAddress(endpoint.getAddress().getHostAddress()).withEndpointPort(endpoint.getPort());
            }
        }

        public Builder withEndpointAddress(String endpointAddress) {
            return withEndpointAddress(Optional.of(endpointAddress));
        }

        public Builder withEndpointAddress(Optional<String> endpointAddress) {
            this.endpointAddress = endpointAddress;
            return this;
        }

        public Builder withPresharedKey(String presharedKey) {
            return withPresharedKey(Optional.of(presharedKey));
        }

        public Builder withPresharedKey(Optional<String> presharedKey) {
            this.presharedKey = presharedKey;
            return this;
        }

        public Builder withPublicKey(String publicKey) {
            return withPublicKey(Optional.of(publicKey));
        }

        public Builder withPublicKey(Optional<String> publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public VpnPeer build() {
            return new DefaultVpnPeer(this);
        }

        class DefaultVpnPeer implements VpnPeer {

            private final Optional<Integer> endpointPort;
            private final Optional<String> endpointAddress;
            private final String publicKey;
            private final List<String> allowedIps;
            private final Optional<Integer> persistentKeepalive;
            private final Optional<String> presharedKey;

            DefaultVpnPeer(Builder builder) {
                persistentKeepalive = builder.persistentKeepalive;
                endpointPort = builder.endpointPort;
                endpointAddress = builder.endpointAddress;
                publicKey = builder.publicKey.orElseThrow(() -> new IllegalStateException("No public key"));
                allowedIps = Collections.unmodifiableList(new ArrayList<>(builder.allowedIps));
                presharedKey = builder.presharedKey;
            }

            @Override
            public Optional<String> presharedKey() {
                return presharedKey;
            }

            @Override
            public Optional<String> endpointAddress() {
                return endpointAddress;
            }

            @Override
            public Optional<Integer> endpointPort() {
                return endpointPort;
            }

            @Override
            public String publicKey() {
                return publicKey;
            }

            @Override
            public Optional<Integer> persistentKeepalive() {
                return persistentKeepalive;
            }

            @Override
            public List<String> allowedIps() {
                return allowedIps;
            }

        }
    }

    Optional<String> endpointAddress();

    Optional<Integer> endpointPort();

    String publicKey();

    Optional<Integer> persistentKeepalive();

    List<String> allowedIps();
    
    Optional<String> presharedKey();
}
