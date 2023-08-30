package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import com.logonbox.vpn.drivers.lib.util.IpUtil;

import uk.co.bithatch.nativeimage.annotations.Serialization;

public interface DNSProvider {

    public interface Factory {
        <P extends DNSProvider> Class<P>[] available();

        DNSProvider create(Optional<Class<? extends DNSProvider>> clazz);
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class DNSEntry implements Serializable {

        public final static class Builder {
            private Optional<String> iface = Optional.empty();
            private List<String> ipv4Servers = new ArrayList<>();
            private List<String> ipv6Servers = new ArrayList<>();
            private List<String> domains = new ArrayList<>();

            public Builder withInterface(String iface) {
                this.iface = Optional.of(iface);
                return this;
            }
            
            public Builder fromSpec(Collection<String> dnsSpec) {
                return fromSpec(dnsSpec.toArray(new String[0]));
            }

            public Builder fromSpec(String... dnsSpec) {
                withIpv4Servers(IpUtil.filterIpV4Addresses(dnsSpec));
                withIpv6Servers(IpUtil.filterIpV6Addresses(dnsSpec));
                withDomains();
                return this;
            }

            public Builder withServers(String... servers) {
                withIpv4Servers(IpUtil.filterIpV4Addresses(servers));
                withIpv6Servers(IpUtil.filterIpV6Addresses(servers));
                return this;
            }

            public Builder addServers(String... servers) {
                addIpv4Servers(IpUtil.filterIpV4Addresses(servers));
                addIpv6Servers(IpUtil.filterIpV6Addresses(servers));
                return this;
            }

            public Builder withServers(Collection<String> servers) {
                withIpv4Servers(IpUtil.filterIpV4Addresses(servers.toArray(new String[0])));
                withIpv6Servers(IpUtil.filterIpV6Addresses(servers.toArray(new String[0])));
                return this;
            }

            public Builder addServers(Collection<String> servers) {
                addIpv4Servers(IpUtil.filterIpV4Addresses(servers.toArray(new String[0])));
                addIpv6Servers(IpUtil.filterIpV6Addresses(servers.toArray(new String[0])));
                return this;
            }

            public Builder withIpv4Servers(String... servers) {
                return withIpv4Servers(Arrays.asList(servers));
            }

            public Builder withIpv4Servers(Collection<String> servers) {
                ipv4Servers.clear();
                return addIpv4Servers(servers);
            }

            public Builder addIpv4Servers(String... servers) {
                return addIpv4Servers(Arrays.asList(servers));
            }

            public Builder addIpv4Servers(Collection<String> servers) {
                ipv4Servers.addAll(servers);
                return this;
            }

            public Builder withIpv6Servers(String... servers) {
                return withIpv6Servers(Arrays.asList(servers));
            }

            public Builder withIpv6Servers(Collection<String> servers) {
                ipv6Servers.clear();
                return addIpv6Servers(servers);
            }

            public Builder addIpv6Servers(String... servers) {
                return addIpv6Servers(Arrays.asList(servers));
            }

            public Builder addIpv6Servers(Collection<String> servers) {
                ipv6Servers.addAll(servers);
                return this;
            }

            public Builder withDomains(String... servers) {
                return withDomains(Arrays.asList(servers));
            }

            public Builder withDomains(Collection<String> servers) {
                domains.clear();
                return addDomains(servers);
            }

            public Builder addDomains(String... servers) {
                return addDomains(Arrays.asList(servers));
            }

            public Builder addDomains(Collection<String> servers) {
                domains.addAll(servers);
                return this;
            }

            public Builder fromConfiguration(VpnConfiguration configuration) {
                return fromSpec(configuration.addresses());
            }

            public DNSEntry build() {
                return new DNSEntry(this);
            }

        }

        private final String iface;
        private final String[] ipv4Servers;
        private final String[] ipv6Servers;
        private final String[] domains;

        private DNSEntry(Builder builder) {
            this.iface = builder.iface.orElseThrow(() -> new IllegalStateException("No interface supplied."));
            this.ipv4Servers = builder.ipv4Servers.toArray(new String[0]);
            this.ipv6Servers = builder.ipv6Servers.toArray(new String[0]);
            this.domains = builder.domains.toArray(new String[0]);
        }

        public String iface() {
            return iface;
        }

        public String[] ipv4Servers() {
            return ipv4Servers;
        }

        public String[] ipv6Servers() {
            return ipv6Servers;
        }

        public String[] domains() {
            return domains;
        }

        public String[] servers() {
            var all = new String[ipv4Servers.length + ipv6Servers.length];
            System.arraycopy(ipv4Servers, 0, all, 0, ipv4Servers.length);
            System.arraycopy(ipv6Servers, 0, all, ipv4Servers.length, ipv6Servers.length);
            return all;
        }

        public boolean empty() {
            return ipv4Servers.length == 0 && ipv6Servers.length == 0;
        }

        public String[] all() {
            var servers = servers();
            var all = new String[servers.length + domains.length];
            System.arraycopy(servers, 0, all, 0, servers.length);
            System.arraycopy(domains, 0, all, servers.length, domains.length);
            return all;
        }
    }

    /**
     * Initialise by the DNS provider. Do not call yourself, this is part of the internal API.
     * 
     * @param platform platform
     */
    void init(PlatformService<?> platform);

    /**
     * Get all current DNS configuration, with one entry for each active network interface.
     * 
     * @return dns configuration entries
     * @throws IOException on error
     */
    List<DNSEntry> entries() throws IOException;

    default Optional<DNSEntry> entry(String iface) throws IOException {
        for (var e : entries()) {
            if (e.iface().equals(iface)) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    /**
     * Make the provided DNS configuration active.
     * 
     * @param entry DNS configuration
     * @throws IOException on error
     */
    void set(DNSEntry entry) throws IOException;

    /**
     * Unset the provided DNS configuration (make it inactive). Ideally, this must
     * include the original DNS servers and domains that were original set by this
     * application as this is the minimum requires of a DNS provider. If you know
     * the provider is able to query existing state, and associate an interface name
     * with a particular configuration (i.e. it supports the {@link #entries()}
     * method), then you may instead use the alternative {@link #unset(String)}.
     * 
     * @param entry DNS configuration to deactivate.
     * @throws IOException on error
     */
    void unset(DNSEntry entry) throws IOException;

    /**
     * Unset any configured
     * 
     * @param iface
     * @throws IOException on error
     */
    default void unset(String iface) throws IOException {
        unset(entry(iface).orElseThrow(() -> new IllegalArgumentException("No DNS set for interface " + iface)));
    }
}
