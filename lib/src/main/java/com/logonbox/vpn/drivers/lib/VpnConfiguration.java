package com.logonbox.vpn.drivers.lib;

import com.sshtools.jini.INI.Section;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface VpnConfiguration extends VpnAdapterConfiguration {

    public final static class Builder extends VpnAdapterConfiguration.AbstractBuilder<Builder> {

        private Optional<Integer> mtu = Optional.empty();
        private List<String> dns = new ArrayList<>();
        private List<String> addresses = new ArrayList<>();
        private List<String> preUp = new ArrayList<>();
        private List<String> postUp = new ArrayList<>();
        private List<String> preDown = new ArrayList<>();
        private List<String> postDown = new ArrayList<>();
        private Optional<String> table = Optional.empty();
        private boolean saveConfig;

        @Override
        protected void readInterfaceSection(Section iface) {
            super.readInterfaceSection(iface);
            withAddresses(iface.getAllOr("Address", new String[0]));
            withDns(iface.getAllOr("DNS", new String[0]));
            withMtu(iface.getIntOr("MTU"));
            withPreUp(iface.getAllOr("PreUp", new String[0]));
            withPreDown(iface.getAllOr("PreDown", new String[0]));
            withPostUp(iface.getAllOr("PostUp", new String[0]));
            withPostDown(iface.getAllOr("PostDown", new String[0]));
            withSaveConfig(iface.getBooleanOr("SaveConfig", false));
            withTable(iface.getOr("Table"));
        }

        public Builder withTable(String table) {
            return withTable(Optional.of(table));
        }

        public Builder withTable(Optional<String> table) {
            this.table = table;
            return this;
        }

        public Builder withSaveConfig() {
            return withSaveConfig(true);
        }

        public Builder withSaveConfig(boolean saveConfig) {
            this.saveConfig = saveConfig;
            return this;
        }

        public Builder addAddresses(String... addresses) {
            return addAddresses(Arrays.asList(addresses));
        }

        public Builder addAddresses(Collection<String> addresses) {
            this.addresses.addAll(addresses);
            return this;
        }

        public Builder withAddresses(String... addresses) {
            return withAddresses(Arrays.asList(addresses));
        }

        public Builder withAddresses(Collection<String> addresses) {
            this.addresses.clear();
            return addAddresses(addresses);
        }

        public Builder addDns(String... dns) {
            return addDns(Arrays.asList(dns));
        }

        public Builder addDns(Collection<String> dns) {
            this.dns.addAll(dns);
            return this;
        }

        public Builder withDns(String... dns) {
            return withDns(Arrays.asList(dns));
        }

        public Builder withDns(Collection<String> dns) {
            this.dns.clear();
            return addDns(dns);
        }

        public Builder withMtu(int listenPort) {
            return withListenPort(Optional.of(listenPort));
        }

        public Builder withMtu(Optional<Integer> mtu) {
            this.mtu = mtu;
            return this;
        }

        public Builder withPreUp(String... preUp) {
            return withPreUp(Arrays.asList(preUp));
        }

        public Builder withPreUp(Collection<String> preUp) {
            this.preUp.clear();
            this.preUp.addAll(preUp);
            return this;
        }

        public Builder withPreDown(String... preDown) {
            return withPreDown(Arrays.asList(preDown));
        }

        public Builder withPreDown(Collection<String> preDown) {
            this.preDown.clear();
            this.preDown.addAll(preDown);
            return this;
        }

        public Builder withPostUp(String... postUp) {
            return withPostUp(Arrays.asList(postUp));
        }

        public Builder withPostUp(Collection<String> postUp) {
            this.postUp.clear();
            this.postUp.addAll(postUp);
            return this;
        }

        public Builder withPostDown(String... postDown) {
            return withPostDown(Arrays.asList(postDown));
        }

        public Builder withPostDown(Collection<String> postDown) {
            this.postDown.clear();
            this.postDown.addAll(postDown);
            return this;
        }

        public Builder fromConfiguration(VpnConfiguration configuration) {
            super.fromConfiguration(configuration);
            withMtu(configuration.mtu());
            withDns(configuration.dns());
            withAddresses(configuration.addresses());
            withPreUp(configuration.preUp());
            withPreDown(configuration.preDown());
            withPostUp(configuration.postUp());
            withPostDown(configuration.postDown());
            withTable(configuration.table());
            withSaveConfig(configuration.saveConfig());
            return this;
        }

        public VpnConfiguration build() {
            return new DefaultVpnConfiguration(this);
        }

        class DefaultVpnConfiguration extends DefaultVpnAdapterConfiguration implements VpnConfiguration {

            private final Optional<Integer> mtu;
            private final List<String> dns;
            private final List<String> addresses;
            private final String[] postUp;
            private final String[] postDown;
            private final String[] preUp;
            private final String[] preDown;
            private final Optional<String> table;
            private final boolean saveConfig;

            DefaultVpnConfiguration(VpnConfiguration.Builder builder) {
                super(builder);
                mtu = builder.mtu;
                dns = Collections.unmodifiableList(new ArrayList<>(builder.dns));
                addresses = Collections.unmodifiableList(new ArrayList<>(builder.addresses));
                preUp = builder.preUp.toArray(new String[0]);
                preDown = builder.preDown.toArray(new String[0]);
                postUp = builder.postUp.toArray(new String[0]);
                postDown = builder.postDown.toArray(new String[0]);
                saveConfig = builder.saveConfig;
                table = builder.table;
            }

            @Override
            public List<String> dns() {
                return dns;
            }

            @Override
            public Optional<Integer> mtu() {
                return mtu;
            }

            @Override
            public List<String> addresses() {
                return addresses;
            }

            @Override
            public String[] preUp() {
                return preUp;
            }

            @Override
            public String[] postUp() {
                return postUp;
            }

            @Override
            public String[] preDown() {
                return preDown;
            }

            @Override
            public String[] postDown() {
                return postDown;
            }

            @Override
            public Optional<String> table() {
                return table;
            }

            @Override
            public boolean saveConfig() {
                return saveConfig;
            }

        }
    }

    String[] preUp();

    String[] postUp();

    String[] preDown();

    String[] postDown();

    List<String> dns();

    Optional<Integer> mtu();

    List<String> addresses();

    Optional<String> table();

    boolean saveConfig();
}
