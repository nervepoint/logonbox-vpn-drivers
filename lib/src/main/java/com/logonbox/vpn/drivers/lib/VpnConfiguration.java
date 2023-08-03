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

import com.logonbox.vpn.drivers.lib.util.Keys;
import com.sshtools.jini.INI;
import com.sshtools.jini.INIReader;
import com.sshtools.jini.INIWriter;
import com.sshtools.jini.INIReader.DuplicateAction;
import com.sshtools.jini.INIReader.MultiValueMode;
import com.sshtools.jini.INIWriter.StringQuoteMode;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface VpnConfiguration {

    public final static class Builder {

        private Optional<Integer> listenPort = Optional.empty();
        private Optional<Integer> mtu = Optional.empty();
        private Optional<String> privateKey = Optional.empty();
        private Optional<String> publicKey = Optional.empty();
        private List<String> dns = new ArrayList<>();
        private List<String> addresses = new ArrayList<>();
        private List<VpnPeer> peers = new ArrayList<>();
        private List<String> preUp = new ArrayList<>();
        private List<String> postUp = new ArrayList<>();
        private List<String> preDown = new ArrayList<>();
        private List<String> postDown = new ArrayList<>();

        public Builder fromFile(Path vpnConfiguration) throws IOException, ParseException {
            try (var in = Files.newBufferedReader(vpnConfiguration)) {
                return fromFileContent(in);
            }
        }

        public Builder fromFileContent(String vpnConfiguration) throws IOException, ParseException {
            return fromFileContent(new StringReader(vpnConfiguration));
        }

        public Builder fromFileContent(Reader vpnConfiguration) throws IOException, ParseException {
            var rdr = new INIReader.Builder().
                    withCommentCharacter('#').
                    withDuplicateSectionAction(DuplicateAction.APPEND).
                    withMultiValueMode(MultiValueMode.SEPARATED)
                    .build();
            
            var ini = rdr.read(vpnConfiguration);
            var iface = ini.section("Interface");
            
            withAddresses(iface.getAllOr("Address", new String[0]));
            withDns(iface.getAllOr("DNS", new String[0]));
            withPrivateKey(iface.getOr("PrivateKey"));
            withPublicKey(iface.getOr("PublicKey"));
            withListenPort(iface.getIntOr("ListenPort"));
            withMtu(iface.getIntOr("MTU"));
            withPreUp(iface.getAllOr("PreUp", new String[0]));
            withPreDown(iface.getAllOr("PreDown", new String[0]));
            withPostUp(iface.getAllOr("PostUp", new String[0]));
            withPostDown(iface.getAllOr("PostDown", new String[0]));
            
            for(var peer : ini.allSections("Peer")) {
                addPeers(new VpnPeer.Builder().
                        withPublicKey(peer.get("PublicKey")).
                        withEndpoint(peer.getOr("Endpoint")).
                        withAllowedIps(peer.getAllOr("AllowedIPs", new String[0])).
                        withPersistentKeepalive(peer.getIntOr("PersistentKeepalive")).
                        build());
            }

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

        public Builder addPeers(VpnPeer... peers) {
            return addPeers(Arrays.asList(peers));
        }

        public Builder addPeers(Collection<VpnPeer> peers) {
            this.peers.addAll(peers);
            return this;
        }

        public Builder withPeers(VpnPeer... peers) {
            return withPeers(Arrays.asList(peers));
        }

        public Builder withPeers(Collection<VpnPeer> peers) {
            this.peers.clear();
            return addPeers(peers);
        }

        public Builder withListenPort(int listenPort) {
            return withListenPort(Optional.of(listenPort));
        }

        public Builder withListenPort(Optional<Integer> listenPort) {
            this.listenPort = listenPort;
            return this;
        }

        public Builder withMtu(int listenPort) {
            return withListenPort(Optional.of(listenPort));
        }

        public Builder withMtu(Optional<Integer> mtu) {
            this.mtu = mtu;
            return this;
        }

        public Builder withPrivateKey(String privateKey) {
            return withPrivateKey(Optional.of(privateKey));
        }

        public Builder withPrivateKey(Optional<String> privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder withPublicKey(String publicKey) {
            return withPublicKey(Optional.of(publicKey));
        }

        public Builder withPublicKey(Optional<String> publicKey) {
            this.publicKey = publicKey;
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

        public VpnConfiguration build() {
            return new DefaultVpnConfiguration(this);
        }

        class DefaultVpnConfiguration implements VpnConfiguration {

            private final Optional<Integer> listenPort;
            private final String privateKey;
            private final String publicKey;
            private final Optional<Integer> mtu;
            private final List<String> dns;
            private final List<VpnPeer> peers;
            private final List<String> addresses;
            private final String[] postUp;
            private final String[] postDown;
            private final String[] preUp;
            private final String[] preDown;

            DefaultVpnConfiguration(Builder builder) {
                listenPort = builder.listenPort;
                privateKey = builder.privateKey.orElse(Keys.genkey().getBase64PrivateKey());
                publicKey = builder.publicKey.orElse(Keys.pubkey(privateKey).getBase64PublicKey());
                mtu = builder.mtu;
                dns = Collections.unmodifiableList(new ArrayList<>(builder.dns));
                peers = Collections.unmodifiableList(new ArrayList<>(builder.peers));
                addresses = Collections.unmodifiableList(new ArrayList<>(builder.addresses));
                preUp = builder.preUp.toArray(new String[0]);
                preDown = builder.preDown.toArray(new String[0]);
                postUp = builder.postUp.toArray(new String[0]);
                postDown = builder.postDown.toArray(new String[0]);
            }

            @Override
            public Optional<Integer> listenPort() {
                return listenPort;
            }

            @Override
            public String publicKey() {
                return publicKey;
            }

            @Override
            public String privateKey() {
                return privateKey;
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
            public List<VpnPeer> peers() {
                return peers;
            }

        }
    }

    Optional<Integer> listenPort();

    String privateKey();

    default String publicKey() {
        return Keys.pubkey(privateKey()).getBase64PublicKey();
    }

    List<String> dns();

    Optional<Integer> mtu();

    List<String> addresses();

    String[] preUp();

    String[] postUp();

    String[] preDown();

    String[] postDown();

    List<VpnPeer> peers();

    default Optional<VpnPeer> firstPeer() {
        if (peers().isEmpty())
            return Optional.empty();
        else
            return Optional.of(peers().get(0));
    }
    
    default String write() {
        var out = new StringWriter();
        write(out);
        return out.toString();
    }
    
    default void write(Path file) throws IOException {
        try(var out = Files.newOutputStream(file)) {
            write(out);
        }
    }
    
    default void write(OutputStream writer) {
        write(new OutputStreamWriter(writer));
    }
    
    default void write(Writer writer) {
        var bldr = new INIWriter.Builder().
                withEmptyValues(false).
                withCommentCharacter('#').
                withStringQuoteMode(StringQuoteMode.NEVER).
                withMultiValueMode(MultiValueMode.SEPARATED);
        
        var doc = INI.create();
        
        var ifaceSection = doc.create("Interface");
        ifaceSection.putAll("Address", addresses().toArray(new String[0]));
        ifaceSection.put("PrivateKey", privateKey());
        listenPort().ifPresent(p -> ifaceSection.put("ListenPort", p));
        mtu().ifPresent(p -> ifaceSection.put("MTU", p));
        ifaceSection.putAll("PreUp", preUp());
        ifaceSection.putAll("PreDown", preDown());
        ifaceSection.putAll("PostUp", postUp());
        ifaceSection.putAll("PostDown", postDown());
        
        for(var peer : peers()) {
            var peerSection = doc.create("Peer");
            peerSection.put("PublicKey", peer.publicKey());
            peer.endpointAddress().ifPresent(a -> 
                peerSection.put("Endpoint", String.format("%s:%d", a, peer.endpointPort().orElse(Vpn.DEFAULT_PORT))));
            peerSection.putAll("AllowedIPs", peer.allowedIps().toArray(new String[0]));
            peer.persistentKeepalive().ifPresent(p -> peerSection.put("PersistentKeepalive", p));
        }
        
        bldr.build().write(doc, writer);
    }

}
