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
import com.sshtools.jini.INI.Section;
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

public interface VpnAdapterConfiguration  {

    public abstract static class AbstractBuilder<B extends AbstractBuilder<B>> {

        protected Optional<Integer> listenPort = Optional.empty();
        protected Optional<String> privateKey = Optional.empty();
        protected Optional<String> publicKey = Optional.empty();
        protected List<VpnPeer> peers = new ArrayList<>();
        protected Optional<Integer> fwMark;

        @SuppressWarnings("unchecked")
        public B fromConfiguration(VpnAdapterConfiguration configuration) {
            withListenPort(configuration.listenPort());
            withPrivateKey(configuration.privateKey());
            withPublicKey(configuration.publicKey());
            withPeers(configuration.peers());
            withFwMark(configuration.fwMark());
            return (B)this;
        }

        public B fromFile(Path vpnConfiguration) throws IOException, ParseException {
            try (var in = Files.newBufferedReader(vpnConfiguration)) {
                return fromFileContent(in);
            }
        }

        public B fromFileContent(String vpnConfiguration) throws IOException, ParseException {
            return fromFileContent(new StringReader(vpnConfiguration));
        }

        @SuppressWarnings("unchecked")
        public B fromFileContent(Reader vpnConfiguration) throws IOException, ParseException {
            var rdr = new INIReader.Builder().
                    withCommentCharacter('#').
                    withDuplicateSectionAction(DuplicateAction.APPEND).
                    withMultiValueMode(MultiValueMode.SEPARATED)
                    .build();
            
            var ini = rdr.read(vpnConfiguration);
            var iface = ini.section("Interface");
            
            readInterfaceSection(iface);
            
            if(ini.containsSection("Peer")) {
                for(var peer : ini.allSections("Peer")) {
                    var peerBldr = new VpnPeer.Builder();
                    readPeerSection(peer, peerBldr);
                    addPeers(peerBldr.build());
                }
            }

            return (B)this;
        }

        public B addPeers(VpnPeer... peers) {
            return addPeers(Arrays.asList(peers));
        }

        @SuppressWarnings("unchecked")
        public B addPeers(Collection<VpnPeer> peers) {
            this.peers.addAll(peers);
            return (B) this;
        }

        public B withPeers(VpnPeer... peers) {
            return withPeers(Arrays.asList(peers));
        }

        public B withPeers(Collection<VpnPeer> peers) {
            this.peers.clear();
            return addPeers(peers);
        }

        public B withListenPort(int listenPort) {
            return withListenPort(Optional.of(listenPort));
        }

        @SuppressWarnings("unchecked")
        public B withListenPort(Optional<Integer> listenPort) {
            this.listenPort = listenPort;
            return (B) this;
        }

        public B withFwMark(int fwMark) {
            return withFwMark(Optional.of(fwMark));
        }

        @SuppressWarnings("unchecked")
        public B withFwMark(Optional<Integer> fwMark) {
            this.fwMark = fwMark;
            return (B) this;
        }

        public B withPrivateKey(String privateKey) {
            return withPrivateKey(Optional.of(privateKey));
        }

        @SuppressWarnings("unchecked")
        public B withPrivateKey(Optional<String> privateKey) {
            this.privateKey = privateKey;
            return (B) this;
        }

        public B withPublicKey(String publicKey) {
            return withPublicKey(Optional.of(publicKey));
        }

        @SuppressWarnings("unchecked")
        public B withPublicKey(Optional<String> publicKey) {
            this.publicKey = publicKey;
            return (B) this;
        }

        protected void readPeerSection(Section peer, com.logonbox.vpn.drivers.lib.VpnPeer.Builder peerBldr) {
            peerBldr.withPublicKey(peer.get("PublicKey")).
                withEndpoint(peer.getOr("Endpoint")).
                withAllowedIps(peer.getAllOr("AllowedIPs", new String[0])).
                withPersistentKeepalive(peer.getIntOr("PersistentKeepalive")).
                withPresharedKey(peer.getOr("PresharedKey"));
        }

        protected void readInterfaceSection(Section iface) {
            withPrivateKey(iface.getOr("PrivateKey"));
            withPublicKey(iface.getOr("PublicKey"));
            withListenPort(iface.getIntOr("ListenPort"));
            withFwMark(iface.getIntOr("FwMark"));
        }

        public abstract VpnAdapterConfiguration build();
        
    }
    public final static class Builder extends AbstractBuilder<Builder> {

        public VpnAdapterConfiguration build() {
            return new DefaultVpnAdapterConfiguration(this);
        }
    }
    
    class DefaultVpnAdapterConfiguration implements VpnAdapterConfiguration {

        private final Optional<Integer> listenPort;
        private final String privateKey;
        private final String publicKey;
        private final List<VpnPeer> peers;
        private final Optional<Integer> fwMark;

        DefaultVpnAdapterConfiguration(AbstractBuilder<?> builder) {
            listenPort = builder.listenPort;
            privateKey = builder.privateKey.orElse(Keys.genkey().getBase64PrivateKey());
            publicKey = builder.publicKey.orElse(Keys.pubkey(privateKey).getBase64PublicKey());
            peers = Collections.unmodifiableList(new ArrayList<>(builder.peers));
            fwMark = builder.fwMark;
        }

        @Override
        public final Optional<Integer> listenPort() {
            return listenPort;
        }

        @Override
        public final String publicKey() {
            return publicKey;
        }

        @Override
        public final String privateKey() {
            return privateKey;
        }

        @Override
        public final List<VpnPeer> peers() {
            return peers;
        }

        @Override
        public final Optional<Integer> fwMark() {
            return fwMark;
        }

    }
    
    Optional<Integer> listenPort();

    String privateKey();

    default String publicKey() {
        return Keys.pubkey(privateKey()).getBase64PublicKey();
    }
    
    Optional<Integer> fwMark();

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
        ifaceSection.put("PrivateKey", privateKey());
        listenPort().ifPresent(p -> ifaceSection.put("ListenPort", p));
        fwMark().ifPresent(p -> ifaceSection.put("FwMark", p));
        
        for(var peer : peers()) {
            var peerSection = doc.create("Peer");
            peerSection.put("PublicKey", peer.publicKey());
            peer.endpointAddress().ifPresent(a -> 
                peerSection.put("Endpoint", String.format("%s:%d", a, peer.endpointPort().orElse(Vpn.DEFAULT_PORT))));
            peerSection.putAll("AllowedIPs", peer.allowedIps().toArray(new String[0]));
            peer.persistentKeepalive().ifPresent(p -> peerSection.put("PersistentKeepalive", p));
            peer.presharedKey().ifPresent(p -> peerSection.put("PresharedKey", p));
        }
        
        bldr.build().write(doc, writer);
    }

}
