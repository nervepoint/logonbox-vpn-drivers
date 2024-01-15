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
import com.logonbox.vpn.drivers.lib.util.Util;
import com.sshtools.jini.INI;
import com.sshtools.jini.INI.Section;
import com.sshtools.jini.INIReader;
import com.sshtools.jini.INIReader.DuplicateAction;
import com.sshtools.jini.INIReader.MultiValueMode;
import com.sshtools.jini.INIWriter;
import com.sshtools.jini.INIWriter.StringQuoteMode;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import uk.co.bithatch.nativeimage.annotations.Serialization;

@Serialization
public interface VpnAdapterConfiguration extends Serializable {

    public abstract static class AbstractBuilder<B extends AbstractBuilder<B>> {

        protected Optional<Integer> listenPort = Optional.empty();
        protected Optional<String> privateKey = Optional.empty();
        protected Optional<String> publicKey = Optional.empty();
        protected List<VpnPeer> peers = new ArrayList<>();
        protected Optional<Integer> fwMark = Optional.empty();

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

        @SuppressWarnings("unchecked")
        public B withoutPrivateKey() {
        	this.privateKey = null;
        	return (B)this;
        }
        
        public B withPrivateKey(String privateKey) {
            return withPrivateKey(Optional.of(privateKey));
        }

        @SuppressWarnings("unchecked")
        public B withPrivateKey(Optional<String> privateKey) {
        	if(privateKey.isPresent() && ( "PRIVATE_KEY_NOT_AVAILABLE".equals(privateKey.get()) || "".equals(privateKey.get())))  {
        		return withoutPrivateKey();
        	}
        	else {
	            this.privateKey = privateKey;
	            return (B) this;
        	}
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
            withFwMark(iface.getOr("FwMark").map(s -> Util.parseFwMark(s)));
        }

        public abstract VpnAdapterConfiguration build();
        
    }
    public final static class Builder extends AbstractBuilder<Builder> {

        public VpnAdapterConfiguration build() {
            return new DefaultVpnAdapterConfiguration(this);
        }
    }
    
    @SuppressWarnings("serial")
    @Serialization
	class DefaultVpnAdapterConfiguration implements VpnAdapterConfiguration {

        private final int listenPort;
        private final String privateKey;
        private final String publicKey;
        private final List<VpnPeer> peers;
        private final int fwMark;

        DefaultVpnAdapterConfiguration(AbstractBuilder<?> builder) {
            listenPort = builder.listenPort.orElse(0);
            privateKey = builder.privateKey == null ? null : builder.privateKey.orElse(Keys.genkey().getBase64PrivateKey());
            publicKey = builder.publicKey.orElseGet(() -> {
            	if(privateKey == null)
            		throw new IllegalStateException("No public key, and no private key, so public key cannot be derived.");
            	return Keys.pubkey(privateKey).getBase64PublicKey();
            });
            peers = new ArrayList<>(builder.peers);
            fwMark = builder.fwMark.orElse(0);
        }

        @Override
        public final Optional<Integer> listenPort() {
            return listenPort == 0 ? Optional.empty() : Optional.of(listenPort);
        }

        @Override
        public final String publicKey() {
            return publicKey;
        }

        @Override
        public final String privateKey() {
        	if(privateKey == null)
        		throw new IllegalStateException("Configuration has no private key.");
            return privateKey;
        }

        @Override
        public final List<VpnPeer> peers() {
            return Collections.unmodifiableList(peers);
        }

        @Override
        public final Optional<Integer> fwMark() {
            return fwMark == 0 ? Optional.empty() : Optional.of(fwMark);
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
    
    default String toDataUri() {
		var str = write();
		var bldr = new StringBuilder();
		bldr.append("data:text/plain;base64,");
		try {
			bldr.append(Base64.getEncoder().encodeToString(str.getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			throw new UnsupportedOperationException();
		}
		return bldr.toString();
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
        var doc = basicDocWithInterface(this);
        
        for(var peer : peers()) {
            writePeer(doc, peer);
        }
        
        writer().write(doc, writer);
    }

    static void writePeer(INI doc, VpnPeer peer) {
		var peerSection = doc.create("Peer");
		peerSection.put("PublicKey", peer.publicKey());
		peer.endpointAddress().ifPresent(a -> 
		    peerSection.put("Endpoint", String.format("%s:%d", a, peer.endpointPort().orElse(Vpn.DEFAULT_PORT))));
		peerSection.putAll("AllowedIPs", peer.allowedIps().toArray(new String[0]));
		peer.persistentKeepalive().ifPresent(p -> peerSection.put("PersistentKeepalive", p));
		peer.presharedKey().ifPresent(p -> peerSection.put("PresharedKey", p));
	}
    
    static INIWriter writer() {
    	return new INIWriter.Builder().
                withEmptyValues(false).
                withCommentCharacter('#').
                withStringQuoteMode(StringQuoteMode.NEVER).
                withMultiValueMode(MultiValueMode.SEPARATED).build();
    }
    
    static INI basicDocWithInterface(VpnAdapterConfiguration adapter ) {
        var doc = INI.create();
        
        var ifaceSection = doc.create("Interface");
        try {
        	ifaceSection.put("PrivateKey", adapter.privateKey());
        }
        catch(IllegalStateException ise) {
        	ifaceSection.put("PublicKey", adapter.publicKey());
        }
        adapter.listenPort().ifPresent(p -> ifaceSection.put("ListenPort", p));
        adapter.fwMark().ifPresent(p -> ifaceSection.put("FwMark", p));
        
        return doc;
    }

}
