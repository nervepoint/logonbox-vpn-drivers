package com.logonbox.vpn.drivers.lib;

import com.logonbox.vpn.drivers.lib.util.OsUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public abstract class AbstractUnixDesktopPlatformService<I extends VpnAddress>
        extends AbstractDesktopPlatformService<I> {

    public AbstractUnixDesktopPlatformService(String interfacePrefix) {
        super(interfacePrefix);
    }

    @Override
    public List<VpnAdapter> adapters() {
        try {
            checkWGCommand();
            var l = new ArrayList<VpnAdapter>();
            for (var line : commands().output(getWGCommand(), "show", "interfaces")) {
                for(var ifaceName : line.split("\\s+")) {
                    l.add(configureExistingSession(address(ifaceName)));
                }
            }
            return l;
        }
        catch(IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    @Override
    protected void onSetDefaultGateway(VpnPeer peer) throws IOException {
        var gw = getDefaultGateway();
        var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
        LOG.info("Routing traffic all through peer {}", addr);
        LOG.info(String.join(" ", Arrays.asList("route", "add", addr, "gw", gw)));
        commands().privileged().logged().run("route", "add", addr, "gw", gw);
    }

    @Override
    protected void onResetDefaultGateway(VpnPeer peer) throws IOException {
        var gw = getDefaultGateway();
        var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
        LOG.info("Removing routing of all traffic  through peer {}", addr);
        LOG.info(String.join(" ", Arrays.asList("route", "del", addr, "gw", gw)));
        commands().privileged().logged().run("route", "del", addr, "gw", gw);
    }

    @Override
    public Instant getLatestHandshake(String iface, String publicKey) throws IOException {
        checkWGCommand();
        for (String line : commands().privileged().output(getWGCommand(), "show", iface, "latest-handshakes")) {
            String[] args = line.trim().split("\\s+");
            if (args.length == 2) {
                if (args[0].equals(publicKey)) {
                    return Instant.ofEpochSecond(Long.parseLong(args[1]));
                }
            }
        }
        return Instant.ofEpochSecond(0);
    }

    @Override
    protected Optional<String> getPublicKey(String interfaceName) throws IOException {
        try {
            checkWGCommand();
            String pk = commands().privileged().output(getWGCommand(), "show", interfaceName, "public-key").iterator()
                    .next().trim();
            if (pk.equals("(none)") || pk.equals(""))
                return Optional.empty();
            else
                return Optional.of(pk);

        } catch (IOException ioe) {
            if (ioe.getMessage() != null && (ioe.getMessage().indexOf("The system cannot find the file specified") != -1
                    || ioe.getMessage().indexOf("Unable to access interface: No such file or directory") != -1))
                return Optional.empty();
            else
                throw ioe;
        }
    }

    protected void checkWGCommand() throws IOException {
    }

    @Override
    public VpnInterfaceInformation information(VpnAdapter adapter) {
        try {
            var iface = adapter.address();
            checkWGCommand();
            var peers = new ArrayList<VpnPeerInformation>();
            var lastHandshake = new AtomicLong(0l);
            var rx = new AtomicLong(0l);
            var tx = new AtomicLong(0l);
            var port = new AtomicInteger();
            var fwmark = new AtomicInteger();
            var publicKey = new StringBuffer();
            var privateKey = new StringBuffer();
    
            for (var line : commands().privileged().output(getWGCommand(), "show", iface.name(), "dump")) {
                var st = new StringTokenizer(line);
                if (st.countTokens() == 4) {
                    privateKey.append(st.nextToken());
                    publicKey.append(st.nextToken());
                    port.set(Integer.parseInt(st.nextToken()));
                    fwmark.set(parseFwMark(st.nextToken()));
                } else {
                    var peerPublicKey = st.nextToken();
                    var presharedKeyVal = st.nextToken();
                    Optional<String> presharedKey;
                    if (presharedKeyVal.equals("(none)")) {
                        presharedKey = Optional.empty();
                    } else {
                        presharedKey = Optional.of(presharedKeyVal);
                    }
                    var remoteAddress = Optional.of(OsUtil.parseInetSocketAddress(st.nextToken()));
                    var allowedIps = Arrays.asList(st.nextToken().split(","));
                    var thisLastHandshake = Instant.ofEpochSecond(Long.parseLong(st.nextToken()));
                    var thisRx = Long.parseLong(st.nextToken());
                    var thisTx = Long.parseLong(st.nextToken());
    
                    lastHandshake.set(Math.max(lastHandshake.get(), thisLastHandshake.toEpochMilli()));
                    rx.addAndGet(thisRx);
                    tx.addAndGet(thisTx);
    
                    peers.add(new VpnPeerInformation() {
    
                        @Override
                        public long tx() {
                            return thisTx;
                        }
    
                        @Override
                        public long rx() {
                            return thisRx;
                        }
    
                        @Override
                        public Instant lastHandshake() {
                            return thisLastHandshake;
                        }
    
                        @Override
                        public Optional<String> error() {
                            return Optional.empty();
                        }
    
                        @Override
                        public Optional<InetSocketAddress> remoteAddress() {
                            return remoteAddress;
                        }
    
                        @Override
                        public List<String> allowedIps() {
                            return allowedIps;
                        }
    
                        @Override
                        public String publicKey() {
                            return peerPublicKey;
                        }
    
                        @Override
                        public Optional<String> presharedKey() {
                            return presharedKey;
                        }
    
                    });
                }
            }
            return new VpnInterfaceInformation() {
    
                @Override
                public String interfaceName() {
                    return iface.name();
                }
    
                @Override
                public long tx() {
                    return tx.get();
                }
    
                @Override
                public long rx() {
                    return rx.get();
                }
    
                @Override
                public List<VpnPeerInformation> peers() {
                    return peers;
                }
    
                @Override
                public Instant lastHandshake() {
                    return Instant.ofEpochMilli(lastHandshake.get());
                }
    
                @Override
                public Optional<String> error() {
                    return Optional.empty();
                }
    
                @Override
                public Optional<Integer> listenPort() {
                    return port.get() == 0 ? Optional.empty() : Optional.of(port.get());
                }
    
                @Override
                public Optional<Integer> fwmark() {
                    return fwmark.get() == 0 ? Optional.empty() : Optional.of(fwmark.get());
                }
    
                @Override
                public String publicKey() {
                    return publicKey.toString();
                }
    
                @Override
                public String privateKey() {
                    return privateKey.toString();
                }
    
            };
        }
        catch(IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    @Override
    public final VpnAdapterConfiguration configuration(VpnAdapter adapter) {
        try {
            try {
                checkWGCommand();
                return new VpnAdapterConfiguration.Builder()
                        .fromFileContent(String.join(System.lineSeparator(),
                                commands().privileged().output(getWGCommand(), "showconf", adapter.address().name())))
                        .build();
            } catch (ParseException e) {
                throw new IOException("Failed to parse configuration.", e);
            }
        }
        catch(IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    private int parseFwMark(String tkn) {
        return tkn.equals("off") ? 0 : Integer.parseInt(tkn);
    }
}
