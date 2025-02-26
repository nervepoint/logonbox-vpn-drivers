package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.VpnInterfaceInformation;
import com.logonbox.vpn.drivers.lib.VpnPeerInformation;

import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Reflectable
@TypeReflect(fields = true, constructors = true)
public class RemoteVpnInterfaceInformation extends Struct {

    @Position(0)
    private String interfaceName = "";

    @Position(1)
    private long tx;

    @Position(2)
    private long rx;

    @Position(3)
    private RemoteVpnPeerInformation[] peers = new RemoteVpnPeerInformation[0];

    @Position(4)
    private long lastHandshake;

    @Position(5)
    private String publicKey = "";

    @Position(6)
    private String privateKey = "";

    @Position(7)
    private int listenPort;

    @Position(8)
    private int fwmark;

    @Position(9)
    private String error = "";

    public RemoteVpnInterfaceInformation() {
    }

    public RemoteVpnInterfaceInformation(String interfaceName, long tx, long rx, RemoteVpnPeerInformation[] peers,
            long lastHandshake, String publicKey, String privateKey, int listenPort, int fwmark, String error) {
        super();
        this.interfaceName = interfaceName;
        this.tx = tx;
        this.rx = rx;
        this.peers = peers;
        this.lastHandshake = lastHandshake;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.listenPort = listenPort;
        this.fwmark = fwmark;
        this.error = error;
    }

    public RemoteVpnInterfaceInformation(VpnInterfaceInformation information) {
        this.interfaceName = information.interfaceName();
        this.tx = information.tx();
        this.rx = information.rx();
        this.peers = information.peers().
                stream().
                map(RemoteVpnPeerInformation::new).
                toList().
                toArray(new RemoteVpnPeerInformation[0]);
    }

    public String getInterfaceName() {
        return interfaceName;
    }

    public long getTx() {
        return tx;
    }

    public long getRx() {
        return rx;
    }

    public RemoteVpnPeerInformation[] getPeers() {
        return peers;
    }

    public long getLastHandshake() {
        return lastHandshake;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public int getListenPort() {
        return listenPort;
    }

    public int getFwmark() {
        return fwmark;
    }

    public String getError() {
        return error;
    }

    @SuppressWarnings("serial")
    public VpnInterfaceInformation toNative() {
        return new VpnInterfaceInformation() {

            @Override
            public long tx() {
                return tx;
            }

            @Override
            public long rx() {
                return rx;
            }

            @Override
            public String publicKey() {
                return publicKey;
            }

            @Override
            public String privateKey() {
                return publicKey;
            }

            @Override
            public List<VpnPeerInformation> peers() {
                return Arrays.asList(peers).stream().map(RemoteVpnPeerInformation::toNative).toList();
            }

            @Override
            public Optional<Integer> listenPort() {
                return listenPort == 0 ? Optional.empty() : Optional.of(listenPort);
            }

            @Override
            public Instant lastHandshake() {
                return Instant.ofEpochMilli(lastHandshake);
            }

            @Override
            public String interfaceName() {
                return interfaceName;
            }

            @Override
            public Optional<Integer> fwmark() {
                return fwmark == 0 ? Optional.empty() : Optional.of(fwmark);
            }

            @Override
            public Optional<String> error() {
                return error.equals("") ? Optional.empty() : Optional.of(error);
            }
        };
    }
}
