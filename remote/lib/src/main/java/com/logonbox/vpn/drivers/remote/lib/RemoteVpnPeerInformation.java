package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.VpnPeerInformation;

import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Reflectable
@TypeReflect(fields = true, constructors = true)
public class RemoteVpnPeerInformation extends Struct {

    @Position(0)
    private String[] allowedIps = new String[0];

    @Position(1)
    private String remoteAddress = "";

    @Position(2)
    private String publicKey = "";

    @Position(3)
    private String presharedKey = "";

    @Position(4)
    private long tx;

    @Position(5)
    private long rx;

    @Position(6)
    private long lastHandshake;

    @Position(7)
    String error = "";    
    
    public RemoteVpnPeerInformation() {
    }
    
    public RemoteVpnPeerInformation(VpnPeerInformation info) {
        this.allowedIps = info.allowedIps().toArray(new String[0]);
        this.remoteAddress = info.remoteAddress().map(InetSocketAddress::toString).orElse("");
        this.publicKey = info.publicKey();
        this.presharedKey = info.presharedKey().orElse("");
        this.tx = info.tx();
        this.rx = info.rx();
        this.lastHandshake = info.lastHandshake().toEpochMilli();
        this.error = info.error().orElse("");
    }

    public RemoteVpnPeerInformation(String[] allowedIps, String remoteAddress, String publicKey, String presharedKey,
            long tx, long rx, long lastHandshake, String error) {
        super();
        this.allowedIps = allowedIps;
        this.remoteAddress = remoteAddress;
        this.publicKey = publicKey;
        this.presharedKey = presharedKey;
        this.tx = tx;
        this.rx = rx;
        this.lastHandshake = lastHandshake;
        this.error = error;
    }

    @SuppressWarnings("serial")
    public VpnPeerInformation toNative() {
        return new VpnPeerInformation() {
            
            @Override
            public long tx() {
                return tx;
            }
            
            @Override
            public long rx() {
                return rx;
            }
            
            @Override
            public Optional<InetSocketAddress> remoteAddress() {
                return remoteAddress.equals("") ? 
                        Optional.empty() : 
                        Optional.of(new InetSocketAddress(
                                    remoteAddress.substring(0, remoteAddress.indexOf(':')), 
                                    Integer.parseInt(remoteAddress.substring(remoteAddress.indexOf(':') + 1))));
            }
            
            @Override
            public String publicKey() {
                return publicKey;
            }
            
            @Override
            public Optional<String> presharedKey() {
                return presharedKey.equals("")?  Optional.empty() : Optional.of(presharedKey);
            }
            
            @Override
            public Instant lastHandshake() {
                return Instant.ofEpochMilli(lastHandshake);
            }
            
            @Override
            public Optional<String> error() {
                return error.equals("")?  Optional.empty() : Optional.of(error);
            }
            
            @Override
            public List<String> allowedIps() {
                return Arrays.asList(allowedIps);
            }
        };
    }
    
}
