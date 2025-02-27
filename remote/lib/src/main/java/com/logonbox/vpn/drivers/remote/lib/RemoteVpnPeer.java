package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.VpnPeer;

import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Reflectable
@TypeReflect(fields = true, constructors = true)
public class RemoteVpnPeer extends Struct {
    @Position(0)
    private String endpointAddress = "";

    @Position(1)
    private int endpointPort = 0;
    
    @Position(2)
    private String publicKey = "";

    @Position(3)
    private int persistentKeepalive = 0;
    
    @Position(4)
    private String[] allowedIps = new String[0];
    
    @Position(5)
    private String presharedKey = "";

    
    public RemoteVpnPeer() {
        
    }
    
    public RemoteVpnPeer(String endpointAddress, int endpointPort, String publicKey, int persistentKeepalive,
			String[] allowedIps, String presharedKey) {
		super();
		this.endpointAddress = endpointAddress;
		this.endpointPort = endpointPort;
		this.publicKey = publicKey;
		this.persistentKeepalive = persistentKeepalive;
		this.allowedIps = allowedIps;
		this.presharedKey = presharedKey;
	}

	public RemoteVpnPeer(VpnPeer peer) {
        this.publicKey = peer.publicKey();
        this.endpointAddress = peer.endpointAddress().orElse("");
        this.endpointPort = peer.endpointPort().orElse(0);
        this.persistentKeepalive = peer.persistentKeepalive().orElse(0);
        this.presharedKey = peer.presharedKey().orElse("");
    }

    public boolean valid() {
        return !publicKey.equals("");
    }
    
    public VpnPeer toNative() {
        var bldr = new VpnPeer.Builder();
        bldr.withPublicKey(publicKey);
        if(!endpointAddress.equals("")) {
            bldr.withEndpointAddress(endpointAddress);
        }
        if(endpointPort > 0) {
            bldr.withEndpointPort(endpointPort);
        }
        if(persistentKeepalive > 0) {
            bldr.withPersistentKeepalive(persistentKeepalive);
        }
        bldr.withAllowedIps(allowedIps);
        if(!presharedKey.equals("")) {
            bldr.withPresharedKey(presharedKey);
        }
        return bldr.build();
    }

    public String getEndpointAddress() {
        return endpointAddress;
    }

    public int getEndpointPort() {
        return endpointPort;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public int getPersistentKeepalive() {
        return persistentKeepalive;
    }

    public String[] getAllowedIps() {
        return allowedIps;
    }

    public String getPresharedKey() {
        return presharedKey;
    }

}
