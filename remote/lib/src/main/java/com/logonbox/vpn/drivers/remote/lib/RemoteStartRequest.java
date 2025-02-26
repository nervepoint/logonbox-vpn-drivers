package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.StartRequest;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;

import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.text.ParseException;

import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Reflectable
@TypeReflect(fields = true, constructors = true)
public class RemoteStartRequest extends Struct {

    @Position(0)
    private String nativeInterfaceName = "";

    @Position(1)
    private String interfaceName = "";

    @Position(2)
    private String configuration = "";

    @Position(3)
    private RemoteVpnPeer peer = new RemoteVpnPeer();

    public RemoteStartRequest() {
    }

    public RemoteStartRequest(StartRequest nativeStartRequest) {
        this.nativeInterfaceName = nativeStartRequest.nativeInterfaceName().orElse("");
        this.interfaceName = nativeStartRequest.interfaceName().orElse("");
        this.configuration = nativeStartRequest.configuration().write();
        this.peer = nativeStartRequest.peer().map(r -> new RemoteVpnPeer(r)).orElseGet(() -> new RemoteVpnPeer());
    }

    public String getNativeInterfaceName() {
        return nativeInterfaceName;
    }

    public String getInterfaceName() {
        return interfaceName;
    }

    public String getConfiguration() {
        return configuration;
    }

    public RemoteVpnPeer getPeer() {
        return peer;
    }

    public StartRequest toNative() {
        try {
            var cfg = new VpnConfiguration.Builder().fromFileContent(configuration).build();
            var bldr = new StartRequest.Builder(cfg);
            if (!nativeInterfaceName.equals(""))
                bldr.withNativeInterfaceName(nativeInterfaceName);
            if (!interfaceName.equals(""))
                bldr.withInterfaceName(interfaceName);
            if(peer.valid())
                bldr.withPeer(peer.toNative());
            return bldr.build();
        } catch(IOException  ioe) {
            throw new UncheckedIOException(ioe);
        }catch (ParseException pe) {
            throw new IllegalStateException(pe);
        }
    }
}
