package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.NATMode;

import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.util.Optional;

import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Reflectable
@TypeReflect(fields = true, constructors = true)
public class RemoteNATMode extends Struct {

    @Position(0)
    private String mode = "";
    @Position(1)
    private String[] names = new String[0];
    
    public RemoteNATMode(Optional<NATMode> nativeNATMode) {
        this.mode = nativeNATMode.isPresent() ?  nativeNATMode.get().getClass().getSimpleName() : "";
        this.names = nativeNATMode.isPresent() ?  nativeNATMode.get().names().toArray(new String[0]) : new String[0];
    }
    
    public RemoteNATMode() {
    }
    
    public Optional<NATMode> toNative() {
        if(mode.equals(NATMode.MASQUERADE.class.getSimpleName())) {
            return Optional.of(NATMode.MASQUERADE.forNames(names));
        }
        else if(mode.equals(NATMode.SNAT.class.getSimpleName())) {
            return Optional.of(NATMode.SNAT.forNames(names));
        }
        else if(mode.equals("")){
            return Optional.empty();
        }
        else {
            throw new UnsupportedOperationException("Unsupported NAT mode.");
        }
    }

    
}
