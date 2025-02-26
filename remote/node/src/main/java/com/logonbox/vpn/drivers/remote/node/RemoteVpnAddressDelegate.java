package com.logonbox.vpn.drivers.remote.node;

import static java.util.Optional.ofNullable;

import com.logonbox.vpn.drivers.lib.VpnAddress;
import com.logonbox.vpn.drivers.remote.lib.RemoteVpnAddress;

import org.freedesktop.dbus.annotations.DBusInterfaceName;

import java.io.IOException;

import uk.co.bithatch.nativeimage.annotations.Proxy;
import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@DBusInterfaceName(RemoteVpnAddressDelegate.DBUS_INTERFACE_NAME)
@Proxy
@Reflectable
@TypeReflect(methods = true, classes = true)
public class RemoteVpnAddressDelegate implements RemoteVpnAddress {
    
    private final VpnAddress delegate;

    RemoteVpnAddressDelegate(VpnAddress delegate) {
        this.delegate = delegate;
    }

    @Override
    public String getObjectPath() {
        return RemoteVpnAddress.OBJECT_PATH + "/" + nativeName();
    }

    @Override
    public boolean isUp() {
        return delegate.isUp();
    }

    @Override
    public boolean isDefaultGateway() {
        return delegate.isDefaultGateway();
    }

    @Override
    public void setDefaultGateway(String address) {
        delegate.setDefaultGateway(address);
    }

    @Override
    public void delete() throws IOException {
        delegate.delete();
    }

    @Override
    public void down() throws IOException {
        delegate.down();
    }

    @Override
    public String getMac() {
        return ofNullable(delegate.getMac()).orElse("");
    }

    @Override
    public boolean isLoopback() {
        return delegate.isLoopback();
    }

    @Override
    public int getMtu() {
        return delegate.getMtu();
    }

    @Override
    public String name() {
        return delegate.name();
    }

    @Override
    public String displayName() {
        return delegate.displayName();
    }

    @Override
    public String nativeName() {
        return delegate.nativeName();
    }

    @Override
    public String peer() {
        return ofNullable(delegate.peer()).orElse("");
    }

    @Override
    public String table() {
        return delegate.table();
    }

    @Override
    public void mtu(int mtu) {
        delegate.mtu(mtu);
    }

    @Override
    public void up() throws IOException {
        delegate.up();
    }

    @Override
    public String shortName() {
        return delegate.shortName();
    }

    @Override
    public boolean hasVirtualName() {
        return delegate.hasVirtualName();
    }

}
