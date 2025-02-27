package com.logonbox.vpn.drivers.remote.lib;

import org.freedesktop.dbus.annotations.DBusBoundProperty;
import org.freedesktop.dbus.annotations.DBusProperty.Access;
import org.freedesktop.dbus.interfaces.DBusInterface;

import java.io.IOException;

import uk.co.bithatch.nativeimage.annotations.Proxy;
import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Proxy
@Reflectable
@TypeReflect(methods = true, classes = true)
public interface RemoteVpnAddress  extends DBusInterface {

    String DBUS_INTERFACE_NAME = "com.logonbox.vpn.drivers.RemoteVpnAddress";
    String OBJECT_PATH = "/" + DBUS_INTERFACE_NAME.replace('.', '/');
    
    @DBusBoundProperty
    boolean isUp();
    
    @DBusBoundProperty
    boolean isDefaultGateway();

    @DBusBoundProperty
    void setDefaultGateway(String address);

    void delete() throws IOException;

    void down() throws IOException;

    @DBusBoundProperty(access = Access.READ, name = "Mac")
    String getMac();

    @DBusBoundProperty
    boolean isLoopback();

    @DBusBoundProperty(access = Access.READ, name = "Mtu")
    int getMtu();

    @DBusBoundProperty(access = Access.READ, name = "Name")
    String name();

    @DBusBoundProperty(access = Access.READ, name = "DisplayName")
    String displayName();

    @DBusBoundProperty(access = Access.READ, name = "ShortName")
    String shortName();

    @DBusBoundProperty(access = Access.READ, name = "NativeName")
    String nativeName();

    @DBusBoundProperty(access = Access.READ, name = "HasVirtualName")
    boolean hasVirtualName();

    @DBusBoundProperty(access = Access.READ, name = "Peer")
    String peer();

    @DBusBoundProperty(access = Access.READ, name = "Table")
    String table();

    @DBusBoundProperty(access = Access.WRITE, name = "Mtu")
    void mtu(int mtu);

    void up() throws IOException;

}
