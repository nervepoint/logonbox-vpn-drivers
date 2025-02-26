package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.DNSProvider.DNSEntry;

import org.freedesktop.dbus.interfaces.DBusInterface;

public interface RemoteDNSProvider extends DBusInterface {
    String DBUS_INTERFACE_NAME = "com.logonbox.vpn.drivers.RemoteDNSProvider";
    String OBJECT_PATH = "/" + DBUS_INTERFACE_NAME.replace('.', '/');
    
    /**
     * Get all current DNS configuration. See {@link DNSProvider#entries()}.
     * 
     * @return dns configuration entries
     */
    RemoteDNSEntry[] entries();

    /**
     * Get an entry given the interface name. See {@link DNSProvider#entry(String)}.
     * 
     * @param iface interface name
     * @return dns entry
     */
    RemoteDNSEntry entry(String iface);

    /**
     * Make the provided DNS configuration active. See {@link DNSProvider#set(DNSEntry)}.
     * 
     * @param entry DNS configuration
     */
    void set(RemoteDNSEntry entry);

    /**
     * Unset the provided DNS configuration (make it inactive). See {@link DNSProvider#unset(DNSEntry)}.
     * 
     * @param entry DNS configuration to deactivate.
     */
    void unset(RemoteDNSEntry entry);

    /**
     * Unset any configured DNS given the interface name. See {@link DNSProvider#unset(String)}.
     * 
     * @param iface
     */
    void unsetIface(String iface);
}
