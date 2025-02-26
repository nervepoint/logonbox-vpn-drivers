package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.DNSProvider.DNSEntry;

import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@Reflectable
@TypeReflect(fields = true, constructors = true)
public class RemoteDNSEntry extends Struct {

    @Position(0)
    private String iface;
    @Position(1)
    private String[] ipv4Servers;
    @Position(2)
    private String[] ipv6Servers;
    @Position(3)
    private String[] domains;
    
    public RemoteDNSEntry(DNSEntry nativeDnsEntry) {
        this.iface = nativeDnsEntry.iface();
        this.ipv4Servers = nativeDnsEntry.ipv4Servers();
        this.ipv6Servers = nativeDnsEntry.ipv6Servers();
        this.domains = nativeDnsEntry.domains();
    }
    
    public RemoteDNSEntry() {
    }
    
    public RemoteDNSEntry(String iface, String[] ipv4Servers, String[] ipv6Servers, String[] domains) {
        super();
        this.iface = iface;
        this.ipv4Servers = ipv4Servers;
        this.ipv6Servers = ipv6Servers;
        this.domains = domains;
    }

    public String getIface() {
        return iface;
    }

    public String[] getIpv4Servers() {
        return ipv4Servers;
    }

    public String[] getIpv6Servers() {
        return ipv6Servers;
    }

    public String[] getDomains() {
        return domains;
    }

    public DNSEntry toNative() {
        var bldr = new DNSEntry.Builder();
        if(iface != null && iface.length() > 0)
            bldr.withInterface(iface);
        if(ipv4Servers != null && ipv4Servers.length > 0)
            bldr.withIpv4Servers(ipv4Servers);
        if(ipv6Servers != null && ipv6Servers.length > 0)
            bldr.withIpv6Servers(ipv6Servers);
        if(domains != null && domains.length > 0)
            bldr.withDomains(domains);
        return bldr.build();
    }

    
}
