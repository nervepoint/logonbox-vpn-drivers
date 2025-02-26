package com.logonbox.vpn.drivers.remote.controller;

import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;

import java.io.IOException;
import java.io.UncheckedIOException;

public class RemoteBusTest {

    public static void main(String[] args) throws Exception {
        try(var conx = DBusConnectionBuilder.forSessionBus().build()) {
            var rps = new BusRemotePlatformService(null, conx);
            System.out.println("Net1 adapter  exists: " + rps.adapterExists("net1"));
            System.out.println("Net1 address exists: " + rps.addressExists("net1"));
            System.out.println("Ip forwarding enabled: " + rps.isIpForwardingEnabledOnSystem());
            System.out.println("Net1 address valid: " + rps.isValidNativeInterfaceName("net1"));
            System.out.println("Crap address valid: " + rps.isValidNativeInterfaceName(" /\\+*"));
            rps.defaultGateway().ifPresentOrElse(gw -> {
                System.out.println("default gateway is " + gw);
            }, () -> {
                System.out.println("no default gateway");
            });
            rps.dns().ifPresentOrElse(prov -> {
                try {
                    var entries = prov.entries();
                    if(entries.isEmpty()) {
                        System.out.println("DNS available, but no entries");
            
                    }
                    else {
                        for(var en : entries) {
                            System.out.println("DNS " + en.iface());
                            System.out.println("  domains:  " + String.join(", ", en.domains()));
                            System.out.println("  ipv4:  " + String.join(", ", en.ipv4Servers()));
                            System.out.println("  ipv6:  " + String.join(", ", en.ipv6Servers()));
                        }
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }, () -> {
                System.out.println("no DNS provider");
            });
            
            rps.adapters().forEach(a -> {
                System.out.println("Adapter: " + a.address().name());
            });
            
            rps.addresses().forEach(a -> {
                System.out.println("Address: " + a.name() + " : " + a.getMac());
            });
        }
    }
}
