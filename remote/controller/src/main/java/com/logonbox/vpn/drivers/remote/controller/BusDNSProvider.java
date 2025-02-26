package com.logonbox.vpn.drivers.remote.controller;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.remote.lib.RemoteDNSEntry;
import com.logonbox.vpn.drivers.remote.lib.RemoteDNSProvider;

import org.freedesktop.dbus.exceptions.DBusExecutionException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class BusDNSProvider implements DNSProvider {
    
    private final RemoteDNSProvider remote;

    public BusDNSProvider(RemoteDNSProvider remote) {
        this.remote  = remote;
    }

    @Override
    public void init(PlatformService<?> platform) {
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        var entries = remote.entries();
        return Arrays.asList(entries).stream().map(RemoteDNSEntry::toNative).toList();
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        remote.set(new RemoteDNSEntry(entry));
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {
        remote.unset(new RemoteDNSEntry(entry));        
    }

    @Override
    public Optional<DNSEntry> entry(String iface) throws IOException {
        try {
            return Optional.of(remote.entry(iface).toNative());
        }
        catch(DBusExecutionException dbe) {
            return Optional.empty();
        }
    }

    @Override
    public void unset(String iface) throws IOException {
        remote.unsetIface(iface);
    }

}
