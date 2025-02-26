package com.logonbox.vpn.drivers.remote.node;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.remote.lib.RemoteDNSEntry;
import com.logonbox.vpn.drivers.remote.lib.RemoteDNSProvider;

import java.io.IOException;
import java.io.UncheckedIOException;

public class RemoteDNSProviderDelegate implements RemoteDNSProvider {

    private final DNSProvider delegate;

    public RemoteDNSProviderDelegate(DNSProvider delegate) {
        this.delegate = delegate;
    }

    @Override
    public String getObjectPath() {
        return RemoteDNSProvider.OBJECT_PATH;
    }

    @Override
    public RemoteDNSEntry[] entries() {
        try {
            return delegate.entries().stream().map(RemoteDNSEntry::new).toList().toArray(new RemoteDNSEntry[0]);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public RemoteDNSEntry entry(String iface) {
        try {
            return new RemoteDNSEntry(delegate.entry(iface)
                    .orElseThrow(() -> new IllegalArgumentException("No such entry with interface " + iface)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void set(RemoteDNSEntry entry) {
        try {
            delegate.set(entry.toNative());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void unset(RemoteDNSEntry entry) {
        try {
            delegate.unset(entry.toNative());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void unsetIface(String iface) {
        try {
            delegate.unset(iface);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

    }
}
