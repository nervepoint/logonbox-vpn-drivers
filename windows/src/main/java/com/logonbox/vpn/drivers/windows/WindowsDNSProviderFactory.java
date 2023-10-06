package com.logonbox.vpn.drivers.windows;

import com.logonbox.vpn.drivers.lib.DNSProvider;

import java.util.Optional;

/**
 * Decides which DNS integration to use on Windows. Currently only NetSH (the netsh command) is supported. 
 */
public class WindowsDNSProviderFactory implements DNSProvider.Factory {

    @SuppressWarnings("unchecked")
    @Override
    public <P extends DNSProvider> Class<P>[] available() {
        return new Class[] {
            NetSHDNSProvider.class
        };
    }

    @Override
    public DNSProvider create(Optional<Class<? extends DNSProvider>> clazz) {
        if(clazz.isPresent()) {
            /* Don't use reflection her for native images' sake */
            var clazzVal = clazz.get();
            if(clazzVal.equals(NetSHDNSProvider.class)) {
                return new NetSHDNSProvider();
            }
            else
                throw new IllegalArgumentException(clazzVal.toString());
        }
        else {
            return create(Optional.of(NetSHDNSProvider.class));
        }
    }
    

}
