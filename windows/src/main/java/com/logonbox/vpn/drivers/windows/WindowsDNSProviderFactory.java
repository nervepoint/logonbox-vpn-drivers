package com.logonbox.vpn.drivers.windows;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.sshtools.liftlib.OS;

import java.util.Optional;

/**
 * Decides which DNS integration to use on Windows. Currently only NetSH (the netsh command) is supported. 
 */
public class WindowsDNSProviderFactory implements DNSProvider.Factory {

    @SuppressWarnings("unchecked")
    @Override
    public <P extends DNSProvider> Class<P>[] available() {
    	if(OS.isWindows()) {
	        return new Class[] {
	        	NullDNSProvider.class,
	            NetSHDNSProvider.class
	        };
    	}
    	else {
    		return new Class[0];
    	}
    }

    @Override
    public DNSProvider create(Optional<Class<? extends DNSProvider>> clazz, SystemContext context) {
        if(clazz.isPresent()) {
            /* Don't use reflection here for native images' sake */
            var clazzVal = clazz.get();
            if(clazzVal.equals(NetSHDNSProvider.class)) {
                return new NetSHDNSProvider();
            }
            else if(clazzVal.equals(NullDNSProvider.class)) {
                return new NullDNSProvider();
            }
            else
                throw new IllegalArgumentException(clazzVal.toString());
        }
        else {
            return create(Optional.of(NullDNSProvider.class), context);
        }
    }
    

}
