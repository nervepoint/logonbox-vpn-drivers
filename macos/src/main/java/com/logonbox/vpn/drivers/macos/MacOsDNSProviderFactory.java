package com.logonbox.vpn.drivers.macos;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.sshtools.liftlib.OS;

import java.util.Optional;

/**
 * Decides which DNS integration to use on Mac. Currently networksetup and 2
 * modes of scutil are supported.
 */
public class MacOsDNSProviderFactory implements DNSProvider.Factory {

    @SuppressWarnings("unchecked")
    @Override
    public <P extends DNSProvider> Class<P>[] available() {
    	if(OS.isMacOs()) {
	        return new Class[] { SCUtilSplitDNSProvider.class, SCUtilCompatibleDNSProvider.class,
	                NetworksetupDNSProvider.class };
    	}
    	else {
    		return new Class[0];
    	}
    }

    @Override
    public DNSProvider create(Optional<Class<? extends DNSProvider>> clazz, SystemContext context) {
        if (clazz.isPresent()) {
            /* Don't use reflection her for native images' sake */
            var clazzVal = clazz.get();
            if (clazzVal.equals(SCUtilSplitDNSProvider.class)) {
                return new SCUtilSplitDNSProvider();
            } else if (clazzVal.equals(SCUtilCompatibleDNSProvider.class)) {
                return new SCUtilCompatibleDNSProvider();
            } else if (clazzVal.equals(NetworksetupDNSProvider.class)) {
                return new NetworksetupDNSProvider();
            } else
                throw new IllegalArgumentException(clazzVal.toString());
        } else {
        	return create(Optional.of(NetworksetupDNSProvider.class), context);
        }
    }

}
