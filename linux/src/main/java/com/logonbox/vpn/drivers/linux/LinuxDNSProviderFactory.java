package com.logonbox.vpn.drivers.linux;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.sshtools.liftlib.OS;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

/**
 * Decides which DNS intergration to use on Linux from Network Manager, SystemD
 * or resolvconf.
 */
public class LinuxDNSProviderFactory implements DNSProvider.Factory {

    @SuppressWarnings("unchecked")
    @Override
    public <P extends DNSProvider> Class<P>[] available() {
    	if(OS.isLinux()) {
    		return new Class[] { ResolvConfDNSProvider.class, NetworkManagerDNSProvider.class, SystemDDNSProvider.class, RawDNSProvider.class };
    	}
    	else {
    		return new Class[0];
    	}
    }

    @Override
    public DNSProvider create(Optional<Class<? extends DNSProvider>> clazz) {
        if (clazz.isPresent()) {
            /* Don't use reflection her for native images' sake */
            var clazzVal = clazz.get();
            if (clazzVal.equals(ResolvConfDNSProvider.class)) {
                return new ResolvConfDNSProvider();
            } else if (clazzVal.equals(NetworkManagerDNSProvider.class)) {
                return new NetworkManagerDNSProvider();
            } else if (clazzVal.equals(SystemDDNSProvider.class)) {
                return new SystemDDNSProvider();
            } else if (clazzVal.equals(RawDNSProvider.class)) {
                return new RawDNSProvider();
            } else
                throw new IllegalArgumentException(clazzVal.toString());
        } else {
            return create(Optional.of(detect()));
        }
    }

    Class<? extends DNSProvider> detect() {
        File f = new File("/etc/resolv.conf");
        try {
            String p = f.getCanonicalFile().getAbsolutePath();
            if (p.equals(f.getAbsolutePath())) {
                return RawDNSProvider.class;
            } else if (p.equals("/run/NetworkManager/resolv.conf")) {
                return NetworkManagerDNSProvider.class;
            } else if (p.equals("/run/systemd/resolve/stub-resolv.conf")) {
                return SystemDDNSProvider.class;
            } else if (p.equals("/run/resolvconf/resolv.conf")) {
                return ResolvConfDNSProvider.class;
            }
        } catch (IOException ioe) {
        }
        throw new UnsupportedOperationException("No supported DNS provider can be used.");
    }

}
