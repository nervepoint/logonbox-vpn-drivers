
package com.logonbox.vpn.drivers.linux;

import java.nio.file.Path;

public class OpenresolvDNSProvider extends ResolvConfDNSProvider {

	@Override
	protected Path interfacesPath() {
		return LinuxDNSProviderFactory.runPath().resolve("resolvconf").resolve("interfaces");
	}

}
