package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.util.Collection;

public abstract class AbstractUnixAddress<P extends AbstractUnixDesktopPlatformService<?>> extends AbstractVirtualInetAddress<P> {

	protected AbstractUnixAddress(String name, String nativeName, P platform) {
		super(name, nativeName, platform);
	}

	public abstract void setRoutes(Collection<String> allows) throws IOException;

}
