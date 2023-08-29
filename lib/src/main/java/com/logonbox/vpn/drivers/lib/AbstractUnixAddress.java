package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.util.Collection;

public abstract class AbstractUnixAddress<P extends AbstractUnixDesktopPlatformService<?>> extends AbstractVirtualInetAddress<P> {

	protected AbstractUnixAddress(P platform, String name) {
		super(platform, name);
	}

	protected AbstractUnixAddress(P platform) {
		super(platform);
	}

	public abstract void setRoutes(Collection<String> allows) throws IOException;

}
