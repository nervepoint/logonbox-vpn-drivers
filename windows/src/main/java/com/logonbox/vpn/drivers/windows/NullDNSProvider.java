package com.logonbox.vpn.drivers.windows;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;

public class NullDNSProvider implements DNSProvider {

	@Override
	public void init(PlatformService<?> platform) {
	}

	@Override
	public List<DNSEntry> entries() throws IOException {
		return Collections.emptyList();
	}

	@Override
	public void set(DNSEntry entry) throws IOException {
	}

	@Override
	public void unset(DNSEntry entry) throws IOException {
	}

}
