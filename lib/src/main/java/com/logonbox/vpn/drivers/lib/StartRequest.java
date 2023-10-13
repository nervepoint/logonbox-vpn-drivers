package com.logonbox.vpn.drivers.lib;

import java.util.Optional;

public final class StartRequest {

	public final static class Builder {
		private Optional<String> nativeInterfaceName;
		private Optional<String> interfaceName;
		private final VpnConfiguration configuration;
		private Optional<VpnPeer> peer;
		
		public Builder(VpnConfiguration configuration) {
			this.configuration = configuration;
		}

		public Builder withInterfaceName(String interfaceName) {
			return withInterfaceName(Optional.of(interfaceName));
		}

		public Builder withInterfaceName(Optional<String> interfaceName) {
			this.interfaceName = interfaceName;
			return this;
		}

		public Builder withNativeInterfaceName(String nativeInterfaceName) {
			return withNativeInterfaceName(Optional.of(nativeInterfaceName));
		}

		public Builder withNativeInterfaceName(Optional<String> nativeInterfaceName) {
			this.nativeInterfaceName = nativeInterfaceName;
			return this;
		}

		public Builder withPeer(VpnPeer peer) {
			return withPeer(Optional.of(peer));
		}
		
		public Builder withPeer(Optional<VpnPeer> peer) {
			this.peer = peer;
			return  this;
		}
		

		public StartRequest build() {
			return new StartRequest(this);
		}
	}

	private final Optional<String> nativeInterfaceName;
	private final Optional<String> interfaceName;
	private final VpnConfiguration configuration;
	private final Optional<VpnPeer> peer;

	private StartRequest(Builder bldr) {
		if(bldr.nativeInterfaceName.isPresent() && !bldr.interfaceName.isPresent()) {
			throw new IllegalStateException("If a native interface name is provided, the wireguard interface name must also be supplied.");
		}
		this.nativeInterfaceName = bldr.nativeInterfaceName;
		this.interfaceName = bldr.interfaceName;
		this.configuration = bldr.configuration;
		this.peer = bldr.peer;
	}

	public Optional<String> nativeInterfaceName() {
		return nativeInterfaceName;
	}

	public Optional<String> interfaceName() {
		return interfaceName;
	}

	public VpnConfiguration configuration() {
		return configuration;
	}

	public Optional<VpnPeer> peer() {
		return peer;
	}
	
}
