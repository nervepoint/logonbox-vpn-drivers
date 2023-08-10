package com.logonbox.vpn.drivers.lib;

import java.io.Serializable;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import uk.co.bithatch.nativeimage.annotations.Serialization;

@Serialization
public interface VpnPeer extends Serializable {

	public final static class Builder {

		private Optional<Integer> endpointPort = Optional.empty();
		private Optional<String> endpointAddress = Optional.empty();
		private Optional<String> publicKey = Optional.empty();
		private List<String> allowedIps = new ArrayList<>();
		private Optional<Integer> persistentKeepalive = Optional.empty();
		private Optional<String> presharedKey;


		public Builder withPeer(VpnPeer peer) {
			withPublicKey(peer.publicKey());
			withEndpointAddress(peer.endpointAddress());
			withEndpointPort(peer.endpointPort());
			withPersistentKeepalive(peer.persistentKeepalive());
			withAllowedIps(peer.allowedIps());
			withPresharedKey(peer.presharedKey());
			return this;
		}

		public Builder addAllowedIps(String... allowedIps) {
			return addAllowedIps(Arrays.asList(allowedIps));
		}

		public Builder addAllowedIps(Collection<String> allowedIps) {
			this.allowedIps.addAll(allowedIps);
			return this;
		}

		public Builder withAllowedIps(String... allowedIps) {
			return withAllowedIps(Arrays.asList(allowedIps));
		}

		public Builder withAllowedIps(Collection<String> allowedIps) {
			this.allowedIps.clear();
			return addAllowedIps(allowedIps);
		}

		public Builder withPersistentKeepalive(int persistentKeepalive) {
			return withPersistentKeepalive(Optional.of(persistentKeepalive));
		}

		public Builder withPersistentKeepalive(Optional<Integer> persistentKeepalive) {
			this.persistentKeepalive = persistentKeepalive;
			return this;
		}

		public Builder withEndpointPort(int endpointPort) {
			return withEndpointPort(Optional.of(endpointPort));
		}

		public Builder withEndpointPort(Optional<Integer> endpointPort) {
			this.endpointPort = endpointPort;
			return this;
		}

		public Builder withEndpoint(Optional<String> endpoint) {
			if (endpoint.isEmpty()) {
				withEndpointAddress(Optional.empty());
				withEndpointPort(Optional.empty());
			} else {
				withEndpoint(endpoint.get());
			}
			return this;
		}

		public Builder withEndpoint(String endpoint) {
			var idx = endpoint.indexOf(':');
			withEndpointAddress(idx == -1 ? endpoint : endpoint.substring(0, idx));
			if (idx == -1) {
				withEndpointAddress(endpoint);
				withEndpointPort(Optional.empty());
			} else {
				withEndpointAddress(endpoint.substring(0, idx));
				withEndpointPort(Integer.parseInt(endpoint.substring(idx + 1)));
			}
			return this;
		}

		public Builder withEndpoint(InetSocketAddress endpoint) {
			if (endpoint == null) {
				return withEndpoint(Optional.empty());
			} else {
				return withEndpointAddress(endpoint.getAddress().getHostAddress()).withEndpointPort(endpoint.getPort());
			}
		}

		public Builder withEndpointAddress(String endpointAddress) {
			return withEndpointAddress(Optional.of(endpointAddress));
		}

		public Builder withEndpointAddress(Optional<String> endpointAddress) {
			this.endpointAddress = endpointAddress;
			return this;
		}

		public Builder withPresharedKey(String presharedKey) {
			return withPresharedKey(Optional.of(presharedKey));
		}

		public Builder withPresharedKey(Optional<String> presharedKey) {
			this.presharedKey = presharedKey;
			return this;
		}

		public Builder withPublicKey(String publicKey) {
			return withPublicKey(Optional.of(publicKey));
		}

		public Builder withPublicKey(Optional<String> publicKey) {
			this.publicKey = publicKey;
			return this;
		}

		public VpnPeer build() {
			return new DefaultVpnPeer(this);
		}

		@SuppressWarnings("serial")
		static class DefaultVpnPeer implements VpnPeer {

			private final int endpointPort;
			private final String endpointAddress;
			private final String publicKey;
			private final List<String> allowedIps;
			private final int persistentKeepalive;
			private final String presharedKey;

			DefaultVpnPeer(Builder builder) {
				persistentKeepalive = builder.persistentKeepalive.orElse(0);
				endpointPort = builder.endpointPort.orElse(0);
				endpointAddress = builder.endpointAddress.orElse(null);
				publicKey = builder.publicKey.orElseThrow(() -> new IllegalStateException("No public key"));
				allowedIps = Collections.unmodifiableList(new ArrayList<>(builder.allowedIps));
				presharedKey = builder.presharedKey.orElse(null);
			}

			@Override
			public Optional<String> presharedKey() {
				return Optional.ofNullable(presharedKey);
			}

			@Override
			public Optional<String> endpointAddress() {
				return Optional.ofNullable(endpointAddress);
			}

			@Override
			public Optional<Integer> endpointPort() {
				return endpointPort == 0 ? Optional.empty() : Optional.of(endpointPort);
			}

			@Override
			public String publicKey() {
				return publicKey;
			}

			@Override
			public Optional<Integer> persistentKeepalive() {
				return persistentKeepalive == 0 ? Optional.empty() : Optional.of(persistentKeepalive);
			}

			@Override
			public List<String> allowedIps() {
				return allowedIps;
			}

		}
	}

	Optional<String> endpointAddress();

	Optional<Integer> endpointPort();

	String publicKey();

	Optional<Integer> persistentKeepalive();

	List<String> allowedIps();

	Optional<String> presharedKey();
}
