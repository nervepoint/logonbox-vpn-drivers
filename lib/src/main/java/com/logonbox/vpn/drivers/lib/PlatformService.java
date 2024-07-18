/**
 * Copyright © 2023 LogonBox Limited (support@logonbox.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the “Software”), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface PlatformService<ADDR extends VpnAddress> {
	
	/**
	 * Create a default instance.
	 * 
	 * @param loader class loader for service locating
	 * @param context system context
	 * @return instance
	 */
	public static PlatformService<? extends VpnAddress> create(ClassLoader loader, SystemContext context) {
		return PlatformServiceFactory.get(loader).createPlatformService(context);
	}

	/**
	 * Create a default instance.
	 * 
	 * @param context system context
	 * @return instance
	 */
	public static PlatformService<? extends VpnAddress> create(SystemContext context) {
		return PlatformServiceFactory.get().createPlatformService(context);
	}

	/**
	 * Stop the VPN. This method should be used as opposed to
	 * {@link VpnAdapter#close()}, as this method will tear down DNS, routes, run
	 * hooks etc.
	 * 
	 * @param configuration configuration containing tear down details
	 * @param adapter       adapter to stop
	 * @throws IOException on error
	 */
	void stop(VpnConfiguration configuration, VpnAdapter session) throws IOException;

	/**
	 * Open file permissions so that it is readable by everyone.
	 * 
	 * @param path path of file to open
	 * @throws IOException
	 */
	void openToEveryone(Path path) throws IOException;

	/**
	 * Restrict a file so that it is readable by only the current user.
	 * 
	 * @param path path of file to restrict
	 * @throws IOException
	 */
	void restrictToUser(Path path) throws IOException;

	/**
	 * Get the system context that called {@link #init(SystemContext)}.
	 * {@link IllegalStateException} will be thrown if not started.
	 * 
	 * @return context
	 */
	SystemContext context();

	/**
	 * Connect, optionally waiting for the first handshake from the given peer.
	 * 
	 * @param startRequest start request
	 * @return the session that can be used to control the interface
	 * @throws IOException on any error
	 */
	VpnAdapter start(StartRequest startRequest)
			throws IOException;

	/**
	 * Get an interface that is using this public key, or {@link Optional#empty()}
	 * if no interface is using this public key at the moment.
	 * 
	 * @param public key return interface
	 * @throws IOException
	 */
	default Optional<VpnAdapter> getByPublicKey(String publicKey) throws IOException {
		for (VpnAdapter ip : adapters()) {
			if (ip.address().isUp()) {
				if (publicKey.equals(ip.information().publicKey())) {
					return Optional.of(ip);
				}
			}
		}
		return Optional.empty();
	}

	/**
	 * Get all interfaces.
	 * 
	 * @return addresses
	 */
	List<ADDR> addresses();

	/**
	 * Get all adapters. These are {@link VpnAddress}es that have been configured
	 * as wireguard adapters. An adapter always has an address, but an address may
	 * not (yet) have an adapter.
	 * 
	 * @return adapters
	 */
	List<VpnAdapter> adapters();

	/**
	 * Run a hook script appropriate for the platform. Ideally, this should be run
	 * as a script fragment.
	 * 
	 * @param configuration configuration containing scripts
	 * @param session       session
	 * @param hookScript    script
	 */
	void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException;

	/**
	 * Get whether or not a particular peer is being used as the default gateway, or
	 * {@link Optional#isEmpty()} will be <code>true</code> if the default gateway
	 * is not currently a peer on this VPN.
	 * 
	 * @return default gateway peer
	 */
	Optional<VpnPeer> defaultGateway();

	/**
	 * Set the peer to be used as the default gateway. This is a syterm wide
	 * setting. If the is disconnected, this will be reset.
	 * 
	 * @param peer peer to use as default gateway
	 * @throws IOException on error
	 */
	void defaultGateway(VpnPeer peer) throws IOException;

	/**
	 * Stop using any currently selected peer as the default gateway.
	 * 
	 * @throws IOException on error
	 */
	void resetDefaulGateway() throws IOException;

	/**
	 * Get an {@link VpnAddress} given its short name.
	 * 
	 * @param name name
	 * @return address
	 */
	ADDR address(String name);

	/**
	 * Get if a {@link VpnAddress} exists given its native interface name
	 * 
	 * @param nativeName name
	 * @return exists
	 */
	default boolean addressExists(String nativeName) {
		for (var addr : addresses()) {
			if (addr.name().equals(nativeName))
				return true;
		}
		return false;
	}

	/**
	 * Get a {@link VpnAdapter} given its native interface name.
	 * 
	 * @param nativeName name
	 * @return address
	 */
	VpnAdapter adapter(String nativeName);

	/**
	 * Get if a {@link VpnAdapter} exists given its native interface name.
	 * 
	 * @param nativeName name
	 * @return exists
	 */
	default boolean adapterExists(String nativeName) {
		for (var addr : adapters()) {
			if (addr.address().nativeName().equals(nativeName))
				return true;
		}
		return false;
	}

	/**
	 * Get the latest handshake given an interface name and public key. By default
	 * this will delegate to {@link VpnAdapter#latestHandshake(String)}, but certain
	 * platforms may provide a optimised version of this call.
	 * <p>
	 * It is preferable when monitoring handshakes to use this call.
	 * 
	 * @param iface     interface name
	 * @param publicKey public key
	 * @return last handshake
	 * @throws IOException
	 */
	default Instant getLatestHandshake(VpnAddress address, String publicKey) throws IOException {
		return adapter(address.nativeName()).latestHandshake(publicKey);
	}

	/**
	 * Retrieve details about the wireguard adapter. Statistics can be obtained via
	 * this object.
	 * 
	 * @param adapter wireguard adapter
	 * @return information
	 * @throws UncheckedIOException on error
	 */
	VpnInterfaceInformation information(VpnAdapter adapter);

	/**
	 * Retrieve configuration of the wireguard adapter.
	 * 
	 * @param adapter wireguard adapter
	 * @return configuration
	 * @throws UncheckedIOException on error
	 */
	VpnAdapterConfiguration configuration(VpnAdapter adapter);

	/**
	 * Get the configured {@link DNSProvider}, or {@link Optional#empty()}.
	 * 
	 * @return DNS provider
	 */
	Optional<DNSProvider> dns();

	/**
	 * Update an adapters configuration. This operation will likely disrupt any
	 * currently active peers. For simple updates of configuration,
	 * {@link #sync(VpnAdapter, VpnConfiguration)} or {@link #append(VpnAdapter, VpnAdapterConfiguration)} are a better choices.
	 * 
	 * @param adapter       adapter
	 * @param configuration new configuration
	 * @throws IOException on error
	 */
	void reconfigure(VpnAdapter vpnAdapter, VpnAdapterConfiguration cfg) throws IOException;

	/**
	 * Synchronize an adapters configuration. This operation will not disrupt any 
	 * currently active peers. For larger updates of configuration, {@link #append(VpnAdapter, VpnAdapterConfiguration)} or {@link #reconfigure(VpnConfiguration, VpnConfiguration)}
	 * are better choices.
	 * 
	 * @param adapter       adapter
	 * @param configuration new configuration
	 * @throws IOException on error
	 */
	void sync(VpnAdapter vpnAdapter, VpnAdapterConfiguration cfg) throws IOException;

	/**
	 * Append to an adapters configuration. This operation will not disrupt any 
	 * currently active peers. For larger updates of configuration, {@link #sync(VpnAdapter, VpnAdapterConfiguration)} or {@link #reconfigure(VpnConfiguration, VpnConfiguration)}
	 * are a better choices.
	 * 
	 * @param adapter       adapter
	 * @param configuration new configuration
	 * @throws IOException on error
	 */
	void append(VpnAdapter vpnAdapter, VpnAdapterConfiguration cfg) throws IOException;

	/**
	 * Remove an active peer from an active adapter. 
	 *  
	 * @param vpnAdapter adapter
	 * @param publicKey public key of peer
	 * @throws IOException if peer cannot be removed
	 */
	void remove(VpnAdapter vpnAdapter, String publicKey) throws IOException;
	
	/**
	 * Get the last native name of an interface given its wireguard interface
	 * name. 
	 * 
	 * @param name wireguard interface name (e.g. derived from configuration file name)
	 * @return native name of interface
	 */
	Optional<String> interfaceNameToNativeName(String name);
	
	/**
	 * Get the last registered wireguard interface name given the native interface name.
	 * 
	 * @param name native interface name
	 * @return wireguard interface name
	 */
	Optional<String> nativeNameToInterfaceName(String name);

	/**
	 * Check if the given native interface name is valid for this platform.
	 * 
	 * @param name interface name
	 * @return valid name for this platform
	 */
	boolean isValidNativeInterfaceName(String name);
	
	/**
	 * Get if IP forwarding is globally enabled. This currently only has an effect
	 * on Linux. All other platforms will just return <code>true</code>
	 * 
	 * @return ip forwarding is enabled on system
	 */
	boolean isIpForwardingEnabledOnSystem();
	
	/**
	 * Set if IP forwarding is globally enabled. This currently only has an effect
	 * on Linux. All other platforms will throw an {@link UnsupportedOperationException}.
	 * 
	 * @param ipForwarding enable ip forwarding globally
	 */
	void setIpForwardingEnabledOnSystem(boolean ipForwarding);

	/**
	 * Set whether the supplied interface should do NAT translation.
	 * 
	 * @param iface native interface name
	 * @param range network range
	 * @param nat 			do NAT translation
	 * @throws IOException on error
	 */
	void setNat(String iface, String range, NATMode... nat) throws IOException; 

	/**
	 * Get whether the supplied interface is doing NAT/SNAT translation.
	 * 
	 * @param iface native interface name
	 * @param range network range
	 * @return doing NAT translation
	 * @throws IOException on error
	 */
	NATMode[] getNat(String iface, String range) throws IOException;

}