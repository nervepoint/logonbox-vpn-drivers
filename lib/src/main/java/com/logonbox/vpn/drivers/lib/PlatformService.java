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
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface PlatformService<ADDR extends VpnAddress> {
    
    /**
     * Create a default instance.
     * 
     * @return instance
     */
    public static PlatformService<? extends VpnAddress> create() {
        return PlatformServiceFactory.get().createPlatformService();
    }

    /**
     * Stop the VPN. This method should be used as opposed to {@link VpnAdapter#close()},
     * as this method will tear down DNS, routes, run hooks etc.
     * 
     * @param configuration configuration containing tear down details
     * @param session session to clean up
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
	 * Get a list of the common names of any 3rd party or distribution packages that
	 * are needed on this platform.
	 * 
	 * @return message packages
	 */
	String[] getMissingPackages();

    /**
     * Get the system context that called {@link #init(SystemContext)}.
     * {@link IllegalStateException} will be thrown if not started.
     * 
     * @return context
     */
    SystemContext context();

	/**
	 * Start the services for this platform.
	 * 
	 * @param ctx context
	 */
	void init(SystemContext ctx);

	/**
	 * Connect, optionally waiting for the first handshake from the given peer.
	 * @param interfaceName TODO
	 * @param configuration the configuration
	 * @param peer peer from which to wait for the first handshake from
	 * 
	 * @return the session that can be used to control the interface
	 * @throws IOException on any error
	 */
	VpnAdapter start(Optional<String> interfaceName, VpnConfiguration configuration, Optional<VpnPeer> peer) throws IOException;

	/**
	 * Get an interface that is using this public key, or {@link Optional#empty()} if no
	 * interface is using this public key at the moment.
	 * 
	 * @param public key return interface
	 * @throws IOException 
	 */
    default Optional<VpnAdapter> getByPublicKey(String publicKey) throws IOException {
        for (VpnAdapter ip : adapters()) {
            if (publicKey.equals(ip.information().publicKey())) {
                return Optional.of(ip);
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
     * Get all adapters. These are {@link VpnAddress}es that have beeon
     * configured as wireguard adapters. An adapter always has an address,
     * but an address may not (yet) have an adapter.
     * 
     * @return adapters
     */
    List<VpnAdapter> adapters();

	/**
	 * Run a hook script appropriate for the platform. Ideally, this should
	 * be run as a script fragment.
	 *  
	 * @param configuration configuration containing scripts
	 * @param session session
	 * @param hookScript script
	 */
	void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException;
	
	/**
	 * Detect the default DNS integration method to use given the current platform and platform configuration. Will NOT return {@link DNSIntegrationMethod#AUTO}.
	 * 
	 * @return method
	 */
	DNSIntegrationMethod dnsMethod();
    
    /**
     * Get an instance of {@link SystemCommands}, used to execute system commands.
     * 
     * @param args
     */
    SystemCommands commands();
    
    /**
     * Get whether or not a particular peer is being used as the default gateway,
     * or {@link Optional#isEmpty()} will be <code>true</code> if the default
     * gateway is not currently a peer on this VPN.
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
     * @throws IOException on error
     */
    void resetDefaulGateway() throws IOException;

    /**
     * Get an {@link VpnAddress} given its short name. Avoid call this too often, it
     * may be slower on some platforms. Instead you should access the 
     * reference of {@link VpnAdapter#address()}.
     * 
     * @param name name
     * @return address
     */
    ADDR address(String name);

    /**
     * Get a {@link VpnAdapter} given its short name. Avoid call this too often, it
     * may be slower on some platforms. Instead you should access the 
     * reference of {@link VpnAdapter#ip()}.
     * 
     * @param name name
     * @return address
     */
    VpnAdapter adapter(String name);

    /**
     * Get the latest handshake given an interface name and public key.
     * By default this will delegate to {@link VpnAdapter#latestHandshake(String)},
     * but certain platforms may provide a optimised version of this call.
     * <p>
     * It is preferable when monitoring handshakes to use this call.
     * 
     * @param iface interface name
     * @param publicKey public key
     * @return last handshake
     * @throws IOException
     */
    default Instant getLatestHandshake(String iface, String publicKey) throws IOException {
        return adapter(iface).latestHandshake(publicKey);
    }

    /**
     * Retrieve details about the wireguard adapter. Statistics can be obtained via this object. 
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
 
}