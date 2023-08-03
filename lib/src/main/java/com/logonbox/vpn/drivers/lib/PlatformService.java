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
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PlatformService<I extends VpnInterface<?>> {
    
    /**
     * Create a default instance.
     * 
     * @return instance
     */
    public static PlatformService<? extends VpnInterface<?>> create() {
        return PlatformServiceFactory.get().createPlatformService();
    }

    /**
     * Do any platform specific clean up. It should not be necessary to 
     * call this yourself.
     * 
     * @param session session to clean up
     */
    void cleanUp(ActiveSession<I> session);

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
	 * @return any sessions that are already active.
	 */
	Collection<ActiveSession<I>> init(SystemContext ctx);

	/**
	 * Connect, optionally waiting for the first handshake from the given peer.
	 * 
	 * @param configuration the configuration
	 * @param peer peer from which to wait for the first handshake from
	 * @return the session that can be used to control the interface
	 * @throws IOException on any error
	 */
	ActiveSession<I> start(VpnConfiguration configuration, Optional<VpnPeer> peer) throws IOException;

	/**
	 * Get an interface that is using this public key, or <code>null</code> if no
	 * interface is using this public key at the moment.
	 * 
	 * @param public key return interface
	 */
	I getByPublicKey(String publicKey);

	/**
	 * Get all interfaces.
	 * 
	 * @param wireguardOnly only wireguard interfaces
	 * @return interfaces
	 */
	List<I> ips(boolean wireguardOnly);

	/**
	 * Run a hook script appropriate for the platform. Ideally, this should
	 * be run as a script fragment.
	 *  
	 * @param session session
	 * @param hookScript script
	 */
	void runHook(ActiveSession<I> session, String... hookScript) throws IOException;
	
	/**
	 * Get the default DNS integration method. Will NOT return {@link DNSIntegrationMethod#AUTO}.
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
     * Get an interface given its short name. Avoid call this too often, it
     * may be slower on some platforms. Instead you should access the 
     * reference of {@link ActiveSession#ip()}.
     * 
     * @param name name
     * @return interface
     */
    I get(String name);

    /**
     * Get the latest handshake given an interface name and public key.
     * By default this will delegate to {@link VpnInterface#latestHandshake(String)},
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
        return get(iface).latestHandshake(publicKey);
    }
 
    
    

}