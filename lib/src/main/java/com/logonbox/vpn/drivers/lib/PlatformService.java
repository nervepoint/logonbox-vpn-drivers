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
import java.util.Collection;
import java.util.List;

public interface PlatformService<I extends VirtualInetAddress<?>> {
    
    /**
     * Create a default instance.
     * 
     * @return instance
     */
    public static PlatformService<? extends VirtualInetAddress<?>> create() {
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
	 * Get a public key given it's private key.
	 * 
	 * @param privateKey private key
	 * @return public key
	 */
	String pubkey(String privateKey);

    /**
     * Get the system context that called {@link #start(SystemContext)}.
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
	Collection<ActiveSession<I>> start(SystemContext ctx);

	/**
	 * Connect.
	 * 
	 * @param logonBoxVPNSession the session
	 * @param configuration      the configuration
	 * @return the virtual interface
	 * @throws IOException on any error
	 */
	ActiveSession<I> connect(WireguardConfiguration configuration) throws IOException;

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
	 * Get the detailed status of the named interface.
	 * 
	 * @param interfaceName interface name
	 * @return detailed status
	 * @throws IOException on error
	 */
	StatusDetail status(String interfaceName) throws IOException;

	/**
	 * Run a hook script appropriate for the platform. Ideally, this should
	 * be run as a script fragment.
	 *  
	 * @param session session
	 * @param hookScript
	 */
	void runHook(ActiveSession<I> session, String hookScript) throws IOException;
	
	/**
	 * Get the default DNS integration method. Will NOT return {@link DNSIntegrationMethod#AUTO}.
	 * 
	 * @return method
	 */
	DNSIntegrationMethod dnsMethod();

    /**
     * Get the instant of the last handshake for a given peer on the specified interface.
     * 
     * @param ipName interface name
     * @param publicKey public key of peer
     * @return instant 
     */
    long getLatestHandshake(String ipName, String publicKey) throws IOException;
    
    /**
     * Get an instance of {@link SystemCommands}, used to execute system commands.
     * 
     * @param args
     */
    SystemCommands commands();

}