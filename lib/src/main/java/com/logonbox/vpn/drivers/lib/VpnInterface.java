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

import com.sshtools.liftlib.OS;

import java.io.IOException;
import java.net.NetworkInterface;
import java.text.MessageFormat;
import java.time.Instant;
import java.util.Enumeration;

public interface VpnInterface<P extends PlatformService<?>> {

	boolean isUp();

	/**
	 * Entirely disconnect and delete the interface.
	 */
	void delete() throws IOException;

	void down() throws IOException;

	String getMac();
	
	VpnConfiguration configuration() throws IOException;
    
    VpnInterfaceInformation information() throws IOException;


    /**
     * Get the detailed status of a peer with the given public key in the named interface .
     * 
     * @param interfaceName interface name
     * @param publicKey public key of peer
     * @return detailed status
     * @throws IOException on error
     * @throws IllegalArgumentException if no such public key
     */
    default VpnPeerInformation information(String publicKey) throws IOException {
        for(var peer : information().peers()) {
            if(peer.publicKey().equals(publicKey))
                return peer;
        }
        throw new IllegalArgumentException(MessageFormat.format("No such peer {0} on interface {1}", publicKey, getName()));
    }

    /**
     * Get the instant of the last handshake for any peer on the specified interface.
     * 
     * @return instant 
     */
    default Instant latestHandshake() throws IOException {
        return information().lastHandshake();
    }

    /**
     * Get the instant of the last handshake for a given peer on the specified interface.
     * 
     * @param publicKey public key of peer
     * @return instant 
     */
    default Instant latestHandshake(String publicKey) throws IOException {
        return information(publicKey).lastHandshake();
    }
	
	default NetworkInterface getByName(String name) throws IOException {
		/* NOTE: This is pretty much useless  to lookup the network by the 
		 * name we know it as on Windows, as for some bizarre reason,
		 * net8 for example (as would show ip "ipconfig /all") comes back 
		 * here as net7!
		 */
		if(OS.isWindows())
			throw new UnsupportedOperationException("Do not use this on Windows.");
		
		for(Enumeration<NetworkInterface> nifEnum = NetworkInterface.getNetworkInterfaces(); nifEnum.hasMoreElements(); ) {
			NetworkInterface nif = nifEnum.nextElement();
			if(nif.getName().equals(name))
				return nif;
		}
		return null;
	}

	int getMtu();

	String getName();
	
	String getDisplayName();

	String getPeer();

	String getTable();

	void setMtu(int mtu);

	void setName(String name);

	void setPeer(String peer);

	void setTable(String table);

	void up() throws IOException;
	
	void dns(String[] dns) throws IOException;

	VpnInterface<P> method(DNSIntegrationMethod method);

	DNSIntegrationMethod method();

	P getPlatform();

	DNSIntegrationMethod calcDnsMethod();

}