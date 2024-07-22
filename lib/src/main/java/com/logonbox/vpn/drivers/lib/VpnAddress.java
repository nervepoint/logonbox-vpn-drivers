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
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.Optional;

import com.sshtools.liftlib.OS;

public interface VpnAddress {

	boolean isUp();
	
	boolean isDefaultGateway();
	
	void setDefaultGateway(String address);

	/**
	 * Entirely disconnect and delete the interface.
	 */
	void delete() throws IOException;

	void down() throws IOException;

	String getMac();
	
	default boolean isLoopback() {
		return networkInterface().map(nif -> { 
			try {
				if(nif.isLoopback())
					return true;
				
				var loopback = true;
				for (var addr : nif.getInterfaceAddresses()) {
					var ipAddr = addr.getAddress();
					if (!ipAddr.isAnyLocalAddress() && !ipAddr.isLinkLocalAddress()
							&& !ipAddr.isLoopbackAddress()) {
						loopback = false;
					}
				}
				
				return loopback;
				
			} catch (SocketException e) {
				return false;
			} 
		}).orElse(false);
	}
	
	default Optional<NetworkInterface> networkInterface() {
		/* NOTE: This is pretty much useless  to lookup the network by the 
		 * name we know it as on Windows, as for some bizarre reason,
		 * net8 for example (as would show ip "ipconfig /all") comes back 
		 * here as net7!
		 */
		if(OS.isWindows())
			throw new UnsupportedOperationException("Do not use this on Windows.");
		
		try {
			for(Enumeration<NetworkInterface> nifEnum = NetworkInterface.getNetworkInterfaces(); nifEnum.hasMoreElements(); ) {
				NetworkInterface nif = nifEnum.nextElement();
				if(nif.getName().equals(nativeName()))
					return Optional.of(nif);
			}
			return Optional.empty();
		}
		catch(IOException ioe) {
			throw new UncheckedIOException(ioe);
		}
	}

	int getMtu();

	String name();

    String displayName();

    default String shortName() {
        if(hasVirtualName())
            return String.format("%s (%s)", name(), nativeName());
        else
            return name();
    }

    String nativeName();
    
    default boolean hasVirtualName() {
    	return !name().equals(nativeName());
    }

	String peer();

	String table();

	void mtu(int mtu);

//	void setName(String name);
//
//	void setPeer(String peer);
//
//	void setTable(String table);

	void up() throws IOException;

}