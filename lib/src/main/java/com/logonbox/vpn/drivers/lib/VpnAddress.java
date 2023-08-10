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
import java.util.Enumeration;

public interface VpnAddress {

	boolean isUp();

	/**
	 * Entirely disconnect and delete the interface.
	 */
	void delete() throws IOException;

	void down() throws IOException;

	String getMac();
	
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

	String name();
	
	String displayName();

	String peer();

	String table();

	void mtu(int mtu);

//	void setName(String name);
//
//	void setPeer(String peer);
//
//	void setTable(String table);

	void up() throws IOException;
	
	void dns(String[] dns) throws IOException;

}