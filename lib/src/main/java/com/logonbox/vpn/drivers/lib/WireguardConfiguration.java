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

import java.util.List;

public interface WireguardConfiguration {
	
	String getUserPrivateKey();

	void setUserPrivateKey(String privateKey);

	String getUserPublicKey();

	void setUserPublicKey(String publicKey);

	String getPublicKey();

	void setPublicKey(String Key);

	void setEndpointAddress(String endpointAddress);

	void setEndpointPort(int endpoingPort);

	String getEndpointAddress();

	int getEndpointPort();

	int getMtu();

	void setMtu(int mtu);

	String getAddress();

	void setAddress(String address);

	List<String> getDns();

	void setDns(List<String> dns);

	int getPersistentKeepalive();

	void setPeristentKeepalive(int peristentKeepalive);

	List<String> getAllowedIps();

	void setAllowedIps(List<String> allowedIps);

	String getPreUp();
	
	String getPostUp();
	
	String getPreDown();
	
	String getPostDown();
	
	boolean isRouteAll();

	void setPreUp(String preUp);

	void setPostUp(String postUp);

	void setPreDown(String preDown);

	void setPostDown(String postDown);

	void setError(String error);
	
	String getError();


}
