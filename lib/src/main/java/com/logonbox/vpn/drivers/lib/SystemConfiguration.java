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

import java.time.Duration;
import java.util.Optional;

public interface SystemConfiguration {
    
    public static class DefaultSystemConfiguration implements SystemConfiguration {
		@Override
		public Duration serviceWait() {
		    return SERVICE_WAIT_TIMEOUT;
		}

		@Override
		public boolean ignoreLocalRoutes() {
		    return false;
		}

		@Override
		public Duration handshakeTimeout() {
		    return HANDSHAKE_TIMEOUT;
		}

		@Override
		public Optional<Integer> defaultMTU() {
		    return Optional.empty();
		}

		@Override
		public Optional<Duration> connectTimeout() {
		    return Optional.of(CONNECT_TIMEOUT);
		}

		@Override
		public Optional<String> dnsIntegrationMethod() {
			var str = System.getProperty("logonbox.vpn.dns", "");
		    return str.equals("") ? Optional.empty() : Optional.of(str);
		}
	}

	Duration HANDSHAKE_TIMEOUT = Duration.ofSeconds(Integer.parseInt(System.getProperty("logonbox.vpn.handshakeTimeout", "180")));
    Duration SERVICE_WAIT_TIMEOUT = Duration.ofSeconds(Integer.parseInt(System.getProperty("logonbox.vpn.serviceWaitTimeout", "2")));
    Duration CONNECT_TIMEOUT = Duration.ofSeconds(Integer.parseInt(System.getProperty("logonbox.vpn.connectTimeout", "12")));
    SystemConfiguration DEFAULT = new DefaultSystemConfiguration();
    
    public static SystemConfiguration defaultConfiguration() {
        return DEFAULT;
    }

    Optional<Integer> defaultMTU();

    Duration serviceWait();

    Optional<Duration> connectTimeout();

    boolean ignoreLocalRoutes();

    Duration handshakeTimeout();

    Optional<String> dnsIntegrationMethod();
}
