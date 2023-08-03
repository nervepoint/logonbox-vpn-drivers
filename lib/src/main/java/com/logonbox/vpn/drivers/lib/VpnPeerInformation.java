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

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Optional;

public interface VpnPeerInformation {

	VpnPeerInformation EMPTY = new VpnPeerInformation() {

		@Override
		public long rx() {
			return 0;
		}

		@Override
		public long tx() {
			return 0;
		}

		@Override
		public Instant lastHandshake() {
			return Instant.ofEpochMilli(0);
		}

		@Override
		public Optional<String> error() {
			return Optional.empty();
		}

        @Override
        public String publicKey() {
            return "";
        }

        @Override
        public Optional<InetSocketAddress> remoteAddress() {
            return Optional.empty();
        }

        @Override
        public Optional<String> presharedKey() {
            return Optional.empty();
        }

	};
	
	Optional<InetSocketAddress> remoteAddress();
	
	String publicKey();
    
    Optional<String> presharedKey();

	long tx();

	long rx();

	Instant lastHandshake();

	Optional<String> error();
}
