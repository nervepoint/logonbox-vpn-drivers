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
package com.logonbox.vpn.drivers.lib.util;

import java.security.SecureRandom;
import java.util.Base64;

public class Keys {

	public static class KeyPair {
		private byte[] publicKey;
		private final byte[] privateKey;

		private KeyPair(byte[] privateKey) {
			this.privateKey = privateKey;
		}

		private KeyPair() {
			privateKey = new byte[32];
		}

		public byte[] getPublicKey() {
			return publicKey;
		}
		
		public String getBase64PublicKey() {
			return Base64.getEncoder().encodeToString(publicKey);
		}

		public byte[] getPrivateKey() {
			return privateKey;
		}

		public String getBase64PrivateKey() {
			return Base64.getEncoder().encodeToString(privateKey);
		}

	}

	private Keys() {
	}

	public static KeyPair genkey() {
		KeyPair kp = new KeyPair();
		SecureRandom random = new SecureRandom();
		random.nextBytes(kp.privateKey);
		kp.publicKey = Curve25519.scalarBaseMult(kp.privateKey);
		return kp;
	}

	public static KeyPair pubkey(String base64PrivateKey) {
		return pubkey(Base64.getDecoder().decode(base64PrivateKey));
	}

	public static KeyPair pubkey(byte[] privateKey) {
		KeyPair kp = new KeyPair(privateKey);
		kp.publicKey = Curve25519.scalarBaseMult(kp.privateKey);
		return kp;
	}
}
