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
package com.logonbox.vpn.drivers.lib.util.impl;


import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.JavaCurve25519Provider;

import uk.co.bithatch.nativeimage.annotations.OtherReflectable;
import uk.co.bithatch.nativeimage.annotations.OtherReflectables;

import com.logonbox.vpn.drivers.lib.util.Keys.KeyPair;
import com.logonbox.vpn.drivers.lib.util.Keys.KeyPairProvider;

@OtherReflectables(
    @OtherReflectable(all = true, value = JavaCurve25519Provider.class)
)
public class WhisperKeys implements KeyPairProvider {

	private static class KeyPairImpl implements KeyPair {
		private final Curve25519KeyPair keyPair;
		private final Curve25519 provider;

		public KeyPairImpl(Curve25519KeyPair keyPair, Curve25519 provider) {
			this.keyPair = keyPair;
			this.provider = provider;
		}

		@Override
		public byte[] getPublicKey() {
			return keyPair.getPublicKey();
		}

		@Override
		public byte[] getPrivateKey() {
			return keyPair.getPrivateKey();
		}

		@Override
		public final byte[] agreement() {
			return provider.calculateAgreement(getPublicKey(), getPublicKey());
		}

		@Override
		public final byte[] sign(byte[] data) {
			return provider.calculateSignature(getPrivateKey(), data);
		}

	}

	private final Curve25519 provider;

	public WhisperKeys() {
		provider = Curve25519.getInstance(Curve25519.JAVA);
	}

	@Override
	public KeyPair genkey() {
		return new KeyPairImpl(provider.generateKeyPair(), provider);
	}

	@Override
	public KeyPair pubkey(byte[] privateKey) {
		/* TODO no API for this! horrible hack that always uses pure Java basic provider */
		var basic = new BasicKeys();
		var pubkeyPair = basic.pubkey(privateKey);
		return new KeyPair() {
			
			@Override
			public byte[] sign(byte[] data) {
				return provider.calculateSignature(getPrivateKey(), data);
			}
			
			@Override
			public byte[] getPublicKey() {
				return pubkeyPair.getPublicKey();
			}
			
			@Override
			public byte[] getPrivateKey() {
				return privateKey;
			}
			
			@Override
			public byte[] agreement() {
				return provider.calculateAgreement(getPublicKey(), getPublicKey());
			}
		};
	}

	@Override
	public boolean verify(byte[] publicKey, byte[] data, byte[] sig) {
		return provider.verifySignature(publicKey, data, sig);
	}

}
