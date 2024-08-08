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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreement;

import com.logonbox.vpn.drivers.lib.util.Keys;
import com.logonbox.vpn.drivers.lib.util.Keys.KeyPair;

import uk.co.bithatch.nativeimage.annotations.Reflectable;

/**
 * TODO: Not yet used
 */
@Reflectable
public class JCEKeys implements Keys.KeyPairProvider {

    private static class KeyPairImpl implements Keys.KeyPair {
        private final XECPublicKey publicKey;
        private final XECPrivateKey privateKey;

        public KeyPairImpl(XECPrivateKey privateKey, XECPublicKey publicKey) {
            super();
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        @Override
		public byte[] getPublicKey() {
            /*
             * https://stackoverflow.com/questions/67332030/java-11-curve25519-implementation-doesnt-behave-as-signals-libary
             */
            var bs = publicKey.getU().toByteArray();
            var b = new byte[bs.length];
            for (int i = 0; i < bs.length; i++) {
                b[bs.length - (i + 1)] = bs[i];
            }
            return b;
        }

        @Override
		public byte[] getPrivateKey() {
            return privateKey.getScalar().get();
        }

        @Override
		public byte[] agreement() {
        	KeyAgreement ka;
			try {
				ka = KeyAgreement.getInstance("XDH");
	        	ka.init(privateKey);
	        	ka.doPhase(publicKey, true);
	        	return ka.generateSecret();
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new IllegalStateException("Failed to create agreement.", e);
			}
        }

        @Override
		public byte[] sign(byte[] data) {
//        	try {
//        		for(var p : Security.getProviders()) {
//        			System.out.println("n = " + p.getName() + " i = " + p.getInfo());
//        			for(var s : p .getServices()) {
//        				if(s.getType().equals("Signature")) {
//							System.out.println("  a = " + s.getAlgorithm() + " t = " + s.getType() + " c = " + s.getClassName());
//						}
//        			}
//        		}
//	        	var sig = Signature.getInstance("Ed25519", Security.getProvider("SunEC"));
//	            sig.initSign(privateKey);
//	            sig.update(data);
//	            return sig.sign();
//        	}
//        	catch(NoSuchAlgorithmException | SignatureException | InvalidKeyException nse) {
//        		throw new IllegalStateException("Failed to sign.", nse);
//        	}


//    		Provider sunEc = Security.getProvider("SunEC");
//			for(var s : sunEc.getServices()) {
//    			if(s.getType().equals("Signature")) {
//					System.out.println("Trying " + s.getAlgorithm());
//    				try {
//			        	var sig = Signature.getInstance(s.getAlgorithm(), sunEc);
//			            sig.initSign(privateKey);
//			            sig.update(data);
//			            return sig.sign();
//    				}
//    				catch(Exception e) {
//    					System.out.println("Failed " + s.getAlgorithm());
//    				}
//    			}
//    		}
//			return null;
			throw new UnsupportedOperationException();
        }

    }

	@Override
	public boolean verify(byte[] publicKey, byte[] data, byte[] sig) {
		throw new UnsupportedOperationException();
	}

    @Override
	public KeyPair genkey() {
        try {
            var kpg = KeyPairGenerator.getInstance("XDH");
            var paramSpec = new NamedParameterSpec("X25519");
            kpg.initialize(paramSpec);
            return genkey(kpg);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException nsae) {
            throw new IllegalStateException("Failed to generate key.", nsae);
        }

    }

    @Override
	public KeyPair pubkey(byte[] privateKey) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("X25519");
            keyPairGenerator.initialize(new NamedParameterSpec("X25519"), new StaticSecureRandom(privateKey));
            return genkey(keyPairGenerator);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException nsae) {
            throw new IllegalStateException("Failed to generate key.", nsae);
        }
    }

    private static KeyPair genkey(KeyPairGenerator kpg) {
        var kp = kpg.generateKeyPair();
        var prikey = (XECPrivateKey) kp.getPrivate();
        var pubkey = (XECPublicKey) kp.getPublic();
        return new KeyPairImpl(prikey, pubkey);
    }

    @SuppressWarnings("serial")
    private static class StaticSecureRandom extends SecureRandom {

        private final byte[] privateKey;

        public StaticSecureRandom(byte[] privateKey) {
            this.privateKey = privateKey.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(privateKey, 0, bytes, 0, privateKey.length);
        }

    }

}
