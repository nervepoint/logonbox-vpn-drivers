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
package com.logonbox.vpn.drivers.windows;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.Union;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * JNA interface to wireguard.dll.
 * 
 * Note, as of 29/06/2023, not all functions are implemented. Just enough to
 * get status calls. For all other functionality we use tunnel.dll (see NetworkConfigurationService).
 * 
 * See https://git.zx2c4.com/wireguard-nt/about/ for full description of API, of Service.cs in the C# example
 * This code was ported from that example.
 */
public interface WireguardLibrary extends Library {

	final static Logger LOG = LoggerFactory.getLogger(WireguardLibrary.class);
	
    public static final String JNA_LIBRARY_NAME = "wireguard";
    public static final NativeLibrary JNA_NATIVE_LIB = NativeLibrary.getInstance(WireguardLibrary.JNA_LIBRARY_NAME);
    public static final WireguardLibrary INSTANCE = (WireguardLibrary) Native.load(WireguardLibrary.JNA_LIBRARY_NAME,
            WireguardLibrary.class);

    PointerByReference WireGuardOpenAdapter(WString name);

    void WireGuardCloseAdapter(PointerByReference handle);

    boolean WireGuardGetConfiguration(PointerByReference handle, Memory memory, IntByReference bytes);

    boolean WireGuardSetConfiguration(PointerByReference handle, Memory memory, IntByReference bytes);

    public static class Adapter implements Closeable {

        private final IntByReference lastGetGuess;
        private final PointerByReference handle;
        private final String name;

        public Adapter(String name) {
        	this.name = name;
            lastGetGuess = new IntByReference(1024);
            handle = INSTANCE.WireGuardOpenAdapter(new WString(name));
            if(handle == null) {
            	throw new IllegalArgumentException("Failed to open adapter " + name);
            }
        }

        public Interface getConfiguration() {
            var iface = new Interface();
            Memory mem;
            for (;;) {
                mem = new Memory(lastGetGuess.getValue());
                if (INSTANCE.WireGuardGetConfiguration(handle, mem, lastGetGuess))
                    break;
                mem.close();

                var err = Native.getLastError();
                if (err != 234 /* ERROR_MORE_DATA */)
                    throw new Win32Exception(err);
            }
            
            try {
                var ioctlIface = new IoctlInterface(mem);
                if ((ioctlIface.flags & IoctlInterfaceFlags.hasPublicKey) != 0)
                    iface.publicKey = new Key(ioctlIface.publicKey);
                if ((ioctlIface.flags & IoctlInterfaceFlags.hasPrivateKey) != 0)
                    iface.privateKey = new Key(ioctlIface.privateKey);
                if ((ioctlIface.flags & IoctlInterfaceFlags.hasListenPort) != 0)
                    iface.listenPort = Short.toUnsignedInt(ioctlIface.listenPort);
                
                var peers = new Peer[(int)Integer.toUnsignedLong(ioctlIface.peersCount)];
                
                var offset = ioctlIface.size();
				var ioctlPeer = new IoctlPeer(mem.share(offset));
                for (var i = 0; i < peers.length; ++i)
                {
                    var peer = new Peer();
                    if ((ioctlPeer.flags & IoctlPeerFlags.hasPublicKey) != 0)
                        peer.publicKey = new Key(ioctlPeer.publicKey);
                    if ((ioctlPeer.flags & IoctlPeerFlags.hasPresharedKey) != 0)
                        peer.presharedKey = new Key(ioctlPeer.presharedKey);
                    if ((ioctlPeer.flags & IoctlPeerFlags.hasPersistentKeepalive) != 0)
                        peer.PersistentKeepalive = Short.toUnsignedInt(ioctlPeer.persistentKeepalive);
                    
                    try {
                        if ((ioctlPeer.flags & IoctlPeerFlags.hasEndpoint) != 0)
                        {
                            if (ioctlPeer.endpoint.si_family == AF_INET)
                            {
                                var ip = new byte[4];
                                System.arraycopy(ioctlPeer.endpoint.ipv4.sin_addr.bytes, 0, ip, 0, 4);
                                    peer.endpoint = new InetSocketAddress(InetAddress.getByAddress(ip), networkToHostOrder(ioctlPeer.endpoint.ipv4.sin_port));
                            }
                            else if (ioctlPeer.endpoint.si_family == AF_INET6)
                            {
                                var ip = new byte[16];
                                System.arraycopy(ioctlPeer.endpoint.ipv6.sin6_addr.bytes, 0, ip, 0, 4);
                                peer.endpoint = new InetSocketAddress(InetAddress.getByAddress(ip), networkToHostOrder(ioctlPeer.endpoint.ipv6.sin6_port));
                            }
                        }
                    } catch (UnknownHostException e) {
                        throw new IllegalArgumentException("Invalid endpoint address");
                    }

                    peer.txBytes = ioctlPeer.txBytes;
                    peer.rxBytes = ioctlPeer.rxBytes;

                    if (ioctlPeer.lastHandshake != 0)
                        peer.lastHandshake = Optional.of(toInstant((long)ioctlPeer.lastHandshake));
                    
                    var allowedIPs = new AllowedIP[ioctlPeer.allowedIPsCount];
                    offset += ioctlPeer.size();
                    var ioctlAllowedIP = new IoctlAllowedIP(mem.share(offset));
                    for (int j = 0; j < allowedIPs.length; j++)
                    {
                        try {
                            var allowedIP = new AllowedIP();
                            if (ioctlAllowedIP.address_family == AF_INET)
                            {
                                var ip = new byte[4];
                                System.arraycopy(ioctlAllowedIP.address.ipv4.bytes, 0, ip, 0, 4);
                                allowedIP.address = InetAddress.getByAddress(ip);
                            }
                            else if (ioctlAllowedIP.address_family == AF_INET6) 
                            {
                                var ip = new byte[16];
                                System.arraycopy(ioctlAllowedIP.address.ipv6.bytes, 0, ip, 0, 16);
                                allowedIP.address = InetAddress.getByAddress(ip);
                            }

                            allowedIP.cidr = Byte.toUnsignedInt(ioctlAllowedIP.cidr);
                        
                            allowedIPs[j] = allowedIP;

                            offset += ioctlAllowedIP.size();
                            ioctlAllowedIP = new IoctlAllowedIP(mem.share(offset));        
                            
                        } catch (UnknownHostException e) {
                            throw new IllegalArgumentException("Invalid endpoint address");
                        }
                    }
                    
                    peer.allowedIPs = allowedIPs;
                    peers[i] = peer;
                    ioctlPeer = new IoctlPeer(mem.share(offset));
                }
                iface.peers = peers;
            } 
            catch(Throwable e) {
            	LOG.error("Failed to get adapter.", e);
            	throw new IllegalStateException("Failed to get adapter " + name, e);
            }
            finally {
                mem.close();
            }
            
            return iface;
        }

        private short networkToHostOrder(short v) {
            return (short)(( (  v << 8 ) & 0xff ) | ( ( v >> 8 ) & 0xff ));
        }

        @Override
        public void close() throws IOException {
            INSTANCE.WireGuardCloseAdapter(handle);
        }

    }

    public static class Interface {
        public int listenPort;
        public Key privateKey;
        public Key publicKey;
        public Peer[] peers;
    }

    public class Peer {
        public Key publicKey;
        public Key presharedKey;
        public int PersistentKeepalive;
        public InetSocketAddress endpoint;
        public long txBytes;
        public long rxBytes;
        public Optional<Instant> lastHandshake = Optional.empty();
        public AllowedIP[] allowedIPs;
    }

    public class AllowedIP {
        public InetAddress address;
        public int cidr;
    }

    public final static class Key {
        private byte[] bytes;

        public byte[] bytes() {
            return bytes;
        }

        public void bytes(byte[] bytes) {
            if (bytes == null || bytes.length != 32)
                throw new IllegalArgumentException("Keys must be 32 bytes");
            this.bytes = bytes;
        }

        public Key(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public String toString() {
            return Base64.getEncoder().encodeToString(bytes);
        }
    }

//    [StructLayout(LayoutKind.Sequential, Pack = 8, Size = 80)]
//            private unsafe struct IoctlInterface
//            {
//                public IoctlInterfaceFlags Flags;
//                public UInt16 ListenPort;
//                public fixed byte PrivateKey[32];
//                public fixed byte PublicKey[32];
//                public UInt32 PeersCount;
//            };

    public static class IoctlInterfaceFlags {
        public final static int hasPublicKey = 1 << 0;
        public final static int hasPrivateKey = 1 << 1;
        public final static int hasListenPort = 1 << 2;
        public final static int replacePeers = 1 << 3;
    }
    
    @FieldOrder({"flags", "listenPort", "privateKey", "publicKey", "peersCount", "reserved"})
    public class IoctlInterface extends Structure {
        public int flags;
        public short listenPort;
        public byte[] privateKey = new byte[32];
        public byte[] publicKey = new byte[32];
        public int peersCount;
        public byte[] reserved = new byte[4];
        
        {
            setAlignType(8);
        }

        public IoctlInterface() {}

        public IoctlInterface(Pointer p) {
            super(p);
            read();
        }
    }
    
    public static class IoctlPeerFlags {
        public final static int hasPublicKey = 1 << 0;
        public final static int hasPresharedKey = 1 << 1;
        public final static int hasPersistentKeepalive = 1 << 2;
        public final static int hasEndpoint = 1 << 3;
        public final static int replaceAllowedIPs = 1 << 5;
        public final static int remove = 1 << 6;
        public final static int updateOnly = 1 << 7;
    }

    @FieldOrder({"bytes", "reserved"})
    public static class IN_ADDR  extends Structure {
        public byte[] bytes = new byte[4];
        public byte[] reserved = new byte[12];
        
    }

    @FieldOrder({"bytes"})
    public static class IN6_ADDR  extends Structure {
        public byte[] bytes = new byte[16];
        
    }

    @FieldOrder({"sin_family", "sin_port", "sin_addr"})
    public static class SOCKADDR_IN extends Structure {
        public short sin_family;
        public short sin_port;
        public IN_ADDR sin_addr;
        
    }


    @FieldOrder({"sin6_family", "sin6_port", "sin6_flowinfo", "sin6_addr", "sin6_scope_id"})
    public static class SOCKADDR_IN6 extends Structure {
        public short sin6_family;
        public short sin6_port;
        public int sin6_flowinfo;
        public IN6_ADDR sin6_addr;
        public int sin6_scope_id;
    }


    public static class SOCKADDR_INET extends Union {
        public SOCKADDR_IN ipv4;
        public SOCKADDR_IN6 ipv6;
        public short si_family;
    }
            
    
    @FieldOrder({"flags", "reserved", "publicKey", "presharedKey", "persistentKeepalive", "endpoint", "txBytes", "rxBytes", "lastHandshake", "allowedIPsCount"})
    public class IoctlPeer extends Structure {
        public int flags;
        public int reserved;
        public byte[] publicKey = new byte[32];
        public byte[] presharedKey = new byte[32];
        public short persistentKeepalive;
        public SOCKADDR_INET endpoint;
        public long txBytes;
        public long rxBytes;
        public long lastHandshake;
        public int allowedIPsCount;
        
        {
            setAlignType(8);
        }

        public IoctlPeer() { }
        
        public IoctlPeer(Pointer p) {
            super(p);
            read();
        }
    }

    @FieldOrder({"address", "address_family", "cidr", "reserved"}) 
    public static class IoctlAllowedIP extends Structure {
    	public static class IoctlAllowedIPUnion extends Union {
            public IN_ADDR ipv4;
            public IN6_ADDR ipv6;
        }
    	
    	public IoctlAllowedIPUnion address;
    	public short address_family;
    	public byte cidr;
    	public byte[] reserved = new byte[4]; 
        
        {
            setAlignType(8);
        }

        public IoctlAllowedIP() { }
        
        public IoctlAllowedIP(Pointer p) {
            super(p);
            setAlignType(8);
            read();
        }

		@Override
		public void read() {
			super.read();
			switch(address_family) {
			case AF_INET:
				address.setType(IN_ADDR.class);
				break;
			case AF_INET6:
				address.setType(IN6_ADDR.class);
				break;
			}
			address.read();
		}
    }
    
    static final Instant ZERO = Instant.parse("1601-01-01T00:00:00Z");
    
    static Instant toInstant(long fileTime) {
        var duration = Duration.of(fileTime / 10, ChronoUnit.MICROS).plus(fileTime % 10 * 100, ChronoUnit.NANOS);
        return ZERO.plus(duration);
    }

    public static int AF_INET = 2;               /* internetwork: UDP, TCP, etc. */
    public static int AF_INET6 = 23;              /* Internetwork Version 6 */
}
