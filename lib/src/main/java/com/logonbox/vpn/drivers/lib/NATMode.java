package com.logonbox.vpn.drivers.lib;

import java.io.UncheckedIOException;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents (2) NAT modes.
 * 
 * TODO: A lot of what this does is silly now. Re-factor.
 */
public abstract class NATMode {

	public final static class SNAT extends NATMode {
		private final Set<String> to;

        @Deprecated
        public SNAT(NetworkInterface... to) {
            this(false, Set.of(to).stream().map(NetworkInterface::getName).collect(Collectors.toSet()));
        }

        @Deprecated
        public SNAT(Set<NetworkInterface> to) {
            this(false, to.stream().map(NetworkInterface::getName).collect(Collectors.toSet()));
        }

        @Deprecated
        private SNAT(boolean dummy, Set<String> to) {
            this.to = to;
        }

        public static SNAT forNames(Set<String> out) {
            return new SNAT(false, out);
        }

        public static SNAT forNames(String... out) {
            return forNames(Set.of(out));
        }

        public Set<String> names() {
            return to;
        }

        @Deprecated
        public Set<NetworkInterface> to() {
            return to.stream().map(t -> {
                try {
                    return NetworkInterface.getByName(t);
                } catch (SocketException e) {
                    throw new UncheckedIOException(e);
                }
            }).collect(Collectors.toSet());
        }

        @Deprecated
        public SNAT addTo(NetworkInterface to) {
            var s = new LinkedHashSet<String>(this.to);
            s.add(to.getName());
            return new SNAT(false, s);
        }
        
        public SNAT addTo(String out) {
            var s = new LinkedHashSet<String>(this.to);
            s.add(out);
            return new SNAT(false, s);
        }

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((to == null) ? 0 : to.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			SNAT other = (SNAT) obj;
			if (to == null) {
				if (other.to != null)
					return false;
			} else if (!to.equals(other.to))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return "SNAT [to=" + to + "]";
		}

		public static Collection<String> toIpv4Addresses(NetworkInterface to) {
			List<String> ipv4addrs = to.getInterfaceAddresses().stream().filter(a -> a.getAddress() instanceof Inet4Address).map(ni -> ni.getAddress().getHostAddress()).toList();
			if(ipv4addrs.isEmpty())
				throw new IllegalStateException("NAT is currently on supported for IPv4 networks.");
			return ipv4addrs;
		}

	}

	public final static class MASQUERADE extends NATMode {
		private final Set<String> out;

		@Deprecated
		public MASQUERADE(NetworkInterface... out) {
			this(false, Set.of(out).stream().map(NetworkInterface::getName).collect(Collectors.toSet()));
		}

		public MASQUERADE(Set<NetworkInterface> out) {
            this(false, out.stream().map(NetworkInterface::getName).collect(Collectors.toSet()));
        }
		
		private MASQUERADE(boolean dummy, Set<String> out) {
		    this.out = out;
		}

        public static MASQUERADE forNames(String... out) {
            return forNames(Set.of(out));
        }

        public static MASQUERADE forNames(Set<String> out) {
            return new MASQUERADE(false, out);
        }

        public Set<String> names() {
            return out;
        }

        @Deprecated
		public Set<NetworkInterface> out() {
			return out.stream().map(t -> {
                try {
                    return NetworkInterface.getByName(t);
                } catch (SocketException e) {
                    throw new UncheckedIOException(e);
                }
            }).collect(Collectors.toSet());
		}

        @Deprecated
		public MASQUERADE addOut(NetworkInterface out) {
			var s = new LinkedHashSet<String>(this.out);
			s.add(out.getName());
			return new MASQUERADE(false, s);
		}
        
        public MASQUERADE addOut(String out) {
            var s = new LinkedHashSet<String>(this.out);
            s.add(out);
            return new MASQUERADE(false, s);
        }

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((out == null) ? 0 : out.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			MASQUERADE other = (MASQUERADE) obj;
			if (out == null) {
				if (other.out != null)
					return false;
			} else if (!out.equals(other.out))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return "MASQUERADE [in=" + out + "]";
		}

	}

    public abstract Set<String> names();

}
