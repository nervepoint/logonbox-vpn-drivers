package com.logonbox.vpn.drivers.lib;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class NATMode {

	public final static class SNAT extends NATMode {
		private final String sourceRangeOrCidr;
		private final Set<NetworkInterface> to;

		public SNAT(String sourceRangeOrCidr) {
			this(sourceRangeOrCidr, Collections.emptySet());
		}
		
		public SNAT(String sourceRangeOrCidr, Set<NetworkInterface> to) {
			this.sourceRangeOrCidr = sourceRangeOrCidr;
			this.to = to;
		}
		
		public SNAT addTo(NetworkInterface to) {
			var l = new LinkedHashSet<>(this.to);
			l.add(to);
			return new SNAT(sourceRangeOrCidr, l);
		}

		public String sourceRangeOrCidr() {
			return sourceRangeOrCidr;
		}

		public Set<NetworkInterface> to() {
			return to;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((sourceRangeOrCidr == null) ? 0 : sourceRangeOrCidr.hashCode());
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
			if (sourceRangeOrCidr == null) {
				if (other.sourceRangeOrCidr != null)
					return false;
			} else if (!sourceRangeOrCidr.equals(other.sourceRangeOrCidr))
				return false;
			if (to == null) {
				if (other.to != null)
					return false;
			} else if (!to.equals(other.to))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return "SNAT [sourceRangeOrCidr=" + sourceRangeOrCidr + ", to=" + to + "]";
		}

		public static String toAddress(NetworkInterface to, Class<? extends InetAddress> clazz) {
			for(var en = to.getInetAddresses(); en.hasMoreElements(); ) {
				var a = en.nextElement();
				if(a.getClass().equals(clazz)) {
					return a.getHostAddress();
				}
			}
			throw new IllegalArgumentException("Address is not " + clazz.getName());
		}

	}

	public final static class MASQUERADE extends NATMode {
		private Set<NetworkInterface> in;

		public MASQUERADE(NetworkInterface... in) {
			this(Set.of(in));
		}

		public MASQUERADE(Set<NetworkInterface> in) {
			this.in = in;
		}

		public Set<NetworkInterface> in() {
			return in;
		}

		public MASQUERADE addIn(NetworkInterface in) {
			var s = new LinkedHashSet<NetworkInterface>(this.in);
			s.add(in);
			return new MASQUERADE(s);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((in == null) ? 0 : in.hashCode());
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
			if (in == null) {
				if (other.in != null)
					return false;
			} else if (!in.equals(other.in))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return "MASQUERADE [in=" + in + "]";
		}

	}

}
