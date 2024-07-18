package com.logonbox.vpn.drivers.lib;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.LinkedHashSet;
import java.util.Set;

public class NATMode {

	public final static class SNAT extends NATMode {
		private final String sourceRangeOrCidr;
		private final NetworkInterface to;

		public SNAT(String sourceRangeOrCidr, NetworkInterface to) {
			this.sourceRangeOrCidr = sourceRangeOrCidr;
			this.to = to;
		}

		public String sourceRangeOrCidr() {
			return sourceRangeOrCidr;
		}

		public NetworkInterface to() {
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

		public String toAddress(Class<? extends InetAddress> clazz) {
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
		private final String iface;
		private Set<String> in;

		public MASQUERADE(String ifaceOut, String... in) {
			this(ifaceOut, Set.of(in));
		}

		public MASQUERADE(String ifaceOut, Set<String> in) {
			this.iface = ifaceOut;
			this.in = in;
		}

		public String iface() {
			return iface;
		}

		public Set<String> in() {
			return in;
		}

		public MASQUERADE addIn(String in) {
			var s = new LinkedHashSet<String>(this.in);
			s.add(in);
			return new MASQUERADE(iface, s);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((iface == null) ? 0 : iface.hashCode());
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
			if (iface == null) {
				if (other.iface != null)
					return false;
			} else if (!iface.equals(other.iface))
				return false;
			if (in == null) {
				if (other.in != null)
					return false;
			} else if (!in.equals(other.in))
				return false;
			return true;
		}

		@Override
		public String toString() {
			return "MASQUERADE [iface=" + iface + ", in=" + in + "]";
		}
	}

}
