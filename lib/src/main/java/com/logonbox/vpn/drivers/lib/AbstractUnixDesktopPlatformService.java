package com.logonbox.vpn.drivers.lib;

import com.logonbox.vpn.drivers.lib.NativeComponents.Tool;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.lib.util.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public abstract class AbstractUnixDesktopPlatformService<I extends VpnAddress>
		extends AbstractDesktopPlatformService<I> {
	private final static Logger LOG = LoggerFactory.getLogger(AbstractUnixDesktopPlatformService.class);

	public AbstractUnixDesktopPlatformService(String interfacePrefix, SystemContext context) {
		super(interfacePrefix, context);
	}

	@Override
	public List<VpnAdapter> adapters() {
		try {
			var l = new ArrayList<VpnAdapter>();
			for (var line : context.commands().output(context.nativeComponents().tool(Tool.WG), "show", "interfaces")) {
				for (var ifaceName : line.split("\\s+")) {
					l.add(configureExistingSession(address(ifaceName)));
				}
			}
			return l;
		} catch (IOException ioe) {
			throw new UncheckedIOException(ioe);
		}
	}

	@Override
	public void reconfigure(VpnAdapter adapter, VpnAdapterConfiguration configuration) throws IOException {
		super.reconfigure(adapter, configuration);
		addRoutes(adapter);
	}

	@Override
	public void sync(VpnAdapter adapter, VpnAdapterConfiguration configuration) throws IOException {
		super.sync(adapter, configuration);
		addRoutes(adapter);
	}

	@Override
	public void append(VpnAdapter adapter, VpnAdapterConfiguration configuration) throws IOException {
		super.append(adapter, configuration);
		addRoutes(adapter);
	}

	@Override
	protected void onSetDefaultGateway(VpnPeer peer) throws IOException {
		var gw = getDefaultGateway();
		var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
		LOG.info("Routing traffic all through peer {}", addr);
		context.commands().privileged().logged().run("route", "add", addr, "gw", gw);
	}

	@Override
	protected void onResetDefaultGateway(VpnPeer peer) throws IOException {
		var gw = getDefaultGateway();
		var addr = peer.endpointAddress().orElseThrow(() -> new IllegalArgumentException("Peer has no address."));
		LOG.info("Removing routing of all traffic  through peer {}", addr);
		context.commands().privileged().logged().run("route", "del", addr, "gw", gw);
	}

	@Override
	public Instant getLatestHandshake(VpnAddress iface, String publicKey) throws IOException {
		for (String line : context.commands().privileged().output(context.nativeComponents().tool(Tool.WG), "show",
				iface.nativeName(), "latest-handshakes")) {
			String[] args = line.trim().split("\\s+");
			if (args.length == 2) {
				if (args[0].equals(publicKey)) {
					return Instant.ofEpochSecond(Long.parseLong(args[1]));
				}
			}
		}
		return Instant.ofEpochSecond(0);
	}

	@Override
	protected Optional<String> getPublicKey(String interfaceName) throws IOException {
		try {
			var iterator = context.commands().privileged()
					.silentOutput(context.nativeComponents().tool(Tool.WG), "show", interfaceName, "public-key")
					.iterator();
			var pk = iterator.hasNext() ? iterator.next().trim() : "";
			if (pk.equals("(none)") || pk.equals(""))
				return Optional.empty();
			else
				return Optional.of(pk);

		} catch (UncheckedIOException uioe) {
			var ioe = uioe.getCause();
			if (ioe.getMessage() != null && (ioe.getMessage().indexOf("The system cannot find the file specified") != -1
					|| ioe.getMessage().indexOf("Unable to access interface: No such file or directory") != -1))
				return Optional.empty();
			else
				throw ioe;
		}
	}


	@SuppressWarnings("serial")
	@Override
	public VpnInterfaceInformation information(VpnAdapter adapter) {
		try {
			var iface = adapter.address();
			var peers = new ArrayList<VpnPeerInformation>();
			var lastHandshake = new AtomicLong(0l);
			var rx = new AtomicLong(0l);
			var tx = new AtomicLong(0l);
			var port = new AtomicInteger();
			var fwmark = new AtomicInteger();
			var publicKey = new StringBuffer();
			var privateKey = new StringBuffer();

			for (var line : context.commands().privileged().output(context.nativeComponents().tool(Tool.WG), "show",
					iface.nativeName(), "dump")) {
				var st = new StringTokenizer(line);
				if (st.countTokens() == 4) {
					privateKey.append(st.nextToken());
					publicKey.append(st.nextToken());
					port.set(Integer.parseInt(st.nextToken()));
					fwmark.set(Util.parseFwMark(st.nextToken()));
				} else {
					var peerPublicKey = st.nextToken();
					var presharedKeyVal = st.nextToken();
					Optional<String> presharedKey;
					if (presharedKeyVal.equals("(none)")) {
						presharedKey = Optional.empty();
					} else {
						presharedKey = Optional.of(presharedKeyVal);
					}
					var remoteAddress = Optional.of(OsUtil.parseInetSocketAddress(st.nextToken()));
					var allowedIps = Arrays.asList(st.nextToken().split(","));
					var thisLastHandshake = Instant.ofEpochSecond(Long.parseLong(st.nextToken()));
					var thisRx = Long.parseLong(st.nextToken());
					var thisTx = Long.parseLong(st.nextToken());

					lastHandshake.set(Math.max(lastHandshake.get(), thisLastHandshake.toEpochMilli()));
					rx.addAndGet(thisRx);
					tx.addAndGet(thisTx);

					peers.add(new VpnPeerInformation() {

						@Override
						public long tx() {
							return thisTx;
						}

						@Override
						public long rx() {
							return thisRx;
						}

						@Override
						public Instant lastHandshake() {
							return thisLastHandshake;
						}

						@Override
						public Optional<String> error() {
							return Optional.empty();
						}

						@Override
						public Optional<InetSocketAddress> remoteAddress() {
							return remoteAddress;
						}

						@Override
						public List<String> allowedIps() {
							return allowedIps;
						}

						@Override
						public String publicKey() {
							return peerPublicKey;
						}

						@Override
						public Optional<String> presharedKey() {
							return presharedKey;
						}

					});
				}
			}
			return new VpnInterfaceInformation() {

				@Override
				public String interfaceName() {
					return iface.name();
				}

				@Override
				public long tx() {
					return tx.get();
				}

				@Override
				public long rx() {
					return rx.get();
				}

				@Override
				public List<VpnPeerInformation> peers() {
					return peers;
				}

				@Override
				public Instant lastHandshake() {
					return Instant.ofEpochMilli(lastHandshake.get());
				}

				@Override
				public Optional<String> error() {
					return Optional.empty();
				}

				@Override
				public Optional<Integer> listenPort() {
					return port.get() == 0 ? Optional.empty() : Optional.of(port.get());
				}

				@Override
				public Optional<Integer> fwmark() {
					return fwmark.get() == 0 ? Optional.empty() : Optional.of(fwmark.get());
				}

				@Override
				public String publicKey() {
					return publicKey.toString();
				}

				@Override
				public String privateKey() {
					return privateKey.toString();
				}

			};
		} catch (IOException ioe) {
			throw new UncheckedIOException(ioe);
		}
	}

	@Override
	public final VpnAdapterConfiguration configuration(VpnAdapter adapter) {
		try {
			try {
				return new VpnAdapterConfiguration.Builder()
						.fromFileContent(String.join(System.lineSeparator(), context.commands().privileged().output(
								context.nativeComponents().tool(Tool.WG), "showconf", adapter.address().nativeName())))
						.build();
			} catch (ParseException e) {
				throw new IOException("Failed to parse configuration.", e);
			}
		} catch (IOException ioe) {
			throw new UncheckedIOException(ioe);
		}
	}

	protected final void addRoutes(VpnAdapter session) throws IOException {

		/* Set routes from the known allowed-ips supplies by Wireguard. */
		session.allows().clear();

		for (var s : context().commands().privileged().output(context().nativeComponents().tool(Tool.WG), "show",
				session.address().nativeName(), "allowed-ips")) {
			var t = new StringTokenizer(s);
			if (t.hasMoreTokens()) {
				t.nextToken();
				while (t.hasMoreTokens())
					session.allows().add(t.nextToken());
			}
		}

		/*
		 * Sort by network subnet size (biggest first)
		 */
		Collections.sort(session.allows(), (a, b) -> {
			var sa = a.split("/");
			var sb = b.split("/");
			Integer ia = Integer.parseInt(sa[1]);
			Integer ib = Integer.parseInt(sb[1]);
			var r = ia.compareTo(ib);
			if (r == 0) {
				return a.compareTo(b);
			} else
				return r * -1;
		});
		/* Actually add routes */
		((AbstractUnixAddress<?>) session.address()).setRoutes(session.allows());
	}
}
