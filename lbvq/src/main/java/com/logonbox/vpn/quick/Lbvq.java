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
package com.logonbox.vpn.quick;

import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.Vpn;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnPeer;
import com.logonbox.vpn.drivers.lib.util.Util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.LogManager;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "lbqv", description = "Start a wireguard tunnel"/* , mixinStandardHelpOptions = true */)
public class Lbvq extends AbstractCommand {

    public static class Peer {

        @Option(names = { "-p",
                "--peer" }, paramLabel = "KEY", description = "Defines a peer that may either be routed to or by this node giving it's public key")
        String peer;

        @Option(names = { "-e",
                "--endpoint" }, paramLabel = "ADDRESS", description = "The address of this peer to connect to. May contain optional port number (defaults to 51820). May be specified multuiple times, each must occur after that --public-key (-p) option that defines the peers public key.")
        Optional<String> endpoint;

        @Option(names = { "-a",
                "--allowed-ip" }, arity = "0..", paramLabel = "IP", description = "Address or range of addresses for which this peer will route traffic. May be specified multuiple times, each must occur after that --public-key (-p) option that defines the peers public key.")
        List<String> allowedIps;

        @Option(names = { "-K",
                "--keep-alive" }, paramLabel = "SECONDS", description = "If the connection is going from a NAT-ed peer to a public peer, the node behind the NAT must regularly send an outgoing ping in order to keep the bidirectional connection alive in the NAT router's connection table. May be specified multuiple times, each must occur after that --public-key (-p) option that defines the peers public key.")
        Optional<Integer> keepAlive;
    }

    private final class LbvqConfiguration implements SystemConfiguration {
        @Override
        public Optional<Duration> connectTimeout() {
            if (connectTimeout.isPresent()) {
                var to = connectTimeout.get();
                if (to == 0)
                    return Optional.empty();
                else
                    return Optional.of(Duration.ofSeconds(to));
            } else {
                return Optional.of(SystemConfiguration.CONNECT_TIMEOUT);
            }
        }

        @Override
        public Optional<Integer> defaultMTU() {
            return mtu;
        }

        @Override
        public DNSIntegrationMethod dnsIntegrationMethod() {
            return dns.orElse(DNSIntegrationMethod.AUTO);
        }

        @Override
        public Duration handshakeTimeout() {
            return handshakeTimeout.map(Duration::ofSeconds).orElse(SystemConfiguration.HANDSHAKE_TIMEOUT);
        }

        @Override
        public boolean ignoreLocalRoutes() {
            return !localRoutes;
        }

        @Override
        public Duration serviceWait() {
            return serviceWait.map(Duration::ofSeconds).orElse(SystemConfiguration.SERVICE_WAIT_TIMEOUT);
        }
    }

    static {
        try (var is = Lbvq.class.getResourceAsStream("/logging.properties")) {
            LogManager.getLogManager().readConfiguration(is);
        } catch (IOException e) {
        }
    }

    public static void main(String[] args) throws Exception {
        System.exit(new CommandLine(new Lbvq()).execute(args));
    }

    @Option(names = { "-U", "--upnp" }, description = "When a UPnP router is available, map the local UDP listening port to an external WAN port, allowing this node to be used as a server. This is not necessary if this node does not accept incom,ing connections from other nodes.")
    private boolean upnp;

    @Option(names = { "-X", "--verbose-exception" }, description = "Show full stack trace on error.")
    private boolean verboseException;

    @Option(names = { "-l",
            "--listen-port" }, paramLabel = "PORT", description = "Act as a server and listen on this UDP port. The port must be publically accessible.")
    private Optional<Integer> listenPort;

    @Option(names = { "-d",
            "--dns" }, paramLabel = "METHOD", description = "The method of DNS integration to use. There should be no need to specify this option, but if you do it must be one of the methods supported by this operating system.")
    private Optional<DNSIntegrationMethod> dns;

    @Option(names = { "-A",
            "--address" }, paramLabel = "IPRANGE", description = "The address range (CIDR) that this node will route. May be specified multiple times. The address to assign to the virtual interface is the first occurence.")
    private List<String> address = new ArrayList<>();

    @Option(names = { "-m", "--mtu" }, paramLabel = "BYTES", description = "The default MTU. ")
    private Optional<Integer> mtu;

    @Option(names = { "-r",
            "--tunnel-local-routes" }, description = "When this option is present, any routes (allowed ips) that are local may be routed via the VPN. Ordinarily you wouln't want to do this.")
    private boolean localRoutes;

    @Option(names = { "-w",
            "--service-wait" }, paramLabel = "SECONDS", description = "Only applicable on operating systems that use a system service to manage the virtual network interface (e.g. Windows), this option defines how long (in seconds) to wait for a response after installation before the service is considered invalid and an error is thrown.")
    private Optional<Integer> serviceWait;

    @Option(names = { "-h",
            "--handshake-timeout" }, paramLabel = "SECONDS", description = "How much time must elapse before the connection is considered dead.")
    private Optional<Integer> handshakeTimeout;

    @Option(names = { "-k",
            "--private-key" }, paramLabel = "KEY", description = "The private key to use for this peer. If not specified, a temporary key will be generated (and the public key displayed).")
    private Optional<String> privateKey;

    @Option(names = { "-t",
            "--timeout" }, paramLabel = "SECONDS", description = "Connection timeout. If no handshake has been received in this time then the connection is considered invalid. An error with thrown and the connection taken down. Only applies if there is a single peer with a single endpoint.")
    private Optional<Integer> connectTimeout;

    @Parameters(arity = "0..1", paramLabel = "FILE", description = "Path to a Wireguard .conf file that describes everything needed to connect. If you have such a file, you probably do not need to supply any other arguments for a basic connection.")
    private Optional<Path> file;

    @ArgGroup(multiplicity = "0..", exclusive = false, order = 0)
    private List<Peer> peers;
    
    private Lbvq() {
    }

    @Override
    protected Integer onCall() throws Exception {

        var cfgBldr = new VpnConfiguration.Builder();

        if (file.isPresent()) {
            cfgBldr.fromFile(file.get());
        }

        if (privateKey.isPresent())
            cfgBldr.withPrivateKey(privateKey);

        if (listenPort.isPresent())
            cfgBldr.withListenPort(listenPort);

        if (!address.isEmpty())
            cfgBldr.withAddresses(address);

        if (peers != null) {
            peers.forEach(p -> {
                cfgBldr.addPeers(new VpnPeer.Builder().withPublicKey(p.peer).withPersistentKeepalive(p.keepAlive)
                        .withAllowedIps(p.allowedIps).withEndpoint(p.endpoint).build());
            });
        }

        var cfg = cfgBldr.build();

        var bldr = new Vpn.Builder();
        bldr.withSystemConfiguration(new LbvqConfiguration());
        bldr.withVpnConfiguration(cfg);

        try (var vpn = bldr.build()) {
            var info = vpn.information();
            var config = vpn.configuration();
            
            System.out.format("interface: %s%n", info.interfaceName());
            System.out.format("  public key: %s%n", config.publicKey());
            System.out.format("  private key: %s%n", "(hidden)");
            info.listenPort().ifPresent(p -> System.out.format("  listening port: %s%n", p));
            System.out.println();
            
            for (var peer : config.peers()) {
                
                System.out.format("peer: %s%n", peer.publicKey());
                
                peer.endpointAddress().ifPresent(ep -> {
                    System.out.format("  endpoint: %s%n", ep, peer.endpointPort().orElse(Vpn.DEFAULT_PORT));
                });
                
                System.out.format("  allowed ips: %s%n", String.join(", ", peer.allowedIps()));
                
                var peerInfo = info.peer(peer.publicKey());
                peerInfo.ifPresent(i -> {
                    var seconds = Duration.between(i.lastHandshake(), Instant.now()).toSeconds(); 
                    System.out.format("  latest handshake: %d %s ago%n", seconds, seconds < 2 ? "second" : "seconds");  
                    System.out.format("  transfer: %s received, %s sent%n", Util.toHumanSize(i.rx()), Util.toHumanSize(i.tx()));
                });
                
                peer.persistentKeepalive().ifPresent(p -> System.out.format("  persistent keepalive: every %d %s%n", p, p < 2 ? "second" : "seconds"));
            }
            
            System.out.println();
            System.out.println("Press RETURN to disconnect.");
            
            new BufferedReader(new InputStreamReader(System.in)).readLine();
        }
        return 0;
    }

}
