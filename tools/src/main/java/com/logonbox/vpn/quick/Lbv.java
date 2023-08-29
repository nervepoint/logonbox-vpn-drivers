package com.logonbox.vpn.quick;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

import com.logonbox.vpn.drivers.lib.ElevatableSystemCommands;
import com.logonbox.vpn.drivers.lib.NativeComponents;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.Vpn;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration;
import com.logonbox.vpn.drivers.lib.util.Keys;
import com.logonbox.vpn.drivers.lib.util.Util;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

@Command(name = "lbv", description = "Set and retrieve configuration of wireguard interfaces, a Java clone of the 'wg' command.", mixinStandardHelpOptions = true, subcommands = {
        Lbv.Show.class, Lbv.ShowConf.class, Lbv.SetConf.class, Lbv.SyncConf.class, Lbv.AddConf.class, Lbv.GenKey.class, Lbv.PubKey.class })
public class Lbv extends AbstractCommand implements SystemContext {

    final static PrintStream out = System.out;

    public static void main(String[] args) throws Exception {
        Lbv cmd = new Lbv();
        System.exit(new CommandLine(cmd).setExecutionExceptionHandler(new ExceptionHandler(cmd)).execute(args));
    }

    private PlatformService<?> platformService;
    private SystemConfiguration configuration;
    private ScheduledExecutorService queue;
    private SystemCommands commands;
    private NativeComponents nativeComponents;

    @Override
    protected Integer onCall() throws Exception {
        platform();
        return 0;
    }

    @Override
    public SystemCommands commands() {
        if (commands == null)
            commands = new ElevatableSystemCommands();
        return commands;
    }

    @Override
    public NativeComponents nativeComponents() {
        if (nativeComponents == null)
            nativeComponents = new NativeComponents();
        return nativeComponents;
    }

    PlatformService<?> platform() {
        if (platformService == null) {
            queue = Executors.newSingleThreadScheduledExecutor();
            configuration = SystemConfiguration.defaultConfiguration();
            platformService = PlatformService.create(this);
        }
        return platformService;
    }

    @Override
    public ScheduledExecutorService queue() {
        return queue;
    }

    @Override
    public SystemConfiguration configuration() {
        return configuration;
    }

    @Override
    public void addScriptEnvironmentVariables(VpnAdapter connection, Map<String, String> env) {
    }

    @Command(name = "show", description = "Shows the current configuration and device information", subcommands = {
            Show.Interfaces.class, Show.All.class, Show.PublicKey.class, Show.ListenPort.class, Show.FwMark.class,
            Show.Peers.class, Show.PresharedKeys.class, Show.Endpoints.class })
    public final static class Show implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Parameters(arity = "0..1")
        private Optional<String> iface;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            if (iface.isPresent())
                show(parent.platform().adapter(iface.get()));
            return 0;
        }

        void show(VpnAdapter vpn) throws IOException {
            var info = vpn.information();
            var config = vpn.configuration();

            out.format("interface: %s%n", info.interfaceName());
            out.format("  public key: %s%n", config.publicKey());
            out.format("  private key: %s%n", "(hidden)");
            info.listenPort().ifPresent(p -> out.format("  listening port: %s%n", p));

            var peers = config.peers();
            if (peers.size() > 0) {
                out.println();
                for (var peer : peers) {

                    out.format("peer: %s%n", peer.publicKey());

                    peer.endpointAddress().ifPresent(ep -> {
                        out.format("  endpoint: %s%n", ep, peer.endpointPort().orElse(Vpn.DEFAULT_PORT));
                    });

                    out.format("  allowed ips: %s%n", String.join(", ", peer.allowedIps()));

                    var peerInfo = info.peer(peer.publicKey());
                    peerInfo.ifPresent(i -> {
                        var seconds = Duration.between(i.lastHandshake(), Instant.now()).toSeconds();
                        out.format("  latest handshake: %d %s ago%n", seconds, seconds < 2 ? "second" : "seconds");
                        out.format("  transfer: %s received, %s sent%n", Util.toHumanSize(i.rx()),
                                Util.toHumanSize(i.tx()));
                    });

                    peer.persistentKeepalive().ifPresent(
                            p -> out.format("  persistent keepalive: every %d %s%n", p, p < 2 ? "second" : "seconds"));
                }
            }
        }

        @Command(name = "public-key", description = "Shows the public key")
        public final static class PublicKey implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ip = parent.parent.platform().adapter(parent.iface.get());
                out.format("%s%n", ip.information().publicKey());
                return 0;
            }

        }

        @Command(name = "private-key", description = "Shows the private key")
        public final static class PrivateKey implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ip = parent.parent.platform().adapter(parent.iface.get());
                out.format("%s%n", ip.information().privateKey());
                return 0;
            }

        }

        @Command(name = "listen-port", description = "Shows the listening port")
        public final static class ListenPort implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ip = parent.parent.platform().adapter(parent.iface.get());
                out.format("%s%n", ip.information().listenPort().orElse(0));
                return 0;
            }

        }

        @Command(name = "fwmark", description = "Shows the fwmark")
        public final static class FwMark implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ip = parent.parent.platform().adapter(parent.iface.get());
                out.format("%s%n", ip.information().fwmark().map(i -> i.toString()).orElse("off"));
                return 0;
            }

        }

        @Command(name = "peers", description = "Shows the peers")
        public final static class Peers implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ip = parent.parent.platform().adapter(parent.iface.get());
                for (var peer : ip.information().peers()) {
                    out.println(peer.publicKey());
                }
                return 0;
            }

        }

        @Command(name = "preshared-keys", description = "Shows the preshared keys")
        public final static class PresharedKeys implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ip = parent.parent.platform().adapter(parent.iface.get());
                for (var peer : ip.information().peers()) {
                    out.format("%s\t%s%n", peer.publicKey(), peer.presharedKey().orElse("(none)"));
                }
                return 0;
            }

        }

        @Command(name = "interfaces", description = "Shows the current configuration and device information")
        public final static class Interfaces implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var ips = parent.parent.platform().adapters();
                if (!ips.isEmpty()) {
                    out.println(String.join(" ", ips.stream().map(a -> a.address().name()).collect(Collectors.toList())));
                }
                return 0;
            }

        }

        @Command(name = "endpoints", description = "Shows the endpoints")
        public final static class Endpoints implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                var ip = parent.parent.platform().adapter(parent.iface.get());
                for (var peer : ip.information().peers()) {
                    out.format("%s\t%s%n", peer.publicKey(),
                            peer.remoteAddress().map(s -> s.toString()).orElse("(none)"));
                }
                return 0;
            }
        }

        @Command(name = "all", description = "Shows all wireguard interfaces", subcommands = { All.PublicKey.class,
                All.PrivateKey.class, All.ListenPort.class, All.FwMark.class, All.Peers.class, All.PresharedKeys.class,
                All.Endpoints.class, All.DNS.class })
        public final static class All implements Callable<Integer> {

            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.initCommand();
                var idx = 0;
                for (var ip : parent.parent.platform().adapters()) {
                    if (idx++ > 0)
                        out.println();
                    parent.show(ip);
                }
                return 0;
            }

            @Command(name = "public-key", description = "Shows the public key")
            public final static class PublicKey implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        out.format("%s\t%s%n", ip.address().name(), ip.information().publicKey());
                    }
                    return 0;
                }

            }

            @Command(name = "private-key", description = "Shows the private key")
            public final static class PrivateKey implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        out.format("%s\t%s%n", ip.address().name(), ip.information().privateKey());
                    }
                    return 0;
                }

            }

            @Command(name = "listen-port", description = "Shows the listening ports")
            public final static class ListenPort implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        out.format("%s\t%s%n", ip.address().name(), ip.information().listenPort().orElse(0));
                    }
                    return 0;
                }

            }

            @Command(name = "fwmark", description = "Shows the fwmark")
            public final static class FwMark implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        out.format("%s\t%s%n", ip.address().name(),
                                ip.information().fwmark().map(i -> i.toString()).orElse("off"));
                    }
                    return 0;
                }

            }

            @Command(name = "peers", description = "Shows the peers")
            public final static class Peers implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        for (var peer : ip.information().peers()) {
                            out.format("%s\t%s%n", ip.address().name(), peer.publicKey());
                        }
                    }
                    return 0;
                }

            }

            @Command(name = "preshared-keys", description = "Shows the preshared keys")
            public final static class PresharedKeys implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        for (var peer : ip.information().peers()) {
                            out.format("%s\t%s\t%s%n", ip.address().name(), peer.publicKey(),
                                    peer.presharedKey().orElse("(none)"));
                        }
                    }
                    return 0;
                }

            }

            @Command(name = "endpoints", description = "Shows the endpoints")
            public final static class Endpoints implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        out.format("%s\t",
                                ip.address().name()); /*
                                                       * TODO: really? this is how "wg show all endpoints" does it, but
                                                       * it looks like a bug. Others always start with interface name
                                                       */
                        for (var peer : ip.information().peers()) {
                            out.format("%s\t%s%n", peer.publicKey(),
                                    peer.remoteAddress().map(s -> s.toString()).orElse("(none)"));
                        }
                    }
                    return 0;
                }

            }

            @Command(name = "dns", description = "Shows the DNS configuration (when supported)")
            public final static class DNS implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().dns()
                            .orElseThrow(() -> new IllegalStateException("No DNS provider available.")).entries()) {
                        var all = ip.all();
                        out.format("%s\t%s%n", ip.iface(), all.length == 0 ? "(none)" : String.join(",", all));
                    }
                    return 0;
                }

            }

            @Command(name = "allowed-ips", description = "Shows the allowed IPs")
            public final static class AllowedIps implements Callable<Integer> {

                @ParentCommand
                private All parent;

                @Override
                public Integer call() throws Exception {
                    parent.parent.parent.initCommand();
                    for (var ip : parent.parent.parent.platform().adapters()) {
                        for (var peer : ip.information().peers()) {
                            out.format("%s\t%s%n", peer.publicKey(), String.join(", ", peer.allowedIps()));
                        }
                    }
                    return 0;
                }

            }

        }
    }

    @Command(name = "showconf", description = "Shows the current configuration of a given WireGuard interface, for use with `setconf'")
    public final static class ShowConf implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Parameters(arity = "1")
        private String iface;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            parent.platform().adapter(iface).configuration().write(out);
            return 0;
        }
    }

    @Command(name = "setconf", description = "Set the current configuration of a given WireGuard interface to the contents of the given configuration file.")
    public final static class SetConf implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Parameters(index = "0", arity = "1")
        private String iface;

        @Parameters(index = "1", arity = "1")
        private Path configuration;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            parent.platform().adapter(iface).reconfigure(new VpnAdapterConfiguration.Builder().fromFile(configuration).build());
            return 0;
        }
    }

    @Command(name = "syncconf", description = "Like setconf, but reads back the existing configuration first and only makes changes that are explicitly different between the configuration file and the interface")
    public final static class SyncConf implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Parameters(index = "0", arity = "1")
        private String iface;

        @Parameters(index = "1", arity = "1")
        private Path configuration;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            parent.platform().adapter(iface).sync(new VpnAdapterConfiguration.Builder().fromFile(configuration).build());
            return 0;
        }
    }

    @Command(name = "addconf", description = "Like setconf, but reads back the existing configuration first and only makes changes that are explicitly different between the configuration file and the interface.")
    public final static class AddConf implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Parameters(index = "0", arity = "1")
        private String iface;

        @Parameters(index = "1", arity = "1")
        private Path configuration;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            parent.platform().adapter(iface).append(new VpnAdapterConfiguration.Builder().fromFile(configuration).build());
            return 0;
        }
    }

    @Command(name = "genkey", description = "Generates a new private key and writes it to stdout")
    public final static class GenKey implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            out.println(Keys.genkey().getBase64PrivateKey());
            return 0;
        }
    }

    @Command(name = "pubkey", description = "Reads a private key from stdin and writes a public key to stdout")
    public final static class PubKey implements Callable<Integer> {

        @ParentCommand
        private Lbv parent;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            try (var in = new BufferedReader(new InputStreamReader(System.in))) {
                out.println(Keys.pubkey(in.readLine().trim()).getBase64PublicKey());
            }
            return 0;
        }
    }

}
