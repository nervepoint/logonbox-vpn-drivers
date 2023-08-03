package com.logonbox.vpn.quick;

import com.logonbox.vpn.drivers.lib.ActiveSession;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.Vpn;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnInterface;
import com.logonbox.vpn.drivers.lib.util.Keys;
import com.logonbox.vpn.drivers.lib.util.Util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

@Command(name = "lbv", description = "Set and retrieve configuration of wireguard interfaces, a Java clone of the 'wg' command.", mixinStandardHelpOptions = true, subcommands = { Lbv.Show.class, Lbv.ShowConf.class, Lbv.GenKey.class, Lbv.PubKey.class })
public class Lbv extends AbstractCommand implements SystemContext {

    final static PrintStream out = System.out;

    public static void main(String[] args) throws Exception {
        System.exit(new CommandLine(new Lbv()).execute(args));
    }

    private PlatformService<?> platformService;
    private SystemConfiguration configuration;
    private ScheduledExecutorService queue;

    @Override
    protected Integer onCall() throws Exception {
        platform();
        return 0;
    }

    PlatformService<?> platform() {
        if(platformService == null) {
            queue = Executors.newSingleThreadScheduledExecutor();
            configuration = SystemConfiguration.defaultConfiguration();
            platformService = PlatformService.create();
            platformService.init(this);
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
    public VpnConfiguration configurationForPublicKey(String publicKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addScriptEnvironmentVariables(ActiveSession<?> connection, Map<String, String> env) {
    }

    @Command(name = "show", description = "Shows the current configuration and device information", subcommands = { Show.Interfaces.class, Show.All.class })
    public final static class Show implements Callable<Integer> {
        
        @ParentCommand
        private Lbv parent;
        
        @Parameters(arity = "0..1")
        private Optional<String> iface;

        @Override
        public Integer call() throws Exception {
            if(iface.isPresent())
                show(parent.platform().get(iface.get()));
            return 0;
        }
        
        void show(VpnInterface<?> vpn) throws IOException {
            var info = vpn.information();
            var config = vpn.configuration();
            
            out.format("interface: %s%n", info.interfaceName());
            out.format("  public key: %s%n", config.publicKey());
            out.format("  private key: %s%n", "(hidden)");
            info.listenPort().ifPresent(p -> out.format("  listening port: %s%n", p));
            out.println();
            
            for (var peer : config.peers()) {
                
                out.format("peer: %s%n", peer.publicKey());
                
                peer.endpointAddress().ifPresent(ep -> {
                    out.format("  endpoint: %s%n", ep, peer.endpointPort().orElse(Vpn.DEFAULT_PORT));
                });
                
                out.format("  allowed ips: %s%n", String.join(", ", peer.allowedIps()));
                
                var peerInfo = info.peer(peer.publicKey());
                peerInfo.ifPresent(i -> {
                    var seconds = Duration.between(i.lastHandshake(), Instant.now()).toSeconds(); 
                    out.format("  latest handshake: %d %s ago%n", seconds, seconds < 2 ? "second" : "seconds");  
                    out.format("  transfer: %s received, %s sent%n", Util.toHumanSize(i.rx()), Util.toHumanSize(i.tx()));
                });
                
                peer.persistentKeepalive().ifPresent(p -> out.format("  persistent keepalive: every %d %s%n", p, p < 2 ? "second" : "seconds"));
            }
        }
        
        @Command(name = "interfaces", description = "Shows the current configuration and device information")
        public final static class Interfaces implements Callable<Integer> {
            
            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.setupLogging();
                var ips = parent.parent.platform().ips(true);
                if(!ips.isEmpty()) {
                    out.println(String.join(" ", ips.stream().map(VpnInterface::getName).toList()));
                }
                return 0;
            }
            
        }
        
        @Command(name = "all", description = "Shows all wireguard interfaces")
        public final static class All implements Callable<Integer> {
            
            @ParentCommand
            private Show parent;

            @Override
            public Integer call() throws Exception {
                parent.parent.setupLogging();
                for(var ip : parent.parent.platform().ips(true)) {
                    parent.show(ip);
                }
                return 0;
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
            parent.setupLogging();
            parent.platform().get(iface).configuration().write(out); 
            return 0;
        }
    }
    
    @Command(name = "genkey", description = "Generates a new private key and writes it to stdout")
    public final static class GenKey implements Callable<Integer> {
        
        @ParentCommand
        private Lbv parent;
        
        @Override
        public Integer call() throws Exception {
            parent.setupLogging();
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
            parent.setupLogging();
            try(var in = new BufferedReader(new InputStreamReader(System.in))) {
                out.println(Keys.pubkey(in.readLine().trim()).getBase64PublicKey());   
            } 
            return 0;
        }
    }

}
