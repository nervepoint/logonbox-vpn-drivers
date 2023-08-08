package com.logonbox.vpn.quick;

import com.logonbox.vpn.drivers.lib.DNSIntegrationMethod;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.Vpn;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.sshtools.liftlib.OS;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

@Command(name = "lbv-quick", description = "Set up a WireGuard interface simply.", mixinStandardHelpOptions = true, subcommands = {
        LbvQuick.Up.class, LbvQuick.Down.class, LbvQuick.Save.class, LbvQuick.Strip.class })
public class LbvQuick extends AbstractCommand implements SystemContext {

    private final class LbvConfiguration implements SystemConfiguration {
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

    final static PrintStream out = System.out;

    public static void main(String[] args) throws Exception {
        var cmd = new LbvQuick();
        System.exit(new CommandLine(cmd).setExecutionExceptionHandler(new ExceptionHandler(cmd)).execute(args));
    }

    @Option(names = { "-s",
            "--configuration-search-path" }, paramLabel = "PATHS", description = "Alternative location(s) to search configuration files named <interface>.conf.")
    private Optional<String> configurationSearchPath;

    @Option(names = { "-d",
            "--dns" }, paramLabel = "METHOD", description = "The method of DNS integration to use. There should be no need to specify this option, but if you do it must be one of the methods supported by this operating system.")
    private Optional<DNSIntegrationMethod> dns;

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

    @Option(names = { "-t",
            "--timeout" }, paramLabel = "SECONDS", description = "Connection timeout. If no handshake has been received in this time then the connection is considered invalid. An error with thrown and the connection taken down. Only applies if there is a single peer with a single endpoint.")
    private Optional<Integer> connectTimeout;

    private SystemConfiguration configuration;
    private ScheduledExecutorService queue;

    @Override
    protected Integer onCall() throws Exception {
        return 0;
    }

    List<Path> configSearchPath() {
        if (configurationSearchPath.isPresent()) {
            return parseStringPaths(configurationSearchPath.get());
        } else {
            var pathsString = System.getProperty("logonbox.vpn.configPath");
            if (pathsString != null) {
                return parseStringPaths(pathsString);
            }
            pathsString = System.getenv("LBVPN_CONFIG_PATH");
            if (pathsString != null) {
                return parseStringPaths(pathsString);
            }
            if (OS.isLinux()) {
                return Arrays.asList(Paths.get("/etc/logonbox-vpn"));
            } else if (OS.isWindows()) {
                return Arrays.asList(Paths.get("C:\\Program Data\\LogonBox\\VPN\\conf.d"));
            } else if (OS.isMacOs()) {
                return Arrays.asList(Paths.get("/Library/LogonBox VPN/conf"));
            } else {
                throw new UnsupportedOperationException("Unknown operating system.");
            }
        }
    }

    private List<Path> parseStringPaths(String paths) {
        var st = new StringTokenizer(paths, File.pathSeparator);
        var l = new ArrayList<Path>();
        while (st.hasMoreTokens()) {
            l.add(Paths.get(st.nextToken()));
        }
        return l;
    }

    @Override
    public ScheduledExecutorService queue() {
        return queue;
    }

    @Override
    public SystemConfiguration configuration() {
        if (configuration == null) {
            configuration = new LbvConfiguration();
        }
        return configuration;
    }

    @Override
    public void addScriptEnvironmentVariables(VpnAdapter connection, Map<String, String> env) {
    }
    
    void logCommandLine(String... args) {
        System.out.format("[#] %s%n", String.join(" ", args));
    }
    
    abstract static class AbstractQuickCommand implements Callable<Integer> {

        @ParentCommand
        protected LbvQuick parent;

        @Parameters(arity = "1", paramLabel = "CONFIG_FILE | INTERFACE", description = "CONFIG_FILE is a configuration file, whose filename is the interface name followed by `.conf'. Otherwise, INTERFACE is an interface name, with configuration found at in the system specific configuration search path (or that provided by the --configuration-search-path option).")
        private Path configFileOrInterface;

        @Override
        public Integer call() throws Exception {
            parent.setupLogging();

            var bldr = new Vpn.Builder().withSystemContext(parent);

            if (Files.exists(configFileOrInterface)) {
                bldr.withInterfaceName(parent.toInterfaceName(configFileOrInterface)); 
                bldr.withVpnConfiguration(configFileOrInterface);
            }
            else {
                var iface = configFileOrInterface.toString();
                bldr.withInterfaceName(iface);
                bldr.withVpnConfiguration(parent.findConfig(iface));
            }

            var vpn = bldr.build();
            vpn.platformService().commands().onLog(parent::logCommandLine);
            return onCall(vpn);
        }
        
        protected abstract Integer onCall(Vpn vpn) throws Exception;

    }

    @Command(name = "up", description = "Bring a VPN interface up.")
    public final static class Up extends AbstractQuickCommand {

        @Override
        protected Integer onCall(Vpn vpn) throws Exception {
            vpn.open();
            return 0;
        }

    }

    @Command(name = "down", description = "Take a VPN interface down.")
    public final static class Down extends AbstractQuickCommand {

        @Override
        protected Integer onCall(Vpn vpn) throws Exception {
            if(!vpn.started())
                throw new IOException(MessageFormat.format("`{0}` is not a VPN interface.", vpn.interfaceName().get()));
            vpn.close();
            return 0;
        }

    }

    @Command(name = "strip", description = "Output the stripped down configuration suitable for use with `lbv`.")
    public final static class Strip extends AbstractQuickCommand {

        @Override
        protected Integer onCall(Vpn vpn) throws Exception {
            vpn.adapter().configuration().write(System.out);
            return 0;
        }

    }

    @Command(name = "save", description = "Save the current configuration without bringing the interface down.")
    public final static class Save extends AbstractQuickCommand {

        @Override
        protected Integer onCall(Vpn vpn) throws Exception {
            
            var bldr = new VpnConfiguration.Builder().
                    fromConfiguration(vpn.configuration());
            
            bldr.fromConfiguration(vpn.adapter().configuration());
            bldr.withPeers(vpn.adapter().configuration().peers());
            
            var cfg = bldr.build();
            cfg.write(System.out);
            
            // TODO write to file
            return 0;
        }

    }

    private Path findConfig(String iface) throws IOException {
        for (var path : configSearchPath()) {
            var cfgPath = path.resolve(iface + ".conf");
            if (Files.exists(cfgPath)) {
                return cfgPath;
            }
        }
        throw new IOException(
                MessageFormat.format("Could not find configuration file for {0} in any search path.", iface));
    }

    public String toInterfaceName(Path configFileOrInterface) {
        var name = configFileOrInterface.getFileName().toString();
        var idx = name.lastIndexOf('.');
        return idx == -1 ? name : name.substring(0, idx);
    }
}
