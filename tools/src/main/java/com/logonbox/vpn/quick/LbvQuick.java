package com.logonbox.vpn.quick;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.StringTokenizer;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.ElevatableSystemCommands;
import com.logonbox.vpn.drivers.lib.NativeComponents;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.Prefs;
import com.logonbox.vpn.drivers.lib.Prefs.PrefType;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.Vpn;
import com.logonbox.vpn.drivers.lib.Vpn.Builder;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.sshtools.liftlib.OS;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import uk.co.bithatch.nativeimage.annotations.Resource;

@Command(name = "lbv-quick", description = "Set up a WireGuard interface simply.", mixinStandardHelpOptions = true, subcommands = {
        LbvQuick.Up.class, LbvQuick.Down.class, LbvQuick.Expire.class, LbvQuick.Unexpire.class,
        LbvQuick.Strip.class, LbvQuick.Safe.class, LbvQuick.DNS.class, LbvQuick.DNSProviders.class
})
@Resource({ "windows-task\\.xml" })
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
        public Optional<String> dnsIntegrationMethod() {
            return dns;
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
    private Optional<String> dns;

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
    private SystemCommands commands;
    private NativeComponents nativeComponents;

    @Override
    protected Integer onCall() throws Exception {
    	CommandLine.usage(this, out);
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
    public SystemCommands commands() {
        if(commands == null)
            commands = new ElevatableSystemCommands();
        return commands;
    }

    @Override
    public NativeComponents nativeComponents() {
        if(nativeComponents == null)
            nativeComponents = new NativeComponents();
        return nativeComponents;
    }

    @Override
    public void addScriptEnvironmentVariables(VpnAdapter connection, Map<String, String> env) {
    }
    
    static void logCommandLine(String... args) {
        var largs = new ArrayList<>(Arrays.asList(args));
        var path = Paths.get(largs.get(0));
        if(path.isAbsolute()) {
            largs.set(0, path.getFileName().toString());
        }
        System.out.format("[#] %s%n", String.join(" ", largs));
    }
    
    abstract static class AbstractQuickCommand implements Callable<Integer> {

        @ParentCommand
        protected LbvQuick parent;

        @Parameters(arity = "1", paramLabel = "CONFIG_FILE | URL | INTERFACE", description = 
        		"CONFIG_FILE is a configuration file, whose filename is the interface name " 
        		+ "followed by `.conf'. It can also be the entire content of a configuration file "
        		+ "if it starts with '['. A URL is also possible, which includes data URL. " 
        		+ "Otherwise, INTERFACE is an interface name, with "
        		+ "configuration found at in the system specific configuration search path "
        		+ "(or that provided by the --configuration-search-path option).")
        private String configFileOrInterface;

        @Override
        public Integer call() throws Exception {
            Optional<Path> file = Optional.empty();
            
            parent.initCommand();

            Optional<String> ifaceName = Optional.empty();
            var bldr = new Vpn.Builder().withSystemContext(parent);
            
            
			if(configFileOrInterface.equals("[")) {
            	bldr.withVpnConfiguration(new InputStreamReader(System.in));
            }
            else if(configFileOrInterface.equals("-")) {
            	bldr.withVpnConfiguration(new InputStreamReader(System.in));
            }
            else if(configFileOrInterface.startsWith("data:text/plain;base64,")) {
            	bldr.withVpnConfiguration(new String(Base64.getDecoder().decode(configFileOrInterface.substring(23)), "UTF-8"));
            }
            else {
            	try {
            		var url = new URL(configFileOrInterface);
            		try(var in = url.openStream()) {
            			bldr.withVpnConfiguration(new InputStreamReader(in));
            		}
            	}
            	catch(MalformedURLException murle) {
            		var asFile = Paths.get(configFileOrInterface);
		            if (Files.exists(asFile)) {
		                var iface = parent.toInterfaceName(asFile);
		                ifaceName = Optional.of(iface);
						bldr.withInterfaceName(iface);
		                file = Optional.of(asFile);
		            }
		            else {
		                var iface = configFileOrInterface;
		                ifaceName = Optional.of(iface);
		                try {
		                	file = Optional.of(parent.findConfig(iface));
			                bldr.withInterfaceName(iface);
		                }
		                catch(IOException ioe) {
		                	file = Optional.empty();
			                bldr.withNativeInterfaceName(iface);
		                }
		            }
		            if(file.isPresent())
		            	bldr.withVpnConfiguration(file.get());
            	}
            }
            onBuild(bldr);

            var vpn = bldr.build();
            vpn.platformService().context().commands().onLog(LbvQuick::logCommandLine);
            return onCall(vpn, file, ifaceName);
        }
        
        protected void onBuild(Builder bldr) {
        }

		protected abstract Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception;

    }

    @Command(name = "up", description = "Bring a VPN interface up.")
    public final static class Up extends AbstractQuickCommand {

        @Option(names = { "-x", "--expire" }, paramLabel = "INTERVAL | TIME | DATE-TIME", description = "Expire this connection after the specified number of seconds. ")
        private Optional<String> expire;

        @Option(names = { "-I",
                "--native-iface" }, paramLabel = "NAME", description = "The native interface name to use. This is platform specific, for example on Mac OS this would default to `utun[number]`. On Windows it would be `net[number]`. On Linux, network interface names are more flexible, and this will default to the name derived from the configuration file name")
        private Optional<String> nativeName;


        @Override
		protected void onBuild(Builder bldr) {
        	bldr.withNativeInterfaceName(nativeName);
		}

		@Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
            vpn.open();
            if(expire.isPresent()) 
            	expire(parent, vpn, parseWhenToSeconds(expire.get()));
            return 0;
        }

    }

    @Command(name = "expire", description = "Expire an existing connection at a certain time.")
    public final static class Expire extends AbstractQuickCommand {

        @Parameters(arity = "1", paramLabel = "INTERVAL | TIME | DATE-TIME", description = "When to expire this connection. This accepts a number of formats.")
        private String when;

		@Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
           	expire(parent, vpn, parseWhenToSeconds(when));
            return 0;
        }
    }

    @Command(name = "unexpire", description = "Remove a connections expiry.")
    public final static class Unexpire extends AbstractQuickCommand {

		@Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
           	unexpire(parent, vpn);
            return 0;
        }
    }

    @Command(name = "down", description = "Take a VPN interface down.")
    public final static class Down extends AbstractQuickCommand {

        @Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
            if(!vpn.started())
                throw new IOException(MessageFormat.format("`{0}` is not a VPN interface.", vpn.interfaceName().get()));
            try {
            	unexpire(parent, vpn);
            }
            finally {
            	vpn.close();
            }
            return 0;
        }

    }
    
    static long parseWhenToSeconds(String when) {
    	var parts = when.split("\\s+");
    	var whenTime = 0l;
    	if(parts.length == 1) {
        	var timefmt = DateFormat.getDateInstance(DateFormat.SHORT);
    		try {
				whenTime  = timefmt.parse(parts[0]).getTime();
			} catch (ParseException e) {
				when = when.toLowerCase();
				if(when.endsWith("s")) {
					return Long.parseLong(when.substring(when.length() - 1));
				}
				else if(when.endsWith("m")) {
					return Long.parseLong(when.substring(when.length() - 1)) * 60;
				}
				else if(when.endsWith("h")) {
					return Long.parseLong(when.substring(when.length() - 1)) * 3600;
				}
				else if(when.endsWith("d")) {
					return Long.parseLong(when.substring(when.length() - 1)) * 3600 * 24;
				}
				else {
					return Long.parseLong(when);
				}
			}
    	}
    	else if(parts.length == 2) {
        	var datefmt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        	try {
				whenTime  = datefmt.parse(when).getTime();
			} catch (ParseException e) {
				throw new IllegalArgumentException("Incorrect short datetime format for this locale.", e);
			}
    	}
    	else 
    		throw new IllegalArgumentException("Unexpected number of elements in datetime or interval string.");
    	
    	var now = System.currentTimeMillis();
    	if(whenTime <= now) {
    		throw new IllegalArgumentException("Specified datetime is in the past.");
    	}
    	return Math.max(1, ( whenTime - now ) / 1000);
    }

    protected enum Encoding {
    	PLAIN, DATA_URI
    }

    protected abstract static class AbstractOutputCommand extends AbstractQuickCommand {

        @Option(names = { "-o",         "--output" }, paramLabel = "PATH", description = "Path to output to. When ommitted, defaults to stdout.")
        private Optional<Path> output;
        
        @Option(names = { "-E", "--output-encoding" }, paramLabel = "ENCODING", description = "How to encode the output.")
        private Encoding encoding = Encoding.PLAIN;

    	
        protected void output(VpnAdapterConfiguration cfg) throws Exception {
        	if(output.isEmpty()) {
        		output(System.out, cfg);
        	}
        	else {
        		try(var out = Files.newOutputStream(output.get())) {
            		output(out, cfg);
        		}
        	}
        }

        protected void output(OutputStream out, VpnAdapterConfiguration cfg) throws Exception {
        	switch(encoding) {
        	case DATA_URI:
        		out.write(cfg.toDataUri().getBytes("UTF-8"));
        		break;
        	default:
        		cfg.write(out);
        		break;
        	}
        	out.flush();
        }

    }

    @Command(name = "strip", description = "Output the stripped down configuration suitable for use with `lbv`.")
    public final static class Strip extends AbstractOutputCommand {

        @Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
        	output(vpn.adapter().configuration());
            return 0;
        }

    }

    @Command(name = "safe", description = "Remove a private key from a configuration and replace it with it's public key. Intended for use with piping configuration to the `down` command.")
    public final static class Safe extends AbstractOutputCommand {

        @Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
        	var cfg = vpn.configuration();
        	
        	var bldr = new VpnConfiguration.Builder();
        	bldr.fromConfiguration(cfg);
        	bldr.withoutPrivateKey();
        	
        	output(bldr.build());
            return 0;
        }

    }

    @Command(name = "save", description = "Save the current configuration without bringing the interface down.")
    public final static class Save extends AbstractQuickCommand {

        @Override
        protected Integer onCall(Vpn vpn, Optional<Path> configFile, Optional<String> interfaceName) throws Exception {
            
            var bldr = new VpnConfiguration.Builder().
                    fromConfiguration(vpn.configuration());
            
            bldr.fromConfiguration(vpn.adapter().configuration());
            bldr.withPeers(vpn.adapter().configuration().peers());
            
            var cfg = bldr.build();
            cfg.write(configFile.orElseThrow(() -> new IllegalStateException("Configuration file must be provided.")));
            
            return 0;
        }

    }

    @Command(name = "dns", description = "Shows the DNS configuration (when supported)")
    public final static class DNS implements Callable<Integer> {

        @ParentCommand
        protected LbvQuick parent;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            for (var ip : PlatformService.create(parent).dns()
                    .orElseThrow(() -> new IllegalStateException("No DNS provider available.")).entries()) {
                var all = ip.all();
                out.format("%s\t%s%n", ip.iface(), all.length == 0 ? "(none)" : String.join(",", all));
            }
            return 0;
        }

    }

    @Command(name = "dns-providers", description = "Shows available DNS systems.")
    public final static class DNSProviders implements Callable<Integer> {

        @ParentCommand
        protected LbvQuick parent;

        @Override
        public Integer call() throws Exception {
            parent.initCommand();
            PlatformService.create(parent).dns().ifPresent(prov -> {
                for(var fact : ServiceLoader.load(DNSProvider.Factory.class))  {
                	for(var clazz : fact.available()) {
                		if(clazz.equals(prov.getClass())) {
                            out.format("*%s%n", clazz.getName());
                		}
                		else {
                            out.println(clazz.getName());
                		}
                	}
                }
            });
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

	@Override
	public void alert(String message, Object... args) {
        System.out.format("[+] %s%n", MessageFormat.format(message, args));
	}
	
	/**
	 * Work how to launch this same application, but without any arguments. This
	 * takes into account if launching from native image or Java (could be improved),
	 * and modular vs non-modular. It should work in a development environment too.
	 * 
	 * @return this command
	 */
	private static List<String> getThisCommand() {
		var info = ProcessHandle.current().info();
		var cmd = info.command().orElseThrow(() -> new UnsupportedOperationException("Expiry not supported, cannot determine own process details."));
		var args = info.arguments().orElse(new String[0]);
		var newArgList = new ArrayList<String>();
		
		if(cmd.toLowerCase().contains("java")) {
			
			newArgList.add(cmd);
			
			/* TODO: Windows does not give us our own arguments :( I think it's this
			 * bug - https://bugs.openjdk.org/browse/JDK-8176725. For now, I am
			 * not going to worry about this too much, as it will work with a native
			 * image
			 * 
			 * We could do something like what happens in liftlib (reuse it?). 
			 */
			if(OS.isWindows())
				throw new UnsupportedOperationException("Cannot reconstruct command line on Windows.");
			
			/* Try to find the classname in the arguments, and remove everything from that point */
			for(var i = 0 ; i < args.length; i++) {
				var arg = args[i];
				if(arg.contains(" ")) {
					/* We know this is not a class name so just add to list of new args
					 */
					newArgList.add(arg);
				}
				else {
					if(arg.equals("-m")) {
						/* Running modular. We know the next argument is the fully qualified module / class,
						 * so add those and ignore what remains 
						 */
						newArgList.add(arg);
						newArgList.add(args[i + 1]);
						break;
					}
					else {
						/* Does this look like a class name? */
						if(arg.matches("[a-z]+[a-z\\.]*\\.[a-zA-Z\\.]*")) {
							/* It does, add this and ignore what remains */
							newArgList.add(arg);
							break;
						}
					}
				}
				newArgList.add(arg);
			}
		}
		else {
			newArgList.add(cmd);
		}
		return newArgList;
	}

	private static String wrapWithQuotes(String arg) {
		if(arg.contains(" ") || arg.contains(";"))
			return "'" + arg + "'";
		else
			return arg;
	}
	
	private static String wrapWithEncodedQuotes(String arg) {
		if(arg.contains(" "))
			return "&quot;" + arg + "&quot;";
		else
			return arg;
	}

	private final static void unexpire(SystemContext context, Vpn vpn) throws IOException {
		unexpire(context, vpn, true);
	}

	private final static void unexpire(SystemContext context, Vpn vpn, boolean log) throws IOException {
		if(OS.isLinux()) {
			if(OS.hasCommand("at")) {
				try {
					var jobId = Long.parseLong(context.commands().privileged().task(new Prefs.GetValue(
							true, LbvQuick.class.getPackageName().replace('.', '/') + "/jobs", vpn.adapter().address().nativeName(), null)
					));
					try {
						maybeLogCommands(context, log).result("atrm", 
								String.valueOf(jobId));
					}
					finally {
						context.commands().privileged().task(new Prefs.RemoveKey(
								true, LbvQuick.class.getPackageName().replace('.', '/') + "/jobs", vpn.adapter().address().nativeName())
						);
					}
				} catch (Exception e) {
				}
			}
			else {
				throw new UnsupportedOperationException("Expiry requires that the `at` command be installed on Linux.");
			}
		}
		else if(OS.isWindows()) {
			if(OS.hasCommand("schtasks")) {
				maybeLogCommands(context, log).result("schtasks", 
						"/delete", 
						"/f", 
						"/tn", "VpnExpiry_" + vpn.adapter().information().interfaceName());
			}
			else {
				throw new UnsupportedOperationException("Expiry requires that the `schtasks` command be installed on Windows.");
			}
		}
		else if(OS.isMacOs()) {
			var task = LbvQuick.class.getPackage().getName() + ".expire." + vpn.adapter().address().nativeName(); 
			maybeLogCommands(context, log).result(
				"launchctl", 
				"stop", 
				task
			);
			maybeLogCommands(context, log).result(
				"rm", "-f", "/Library/LaunchAgents/" + task + ".plist"
			);
		}
	}

	private static SystemCommands maybeLogCommands(SystemContext context, boolean log) {
		if(log)
			return context.commands().privileged().logged();
		else
			return context.commands().privileged();
	}
	
	private final static void expire(SystemContext context, Vpn vpn, long seconds) throws IOException {
		unexpire(context, vpn, false);
		
		var taskArgs = getThisCommand();
		taskArgs.add("down");
		taskArgs.add(vpn.configuration().toDataUri());
		
		if(OS.isLinux()) {
			if(OS.hasCommand("at")) {
				/* NOTE at only has 'minute' resolution */
				var time = Math.max(1, seconds / 60);
				var cmds = Arrays.asList("at", "-M", "now + " + time + " minutes");
				logCommandLine(cmds.toArray(new String[0]));
				
				var taskCmd = String.join(" ", taskArgs.stream().map(LbvQuick::wrapWithQuotes).collect(Collectors.toList()));
				for(var line : context.commands().privileged().pipeTo(taskCmd, cmds.toArray(new String[0]))) {
					if(line.startsWith("job ")) {
						var args = line.split("\\s+");
						if(args.length > 1) {
							try {
								var jobId = Long.parseLong(args[1]);
								context.commands().privileged().task(new Prefs.PutValue(
										true, LbvQuick.class.getPackageName().replace('.', '/') + "/jobs", vpn.adapter().address().nativeName(), jobId, PrefType.LONG
								));
								return;
							}
							catch(Exception e) {
								context.alert("Failed to save job ID for scheduled expiry, expiry may not work as expected");
							}
						}
					}
				}
				context.alert("Failed to find job ID for scheduled expiry, expiry may not work as expected");
			}
			else {
				throw new UnsupportedOperationException("Expiry requires that the `at` command be installed on Linux.");
			}
		}
		else if(OS.isWindows()) {
			if(OS.hasCommand("schtasks")) {
				/* NOTE schtasks also only has 'minute' resolution */
				
				
				/* Stupidly, you can't turn off power management on tasks created
				 * by schtasks! So instead we use raw task XML. Dumbdumbdumbdumb
				 */
				
				var fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
				var xmlFile = Files.createTempFile("vpntask", ".xml");
				try {
					var wrt = new StringWriter();
					try(var in = new InputStreamReader(LbvQuick.class.getResourceAsStream("/windows-task.xml"), "UTF-16")) {
						in.transferTo(wrt);
					}
					var str = wrt.toString();
					str = str.replace("${author}", System.getenv("USERDOMAIN") + "\\" + System.getProperty("user.name"));
					str = str.replace("${uri}", "\\VpnExpiry_" + vpn.adapter().information().interfaceName());
					str = str.replace("${start}", fmt.format(new Date(System.currentTimeMillis() + (seconds * 1000))));
					str = str.replace("${cmd}", taskArgs.get(0));
					str = str.replace("${cwd}", System.getProperty("user.dir"));
					str = str.replace("${args}", String.join(" ", 
							taskArgs.subList(1, taskArgs.size()).stream().map(LbvQuick::wrapWithEncodedQuotes).collect(Collectors.toList())));
					
					try(var out = new PrintWriter(Files.newBufferedWriter(xmlFile))) {
						out.println(str);
					}
					
					var cmds = new String[] {
							"schtasks", 
							"/create", 
							"/f", 
							"/tn", "VpnExpiry_" + vpn.adapter().information().interfaceName(),
							"/xml", xmlFile.toString()
					};
					logCommandLine(cmds);
					context.commands().privileged().run(cmds);
				}
				finally {
					Files.delete(xmlFile);
				}
			}
			else {
				throw new UnsupportedOperationException("Expiry requires that the `schtasks` command be installed on Windows.");
			}
		}
		else if(OS.isMacOs()) {
				
			var wrt = new StringWriter();
			try(var in = new InputStreamReader(LbvQuick.class.getResourceAsStream("/macos-task.plist"), "UTF-16")) {
				in.transferTo(wrt);
			}
			var str = wrt.toString();
			var task = LbvQuick.class.getPackage().getName() + ".expire." + vpn.adapter().address().nativeName(); 
			str = str.replace("${task}", task);
			str = str.replace("${args}", String.join(System.lineSeparator(), 
					taskArgs.subList(1, taskArgs.size()).stream().map(s -> "<string>" + s + "</string>").collect(Collectors.toList())));
			

			context.commands().privileged().run(new String[] {
				"sh", "-c",
				"echo '" + str + "' > /Library/LaunchAgents/" + task + ".plist"
			});
			
			var cmds = new String[] {
				"launchctl", 
				"start", 
				task
			};
			logCommandLine(cmds);
			context.commands().privileged().run(cmds);
		}
		else
			throw new UnsupportedOperationException("Expiry is not supported on this platform.");
	}
}
