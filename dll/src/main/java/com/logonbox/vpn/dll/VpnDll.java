package com.logonbox.vpn.dll;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CTypeConversion;
import org.slf4j.bridge.SLF4JBridgeHandler;

import com.logonbox.vpn.drivers.lib.AbstractSystemContext;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.Vpn;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.sshtools.liftlib.OS;

/**
 * This alternative API to the LogonBox VPN library can be compiled to a
 * reusable native DLL. To reach the widest audience, and avoid having to link
 * to Graal, it is expressed as C type API.
 * <p>
 * This has many of the same features as the fluent Java and follows the same
 * form, but flattened to be C compatible. In general you will be create and
 * passing <code>long</code> handles around between various static methods.
 * <p>
 * In it's simplest form, just call {@link #up(IsolateThread, CCharPointer, long, long)} with
 * the configuration file and zero for the last two arguments. You will be returned a further
 * <code>long</code>, which is a handle to the VPN instance. This may be used to further query, manipulate
 * and stop the VPN instance.
 * <p>
 * For further configuration, before calling <code>up()</code>, use {@link #systemconf_create(IsolateThread)}
 * and {@link #context_create(IsolateThread)} which both returns handles. This may be used to configure
 * the system configuration bbject and the context using those handles and the various related methods
 * such as {@link #systemconf_set_connect_timeout(IsolateThread, long, long)}, etc.
 * <p>
 * For error handling, functions will either return a <code>boolean</code> of <code>false</code>,
 * or they will return <code>zero</code> where otherwise a valid handle (greater than zero) would be
 * returned.
 * <p>
 * You can discover the error code and error text by using {@link #get_error_code(IsolateThread)} and
 * {@link #get_error_text(IsolateThread, CCharPointer)}. Error state is cleared once <strong>any</strong>
 * function completes successfully.
 */
public class VpnDll {

	public enum Error {
		NO_SUCH_VPN_INSTANCE, NO_SUCH_CONFIGURATION, NO_SUCH_CONTEXT, FAILED_TO_FIND_CONFIGURATION, FAILED_TO_LOAD_CONFIGURATION,
		FAILED_TO_PARSE_CONFIGURATION, FAILED_TO_CLOSE, FAILED_TO_OPEN;

		public String toErrorString() {
			switch (this) {
			case NO_SUCH_VPN_INSTANCE:
				return "There is no 'vpn' object with the provided handle.";
			case FAILED_TO_CLOSE:
				return "Failed to close the requested VPN configuration.";
			case FAILED_TO_FIND_CONFIGURATION:
				return "Failed to find configuration for the requested interface in any search path.";
			case FAILED_TO_PARSE_CONFIGURATION:
				return "Failed to parse the provided configuration content.";
			case FAILED_TO_LOAD_CONFIGURATION:
				return "Failed to load the requested configuration from the file.";
			case NO_SUCH_CONFIGURATION:
				return "There is no 'configuration' object with the provided handle";
			case NO_SUCH_CONTEXT:
				return "There is no 'context' object with the provided handle";
			default:
				return "Unknown error.";
			}
		}
	}
	
	@SuppressWarnings("serial")
	private final static class ErrorException extends Exception {
		final Error error;
		
		ErrorException(Error error) {
			this.error = error;
		}
	}

	public static class VpnDllConfiguration implements SystemConfiguration {

		private Duration serviceWait = SERVICE_WAIT_TIMEOUT;
		private boolean ignoreLocalRoutes;
		private Duration handshakeTimeout = HANDSHAKE_TIMEOUT;
		private Optional<Integer> defaultMTU = Optional.empty();
		private Optional<Duration> connectTimeout = Optional.empty();
		private Optional<String> dnsIntegrationMethod = Optional.empty();

		@Override
		public Duration serviceWait() {
			return serviceWait;
		}

		@Override
		public boolean ignoreLocalRoutes() {
			return ignoreLocalRoutes;
		}

		@Override
		public Duration handshakeTimeout() {
			return handshakeTimeout;
		}

		@Override
		public Optional<Integer> defaultMTU() {
			return defaultMTU;
		}

		@Override
		public Optional<Duration> connectTimeout() {
			return connectTimeout;
		}

		@Override
		public Optional<String> dnsIntegrationMethod() {
			return dnsIntegrationMethod;
		}
	}

	private final static class VpnDllContext extends AbstractSystemContext {

		private SystemConfiguration configuration = SystemConfiguration.DEFAULT;
		private ScheduledExecutorService queue = Executors.newSingleThreadScheduledExecutor();
		private Map<String, String> envToAdd = new ConcurrentHashMap<>();

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
			env.putAll(envToAdd);
		}

		@Override
		public void alert(String message, Object... args) {
			// TODO log?
			System.out.println(MessageFormat.format(message, args));
		}

	}

	static {
		System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", System.getProperty("logLevel", "INFO"));
		SLF4JBridgeHandler.removeHandlersForRootLogger();
		SLF4JBridgeHandler.install();
	}

	////////////////////////////////////////////////////////////////////////
	//
	// Gloal
	//
	////////////////////////////////////////////////////////////////////////
	private static Error error = null;
	private static Optional<String> configurationSearchPath = Optional.empty();

	@CEntryPoint(name = "get_error_code")
	static int get_error_code(IsolateThread thread) {
		return error == null ? -1 : error.ordinal();
	}

//	@CEntryPoint(name = "get_error_text")
//	static CCharPointer get_error_text(IsolateThread thread, CCharPointer dns) {
//		return error == null ? null : CTypeConversion.toCString(error.name()).get();
//	}

	@CEntryPoint(name = "set_configuration_search_path")
	static boolean set_configuration_search_path(IsolateThread thread, CCharPointer path) {
		configurationSearchPath = Optional.of(CTypeConversion.toJavaString(path));
		error = null;
		return false;
	}

	////////////////////////////////////////////////////////////////////////
	//
	// System Configuration
	//
	////////////////////////////////////////////////////////////////////////

	private final static Map<Long, VpnDllConfiguration> configuration = new ConcurrentHashMap<>();
	private final static AtomicLong configurationId = new AtomicLong(1);

	@CEntryPoint(name = "systemconf_create")
	static long systemconf_create(IsolateThread thread) {
		var cfg = new VpnDllConfiguration();
		var id = configurationId.getAndIncrement();
		configuration.put(id, cfg);
		error = null;
		return id;
	}

	@CEntryPoint(name = "systemconf_destroy")
	static boolean systemconf_destroy(IsolateThread thread, long handle) {
		var removed = configuration.remove(handle) != null;
		error = removed ? null : Error.NO_SUCH_CONFIGURATION;
		return removed;
	}

	@CEntryPoint(name = "systemconf_set_service_wait")
	static boolean systemconf_set_service_wait(IsolateThread thread, long handle, long ms) {
		var cfg = configuration.get(handle);
		if (cfg != null) {
			cfg.serviceWait = Duration.ofMillis(ms);
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONFIGURATION;
		return false;
	}

	@CEntryPoint(name = "systemconf_set_ignore_local_routes")
	static boolean systemconf_set_ignore_local_routes(IsolateThread thread, long handle, boolean ignore) {
		var cfg = configuration.get(handle);
		if (cfg != null) {
			cfg.ignoreLocalRoutes = ignore;
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONFIGURATION;
		return false;
	}

	@CEntryPoint(name = "systemconf_set_handshake_timeout")
	static boolean systemconf_set_handshake_timeout(IsolateThread thread, long handle, long ms) {
		var cfg = configuration.get(handle);
		if (cfg != null) {
			cfg.handshakeTimeout = Duration.ofMillis(ms);
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONFIGURATION;
		return false;
	}

	@CEntryPoint(name = "systemconf_set_default_mtu")
	static boolean systemconf_set_default_mtu(IsolateThread thread, long handle, int mtu) {
		var cfg = configuration.get(handle);
		if (cfg != null) {
			cfg.defaultMTU = Optional.of(mtu);
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONFIGURATION;
		return false;
	}

	@CEntryPoint(name = "systemconf_set_connect_timeout")
	static boolean systemconf_set_connect_timeout(IsolateThread thread, long handle, long ms) {
		var cfg = configuration.get(handle);
		if (cfg != null) {
			cfg.connectTimeout = Optional.of(Duration.ofMillis(ms));
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONFIGURATION;
		return false;
	}

	@CEntryPoint(name = "systemconf_set_dns_method")
	static boolean systemconf_set_dns_method(IsolateThread thread, long handle, CCharPointer dns) {
		var cfg = configuration.get(handle);
		if (cfg != null) {
			cfg.dnsIntegrationMethod = Optional.of(CTypeConversion.toJavaString(dns));
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONFIGURATION;
		return false;
	}

	////////////////////////////////////////////////////////////////////////
	//
	// Context
	//
	////////////////////////////////////////////////////////////////////////

	private final static Map<Long, VpnDllContext> context = new ConcurrentHashMap<>();
	private final static AtomicLong contextId = new AtomicLong(1);

	@CEntryPoint(name = "context_create")
	static long context_create(IsolateThread thread) {
		var ctx = new VpnDllContext();
		var id = contextId.getAndIncrement();
		context.put(id, ctx);
		error = null;
		return id;
	}

	@CEntryPoint(name = "context_destroy")
	static boolean context_destroy(IsolateThread thread, long handle) {
		var removed = context.remove(handle) != null;
		error = removed ? null : Error.NO_SUCH_CONTEXT;
		return removed;
	}

	@CEntryPoint(name = "context_set_configuration")
	static boolean context_set_configuration(IsolateThread thread, long handle, long cfgHandle) {

		var ctx = context.get(handle);
		if (ctx != null) {
			var cfg = configuration.get(cfgHandle);
			if (cfg == null) {
				error = Error.NO_SUCH_CONFIGURATION;
				return false;
			}
			ctx.configuration = cfg;
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONTEXT;
		return false;
	}

	@CEntryPoint(name = "context_add_environment_variable")
	static boolean context_add_environment_variable(IsolateThread thread, long handle, CCharPointer name,
			CCharPointer value) {

		var ctx = context.get(handle);
		if (ctx != null) {
			ctx.envToAdd.put(CTypeConversion.toJavaString(name), CTypeConversion.toJavaString(value));
			error = null;
			return true;
		}
		error = Error.NO_SUCH_CONTEXT;
		return false;
	}

	////////////////////////////////////////////////////////////////////////
	//
	// Quick Up / Down / Status etc
	//
	////////////////////////////////////////////////////////////////////////

	private final static AtomicLong vpnId = new AtomicLong(1);
	private final static Map<Long, Vpn> vpns = new ConcurrentHashMap<>();
	private final static Map<String, Long> active = new ConcurrentHashMap<>();

	@CEntryPoint(name = "up")
	static long up(IsolateThread thread, CCharPointer configurationFileOrInterface, long systemconfHandle,
			long contextHandle) {
		var configurationFileOrInterfaceString = CTypeConversion.toJavaString(configurationFileOrInterface);
		var bldr = new Vpn.Builder();
		try {
			buildVpn(bldr, configurationFileOrInterfaceString, systemconfHandle, contextHandle);
		}
		catch(ErrorException ee) {
			error = ee.error;
			return 0;
		}

		var vpn = bldr.build();
		try {
			vpn.open();
			var id = vpnId.getAndIncrement();
			vpns.put(id, vpn);
			active.put(configurationFileOrInterfaceString, id);
			error = null;
			return id;
		} catch (IOException e) {
			error = Error.FAILED_TO_OPEN;
			return 0;
		}
	}
	
	@CEntryPoint(name = "down")
	static boolean down(IsolateThread thread, long vpnHandle) {
		var vpn = vpns.get(vpnHandle);
		if(vpn == null) {
			error = Error.NO_SUCH_VPN_INSTANCE;
			return false;
		}
		try {
			vpn.close();
			error = null;
		}
		catch(IOException ioe) {
			error = Error.FAILED_TO_CLOSE;
			return false;
		}
		finally {
			vpns.remove(vpnHandle);
			while (active.values().remove(vpnHandle));
		}
		return true;
	}
	
	@CEntryPoint(name = "stop")
	static boolean stop(IsolateThread thread, CCharPointer configurationFileOrInterface, long systemconfHandle,
			long contextHandle) {
		var configurationFileOrContentOrIface = CTypeConversion.toJavaString(configurationFileOrInterface);
		if(active.containsKey(configurationFileOrContentOrIface)) {
			return down(thread, active.get(configurationFileOrContentOrIface));
		}

		var bldr = new Vpn.Builder();
		try {
			buildVpn(bldr, configurationFileOrContentOrIface, systemconfHandle, contextHandle);
		}
		catch(ErrorException ee) {
			error = ee.error;
			return false;
		}

		var vpn = bldr.build();
		try {
			vpn.close();
		} catch (IOException e) {
			error = Error.FAILED_TO_CLOSE;
			return false;
		}
		
		return true;
	}
	
	private static void buildVpn(Vpn.Builder bldr, String configurationFileOrContentOrIface, long systemconfHandle, long contextHandle) throws ErrorException {
		if (systemconfHandle > 0) {
			var cfg = configuration.get(systemconfHandle);
			if (cfg == null) {
				throw new ErrorException(Error.NO_SUCH_CONFIGURATION);
			}
			bldr.withSystemConfiguration(cfg);
		}

		if (contextHandle > 0) {
			var ctx = context.get(contextHandle);
			if (ctx == null) {
				throw new ErrorException(Error.NO_SUCH_CONTEXT);
			}
			bldr.withSystemContext(ctx);
		}

    	var pattern  = Pattern.compile(".*\\[Interface\\].*", Pattern.DOTALL);
		if(pattern.matcher(configurationFileOrContentOrIface).matches()) {
		    try {
                bldr.withVpnConfiguration(configurationFileOrContentOrIface);
            } catch (ParseException e) {
                throw new ErrorException(Error.FAILED_TO_PARSE_CONFIGURATION);
            } catch (IOException e) {
                throw new ErrorException(Error.FAILED_TO_LOAD_CONFIGURATION);
            }
		}
		else {
		    var configFile = Paths.get(configurationFileOrContentOrIface);
    		Path file;
    		if (Files.exists(configFile)) {
    			bldr.withInterfaceName(toInterfaceName(configFile));
    			file = configFile;
    		} else {
    			var iface = configFile.toString();
    			bldr.withInterfaceName(iface);
    			try {
    				file = findConfig(iface);
    			} catch (IOException e) {
    				throw new ErrorException(Error.FAILED_TO_FIND_CONFIGURATION);
    			}
    		}
    
    		try {
    			bldr.withVpnConfiguration(file);
    		} catch (ParseException e) {
    			throw new ErrorException(Error.FAILED_TO_PARSE_CONFIGURATION);
    		} catch (IOException e) {
    			throw new ErrorException(Error.FAILED_TO_LOAD_CONFIGURATION);
    		}
		}
	}

	private static List<Path> configSearchPath() {
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

	private static List<Path> parseStringPaths(String paths) {
		var st = new StringTokenizer(paths, File.pathSeparator);
		var l = new ArrayList<Path>();
		while (st.hasMoreTokens()) {
			l.add(Paths.get(st.nextToken()));
		}
		return l;
	}

	private static Path findConfig(String iface) throws IOException {
		for (var path : configSearchPath()) {
			var cfgPath = path.resolve(iface + ".conf");
			if (Files.exists(cfgPath)) {
				return cfgPath;
			}
		}
		throw new IOException(
				MessageFormat.format("Could not find configuration file for {0} in any search path.", iface));
	}

	private static String toInterfaceName(Path configFileOrInterface) {
		var name = configFileOrInterface.getFileName().toString();
		var idx = name.lastIndexOf('.');
		return idx == -1 ? name : name.substring(0, idx);
	}

}
