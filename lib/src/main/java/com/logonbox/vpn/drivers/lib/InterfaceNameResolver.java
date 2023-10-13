package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class InterfaceNameResolver {
    private final static Logger LOG = LoggerFactory.getLogger(InterfaceNameResolver.class);

	public final static class Result {
		private final Optional<String> interfaceName;
		private final Optional<String> nativeName;
		private final Optional<String> resolvedName;

		private Result(Optional<String> interfaceName, Optional<String> nativeName, Optional<String> resolvedName) {
			super();
			this.interfaceName = interfaceName;
			this.nativeName = nativeName;
			this.resolvedName = resolvedName;
		}

		public Optional<String> iInterfaceName() {
			return interfaceName;
		}

		public Optional<String> nativeName() {
			return nativeName;
		}

		public Optional<String> resolvedName() {
			return resolvedName;
		}

	}

	private PlatformService<?> platform;

	public InterfaceNameResolver(PlatformService<?> platform) {
		this.platform = platform;
	}
	
	public Result resolve(VpnConfiguration configuration, Optional<String> interfaceName, Optional<String> nativeInterfaceName) throws IOException {
		if(interfaceName.isEmpty() && nativeInterfaceName.isEmpty()) {
			/* No specific interface name(s) requested. This would happen when ONLY
			 * the configuration content has been supplied (e.g. with a piped wireguard
			 * configuration in a 'down' command). 
			 * 
			 * In this case, we look for an existing interface that is configured
			 * with the same public key. If we find it, it's interface name becomes
			 * both the native interface name and the wireguard interface name. If there
			 * is no such interface, we find the next available native interface name, and
			 * that will be used (and the same name used for wireguard interface name)  
			 */
			
			LOG.info("No specific interface names requested, detecting");
			var byPk = platform.getByPublicKey(configuration.publicKey()); // TODO maybe inefficient
			if(byPk.isPresent()) {
				var addr = byPk.get().address();
				interfaceName = Optional.of(addr.name());
				nativeInterfaceName = Optional.of(addr.nativeName());
				LOG.info("Found interface {} for {}, using that", addr.shortName(), byPk.get());
			}
			else			
				LOG.info("No existing interfaces matching public key found, will assign next available name");
		}
		else {
			if(nativeInterfaceName.isPresent()) {
				/* An explicit native name was requested, just use that */
				LOG.info("{} was explicitly requested as native name, will use that", nativeInterfaceName.get());
			}
			else {
				/* A wireguard interface name was requested, but no explicit native name.
				 * Look up to see if we already have a mapping. If we do, use that  
				 * native name as if it were requested explicitly. 
				 * 
				 * If we don't have a mapping, then the behaviour is platform specific.
				 * Linux can name interfaces "anything", so the native name is set to
				 * be the same as the wireguard name. Mac would be assigned the next 
				 * free "utun" address, and Windows the next "net".
				 */
				nativeInterfaceName = platform.interfaceNameToNativeName(interfaceName.get());
			}
		}

		/* Resolve actual native name to use. If not already decided, this will be platform 
		 * specific. Linux will use the wireguard name, other platforms will use the next free
		 * native name available
		 */
		var resolvedInterfaceName = nativeInterfaceName.isPresent() ? nativeInterfaceName : interfaceName;
		
		return new Result(interfaceName, nativeInterfaceName, resolvedInterfaceName);
	}
}
