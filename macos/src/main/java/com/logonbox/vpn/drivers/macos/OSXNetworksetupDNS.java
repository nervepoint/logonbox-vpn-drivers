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
package com.logonbox.vpn.drivers.macos;

import static com.logonbox.vpn.drivers.lib.util.OsUtil.debugCommandArgs;

import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class OSXNetworksetupDNS implements Closeable {
	final static Logger LOG = LoggerFactory.getLogger(OSXNetworksetupDNS.class);

    private final SystemCommands commands;
    
    private final Map<String, OSXService> defaultServices = new HashMap<>();
    private final Map<String, InterfaceDNS> interfaceDns = new HashMap<>();
    private final Map<String, OSXService> currentServices = new HashMap<>();
    private final ScheduledFuture<?> task;
	
	OSXNetworksetupDNS(SystemCommands commands, SystemContext ctx) {
	    this.commands = commands;
		try {
			collectNewServiceDns();
		} catch (IOException e) {
			throw new IllegalStateException("Failed to collect.", e);
		}
        task = ctx.queue().scheduleWithFixedDelay(() -> {
            try {
                collectNewServiceDns();
            } catch (IOException e) {
                LOG.warn("Failed to collect new DNS data.", e);
            }
        }, 1, 1, TimeUnit.MINUTES);
	}
	
	public static class OSXService {
		private String name;
		private Set<String> servers = new LinkedHashSet<>();
		private Set<String> domains =new LinkedHashSet<>();
		
		public OSXService(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}

		public Set<String> getServers() {
			return servers;
		}

		public Set<String> getDomains() {
			return domains;
		}

		@Override
		public String toString() {
			return "OSXService [name=" + name + ", servers=" + servers + ", domains=" + domains + "]";
		}
		
	}
	
	public static class InterfaceDNS {

		private String iface;
		private Set<String> servers = new LinkedHashSet<>();
		private Set<String> domains =new LinkedHashSet<>();
		
		public InterfaceDNS(String iface, String[] dnsSpec) {
			this.iface = iface;
			servers.addAll(Arrays.asList(IpUtil.filterAddresses(dnsSpec)));
			domains.addAll(Arrays.asList(IpUtil.filterNames(dnsSpec)));
		}

		public String getIface() {
			return iface;
		}

		public Set<String> getServers() {
			return servers;
		}

		public Set<String> getDomains() {
			return domains;
		}
	}


	public void configure(InterfaceDNS dns) {
		/* Add an existing interface, AND remove any DNS details from 
		 * the default discovered services. This is to deal with existing
		 * wireguard sessions when the service is first started, for 
		 * example after the service has crashed. We don't
		 * want {@link OSXNetworksetupDNS} thinking that the addresses were default.  
		 */
		if(interfaceDns.containsKey(dns.getIface()))
			throw new IllegalArgumentException(String.format("DNS for interface %s already pushed.", dns.getIface()));
		interfaceDns.put(dns.getIface(), dns);
		for(Map.Entry<String, OSXService> srvEn : defaultServices.entrySet()) {
			srvEn.getValue().getDomains().removeAll(dns.getDomains());
			srvEn.getValue().getServers().removeAll(dns.getServers());
		}
	}
	
	public synchronized void pushDns(InterfaceDNS dns) throws IOException {
		LOG.info("Pushing DNS state for {}", dns.getIface());
		if(interfaceDns.containsKey(dns.getIface()))
			throw new IllegalArgumentException(String.format("DNS for interface %s already pushed.", dns.getIface()));
		interfaceDns.put(dns.getIface(), dns);
		updateDns();
	}
	
	public synchronized void changeDns(InterfaceDNS dns) throws IOException {
		LOG.info("Changing DNS state for {}", dns.getIface());
		interfaceDns.put(dns.getIface(), dns);
		updateDns();
	}
	
	public synchronized void popDns(String iface) throws IOException {
		LOG.info("Popping DNS state for {}", iface);
		if(!interfaceDns.containsKey(iface))
			throw new IllegalArgumentException(String.format("DNS for interface %s not pushed.", iface));
		interfaceDns.remove(iface);
		updateDns();
	}
	
	public synchronized boolean isSet(String iface) {
		return interfaceDns.containsKey(iface);
	}

	protected void updateDns() throws IOException {
		LOG.info("Updating DNS state");
		LOG.info("Current default state: {}", defaultServices.values());
		LOG.info("Current internal state: {}", interfaceDns.values());
		
		/* Get all unique DNS servers and domains */
		var dnsServers = new LinkedHashSet<String>();
		var dnsDomains = new LinkedHashSet<String>();
		for(var ifaceDns : interfaceDns.values()) {
			dnsServers.addAll(ifaceDns.getServers());
			dnsDomains.addAll(ifaceDns.getDomains());
		}
		
		/* Build a new map of defaultServices that merges the original DNS configuration
		 * with all pushed interface dns configuration
		 */
		var newServices = new HashMap<String, OSXService>();
		for(var srvEn : defaultServices.entrySet()) {
			var newSrv = new OSXService(srvEn.getKey());
			newSrv.getServers().addAll(dnsServers);
			newSrv.getServers().addAll(srvEn.getValue().getServers());
			newSrv.getDomains().addAll(dnsDomains);
			newSrv.getDomains().addAll(srvEn.getValue().getDomains());
			newServices.put(srvEn.getKey(), newSrv);
		}

		/* Now actually set the DNS based on this merged map */
		for(Map.Entry<String, OSXService> srvEn : newServices.entrySet()) {
			LOG.info("Setting DNS for service {}", srvEn.getKey());
			var args = new ArrayList<String>(Arrays.asList("networksetup", "-setdnsservers", srvEn.getKey()));
			if(srvEn.getValue().getServers().isEmpty()) 
				args.add("Empty");
			else 
				args.addAll(srvEn.getValue().getServers());
			checkForError(commands.output(OsUtil.debugCommandArgs(args.toArray(new String[0]))));
			args = new ArrayList<>(Arrays.asList("networksetup", "-setsearchdomains", srvEn.getKey()));
			if(srvEn.getValue().getDomains().isEmpty()) 
				args.add("Empty");
			else
				args.addAll(srvEn.getValue().getDomains());
			checkForError(commands.output(OsUtil.debugCommandArgs(args.toArray(new String[0]))));
		}

		commands.privileged().logged().result("dscacheutil", "-flushcache");
		commands.privileged().logged().result("killall", "-HUP", "mDNSResponder");
		
		synchronized(currentServices) {
		    currentServices.clear();
		    currentServices.putAll(newServices);
		}
	}
	

	private Set<String> collectNewServiceDns() throws IOException {
		var foundServices = new HashSet<String>();
		LOG.debug("Running network setup to determine all network service.");
		for(var service : commands.output(debugCommandArgs("networksetup", "-listallnetworkservices"))) {
			if(service.startsWith("*")) {
				service = service.substring(1);
				LOG.debug("{} is disabled service.", service);
			}
			else if(service.startsWith("An asterisk")) {
				continue;
			}
			LOG.debug("{} service found.", service);
			foundServices.add(service);
			
			var srv = defaultServices.get(service);
			if(srv == null) {
				srv = new OSXService(service);
				defaultServices.put(service, srv);
			}
			
			for(var out : commands.output(debugCommandArgs("networksetup", "-getdnsservers", service))) {
				if(out.indexOf(' ') != -1) {
					/* Multi-word message indicating no Dns servers */
					srv.getServers().clear();
					break;
				}
				else {
					if(isDNSAddressUsedByIface(out)) {
						LOG.debug("{} service has %s for DNS, but it supplied by a VPN interface.", service, out);
					}
					else {
						LOG.debug("{} service has %s for DNS.", service, out);
						srv.getServers().add(out);
					}
				}
 			}
			
			for(var out : commands.output(debugCommandArgs("networksetup", "-getsearchdomains", service))) {
				if(out.indexOf(' ') != -1) {
					/* Multi-word message indicating no Dns servers */
					srv.getDomains().clear();
					break;
				}
				else {

					if(isDNSDomainUsedByIface(out)) {
						LOG.debug("{} service has {} for domain search, but it is supplied by a VPN interface.", service, out);
					}
					else {
						LOG.debug("{} service has {} for domain search.", service, out);
						srv.getDomains().add(out);
					}
				}
 			}
		}
		
		/* Remove anything that doesn't exist */
		for(var serviceIt = defaultServices.entrySet().iterator(); serviceIt.hasNext(); ) {
			var serviceEn = serviceIt.next();
			if(!foundServices.contains(serviceEn.getKey())) {
				LOG.debug("Removing service {}, it either doesn't exist or has no DNS configuration.", serviceEn.getKey());
				serviceIt.remove();
			}
		}
		
		return foundServices;
	}
	
	private boolean isDNSAddressUsedByIface(String ip) {
		for(var en : interfaceDns.values()) {
			if(en.getServers().contains(ip)) {
				return true;
			}
		}
		return false;
	}
	
	private boolean isDNSDomainUsedByIface(String ip) {
		for(var en : interfaceDns.values()) {
			if(en.getDomains().contains(ip)) {
				return true;
			}
		}
		return false;
	}

	private void checkForError(Iterable<String> output) throws IOException {
		for(String line : output) {
			if(line.contains("Error"))
				throw new IOException(line);
		}
	}


    @Override
    public void close() throws IOException {
        if(task != null)
            task.cancel(false);
    }
	
}
