package com.logonbox.vpn.drivers.macos;

import static com.logonbox.vpn.drivers.lib.util.OsUtil.debugCommandArgs;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.util.OsUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NetworksetupDNSProvider implements DNSProvider {
    final static Logger LOG = LoggerFactory.getLogger(NetworksetupDNSProvider.class);

    private SystemCommands commands;

    private final Map<String, OSXService> defaultServices = new HashMap<>();
    private final Map<String, DNSEntry> interfaceDns = new HashMap<>();
    private final Map<String, OSXService> currentServices = new HashMap<>();

    @Override
    public void init(PlatformService<?> platform) {
        this.commands = platform.context().commands();
        try {
            collectNewServiceDns();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        return Collections.unmodifiableList(new ArrayList<DNSEntry>(interfaceDns.values()));
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
//        /* Add an existing interface, AND remove any DNS details from 
//         * the default discovered services. This is to deal with existing
//         * wireguard sessions when the service is first started, for 
//         * example after the service has crashed. We don't
//         * want {@link OSXNetworksetupDNS} thinking that the addresses were default.  
//         */
//        if(interfaceDns.containsKey(entry.iface()))
//            throw new IllegalArgumentException(String.format("DNS for interface %s already pushed.", entry.iface()));
//        interfaceDns.put(entry.iface(), entry);
//        for(Map.Entry<String, OSXService> srvEn : defaultServices.entrySet()) {
//            srvEn.getValue().getDomains().removeAll(Arrays.asList(entry.domains()));
//            srvEn.getValue().getServers().removeAll(Arrays.asList(entry.servers()));
//        }

        LOG.info("Pushing DNS state for {}", entry.iface());
        if (interfaceDns.containsKey(entry.iface()))
            throw new IllegalArgumentException(String.format("DNS for interface %s already pushed.", entry.iface()));
        interfaceDns.put(entry.iface(), entry);
        updateDns();
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {
        LOG.info("Popping DNS state for {}", entry.iface());
        if (!interfaceDns.containsKey(entry.iface()))
            throw new IllegalArgumentException(String.format("DNS for interface %s not pushed.", entry.iface()));
        interfaceDns.remove(entry.iface());
        updateDns();

    }

    public static class OSXService {
        private String name;
        private Set<String> servers = new LinkedHashSet<>();
        private Set<String> domains = new LinkedHashSet<>();

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

    protected void updateDns() throws IOException {
        LOG.info("Updating DNS state");
        LOG.info("Current default state: {}", defaultServices.values());
        LOG.info("Current internal state: {}", interfaceDns.values());

        /* Get all unique DNS servers and domains */
        var dnsServers = new LinkedHashSet<String>();
        var dnsDomains = new LinkedHashSet<String>();
        for (var ifaceDns : interfaceDns.values()) {
            dnsServers.addAll(Arrays.asList(ifaceDns.servers()));
            dnsDomains.addAll(Arrays.asList(ifaceDns.domains()));
        }

        /*
         * Build a new map of defaultServices that merges the original DNS configuration
         * with all pushed interface dns configuration
         */
        var newServices = new HashMap<String, OSXService>();
        for (var srvEn : defaultServices.entrySet()) {
            var newSrv = new OSXService(srvEn.getKey());
            newSrv.getServers().addAll(dnsServers);
            newSrv.getServers().addAll(srvEn.getValue().getServers());
            newSrv.getDomains().addAll(dnsDomains);
            newSrv.getDomains().addAll(srvEn.getValue().getDomains());
            newServices.put(srvEn.getKey(), newSrv);
        }

        /* Now actually set the DNS based on this merged map */
        for (Map.Entry<String, OSXService> srvEn : newServices.entrySet()) {
            LOG.info("Setting DNS for service {}", srvEn.getKey());
            var args = new ArrayList<String>(Arrays.asList("networksetup", "-setdnsservers", srvEn.getKey()));
            if (srvEn.getValue().getServers().isEmpty())
                args.add("Empty");
            else
                args.addAll(srvEn.getValue().getServers());
            checkForError(commands.output(OsUtil.debugCommandArgs(args.toArray(new String[0]))));
            args = new ArrayList<>(Arrays.asList("networksetup", "-setsearchdomains", srvEn.getKey()));
            if (srvEn.getValue().getDomains().isEmpty())
                args.add("Empty");
            else
                args.addAll(srvEn.getValue().getDomains());
            checkForError(commands.output(OsUtil.debugCommandArgs(args.toArray(new String[0]))));
        }

        commands.privileged().logged().result("dscacheutil", "-flushcache");
        commands.privileged().logged().result("killall", "-HUP", "mDNSResponder");

        synchronized (currentServices) {
            currentServices.clear();
            currentServices.putAll(newServices);
        }
    }

    private void collectNewServiceDns() throws IOException {
        var foundServices = new HashSet<String>();
        LOG.debug("Running network setup to determine all network service.");
        for (var service : commands.output(debugCommandArgs("networksetup", "-listallnetworkservices"))) {
            if (service.startsWith("*")) {
                service = service.substring(1);
                LOG.debug("{} is disabled service.", service);
            } else if (service.startsWith("An asterisk")) {
                continue;
            }
            LOG.debug("{} service found.", service);
            foundServices.add(service);

            var srv = defaultServices.get(service);
            if (srv == null) {
                srv = new OSXService(service);
                defaultServices.put(service, srv);
            }

            for (var out : commands.output(debugCommandArgs("networksetup", "-getdnsservers", service))) {
                if (out.indexOf(' ') != -1) {
                    /* Multi-word message indicating no Dns servers */
                    srv.getServers().clear();
                    break;
                } else {
                    if (isDNSAddressUsedByIface(out)) {
                        LOG.debug("{} service has %s for DNS, but it supplied by a VPN interface.", service, out);
                    } else {
                        LOG.debug("{} service has %s for DNS.", service, out);
                        srv.getServers().add(out);
                    }
                }
            }

            for (var out : commands.output(debugCommandArgs("networksetup", "-getsearchdomains", service))) {
                if (out.indexOf(' ') != -1) {
                    /* Multi-word message indicating no Dns servers */
                    srv.getDomains().clear();
                    break;
                } else {

                    if (isDNSDomainUsedByIface(out)) {
                        LOG.debug("{} service has {} for domain search, but it is supplied by a VPN interface.",
                                service, out);
                    } else {
                        LOG.debug("{} service has {} for domain search.", service, out);
                        srv.getDomains().add(out);
                    }
                }
            }
        }

        /* Remove anything that doesn't exist */
        for (var serviceIt = defaultServices.entrySet().iterator(); serviceIt.hasNext();) {
            var serviceEn = serviceIt.next();
            if (!foundServices.contains(serviceEn.getKey())) {
                LOG.debug("Removing service {}, it either doesn't exist or has no DNS configuration.",
                        serviceEn.getKey());
                serviceIt.remove();
            }
        }

    }

    private boolean isDNSAddressUsedByIface(String ip) {
        for (var en : interfaceDns.values()) {
            if (Arrays.asList(en.servers()).contains(ip)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDNSDomainUsedByIface(String ip) {
        for (var en : interfaceDns.values()) {
            if (Arrays.asList(en.domains()).contains(ip)) {
                return true;
            }
        }
        return false;
    }

    private void checkForError(Iterable<String> output) throws IOException {
        for (String line : output) {
            if (line.contains("Error"))
                throw new IOException(line);
        }
    }
}
