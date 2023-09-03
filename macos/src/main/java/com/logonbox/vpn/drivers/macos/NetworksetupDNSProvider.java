package com.logonbox.vpn.drivers.macos;

import static com.logonbox.vpn.drivers.lib.util.OsUtil.debugCommandArgs;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.SystemCommands;
import com.logonbox.vpn.drivers.lib.util.OsUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
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
    private final Map<String, OSXService> currentServices = new HashMap<>();

    @Override
    public void init(PlatformService<?> platform) {
        this.commands = platform.context().commands().logged();
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        collectServiceDns();
        LOG.info("Updating DNS state");
        LOG.info("Current default state: {}", defaultServices.values());

        var newServices = new HashMap<String, OSXService>();
        for (var srvEn : defaultServices.entrySet()) {
            var newSrv = new OSXService(srvEn.getKey());
            newSrv.getServers().addAll(Arrays.asList(entry.servers()));
            newSrv.getServers().addAll(srvEn.getValue().getServers());
            newSrv.getDomains().addAll(Arrays.asList(entry.domains()));
            newSrv.getDomains().addAll(srvEn.getValue().getDomains());
            newServices.put(srvEn.getKey(), newSrv);
        }

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

    @Override
    public void unset(DNSEntry entry) throws IOException {
        collectServiceDns();
        LOG.info("Updating DNS state");
        LOG.info("Current default state: {}", defaultServices.values());

        var newServices = new HashMap<String, OSXService>();
        for (var srvEn : defaultServices.entrySet()) {
            var newSrv = new OSXService(srvEn.getKey());
            newSrv.getServers().addAll(srvEn.getValue().getServers());
            newSrv.getServers().removeAll(Arrays.asList(entry.servers()));
            newSrv.getDomains().addAll(srvEn.getValue().getDomains());
            newSrv.getDomains().removeAll(Arrays.asList(entry.domains()));
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

    private void collectServiceDns() throws IOException {
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
                    LOG.debug("{} service has %s for DNS.", service, out);
                    srv.getServers().add(out);
                }
            }

            for (var out : commands.output(debugCommandArgs("networksetup", "-getsearchdomains", service))) {
                if (out.indexOf(' ') != -1) {
                    /* Multi-word message indicating no Dns servers */
                    srv.getDomains().clear();
                    break;
                } else {
                    LOG.debug("{} service has {} for domain search.", service, out);
                    srv.getDomains().add(out);
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

    private void checkForError(Iterable<String> output) throws IOException {
        for (String line : output) {
            if (line.contains("Error"))
                throw new IOException(line);
        }
    }
}
