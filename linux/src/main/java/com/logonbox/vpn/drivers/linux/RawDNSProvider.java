package com.logonbox.vpn.drivers.linux;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.sshtools.liftlib.ElevatedClosure;

import uk.co.bithatch.nativeimage.annotations.Serialization;

/**
 * Very dumb {@link DNSProvider} that edits /etc/resolv.conf directly, using
 * marker lines to determine what was added by us.
 */
public class RawDNSProvider implements DNSProvider {
    private PlatformService<?> platform;

    private static final String END_LOGONBOX_VPN_RESOLVCONF = "###### END-LOGONBOX-VPN ######";
    private static final String START_LOGONBOX_VPN__RESOLVECONF = "###### START-LOGONBOX-VPN ######";

    @Override
    public void init(PlatformService<?> platform) {
        this.platform = platform;
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        var file = Paths.get("/etc/resolv.conf");
        String line;
        var dns = new ArrayList<DNSEntry.Builder>();
        DNSEntry.Builder systemBldr = null;
        DNSEntry.Builder vpnBldr = null;
        String iface = "wg0";
        try (var r = Files.newBufferedReader(file)) {
            var inLbVpn = false;
            while ((line = r.readLine()) != null) {
                if (line.startsWith(START_LOGONBOX_VPN__RESOLVECONF)) {
                    inLbVpn = true;
                } else if (line.startsWith(END_LOGONBOX_VPN_RESOLVCONF)) {
                    inLbVpn = false;
                } else {
                    line = line.trim();
                    
                    if(inLbVpn && line.startsWith("# net: ")) {
                    	iface = line.substring(7);
                    	vpnBldr = null;
                    }
                    else if(line.isEmpty() || line.startsWith("#")) {
                    	continue;
                    }

                    var l = Arrays.asList(line.split("\\s+"));
                    if(inLbVpn) {
                    	if(vpnBldr == null) {
                    		vpnBldr = new DNSEntry.Builder();
                    		vpnBldr.withInterface(iface);
	                		dns.add(vpnBldr);
	                	}
                        if (l.get(0).equals("nameserver")) 
                        	vpnBldr.addServers(l.subList(1, l.size()));
                        if (l.get(0).equals("search")) 
                        	vpnBldr.addDomains(l.subList(1, l.size()));
                    }
                    else {
                    	if(systemBldr == null) {
                    		systemBldr = new DNSEntry.Builder();
                    		systemBldr.withInterface(IpUtil.getBestLocalNic().getName());
                    		dns.add(0, systemBldr);
                    	}
                        if (l.get(0).equals("nameserver")) 
                        	systemBldr.addServers(l.subList(1, l.size()));
                        if (l.get(0).equals("search")) 
                        	systemBldr.addDomains(l.subList(1, l.size()));
                    }
                }
            }
        } 
        return dns.stream().map(bldr -> bldr.build()).collect(Collectors.toList());
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        synchronized (AbstractLinuxPlatformService.lock) {
            try {
                platform.context().commands().privileged().logged().task(new UpdateResolvDotConf(entry.servers(), entry.iface(), entry.domains(), true));
            } catch (IOException ioe) {
                throw ioe;
            } catch (Exception e) {
                throw new IOException("Failed to set DNS.", e);
            }
        }
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {

        synchronized (AbstractLinuxPlatformService.lock) {
            try {
                platform.context().commands().privileged().logged().task(new UpdateResolvDotConf(entry.servers(), entry.iface(), entry.domains(), false));
            } catch (IOException ioe) {
                throw ioe;
            } catch (Exception e) {
                throw new IOException("Failed to set DNS.", e);
            }
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class UpdateResolvDotConf implements ElevatedClosure<Serializable, Serializable> {

        String[] dns;
        boolean add;
        String iface;
        String[] search;

        public UpdateResolvDotConf() {
        }

        UpdateResolvDotConf(String[] dns, String iface, String[] search, boolean add) {
            this.dns = dns;
            this.add = add;
            this.iface = iface;
            this.search = search;
        }

        @Override
        public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
        	
        	var file = Paths.get("/etc/resolv.conf");
        	var outfile = Paths.get("/etc/resolv.conf.out");
            var inIface = "wg0";
            var haveEnd = false;
            var haveStart = false;
            String line;
            try (var r = Files.newBufferedReader(file)) {

                try (var w = new PrintWriter(Files.newBufferedWriter(outfile), true)) {
            	
	                var inLbVpn = false;
	                while ((line = r.readLine()) != null) {
	                    if (line.startsWith(START_LOGONBOX_VPN__RESOLVECONF)) {
	                    	haveStart = true;
	                        inLbVpn = true;
	                    } else if (line.startsWith(END_LOGONBOX_VPN_RESOLVCONF)) {
	                    	haveEnd = true;
	                    	if(add) {
	                    		w.println("# net: " + iface);
	                    		for(var ns : dns) 
		                    		w.println("nameserver " + ns);
	                    		if(search.length >0) 
		                    		w.println("search " + String.join(" ", search));
	                    	}
	                        inLbVpn = false;
	                        inIface = null;
	                    } else {
	                        line = line.trim();
	                        if(inLbVpn) {
		                        
		                        if(inLbVpn && line.startsWith("# net: ")) {
		                        	inIface = line.substring(7);
		                        }
		                        else if(line.isEmpty() || line.startsWith("#")) {
		                        	continue;
		                        }
		
		                        if(iface.equals(inIface)) {
		                        	continue;
		                        }
		                        else 
		                        	w.println(line);
	                        }
	                        else {
	                        	w.println(line);
	                        }
	                    }
	                }
	                
	                if(!haveStart && add) {
	                	w.println(START_LOGONBOX_VPN__RESOLVECONF);
	                }
	                if(!haveEnd && add) {
	                	w.println("# net: " + iface);
                		for(var ns : dns) 
                    		w.println("nameserver " + ns);
                		if(search.length >0) 
                    		w.println("search " + String.join(" ", search));
	                	w.println(END_LOGONBOX_VPN_RESOLVCONF);
	                }
                }
            } 
            Files.move(outfile, file, StandardCopyOption.REPLACE_EXISTING);
            return null;
        }
    }
}
