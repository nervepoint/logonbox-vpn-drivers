
package com.logonbox.vpn.drivers.linux;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;

public class ResolvConfDNSProvider implements DNSProvider {

    private PlatformService<?> platform;

    @Override
    public List<DNSEntry> entries() throws IOException {
        var dir = interfacesPath();
        if(Files.exists(dir)) {
            var l = new ArrayList<DNSEntry>();
            try(var str = Files.newDirectoryStream(dir)) {
                for(var f : str) {
                	dnsEntry(f).ifPresent(d -> l.add(d));
                }
            }
            return l;
        }
        else
            return Collections.emptyList();
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        if(entry.empty()) {
            unset(entry);
        }
        else {
            var sw = new StringWriter();
            try (var pw = new PrintWriter(sw)) {
                pw.println(String.format("nameserver %s", String.join(" ", entry.servers())));
                if(entry.domains().length > 0)
                    pw.println(String.format("search %s", String.join(" ", entry.domains())));
            }
            platform.context().commands().privileged().logged().pipeTo(sw.toString(), "resolvconf", "-a",
                    resolvconfIfacePrefix() + "." + entry.iface(), "-m", "0", "-x");
        }
        
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {
        platform.context().commands().privileged().logged().result("resolvconf", "-d",
                resolvconfIfacePrefix() + "." + entry.iface(), "-f");
        
    }

    @Override
    public void init(PlatformService<?> platform) {
        this.platform = platform;
    }

	protected Path interfacesPath() {
		return LinuxDNSProviderFactory.runPath().resolve("resolvconf").resolve("interface");
	}

    private String resolvconfIfacePrefix() {
        var f = new File("/etc/resolvconf/interface-order");
        if (f.exists()) {
            try (var br = new BufferedReader(new FileReader(f))) {
                String l;
                var p = Pattern.compile("^([A-Za-z0-9-]+)\\*$");
                while ((l = br.readLine()) != null) {
                    var m = p.matcher(l);
                    if (m.matches()) {
                        return m.group(1);
                    }
                }
            } catch (IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
        }
        return "";
    }

    private Optional<DNSEntry> dnsEntry(Path resolvConf) throws IOException {
        try(var rdr = Files.newBufferedReader(resolvConf)) {
            String line;
            var bldr = new DNSEntry.Builder();
            var ifname = resolvConf.getFileName().toString();
            if(ifname.endsWith(".inet")) {
            	ifname = ifname.substring(0, ifname.length() - 4); 
            }
            if(ifname.equals("systemd-resolved")) {
            	var sysd = new SystemDDNSProvider();
            	sysd.init(platform);
            	return sysd.entry(platform.context().getBestLocalNic().getName());
            }
			bldr.withInterface(ifname);
            while( ( line = rdr.readLine() ) != null) {
                if(line.startsWith("nameserver")) {
                    bldr.addServers(line.substring(11).trim().split("\\s+"));
                }
                else if(line.startsWith("search")) {
                    bldr.addDomains(line.substring(7).trim().split("\\s+"));
                }
            }
            return Optional.of(bldr.build());
        }
    }
}
