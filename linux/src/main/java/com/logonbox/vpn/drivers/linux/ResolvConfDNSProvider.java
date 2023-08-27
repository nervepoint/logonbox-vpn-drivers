package com.logonbox.vpn.drivers.linux;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public class ResolvConfDNSProvider implements DNSProvider {

    private PlatformService<?> platform;

    @Override
    public List<DNSEntry> entries() throws IOException {
        var dir = Paths.get("/var/run/resolvconf/interfaces");
        if(Files.exists(dir)) {
            var l = new ArrayList<DNSEntry>();
            try(var str = Files.newDirectoryStream(dir, f -> f.getFileName().toString().startsWith(resolvconfIfacePrefix() + "."))) {
                for(var f : str) {
                    l.add(dnsEntry(f));
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

    private DNSEntry dnsEntry(Path resolvConf) throws IOException {
        try(var rdr = Files.newBufferedReader(resolvConf)) {
            String line;
            var bldr = new DNSEntry.Builder();
            while( ( line = rdr.readLine() ) != null) {
                if(line.startsWith("nameserver")) {
                    bldr.addServers(line.substring(11).trim().split("\\s+"));
                }
                else if(line.startsWith("search")) {
                    bldr.addDomains(line.substring(7).trim().split("\\s+"));
                }
            }
            return bldr.build();
        }
    }
}
