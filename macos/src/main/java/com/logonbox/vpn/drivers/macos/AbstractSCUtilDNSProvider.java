package com.logonbox.vpn.drivers.macos;

import static com.logonbox.vpn.drivers.lib.util.OsUtil.debugCommandArgs;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractSCUtilDNSProvider implements DNSProvider {
    final static Logger LOG = LoggerFactory.getLogger(AbstractSCUtilDNSProvider.class);

    protected PlatformService<?> platform;

    @Override
    public void init(PlatformService<?> platform) {
        this.platform = platform;        
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        var l = new ArrayList<DNSEntry>();
        DNSEntry.Builder bldr = null;
        for (var line : platform.context().commands().output(debugCommandArgs("scutil", "--dns"))) {
            line = line.trim();
            if(line.startsWith("resolver ")) {
                bldr = new DNSEntry.Builder();
            }
            else if(bldr != null && line.startsWith("search domain")) {
                bldr.addDomains(line.split(":")[1].trim());
            }
            else if(bldr != null && line.startsWith("nameserver[")) {
                bldr.addServers(line.split(":")[1].trim());
            }
            else if(bldr != null && line.startsWith("if_index")) {
                var iface = line.split(" ")[3].trim();
                bldr.withInterface(iface.substring(1, iface.length() - 1));
                l.add(bldr.build());
            }
        }
        
        return l;
    }

}
