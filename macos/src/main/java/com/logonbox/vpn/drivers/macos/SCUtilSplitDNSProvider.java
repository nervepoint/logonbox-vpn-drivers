package com.logonbox.vpn.drivers.macos;

import static java.lang.String.format;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.util.List;

public class SCUtilSplitDNSProvider implements DNSProvider {
    final static Logger LOG = LoggerFactory.getLogger(SCUtilSplitDNSProvider.class);

    private PlatformService<?> platform;

    @Override
    public void init(PlatformService<?> platform) {
        this.platform = platform;        
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        LOG.info("Creating split resolver");
        try(var str = new StringWriter()) {
            str.append(format("d.add ServerAddresses * %s%n", String.join(" ", entry.servers())));
            str.append(format("d.add SupplementalMatchDomains * %s%n", String.join(" ", entry.domains())));
            str.append(format("set State:/Network/Service/%s/DNS%nquit%n", entry.iface()));
            platform.context().commands().privileged().logged().pipeTo(str.toString(), "scutil");
        }
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {
        LOG.info("Removing resolver");
        try(var str = new StringWriter()) {
            str.append(format("remove State:/Network/Service/%s/DNS%nquit%n", entry.iface()));
            platform.context().commands().privileged().logged().pipeTo(str.toString(), "scutil");
        }
        
    }

}
