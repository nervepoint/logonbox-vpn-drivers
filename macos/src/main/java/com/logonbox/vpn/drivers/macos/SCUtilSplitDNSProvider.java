package com.logonbox.vpn.drivers.macos;

import static java.lang.String.format;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;

public class SCUtilSplitDNSProvider extends AbstractSCUtilDNSProvider {
    final static Logger LOG = LoggerFactory.getLogger(SCUtilSplitDNSProvider.class);

    @Override
    public void set(DNSEntry entry) throws IOException {
        LOG.info("Creating split resolver");
        try(var str = new StringWriter()) {
        	str.append(String.format("d.init%n"));
            str.append(format("d.add ServerAddresses * %s%n", String.join(" ", entry.servers())));
            if(entry.domains().length > 0)
            	str.append(format("d.add SupplementalMatchDomains * %s%n", String.join(" ", entry.domains())));
            str.append(format("set State:/Network/Interface/%s/DNS%nquit%n", entry.iface()));
            System.out.println(str);
            platform.context().commands().privileged().logged().pipeTo(str.toString(), "scutil");
        }
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {
        LOG.info("Removing resolver");
        try(var str = new StringWriter()) {
        	str.append(String.format("d.init%n"));
            str.append(format("remove State:/Network/Interface/%s/DNS%nquit%n", entry.iface()));
            platform.context().commands().privileged().logged().pipeTo(str.toString(), "scutil");
        }
        
    }

}
