package com.logonbox.vpn.drivers.linux;

import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.sshtools.liftlib.ElevatedClosure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import uk.co.bithatch.nativeimage.annotations.Serialization;

/**
 * Very dumb {@link DNSProvider} that edits /etc/resolv.conf directly, using
 * marker lines to determine what was added by us. It does not support search
 * domains, and it does not support querying of current state.
 */
public class RawDNSProvider implements DNSProvider {
    private final static Logger LOG = LoggerFactory.getLogger(RawDNSProvider.class);
    private PlatformService<?> platform;

    private static final String END_LOGONBOX_VPN_RESOLVCONF = "###### END-LOGONBOX-VPN ######";
    private static final String START_LOGONBOX_VPN__RESOLVECONF = "###### START-LOGONBOX-VPN ######";

    @Override
    public void init(PlatformService<?> platform) {
        this.platform = platform;
    }

    @Override
    public List<DNSEntry> entries() throws IOException {
        throw new UnsupportedOperationException("This DNS provider cannot query current configuration.");
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        synchronized (AbstractLinuxPlatformService.lock) {
            try {
                platform.context().commands().privileged().logged().task(new UpdateResolvDotConf(entry.servers(), true));
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
                platform.context().commands().privileged().logged().task(new UpdateResolvDotConf(entry.servers(), false));
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

        public UpdateResolvDotConf() {
        }

        UpdateResolvDotConf(String[] dns, boolean add) {
            this.dns = dns;
            this.add = add;
        }

        @Override
        public Serializable call(ElevatedClosure<Serializable, Serializable> proxy) throws Exception {
            List<String> headlines = new ArrayList<>();
            List<String> bodylines = new ArrayList<>();
            List<String> taillines = new ArrayList<>();
            List<String> dnslist = new ArrayList<>();
            File file = new File("/etc/resolv.conf");
            String line;
            int sidx = -1;
            int eidx = -1;
            Set<String> rowdns = new HashSet<>();
            try (BufferedReader r = new BufferedReader(new FileReader(file))) {
                int lineNo = 0;
                while ((line = r.readLine()) != null) {
                    if (line.startsWith(START_LOGONBOX_VPN__RESOLVECONF)) {
                        sidx = lineNo;
                    } else if (line.startsWith(END_LOGONBOX_VPN_RESOLVCONF)) {
                        eidx = lineNo;
                    } else {
                        line = line.trim();
                        if (line.startsWith("nameserver")) {
                            List<String> l = Arrays.asList(line.split("\\s+"));
                            rowdns.addAll(l.subList(1, l.size()));
                        }
                        dnslist.addAll(rowdns);
                        if (sidx != -1 && eidx == -1)
                            bodylines.add(line);
                        else {
                            if (sidx == -1 && eidx == -1)
                                headlines.add(line);
                            else
                                taillines.add(line);
                        }
                    }
                    lineNo++;
                }
            } catch (IOException ioe) {
                throw new IllegalStateException("Failed to read resolv.conf", ioe);
            }

            File oldfile = new File("/etc/resolv.conf");
            oldfile.delete();

            if (file.renameTo(oldfile)) {
                LOG.info(String.format("Failed to backup resolv.conf by moving %s to %s", file, oldfile));
            }

            try (PrintWriter pw = new PrintWriter(new FileWriter(file, true))) {
                for (String l : headlines) {
                    pw.println(l);
                }
                if (dns.length > 0) {
                    pw.println(START_LOGONBOX_VPN__RESOLVECONF);
                    if (add) {
                        for (String d : dns) {
                            if (!rowdns.contains(d))
                                pw.println(String.format("nameserver %s", d));
                        }
                    } else {
                        for (String d : dnslist) {
                            if (!Arrays.asList(dns).contains(d)) {
                                pw.println(String.format("nameserver %s", d));
                            }
                        }
                    }
                    pw.println(END_LOGONBOX_VPN_RESOLVCONF);
                }
                for (String l : taillines) {
                    pw.println(l);
                }
            } catch (IOException ioe) {
                throw new IllegalStateException("Failed to write resolv.conf", ioe);
            }
            return null;
        }
    }
}
