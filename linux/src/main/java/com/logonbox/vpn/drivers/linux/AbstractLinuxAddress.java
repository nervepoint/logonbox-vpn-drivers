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
package com.logonbox.vpn.drivers.linux;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.logonbox.vpn.drivers.lib.AbstractUnixAddress;
import com.logonbox.vpn.drivers.lib.AbstractUnixDesktopPlatformService;
import com.logonbox.vpn.drivers.lib.NativeComponents.Tool;
import com.logonbox.vpn.drivers.lib.util.IpUtil;
import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.logonbox.vpn.drivers.lib.util.Util;

public abstract class AbstractLinuxAddress extends AbstractUnixAddress<AbstractLinuxPlatformService> {

    private static final String NFT_COMMAND = "nft";

    private static final String TABLE_PREFIX = "logonbox-vpn-";

    public final static String TABLE_AUTO = "auto";
    public final static String TABLE_OFF = "off";

    private final static Logger LOG = LoggerFactory.getLogger(AbstractLinuxAddress.class);
    private Set<String> addresses = new LinkedHashSet<>();
    private boolean haveSetFirewall;

    AbstractLinuxAddress(String name, AbstractLinuxPlatformService platform) {
        super(platform, name);
        haveSetFirewall = calcFirewallSet();
    }

    public void addAddress(String address) throws IOException {
        if (addresses.contains(address))
            throw new IllegalStateException(String.format("Interface %s already has address %s", shortName(), address));
        if (addresses.size() > 0 && Util.isNotBlank(peer()))
            throw new IllegalStateException(String.format(
                    "Interface %s is configured to have a single peer %s, so cannot add a second address %s", shortName(),
                    peer(), address));

        if (Util.isNotBlank(peer())) {
            commands.privileged().logged().result("ip", "address", "add", "dev", nativeName(), address, "peer", peer());
        } else
            commands.privileged().logged().result("ip", "address", "add", "dev", nativeName(), address);
        addresses.add(address);
    }

    @Override
    public void delete() throws IOException {
        if (haveSetFirewall) {
            removeFirewall();
        }
        var table = table();
        var fwmark = getFWMark("table");
        if ((Util.isBlank(table) || table.equals(TABLE_AUTO))
                && fwmark > 0 /* && [[ $(wg show "$INTERFACE" allowed-ips) =~ /0(\ |$'\n'|$) ]] */) {
            while (commandOutputMatches(".*lookup " + fwmark + ".*", "ip", "-4", "rule", "show")) {
                commands.privileged().logged().result("ip", "-4", "rule", "delete", "table", String.valueOf(fwmark));
            }
            while (commandOutputMatches(".*from all lookup main suppress_prefixlength 0.*", "ip", "-4", "rule",
                    "show")) {
                commands.privileged().logged().result("ip", "-4", "rule", "delete", "table", "main",
                        "suppress_prefixlength", "0");
            }
            while (commandOutputMatches(".*lookup " + fwmark + ".*", "ip", "-6", "rule", "show")) {
                commands.privileged().logged().result("ip", "-6", "rule", "delete", "table", String.valueOf(fwmark));
            }
            while (commandOutputMatches(".*from all lookup main suppress_prefixlength 0.*", "ip", "-6", "rule",
                    "show")) {
                commands.privileged().logged().result("ip", "-6", "rule", "delete", "table", "main",
                        "suppress_prefixlength", "0");
            }
        }
        onDelete();
    }

    protected abstract void onDelete() throws IOException;

    @Override
    public String displayName() {
        try {
            var iface = getByName(nativeName());
            return iface == null ? "Unknown" : iface.getDisplayName();
        } catch (IOException ioe) {
            return "Unknown";
        }
    }

    @Override
    public void down() throws IOException {

        if (haveSetFirewall) {
            removeFirewall();
        }

        setRoutes(new ArrayList<>());
    }

    public Set<String> getAddresses() {
        return addresses;
    }

    @Override
    public String getMac() {
        try {
            var iface = getByName(nativeName());
            return iface == null ? null : IpUtil.toIEEE802(iface.getHardwareAddress());
        } catch (IOException ioe) {
            return null;
        }
    }

    public boolean hasAddress(String address) {
        return addresses.contains(address);
    }

//    @Override
//    public void setPeer(String peer) {
//        if (!Objects.equals(peer, this.peer())) {
//            if (Util.isNotBlank(peer) && addresses.size() > 1)
//                throw new IllegalStateException(String.format(
//                        "Interface %s is already configured to have multiple addresses, so cannot have a single peer %s",
//                        name(), peer));
//            super.setPeer(peer);
//        }
//    }

    public void removeAddress(String address) throws IOException {
        if (!addresses.contains(address))
            throw new IllegalStateException(String.format("Interface %s not not have address %s", shortName(), address));
        if (addresses.size() > 0 && Util.isNotBlank(peer()))
            throw new IllegalStateException(String.format(
                    "Interface %s is configured to have a single peer %s, so cannot add a second address %s", shortName(),
                    peer(), address));

        commands.privileged().logged().result("ip", "address", "del", address, "dev", nativeName());
        addresses.remove(address);
    }

    public void setAddresses(String... addresses) {
        var addr = Arrays.asList(addresses);
        var exceptions = new ArrayList<Exception>();
        for (var a : addresses) {
            if (!hasAddress(a)) {
                try {
                    addAddress(a);
                } catch (Exception e) {
                    exceptions.add(e);
                }
            }
        }

        for (var a : new ArrayList<>(this.addresses)) {
            if (!addr.contains(a)) {
                try {
                    removeAddress(a);
                } catch (Exception e) {
                    exceptions.add(e);
                }
            }
        }

        if (!exceptions.isEmpty()) {
            var e = exceptions.get(0);
            if (e instanceof RuntimeException)
                throw (RuntimeException) e;
            else
                throw new IllegalArgumentException("Failed to set addresses.", e);
        }
    }

    @Override
    public void setRoutes(Collection<String> allows) throws IOException {

        /* Remove all the current routes for this interface */
        var have = new HashSet<>();
        for (var row : commands.privileged().output("ip", "route", "show", "dev", nativeName())) {
            String[] l = row.split("\\s+");
            if (l.length > 0) {
                have.add(l[0]);
                if (!allows.contains(l[0])) {
                    LOG.info("Removing route {} for {}", l[0], shortName());
                    commands.privileged().logged().result("ip", "route", "del", l[0], "dev", nativeName());
                }
            }
        }

        for (String route : allows) {
            if (!have.contains(route))
                addRoute(route);
        }
    }

    @Override
    public String toString() {
        return "Ip [name=" + name() + ", addresses=" + addresses + ", peer=" + peer() + "]";
    }

    @Override
    public void up() throws IOException {
        if (getMtu() > 0) {
            commands.privileged().logged().result("ip", "link", "set", "mtu", String.valueOf(getMtu()), "up", "dev",
                    nativeName());
        } else {
            /*
             * First detect MTU, then bring up. First try from existing Wireguard
             * connections?
             */
            int tmtu = 0;
            // TODO
//				for (String line : OSCommand.runCommandAndCaptureOutput("wg", "show", name, "endpoints")) {
//				 [[ $endpoint =~ ^\[?([a-z0-9:.]+)\]?:[0-9]+$ ]] || continue
//	                output="$(ip route get "${BASH_REMATCH[1]}" || true)"
//	                [[ ( $output =~ mtu\ ([0-9]+) || ( $output =~ dev\ ([^ ]+) && $(ip link show dev "${BASH_REMATCH[1]}") =~ mtu\ ([0-9]+) ) ) && ${BASH_REMATCH[1]} -gt $mtu ]] && mtu="${BASH_REMATCH[1]}"
            // TODO
//				}

            if (tmtu == 0) {
                /* Not found, try the default route */
                for (var line : commands.privileged().output("ip", "route", "show", "default")) {
                    var t = new StringTokenizer(line);
                    while (t.hasMoreTokens()) {
                        var tk = t.nextToken();
                        if (tk.equals("dev")) {
                            for (var iline : commands.privileged().output("ip", "link", "show", "dev", t.nextToken())) {
                                var it = new StringTokenizer(iline);
                                while (it.hasMoreTokens()) {
                                    var itk = it.nextToken();
                                    if (itk.equals("mtu")) {
                                        tmtu = Integer.parseInt(it.nextToken());
                                        break;
                                    }
                                }
                                break;
                            }
                            break;
                        }
                    }
                    break;
                }
            }

            /* Still not found, use generic default */
            if (tmtu == 0)
                tmtu = 1500;

            /* Subtract 80, because .. */
            tmtu -= 80;

            /* Bring it up! */
            commands.privileged().logged().result("ip", "link", "set", "mtu", String.valueOf(tmtu), "up", "dev",
                    nativeName());
        }
    }
    
    private boolean calcFirewallSet() {
        var nftable = TABLE_PREFIX + nativeName();
        if (OsUtil.doesCommandExist(NFT_COMMAND)) {
            if(LOG.isDebugEnabled()) {
                LOG.debug("Checking if firewall already setup for {} using nft", shortName());
            }
            for(var line : commands.privileged().silentOutput("nft", "list", "ruleset")) {
                if(line.startsWith("table ip " + nftable + "{")) {
                    LOG.info("Firewall is configured using nft");
                   return true;
                }
            }
        } else {
            if(LOG.isDebugEnabled()) {
                LOG.debug("Checking if firewall already setup for {} using iptables", shortName());
            }
            for(var line : commands.privileged().silentOutput("iptables-save")) {
                if(line.contains("LogonBoxVPN rule for " + nativeName())) {
                    LOG.info("Firewall is configured using iptables");
                   return true;
                }
            }
            
        }
        return false;
    }

    private void addDefault(String route) throws IOException {
        int table = getFWMark("table");
        if (table == 0) {
            table = 51820;
            while (!commands.privileged().silentOutput("ip", "-4", "route", "show", "table", String.valueOf(table)).isEmpty()
                    || !commands.privileged().silentOutput("ip", "-6", "route", "show", "table", String.valueOf(table))
                            .isEmpty()) {
                table++;
            }
            commands.privileged().logged().result(platform.context().nativeComponents().tool(Tool.WG), "set", name(), "fwmark",
                    String.valueOf(table));
        }
        var proto = "-4";
        var iptables = "iptables";
        var pf = "ip";

        if (route.matches(".*:.*")) {
            proto = "-6";
            iptables = "ip6tables";
            pf = "ip6";
        }

        commands.privileged().logged().result("ip", proto, "route", "add", route, "dev", nativeName(), "table",
                String.valueOf(table));
        commands.privileged().logged().result("ip", proto, "rule", "add", "not", "fwmark", String.valueOf(table),
                "table", String.valueOf(table));
        commands.privileged().logged().result("ip", proto, "rule", "add", "table", "main", "suppress_prefixlength",
                "0");

        var marker = String.format("-m comment --comment \"LogonBoxVPN rule for %s\"", nativeName());
        var restore = "*raw\n";
        var nftable = TABLE_PREFIX + nativeName();

        var nftcmd = new StringBuilder();
        nftcmd.append(String.format("add table %s %s\n", pf, nftable));
        nftcmd.append(
                String.format("add chain %s %s preraw { type filter hook prerouting priority -300; }\n", pf, nftable));
        nftcmd.append(String.format("add chain %s %s premangle { type filter hook prerouting priority -150; }\n", pf,
                nftable));
        nftcmd.append(String.format("add chain %s %s postmangle { type filter hook postrouting priority -150; }\n", pf,
                nftable));

        var pattern = Pattern.compile(".*inet6?\\ ([0-9a-f:.]+)/[0-9]+.*");
        for (var line : commands.privileged().output("ip", "-o", proto, "addr", "show", "dev", nativeName())) {
            var m = pattern.matcher(line);
            if (!m.matches()) {
                continue;
            }

            restore += String.format("-I PREROUTING ! -i %s -d %s -m addrtype ! --src-type LOCAL -j DROP %s\n", nativeName(),
                    m.group(1), marker);
            nftcmd.append(String.format("add rule %s %s preraw iifname != \"%s\" %s daddr %s fib saddr type != local drop\n", pf,
                    nftable, nativeName(), pf, m.group(1)));
        }

        restore += String.format(
                "COMMIT\n*mangle\n-I POSTROUTING -m mark --mark %d -p udp -j CONNMARK --save-mark %s\n-I PREROUTING -p udp -j CONNMARK --restore-mark %s\nCOMMIT\n",
                table, marker, marker);
        nftcmd.append(String.format("add rule %s %s postmangle meta l4proto udp mark %d ct mark set mark \n", pf, nftable, table));
        nftcmd.append(String.format("add rule %s %s premangle meta l4proto udp meta mark set ct mark \n", pf, nftable));

        if (proto.equals("-4")) {
            commands.privileged().logged().result("sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1");
        }

        if (OsUtil.doesCommandExist(NFT_COMMAND)) {
            LOG.info("Updating firewall: {}", nftcmd.toString());
            var temp = Files.createTempFile("nftvpn", ".fwl");
            try {
                try(var out = Files.newBufferedWriter(temp)) {
                    out.write(nftcmd.toString());
                }
                commands.privileged().logged().pipeTo(nftcmd.toString(), "nft", "-f", temp.toAbsolutePath().toString());
            }
            finally {
                Files.delete(temp);
            }
        } else {
            LOG.info("Updating firewall: {}", restore);
            commands.privileged().logged().pipeTo(restore, iptables + "-restore", "-n");
        }
        haveSetFirewall = true;
    }

    private void addRoute(String route) throws IOException {
        var proto = "-4";
        if (route.matches(".*:.*"))
            proto = "-6";
        if (TABLE_OFF.equals(table()))
            return;
        if (!TABLE_AUTO.equals(table())) {
            commands.privileged().logged().result("ip", proto, "route", "add", route, "dev", nativeName(), "table", table());
        } else if (route.endsWith("/0")) {
            addDefault(route);
        } else {
            try {
                var res = commands.privileged().output("ip", proto, "route", "show", "dev", nativeName(), "match", route)
                        .iterator().next();
                if (Util.isNotBlank(res)) {
                    // Already have
                    return;
                }
            } catch (Exception e) {
            }
            LOG.info("Adding route {} to {} for {}", route, shortName(), proto);
            commands.privileged().logged().result("ip", proto, "route", "add", route, "dev", nativeName());
        }
    }

    private boolean commandOutputMatches(String pattern, String... args) throws IOException {
        for (String line : commands.privileged().output(args)) {
            if (line.matches(pattern))
                return true;
        }
        return false;
    }

    private int getFWMark(String table) {
        try {
            Collection<String> lines = commands.privileged().output(platform.context().nativeComponents().tool(Tool.WG), "show",
                    name(), "fwmark");
            if (lines.isEmpty())
                throw new IOException();
            else {
                String fwmark = lines.iterator().next();
                return AbstractUnixDesktopPlatformService.parseFwMark(fwmark);
            }
        } catch (IOException ioe) {
            return 0;
        }
    }

    private void removeFirewall() throws IOException {
        try {
            if (OsUtil.doesCommandExist(NFT_COMMAND)) {
                var nftcmd = new StringBuilder();
                for (var table : commands.privileged().output("nft", "list", "tables")) {
                    if (table.contains(TABLE_PREFIX)) {
                        nftcmd.append(String.format("%s\n", table));
                    }
                }
                if (nftcmd.length() > 0) {
                    commands.privileged().logged().pipeTo(nftcmd.toString(), "nft", "-f");
                }
            }
            if (OsUtil.doesCommandExist("iptables")) {
                for (var iptables : new String[] { "iptables", "ip6tables" }) {
                    var restore = new StringBuilder();
                    var found = false;
                    for (var line : commands.privileged().output(iptables + "-save")) {
                        if (line.startsWith("*") || line.equals("COMMIT")
                                || line.matches("-A .*-m comment --comment \"LogonBoxVPN rule for " + nativeName() + ".*"))
                            continue;
                        if (line.startsWith("-A"))
                            found = true;
                        restore.append(String.format("%s\n", line.replace("#-A", "-D"))); // TODO is this really #-A?
                    }
                    if (found) {
                        LOG.info("Updating firewall: {}", restore.toString());
                        commands.privileged().logged().pipeTo(restore.toString(), iptables + "-restore", "-n");
                    }
                }
            }
        }
        finally {
            haveSetFirewall = false;
        }

    }


}
