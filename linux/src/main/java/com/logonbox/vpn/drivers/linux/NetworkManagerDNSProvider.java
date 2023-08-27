package com.logonbox.vpn.drivers.linux;

import com.github.jgonian.ipmath.Ipv4;
import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.util.Util;
import com.logonbox.vpn.drivers.linux.dbus.NetworkManager;
import com.logonbox.vpn.drivers.linux.dbus.NetworkManager.Ipv6Address;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.Properties;
import org.freedesktop.dbus.types.UInt32;
import org.freedesktop.dbus.types.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 
 * NetworkManager based DNS provider.
 * 
 * This will be using split DNS if the backend is systemd or dnsmasq, or
 * compatible for default backend.
 * 
 * TODO we need to check the backend in use if NetworkManager is chosen to know
 * if we can do split DNS.
 * 
 * https://wiki.gnome.org/Projects/NetworkManager/DNS
 */

public class NetworkManagerDNSProvider implements DNSProvider {
    private static final String NETWORK_MANAGER_BUS_NAME = "org.freedesktop.NetworkManager";
    private final static Logger LOG = LoggerFactory.getLogger(NetworkManagerDNSProvider.class);

    @SuppressWarnings("unchecked")
    @Override
    public List<DNSEntry> entries() throws IOException {
        var l = new ArrayList<DNSEntry>();
        try (var conn = DBusConnectionBuilder.forSystemBus().build()) {

            var mgr = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, "/org/freedesktop/NetworkManager",
                    NetworkManager.class);

            for (var path : mgr.GetAllDevices()) {

                try {
                    var props = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, path.getPath(), Properties.class);
                    var propsMap = props.GetAll("org.freedesktop.NetworkManager.Device");
                    var ipName = (String) props.Get("org.freedesktop.NetworkManager.Device", "Interface");

                    var bldr = new DNSEntry.Builder();
                    bldr.withInterface(ipName);

                    var ip4Config = (DBusPath) propsMap.get("Ip4Config").getValue();
                    if (ip4Config != null && !ip4Config.getPath().equals("/")) {
                        var settings = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, ip4Config.getPath(),
                                Properties.class);
                        var settingsMap = settings.GetAll("org.freedesktop.NetworkManager.IP4Config");
                        if (settingsMap.containsKey("Searches")) {
                            bldr.addDomains(((Variant<ArrayList<String>>) settingsMap.get("Searches")).getValue());

                        }
                        if (settingsMap.containsKey("Nameservers")) {
                            var ns = (ArrayList<UInt32>) settingsMap.get("Nameservers").getValue();
                            bldr.withIpv4Servers(
                                    ns.stream().map(addr -> uint32ToIpv4Address(addr)).toList().toArray(new String[0]));
                        }
                    }

                    var ip6Config = (DBusPath) propsMap.get("Ip6Config").getValue();
                    if (ip6Config != null && !ip6Config.getPath().equals("/")) {
                        var settings = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, ip6Config.getPath(),
                                Properties.class);
                        var settingsMap = settings.GetAll("org.freedesktop.NetworkManager.IP6Config");
                        if (settingsMap.containsKey("Searches")) {
                            bldr.addDomains(((Variant<ArrayList<String>>) settingsMap.get("Searches")).getValue());

                        }
                        if (settingsMap.containsKey("Nameservers")) {
                            var ns = (ArrayList<ArrayList<Byte>>) settingsMap.get("Nameservers").getValue();
                            bldr.withIpv6Servers(
                                    ns.stream().map(addr -> LinuxPlatformServiceFactory.bytesToIpAddress(addr)).toList()
                                            .toArray(new String[0]));
                        }
                    }

                    l.add(bldr.build());

                } catch (Exception e) {
                    LOG.warn("Skipping {}, error occurred.", path, e);
                }
            }
            return l;
        } catch (DBusException dbe) {
            throw new IOException("Failed to connect to system bus.", dbe);
        }
    }

    @Override
    public void init(PlatformService<?> platform) {
    }

    @Override
    public void set(DNSEntry entry) throws IOException {
        try (var conn = DBusConnectionBuilder.forSystemBus().build()) {
            LOG.info("Setting DNS fo {} to {},{},{} via NetworkManager", entry.iface(),
                    Arrays.asList(entry.ipv4Servers()), Arrays.asList(entry.ipv6Servers()),
                    Arrays.asList(entry.domains()));
            var mgr = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, "/org/freedesktop/NetworkManager",
                    NetworkManager.class);
            var iface = entry.iface();
            doSet(conn, mgr, iface, entry.ipv4Servers(), entry.ipv6Servers(), entry.domains());
        } catch (DBusException dbe) {
            throw new IOException("Failed to connect to system bus.", dbe);
        }
    }

    @Override
    public void unset(DNSEntry entry) throws IOException {
        try (var conn = DBusConnectionBuilder.forSystemBus().build()) {
            LOG.info("Unsetting DNS for via NetworkManager", entry.iface());
            var mgr = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, "/org/freedesktop/NetworkManager",
                    NetworkManager.class);
            doSet(conn, mgr, entry.iface(), new String[0], new String[0], new String[0]);
        } catch (DBusException dbe) {
            throw new IOException("Failed to connect to system bus.", dbe);
        }
    }

    private void doSet(DBusConnection conn, NetworkManager mgr, String iface, String[] ipv4, String[] ipv6,
            String[] domains) throws IOException, DBusException {
        var path = mgr.GetDeviceByIpIface(iface);
        if (path == null)
            throw new IOException(String.format("No interface %s", iface));

        LOG.info("DBus device path is {}", path.getPath());

        var props = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, path.getPath(), Properties.class);
        var propsMap = props.GetAll("org.freedesktop.NetworkManager.Device");
        @SuppressWarnings("unchecked")
        var availableConnections = (List<DBusPath>) propsMap.get("AvailableConnections").getValue();
        for (var availableConnectionPath : availableConnections) {

            LOG.debug("   with connection @ {}", availableConnectionPath);

            var settings = conn.getRemoteObject(NETWORK_MANAGER_BUS_NAME, availableConnectionPath.getPath(),
                    NetworkManager.Settings.Connection.class);
            var settingsMap = settings.GetSettings();

            if (LOG.isDebugEnabled()) {
                for (var en : settingsMap.entrySet()) {
                    LOG.debug("  {}", en.getKey());
                    for (var en2 : en.getValue().entrySet()) {
                        LOG.debug("    {} = {}", en2.getKey(), en2.getValue().getValue());
                    }
                }
            }

            var newSettingsMap = new HashMap<>(settingsMap);

            if (settingsMap.containsKey("ipv4") && "manual".equals(settingsMap.get("ipv4").get("method").getValue())) {
                var ipv4Map = new HashMap<>(settingsMap.get("ipv4"));
                ipv4Map.put("dns-search", new Variant<String[]>(domains));
                ipv4Map.put("dns", new Variant<UInt32[]>(Arrays.asList(ipv4).stream()
                        .map((addr) -> ipv4AddressToUInt32(addr)).collect(Collectors.toList()).toArray(new UInt32[0])));
                newSettingsMap.put("ipv4", ipv4Map);
            }

            if (settingsMap.containsKey("ipv6") && "manual".equals(settingsMap.get("ipv6").get("method").getValue())) {
                var ipv6Map = new HashMap<>(settingsMap.get("ipv6"));
                ipv6Map.put("dns-search", new Variant<String[]>(domains));
                ipv6Map.put("dns",
                        new Variant<Ipv6Address[]>(Arrays.asList(ipv6).stream().map((addr) -> ipv6AddressToStruct(addr))
                                .collect(Collectors.toList()).toArray(new Ipv6Address[0])));
                newSettingsMap.put("ipv6", ipv6Map);
            }

            settings.Update(newSettingsMap);
            settings.Save();
        }
    }

    private UInt32 ipv4AddressToUInt32(String address) {
        var ipv4 = Ipv4.of(address);
        var ipv4val = ipv4.asBigInteger().intValue();
        return new UInt32(Util.byteSwap(ipv4val));
    }

    private String uint32ToIpv4Address(UInt32 address) {
        var ipv4 = Ipv4.of(Integer.toUnsignedLong(Util.byteSwap(address.intValue())));
        return ipv4.toString();
    }

    private Ipv6Address ipv6AddressToStruct(String address) {
        /* TODO */
        throw new UnsupportedOperationException("TODO");
    }
}
