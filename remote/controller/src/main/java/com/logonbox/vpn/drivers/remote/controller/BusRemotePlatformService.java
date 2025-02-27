package com.logonbox.vpn.drivers.remote.controller;

import com.logonbox.vpn.drivers.lib.BasePlatformService;
import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.NATMode;
import com.logonbox.vpn.drivers.lib.StartRequest;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration;
import com.logonbox.vpn.drivers.lib.VpnAddress;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.lib.VpnInterfaceInformation;
import com.logonbox.vpn.drivers.lib.VpnPeer;
import com.logonbox.vpn.drivers.remote.lib.RemoteDNSProvider;
import com.logonbox.vpn.drivers.remote.lib.RemoteNATMode;
import com.logonbox.vpn.drivers.remote.lib.RemotePlatformService;
import com.logonbox.vpn.drivers.remote.lib.RemoteStartRequest;
import com.logonbox.vpn.drivers.remote.lib.RemoteVpnPeer;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.exceptions.DBusExecutionException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public final class BusRemotePlatformService extends BasePlatformService<BusVpnAddress> {

    private final RemotePlatformService remote;
    private final SystemContext context;
    private final Optional<DNSProvider> dnsProvider;

    static Optional<RemoteDNSProvider> getDNSProvider(DBusConnection connection) throws DBusException {
        try {
            return Optional.of(connection.getRemoteObject(RemotePlatformService.BUS_NAME, RemoteDNSProvider.OBJECT_PATH,
                    RemoteDNSProvider.class));
        } catch (DBusExecutionException dbee) {
            return Optional.empty();
        }
    }

    public BusRemotePlatformService(SystemContext context, DBusConnection connection) throws DBusException {
        this(context, connection.getRemoteObject(RemotePlatformService.BUS_NAME, RemotePlatformService.OBJECT_PATH,
                RemotePlatformService.class), getDNSProvider(connection));
    }

    public BusRemotePlatformService(SystemContext context, RemotePlatformService remote,
            Optional<RemoteDNSProvider> dnsProvider) {
        this.remote = remote;
        this.context = context;
        this.dnsProvider = dnsProvider.map(BusDNSProvider::new);
    }

    @Override
    public boolean adapterExists(String nativeName) {
        return remote.adapterExists(nativeName);
    }

    @Override
    public List<VpnAdapter> adapters() {
        return Arrays.asList(remote.adapters()).stream().map(a -> new VpnAdapter(this, adapterAddress(a)))
                .toList();
    }

    protected Optional<VpnAddress> adapterAddress(String a) {
        try {
            return Optional.of(address(a));
        }
        catch(Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public BusVpnAddress address(String name) {
        return new BusVpnAddress(remote.address(name));
    }

    @Override
    public List<BusVpnAddress> addresses() {
        return Arrays.asList(remote.addresses()).stream().map(BusVpnAddress::new).toList();
    }

    @Override
    public boolean addressExists(String nativeName) {
        return remote.addressExists(nativeName);
    }

    @Override
    public void append(VpnAdapter vpnAdapter, VpnAdapterConfiguration cfg) throws IOException {
        remote.append(vpnAdapter.address().nativeName(), cfg.write());

    }

    @Override
    public VpnAdapterConfiguration configuration(VpnAdapter adapter) {
        try {
            return new VpnAdapterConfiguration.Builder()
                    .fromFileContent(remote.configuration(adapter.address().nativeName())).build();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public SystemContext context() {
        return context;
    }

    @Override
    public Optional<Gateway> defaultGateway() {
        var gw = remote.defaultGateway();
        if (gw.length == 0)
            return Optional.empty();
        else
            return Optional.of(new Gateway(gw[0], gw[1]));
    }

    @Override
    public void defaultGateway(Optional<Gateway> iface) {
        iface.ifPresentOrElse(i -> {
            remote.defaultGateway(new String[] { i.nativeIface(), i.address() });
        }, () -> {
            remote.defaultGateway(new String[0]);
        });
    }

    @Override
    public Optional<VpnPeer> defaultGatewayPeer() {
        var remotePeer =  remote.defaultGatewayPeer();
        if(remotePeer.valid())
            return Optional.of(remotePeer.toNative());
        else
            return Optional.empty();
    }

    @Override
    public void defaultGatewayPeer(VpnPeer peer) throws IOException {
        remote.defaultGatewayPeer(new RemoteVpnPeer(peer)); 
    }

    @Override
    public Optional<DNSProvider> dns() {
        return dnsProvider;
    }

    @Override
    public Optional<VpnAdapter> getByPublicKey(String publicKey) throws IOException {
        var iface = remote.getByPublicKey(publicKey);
        return iface.equals("") ? Optional.empty() : Optional.of(adapter(iface));
    }

    @Override
    public Instant getLatestHandshake(VpnAddress address, String publicKey) throws IOException {
        return Instant.ofEpochMilli(remote.getLatestHandshake(address.nativeName(), publicKey));
    }

    @Override
    public Optional<NATMode> getNat(String iface) throws IOException {
        return remote.getNat(iface).toNative();
    }

    @Override
    public VpnInterfaceInformation information(VpnAdapter adapter) {
        return remote.information(adapter.address().nativeName()).toNative();
    }

    @Override
    public Optional<String> interfaceNameToNativeName(String name) {
        var nname = remote.interfaceNameToNativeName(name);
        return nname.equals("") ? Optional.empty() : Optional.of(nname);
    }

    @Override
    public boolean isIpForwardingEnabledOnSystem() {
        return remote.isIpForwardingEnabledOnSystem();
    }

    @Override
    public boolean isValidNativeInterfaceName(String name) {
        return remote.isValidNativeInterfaceName(name);
    }

    @Override
    public Optional<String> nativeNameToInterfaceName(String name) {
        var iname = remote.nativeNameToInterfaceName(name);
        return iname.equals("") ? Optional.empty() : Optional.of(iname);
    }

    @Override
    public void openToEveryone(Path path) throws IOException {
        throw new UnsupportedOperationException("Not applicable to remote VPN");
    }

    @Override
    public void reconfigure(VpnAdapter vpnAdapter, VpnAdapterConfiguration cfg) throws IOException {
        remote.reconfigure(vpnAdapter.address().nativeName(), cfg.write());
    }

    @Override
    public void remove(VpnAdapter vpnAdapter, String publicKey) throws IOException {
        remote.remove(vpnAdapter.address().nativeName(), publicKey);
    }

    @Override
    public void resetDefaultGatewayPeer() throws IOException {
        remote.resetDefaultGatewayPeer();
    }

    @Override
    public void restrictToUser(Path path) throws IOException {
        throw new UnsupportedOperationException("Not applicable to remote VPN");
    }

    @Override
    public void runHook(VpnConfiguration configuration, VpnAdapter session, String... hookScript) throws IOException {
        remote.runHook(configuration.write(), session.address().nativeName(), hookScript);
    }

    @Override
    public void setIpForwardingEnabledOnSystem(boolean ipForwarding) {
        remote.setIpForwardingEnabledOnSystem(ipForwarding);
    }

    @Override
    public void setNat(String iface, Optional<NATMode> nat) throws IOException {
        remote.setNat(iface, new RemoteNATMode(nat));
    }

    @Override
    public VpnAdapter start(StartRequest startRequest) throws IOException {
       return adapter(remote.start(new RemoteStartRequest(startRequest)));
    }

    @Override
    public void sync(VpnAdapter vpnAdapter, VpnAdapterConfiguration cfg) throws IOException {
        remote.sync(vpnAdapter.address().nativeName(), cfg.write());

    }

}
