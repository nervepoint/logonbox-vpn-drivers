package com.logonbox.vpn.drivers.remote.node;

import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.PlatformService.Gateway;
import com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration;
import com.logonbox.vpn.drivers.lib.VpnConfiguration;
import com.logonbox.vpn.drivers.remote.lib.RemoteNATMode;
import com.logonbox.vpn.drivers.remote.lib.RemotePlatformService;
import com.logonbox.vpn.drivers.remote.lib.RemoteStartRequest;
import com.logonbox.vpn.drivers.remote.lib.RemoteVpnAddress;
import com.logonbox.vpn.drivers.remote.lib.RemoteVpnInterfaceInformation;
import com.logonbox.vpn.drivers.remote.lib.RemoteVpnPeer;

import org.freedesktop.dbus.annotations.DBusInterfaceName;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import uk.co.bithatch.nativeimage.annotations.Proxy;
import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@DBusInterfaceName(RemotePlatformServiceDelegate.DBUS_INTERFACE_NAME)
@Proxy
@Reflectable
@TypeReflect(methods = true, classes = true)
public class RemotePlatformServiceDelegate implements RemotePlatformService {

    private final PlatformService<?> delegate;
    private final List<? extends RemoteVpnAddress> addresses;

    public RemotePlatformServiceDelegate(PlatformService<?> delegate, List<? extends RemoteVpnAddress> addresses) {
        this.delegate = delegate;
        this.addresses = addresses;
    }

    @Override
    public String getObjectPath() {
        return OBJECT_PATH;
    }

    @Override
    public boolean adapterExists(String adapterName) {
        return delegate.adapterExists(adapterName);
    }

    @Override
    public boolean addressExists(String nativeName) {
        return delegate.addressExists(nativeName);
    }

    @Override
    public boolean isIpForwardingEnabledOnSystem() {
        return delegate.isIpForwardingEnabledOnSystem();
    }

    @Override
    public void setIpForwardingEnabledOnSystem(boolean ipForwarding) {
        delegate.setIpForwardingEnabledOnSystem(ipForwarding);
    }

    @Override
    public boolean isValidNativeInterfaceName(String name) {
        return delegate.isValidNativeInterfaceName(name);
    }

    @Override
    public String[] defaultGateway() {
        var gw = delegate.defaultGateway();
        return gw.isEmpty() ? new String[0] : new String[] { gw.get().nativeIface(), gw.get().address() };
    }

    @Override
    public void resetDefaultGatewayPeer() {
        try {
            delegate.resetDefaultGatewayPeer();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void defaultGateway(String[] gw) {
        if (gw.length == 0)
            delegate.defaultGateway(Optional.empty());
        else
            delegate.defaultGateway(Optional.of(new Gateway(gw[0], gw[1])));
    }

    @Override
    public String[] adapters() {
        return delegate.adapters().stream().map(a -> a.address().nativeName()).toList().toArray(new String[0]);
    }

    @Override
    public RemoteVpnAddress address(String name) {
        return new RemoteVpnAddressDelegate(delegate.address(name));
    }

    @Override
    public RemoteVpnAddress[] addresses() {
        return addresses.toArray(new RemoteVpnAddress[0]);
    }

    @Override
    public void append(String nativeName, String configuration) {
        try {
            delegate.append(delegate.adapter(nativeName),
                    new VpnAdapterConfiguration.Builder().fromFileContent(configuration).build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ParseException pe) {
            throw new IllegalStateException(pe);
        }
    }

    @Override
    public void reconfigure(String nativeName, String configuration) {
        try {
            delegate.reconfigure(delegate.adapter(nativeName),
                    new VpnAdapterConfiguration.Builder().fromFileContent(configuration).build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ParseException pe) {
            throw new IllegalStateException(pe);
        }
    }

    @Override
    public void sync(String nativeName, String configuration) {
        try {
            delegate.sync(delegate.adapter(nativeName),
                    new VpnAdapterConfiguration.Builder().fromFileContent(configuration).build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ParseException pe) {
            throw new IllegalStateException(pe);
        }

    }

    @Override
    public void remove(String nativeName, String publicKey) {
        try {
            delegate.remove(delegate.adapter(nativeName), publicKey);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public String interfaceNameToNativeName(String name) {
        return delegate.interfaceNameToNativeName(name).orElse("");
    }

    @Override
    public String nativeNameToInterfaceName(String name) {
        return delegate.nativeNameToInterfaceName(name).orElse("");
    }

    @Override
    public long getLatestHandshake(String nativeName, String publicKey) {
        try {
            return delegate.getLatestHandshake(delegate.address(nativeName), publicKey).toEpochMilli();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public RemoteVpnInterfaceInformation information(String nativeName) {
        return new RemoteVpnInterfaceInformation(delegate.information(delegate.adapter(nativeName)));
    }

    @Override
    public String configuration(String nativeName) {
        return delegate.configuration(delegate.adapter(nativeName)).write();
    }

    @Override
    public String getByPublicKey(String publicKey) {
        try {
            return delegate.getByPublicKey(publicKey).map(a -> a.address().nativeName()).orElse("");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void runHook(String configuration, String nativeName, String[] hookScript) {
        var adapter = delegate.adapter(nativeName);
        try {
            var cfg = new VpnConfiguration.Builder().fromFileContent(configuration).build();
            delegate.runHook(cfg, adapter, hookScript);
        }
        catch(IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
        catch(ParseException pe) {
            throw new IllegalArgumentException(pe);
        }
    }

    @Override
    public void setNat(String iface, RemoteNATMode natMode) {
        try {
            delegate.setNat(iface, natMode.toNative());
        }
        catch(IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
        
    }

    @Override
    public String start(RemoteStartRequest remoteStartRequest) {
        try {
            return delegate.start(remoteStartRequest.toNative()).address().nativeName();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public RemoteNATMode getNat(String iface) {
        try {
            return new RemoteNATMode(delegate.getNat(iface));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public RemoteVpnPeer defaultGatewayPeer() {
        return delegate.defaultGatewayPeer().map(RemoteVpnPeer::new).orElseGet(() -> new RemoteVpnPeer());
    }

    @Override
    public void defaultGatewayPeer(RemoteVpnPeer peer) {
        try {
            delegate.defaultGatewayPeer(peer.toNative());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
