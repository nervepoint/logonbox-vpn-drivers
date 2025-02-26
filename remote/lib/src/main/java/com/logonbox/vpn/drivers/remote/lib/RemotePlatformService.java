package com.logonbox.vpn.drivers.remote.lib;

import com.logonbox.vpn.drivers.lib.PlatformService;

import org.freedesktop.dbus.annotations.DBusBoundProperty;
import org.freedesktop.dbus.interfaces.DBusInterface;

/**
 * Adapters a {@link PlatformService} to a {@link DBusInterface} to allow VPN
 * interfaces to be remotely controlled over D-Bus. This interface is used both
 * on the node agent side acting as a provider, and the controller (cloud) side
 * acting as a consumer.
 */
public interface RemotePlatformService extends DBusInterface {

    String DBUS_INTERFACE_NAME = "com.logonbox.vpn.drivers.RemotePlatformService";
    String OBJECT_PATH = "/" + DBUS_INTERFACE_NAME.replace('.', '/');
    String BUS_NAME = "com.logonbox.vpn.drivers.Remote";

    /**
     * Get if any adapter exists with the logical name. See
     * {@link PlatformService#adapterExists(String)}.
     * 
     * @param adapterName logical adapter name
     * @return adapter exists
     */
    boolean adapterExists(String adapterName);

    /**
     * Get if any adapter exists with the native name. See
     * {@link PlatformService#addressExists(String)}.
     * 
     * @param nativeName native adapter name
     * @return address exists
     */
    boolean addressExists(String nativeName);

    /**
     * Get if IP forwarding is globally enabled. See
     * {@link PlatformService#isIpForwardingEnabledOnSystem()}.
     * 
     * @return ip forwarding is enabled on system
     */
    @DBusBoundProperty
    boolean isIpForwardingEnabledOnSystem();

    /**
     * Set if IP forwarding is globally enabled. See
     * {@link PlatformService#setIpForwardingEnabledOnSystem(boolean)}.
     * 
     * @param ipForwarding enable ip forwarding globally
     */
    @DBusBoundProperty
    void setIpForwardingEnabledOnSystem(boolean ipForwarding);

    /**
     * Get if the given interface name is valid for this platform. See
     * {@link PlatformService#isValidNativeInterfaceName(String)}.
     * 
     * @param name interface name
     * @return valid name
     */
    boolean isValidNativeInterfaceName(String name);

    /**
     * Get the default gateway for this system. See
     * {@link PlatformService#defaultGateway()}. The array returned consists of 2
     * elements, the native interface name followed by the address. If there is no
     * gateway, an empty array will be returned.
     * 
     * @return default gateway details
     */
    String[] defaultGateway();

    /**
     * Set the default gateway peer. See
     * {@link PlatformService#resetDefaultGatewayPeer()}.
     */
    void resetDefaultGatewayPeer();

    /**
     * Set the default gateway for this system. See
     * {@link PlatformService#defaultGateway(java.util.Optional)}. The array
     * required consists of 2 elements, the native interface name followed by the
     * address. If there is no gateway, an empty array should be used.
     * 
     * @param gw gateway spec
     */
    void defaultGateway(String[] gw);

    /**
     * Get a list of all the native interface names that are configured as active
     * VPN interfaces. See {@link PlatformService#adapters()}.
     * 
     * @return adapters
     */
    String[] adapters();

    /**
     * Get a native interface given its native name. See
     * {@link PlatformService#address(String)}.
     * 
     * @param name name
     * @return native interface
     */
    RemoteVpnAddress address(String name);

    /**
     * Get all available addresses. See {@link PlatformService#addresses()}.
     * 
     * @return addresses
     */
    RemoteVpnAddress[] addresses();

    /**
     * Append a new VPN peer configuration to the interface. See
     * {@link PlatformService#append(com.logonbox.vpn.drivers.lib.VpnAdapter, com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration)}.
     * 
     * @param nativeName    native interface name
     * @param configuration configuration in INI format
     */
    void append(String nativeName, String configuration);

    /**
     * Update a new VPN peer configuration on the interface. See
     * {@link PlatformService#reconfigure(com.logonbox.vpn.drivers.lib.VpnAdapter, com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration)}.
     * 
     * @param nativeName    native interface name
     * @param configuration configuration in INI format
     */
    void reconfigure(String nativeName, String configuration);

    /**
     * Synchronize a VPN peer configuration on the interface. See
     * {@link PlatformService#sync(com.logonbox.vpn.drivers.lib.VpnAdapter, com.logonbox.vpn.drivers.lib.VpnAdapterConfiguration)}.
     * 
     * @param nativeName    native interface name
     * @param configuration configuration in INI format
     */
    void sync(String nativeName, String configuration);

    /**
     * Remove a peer with the given public key from the specified adapter. See
     * {@link PlatformService#remove(com.logonbox.vpn.drivers.lib.VpnAdapter, String)}.
     * 
     * @param nativeName native adapter name
     * @param publicKey  public key of peer
     */
    void remove(String nativeName, String publicKey);

    /**
     * Convert a logical interface name to a native interface name if possible. If
     * not possible or applicable, an empty string will be returned. See
     * {@link PlatformService#interfaceNameToNativeName(String)}.
     * 
     * @param name logical interface name
     * @return native interface name
     */
    String interfaceNameToNativeName(String name);

    /**
     * Convert a native interface name to a logical interface name if possible. If
     * not possible or applicable, an empty string will be returned. See
     * {@link PlatformService#nativeNameToInterfaceName(String)}.
     * 
     * @param name logical interface name
     * @return native interface name
     */
    String nativeNameToInterfaceName(String name);

    /**
     * Get the time in milliseconds of a particular peer on a particular interface
     * since the epoch when the last handshake was received. See
     * {@link PlatformService#getLatestHandshake(com.logonbox.vpn.drivers.lib.VpnAddress, String)}.
     * Zero will be returned if there has never been a handshake.
     * 
     * @param nativeName
     * @param publicKey
     * @return last handshake
     */
    long getLatestHandshake(String nativeName, String publicKey);

    /**
     * Get information about the specified interface. See
     * {@link PlatformService#information(com.logonbox.vpn.drivers.lib.VpnAdapter)}.
     * 
     * @param nativeName native name
     * @return vpn interface information
     */
    RemoteVpnInterfaceInformation information(String nativeName);

    /**
     * Get the configuration of the specified interface as an INI format
     * configuration file. See
     * {@link PlatformService#configuration(com.logonbox.vpn.drivers.lib.VpnAdapter)}.
     * 
     * @param nativeName native interface name
     * @return configuration
     */
    String configuration(String nativeName);

    /**
     * Get the interface name the public key exists on. See
     * {@link PlatformService#getByPublicKey(String)}.
     * 
     * @param publicKey
     * @return native interface name
     */
    String getByPublicKey(String publicKey);

    /**
     * Runs a script in the context of the given configuration and native interface.
     * See
     * {@link PlatformService#runHook(com.logonbox.vpn.drivers.lib.VpnConfiguration, com.logonbox.vpn.drivers.lib.VpnAdapter, String...)}.
     * 
     * @param configuration configuration
     * @param nativeName    native name
     * @param hookScript    script
     */
    void runHook(String configuration, String nativeName, String[] hookScript);

    /**
     * Sets or unsets the NAT mode on the specified interface. See
     * {@link PlatformService#setNat(String, java.util.Optional)}.
     * 
     * @param iface      interface
     * @param mode       mode
     */
    void setNat(String iface, RemoteNATMode mode);

    /**
     * Request to start a new VPN configuration. See
     * {@link PlatformService#start(com.logonbox.vpn.drivers.lib.StartRequest)}.
     * 
     * @param remoteStartRequest start request
     * @return interface name
     */
    String start(RemoteStartRequest remoteStartRequest);

    /**
     * Get the NAT mode for an interface. See {@link PlatformService#getNat(String)}.
     * 
     * @param iface interface
     * @return nat mode
     */
    RemoteNATMode getNat(String iface);

    /**
     * Get the remote gateway peer, if any. Test if {@link RemoteVpnPeer#valid()}, when <code>false</code>,
     * the is no gateway peer.
     * 
     * @return remote gateway peer
     */
    RemoteVpnPeer defaultGatewayPeer();

    /**
     * Set the remote gateway peer, if any. If a {@link RemoteVpnPeer#valid()} is <code>false</code>,
     * any current gateway peer will be unset.
     *  
     * @param peer peer
     */
    void defaultGatewayPeer(RemoteVpnPeer peer);

}
