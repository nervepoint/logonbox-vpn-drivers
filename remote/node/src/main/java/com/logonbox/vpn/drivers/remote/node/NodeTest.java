package com.logonbox.vpn.drivers.remote.node;

import static java.lang.Thread.sleep;
import static java.time.Duration.ofDays;

import com.logonbox.vpn.drivers.lib.AbstractSystemContext;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.remote.lib.RemotePlatformService;

import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;

import java.text.MessageFormat;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;

public class NodeTest extends AbstractSystemContext implements Callable<Integer> {

    public static void main(String[] args) throws Exception {
        System.exit(new NodeTest().call());
    }

    private final SystemConfiguration cfg;
    
    public NodeTest() {
        cfg = SystemConfiguration.defaultConfiguration();
    }
    
    @Override
    public Integer call() throws Exception {
        var ps = PlatformService.create(this);
        
        var conx = DBusConnectionBuilder.forSessionBus().build();
        conx.requestBusName(RemotePlatformService.BUS_NAME);
        
        var addresses = ps.addresses().stream().map(RemoteVpnAddressDelegate::new).
                peek(a -> {
                    try {
                        System.out.println("EXP: " +a);
                        conx.exportObject(a);
                    } catch (DBusException e) {
                        throw new IllegalStateException(e);
                    }
                }).
                toList();
        
        conx.exportObject(new RemotePlatformServiceDelegate(ps, addresses));
        if(ps.dns().isPresent())
            conx.exportObject(new RemoteDNSProviderDelegate(ps.dns().get()));
        
        System.out.println("*Ready*");
        
        sleep(ofDays(Integer.MAX_VALUE));
        
        return 0;
    }

    @Override
    public ScheduledExecutorService queue() {
        throw new UnsupportedOperationException();
    }

    @Override
    public SystemConfiguration configuration() {
        return cfg;
    }

    @Override
    public void addScriptEnvironmentVariables(VpnAdapter connection, Map<String, String> env) {
    }

    @Override
    public void alert(String message, Object... args) {
        System.out.println(MessageFormat.format(message, args));
    }
}
