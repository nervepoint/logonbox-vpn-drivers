package com.logonbox.vpn.drivers.remote.node;

import static java.lang.Thread.sleep;

import java.text.MessageFormat;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;

import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;

import com.logonbox.vpn.drivers.lib.AbstractSystemContext;
import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.SystemConfiguration;
import com.logonbox.vpn.drivers.lib.VpnAdapter;
import com.logonbox.vpn.drivers.remote.lib.RemotePlatformService;

public class Node extends AbstractSystemContext implements Callable<Integer> {

    public static void main(String[] args) throws Exception {
        System.exit(new Node().call());
    }

    private final SystemConfiguration cfg;
    
    public Node() {
        cfg = SystemConfiguration.defaultConfiguration();
    }
    
    @Override
    public Integer call() throws Exception {
        var ps = PlatformService.create(this);
        
        var conx = DBusConnectionBuilder.forSessionBus().build();
        conx.requestBusName(RemotePlatformService.BUS_NAME);
        
        new RemotePlatformServiceDelegate(ps, conx);
        
        System.out.println("*Ready*");
        
        sleep(Integer.MAX_VALUE);
        
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
