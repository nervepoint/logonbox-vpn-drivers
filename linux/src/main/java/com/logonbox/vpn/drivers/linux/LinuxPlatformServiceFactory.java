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

import com.logonbox.vpn.drivers.lib.PlatformService;
import com.logonbox.vpn.drivers.lib.PlatformServiceFactory;
import com.logonbox.vpn.drivers.lib.SystemContext;
import com.logonbox.vpn.drivers.lib.VpnAddress;
import com.sshtools.liftlib.OS;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import uk.co.bithatch.nativeimage.annotations.Resource;

@Resource({ "linux-x84-64/.*" })
public class LinuxPlatformServiceFactory implements PlatformServiceFactory {
    final static Logger LOG = LoggerFactory.getLogger(LinuxPlatformServiceFactory.class);

    @Override
    public boolean isSupported() {
        return OS.isLinux();
    }

    @Override
    public PlatformService<? extends VpnAddress> createPlatformService(SystemContext context) {
        PlatformService<? extends VpnAddress> ps = null;
        if (Boolean.getBoolean("logonbox.vpn.forceUserspace")) {
            LOG.warn("Forcing use of userspace implementation through system property.");
        } else if (Boolean.getBoolean("logonbox.vpn.forceKernel")) {
            LOG.warn("Forcing use of kernel implementation through system property.");
            ps = new KernelLinuxPlatformService(context);
        } else {
            var modulesPath = Paths.get("/sys/module/wireguard");
            if (Files.exists(modulesPath)) {
                LOG.info("Found wireguard module, using kernel implementation");
                ps = new KernelLinuxPlatformService(context);
            } else {
                LOG.info("Wireguard module not loaded, trying to load");
                try {
                    if(context.commands().privileged().logged().result("modprobe", "wireguard") == 0) {
                        LOG.info("Wireguard loaded, using kernel driver");
                        ps = new KernelLinuxPlatformService(context);
                    }
                    else
                        LOG.info("Cannot load wireguard, assuming userspace implementation");
                } catch (IOException e) {
                    LOG.info("Cannot detect if wireguard module is available, assuming userspace implementation");
                }
            }
        }
        if(ps == null) {
            ps = new UserspaceLinuxPlatformService(context);
        }
        return ps;
    }

    static String bytesToIpAddress(List<Byte> addr) {
        var b = new byte[addr.size()];
        for (int i = 0; i < addr.size(); i++)
            b[i] = addr.get(i);
        try {
            return InetAddress.getByAddress(b).getHostAddress();
        } catch (UnknownHostException e) {
            throw new UncheckedIOException(e);
        }
    }

}
