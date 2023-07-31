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
package com.logonbox.vpn.drivers.windows.service;

import com.logonbox.vpn.drivers.windows.WindowsIP;
import com.logonbox.vpn.drivers.windows.WindowsPlatformServiceImpl;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;

public class ServiceTest {

	public static void main(String[] args) throws Exception {
		
		if (args.length > 0 && args[0].equals("status")) {
			for (Enumeration<NetworkInterface> nifEn = NetworkInterface.getNetworkInterfaces(); nifEn
					.hasMoreElements();) {
				NetworkInterface nif = nifEn.nextElement();
				System.out.println("   -> " + nif.getName() + " : " + nif.getMTU() + " np:");
			}	
		}
		else if (args.length > 0 && args[0].equals("ips")) {
			WindowsPlatformServiceImpl w = new WindowsPlatformServiceImpl();
			System.out.println("WGs");
			for (WindowsIP ip : w.ips(true)) {
				System.out.println("   -> " + ip.getName());
			}	
			System.out.println("All");
			for (WindowsIP ip : w.ips(false)) {
				System.out.println("   -> " + ip.getName());
			}	
		}
		else if (args.length > 0 && args[0].equals("uninstall")) {

			WindowsPlatformServiceImpl w = new WindowsPlatformServiceImpl();
			if (args.length > 1) {
				w.uninstall(WindowsPlatformServiceImpl.TUNNEL_SERVICE_NAME_PREFIX + "$" + args[1]);
			} else {
				for (int i = 0; i < 50; i++) {
					System.out.println("Uninstall net" + i);
					try {
						w.uninstall(WindowsPlatformServiceImpl.TUNNEL_SERVICE_NAME_PREFIX + "$net" + i);
						w.uninstall("WireGuardTunnel" + "$net" + i);
					} catch (Exception e) {
					}
				}
			}
		} else if (args.length > 0 && args[0].equals("install")) {
			Path cfgFile = Paths.get("TEMP-TEST-WIREGUARD.conf");
			if (!Files.exists(cfgFile)) {
				throw new IllegalStateException("Need " + cfgFile + ", run this tool from the root of its project.");
			}

			String name = args.length > 1 ? args[1] : "net10";

			/* Create a temp directory for the actual config file */
			Path cwd = Paths.get("tmp");
			Path cfgDir = cwd.resolve("conf");
			Path connectionsDir = cfgDir.resolve("connections");
			if (!Files.exists(connectionsDir)) {
				Files.createDirectories(connectionsDir);
			}

			/*
			 * Copy the test config file to a filename with the name of the intferace in it
			 */
			Path netCfgFile = connectionsDir.resolve(name + ".conf");
			try (OutputStream o = Files.newOutputStream(netCfgFile)) {
				try (InputStream i = Files.newInputStream(cfgFile)) {
					i.transferTo(o);
				}
			}

			/* Install the service */
			WindowsPlatformServiceImpl w = new WindowsPlatformServiceImpl();
			w.installService(name, cwd);
		} else
			throw new IllegalArgumentException(
					String.format("Usage: %s <install [netX]|uninstall [netX]>", ServiceTest.class.getName()));
	}
}
