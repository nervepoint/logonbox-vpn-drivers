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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;

import com.sshtools.forker.common.XKernel32;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.WString;

public class NetworkConfigurationService {

	public static interface TunnelInterface extends Library {
		/** Unused, keys are generated using Java */
		void WireGuardGenerateKeyPair(ByteBuffer publicKey, ByteBuffer privateKey);

		boolean WireGuardTunnelService(WString confFile);
	}

	public static TunnelInterface INSTANCE;

	static {
		INSTANCE = Native.load("tunnel", TunnelInterface.class);
	}

	private static void log(String msgFmt, Object... args) {
		System.out.println(String.format(msgFmt, args));
	}

	/**
	 * main.
	 *
	 * @param args arguments
	 */
	public static void main(String[] args) throws Exception {
		File confFile = null;
		if (args.length == 3 && args[0].equals("/service")) {
			Runtime.getRuntime().addShutdownHook(new Thread() {
				public void run() {
					System.out.println("Shutting down tunneler");
					System.out.flush();
					System.err.flush();
				}
			});
			String cwd = args[1];
			String name = args[2];
			
			XKernel32.INSTANCE.SetCurrentDirectoryW(cwd);

			/* Capture stdout and stderr to a log file */
			FileOutputStream fos = new FileOutputStream(new File("logs" + File.separator + name + "-service.log"));
			System.setErr(new PrintStream(fos, true));
			System.setOut(new PrintStream(fos, true));

			/* Configuration path */
			confFile = new File("conf" + File.separator + "connections" + File.separator + name + ".conf");

			System.out
					.println(String.format("Running from %s for interface %s (configuration %s)", cwd, name, confFile));
			if (!confFile.exists())
				throw new FileNotFoundException(String.format("No configuration file %s", confFile));

		} else if (args.length == 1) {
			confFile = new File(args[0]);
		} else {
			System.err.println(String.format("%s: Unexpected arguments (%d supplied). Use /service <dir> <name>",
					NetworkConfigurationService.class.getName(), args.length));
			System.exit(1);
		}

		NetworkConfigurationService service = new NetworkConfigurationService(confFile);
		System.exit(service.startNetworkService());
	}

	private String name;
	private File confFile;

	public NetworkConfigurationService() {
	}

	public NetworkConfigurationService(File confFile) {
		this.confFile = confFile;
		name = getBasename(confFile.getName());
		System.out.println(String.format("Preparing Wireguard configuration for %s (in %s)", name, confFile));
	}
	
	static String getBasename(String name) {
		int idx = name.indexOf('.');
		return idx == -1 ? name : name.substring(0, idx);
	}


	private int startNetworkService() {
		log("Activating Wireguard configuration for %s (in %s)", name, confFile);
		if (INSTANCE.WireGuardTunnelService(new WString(confFile.getPath()))) {
			log("Wireguard shutdown cleanly for %s", name);
			return 0;
		} else {
			log("%s: Failed to activate %s", NetworkConfigurationService.class.getName(), name);
			return 1;
		}
	}
}
