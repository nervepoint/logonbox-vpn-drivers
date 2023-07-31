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
package com.logonbox.vpn.drivers.lib.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OsUtil {
	public final static Logger LOG = LoggerFactory.getLogger(OsUtil.class);

	public static boolean doesCommandExist(String command) {
		return getPathOfCommandInPath(command) != null;
	}

	public static Path getPathOfCommandInPathOrFail(String command) throws IOException {
		Path p = getPathOfCommandInPath(command);
		if(p == null)
			throw new IOException("Could not location command '" + command + "'.");
		return p;
	}
	
	public static Path getPathOfCommandInPath(String command) {
		Set<String> path = new LinkedHashSet<>(Arrays.asList(System.getenv("PATH").split(File.pathSeparator)));
		if (SystemUtils.IS_OS_MAC_OSX) {
			/* Hack for brew */
			path.add("/usr/local/bin");
		}
		for (String dir : path) {
			Path wg = Paths.get(dir, command);
			if (Files.exists(wg))
				return wg;
		}
		return null;
	}

	public static String[] debugCommandArgs(String... args) {
		LOG.debug("Executing commands: " + String.join(" ", args));
		return args;
	}

    private static final boolean IS_64BIT = is64bit0();
    private static final boolean IS_AARCH64 = isAarch640();

    public static String getOS() {
    	if (SystemUtils.IS_OS_WINDOWS) {
    		return "windows";
    	} else if (SystemUtils.IS_OS_LINUX) {
    		return "linux";
    	} else if (SystemUtils.IS_OS_MAC_OSX) {
    		return "osx";
    	} else {
    		return "other";
    	}
    }

    public static boolean is64bit() {
    	return IS_64BIT;
    }

    public static boolean isAarch64() {
    	return IS_AARCH64;
    }

    public static boolean isAdministrator() {
    	if (SystemUtils.IS_OS_WINDOWS) {
    		try {
    			String programFiles = System.getenv("ProgramFiles");
    			if (programFiles == null) {
    				programFiles = "C:\\Program Files";
    			}
    			Path temp = Files.createTempFile(Paths.get(programFiles), "foo", "txt");
    			temp.toFile().deleteOnExit();
    			Files.delete(temp);
    			return true;
    		} catch (Exception e) {
    			return false;
    		}
    	}
    	if (SystemUtils.IS_OS_UNIX) {
    		return System.getProperty("forker.administratorUsername", System.getProperty("vm.rootUser", "root"))
    				.equals(System.getProperty("user.name"));
    	}
    	return false;
    }

    private static boolean is64bit0() {
    	String systemProp = System.getProperty("com.ibm.vm.bitmode");
    	if (systemProp != null) {
    		return "64".equals(systemProp);
    	}
    	systemProp = System.getProperty("sun.arch.data.model");
    	if (systemProp != null) {
    		return "64".equals(systemProp);
    	}
    	systemProp = System.getProperty("java.vm.version");
    	return systemProp != null && systemProp.contains("_64");
    }

    private static boolean isAarch640() {
    	return "aarch64".equals(System.getProperty("os.arch"));
    }
}
