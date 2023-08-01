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
package com.logonbox.vpn.drivers.windows;

import com.sshtools.liftlib.OS;
import com.sun.jna.Platform;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.ResourceBundle;

public class WindowsFileSecurity {

    public final static ResourceBundle BUNDLE = ResourceBundle.getBundle(WindowsFileSecurity.class.getName());

    static Logger log = LoggerFactory.getLogger(WindowsFileSecurity.class);

    static void restrictToUser(Path path) throws IOException {
        var file = path.toFile();
        file.setReadable(false, false);
        file.setWritable(false, false);
        file.setExecutable(false, false);
        file.setReadable(true, true);
        file.setWritable(true, true);
        if (Platform.isWindows()) {
            List<AclEntry> acl = new ArrayList<>();
            if (OS.isAdministrator()) {
                try {
                    acl.add(set(true, path, "Administrators", WindowsPlatformServiceImpl.SID_ADMINISTRATORS_GROUP,
                            AclEntryType.ALLOW, AclEntryPermission.values()));
                } catch (Throwable upnfe2) {
                    log.debug("Failed to add administrators permission.", upnfe2);
                }
                try {
                    acl.add(set(true, path, "SYSTEM", WindowsPlatformServiceImpl.SID_SYSTEM, AclEntryType.ALLOW,
                            AclEntryPermission.values()));
                } catch (Throwable upnfe2) {
                    log.debug("Failed to add administrators permission.", upnfe2);
                }
            }
            if (acl.isEmpty()) {
                log.warn(String.format("Only basic permissions set for %s", path));
            } else {
                log.info(String.format("Setting permissions on %s to %s", path, acl));
                AclFileAttributeView aclAttr = Files.getFileAttributeView(path, AclFileAttributeView.class);
                aclAttr.setAcl(acl);
            }
        }
    }

    static void openToEveryone(Path path) throws IOException {
        AclFileAttributeView aclAttr = Files.getFileAttributeView(path, AclFileAttributeView.class);
        List<AclEntry> acl = new ArrayList<>();
        if (OS.isAdministrator()) {
            try {
                acl.add(set(true, path, "Administrators", WindowsPlatformServiceImpl.SID_ADMINISTRATORS_GROUP,
                        AclEntryType.ALLOW, AclEntryPermission.values()));
            } catch (Throwable upnfe2) {
                log.debug("Failed to add administrators permission.", upnfe2);
            }
            try {
                acl.add(set(true, path, "SYSTEM", WindowsPlatformServiceImpl.SID_SYSTEM, AclEntryType.ALLOW,
                        AclEntryPermission.values()));
            } catch (Throwable upnfe2) {
                log.debug("Failed to add administrators permission.", upnfe2);
            }
        }
        try {
            acl.add(set(true, path, "Everyone", WindowsPlatformServiceImpl.SID_WORLD, AclEntryType.ALLOW,
                    AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA));
        } catch (Throwable upnfe) {
            log.warn("Failed to set Everyone permission.", upnfe);
        }
        try {
            acl.add(set(true, path, "Users", WindowsPlatformServiceImpl.SID_USERS, AclEntryType.ALLOW,
                    AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA));
        } catch (Throwable upnfe2) {
            log.warn("Failed to set Users permission.", upnfe2);
        }
        if (acl.isEmpty()) {

            /* No everyone user, fallback to basic java.io.File methods */
            log.warn("Falling back to basic file permissions method.");
            path.toFile().setReadable(true, false);
            path.toFile().setWritable(true, false);
        } else {
            aclAttr.setAcl(acl);
        }
    }

    private static AclEntry set(boolean asGroup, Path path, String name, String sid, AclEntryType type,
            AclEntryPermission... perms) throws IOException {
        try {
            log.debug("Trying to set '" + sid + "' or name of " + name + " on " + path + " as Group: " + asGroup + " : "
                    + type + " : " + Arrays.asList(perms));
            String bestRealName = WindowsPlatformServiceImpl.getBestRealName(sid, name);
            log.debug("Best real name : " + bestRealName);
            return perms(asGroup, path, bestRealName, type, perms);
        } catch (Throwable t) {
            log.debug("Failed to get AclEntry using either SID of '" + sid + "' or name of " + name
                    + ". Attempting using localised name.", t);
            return perms(asGroup, path, name, type, perms);
        }
    }

    private static AclEntry perms(boolean asGroup, Path path, String name, AclEntryType type,
            AclEntryPermission... perms) throws IOException {
        UserPrincipalLookupService upls = path.getFileSystem().getUserPrincipalLookupService();
        UserPrincipal user = asGroup ? upls.lookupPrincipalByGroupName(name) : upls.lookupPrincipalByName(name);
        AclEntry.Builder builder = AclEntry.newBuilder();
        builder.setPermissions(EnumSet.copyOf(Arrays.asList(perms)));
        builder.setPrincipal(user);
        builder.setType(type);
        return builder.build();
    }
}
