package com.logonbox.vpn.drivers.remote.controller;

import com.logonbox.vpn.drivers.lib.VpnAddress;
import com.logonbox.vpn.drivers.remote.lib.RemoteVpnAddress;

import java.io.IOException;
import java.net.NetworkInterface;
import java.util.Optional;

public class BusVpnAddress implements VpnAddress {

    private final RemoteVpnAddress remote;

    BusVpnAddress(RemoteVpnAddress remote) {
        this.remote = remote;
    }

    @Override
    public boolean isUp() {
        return remote.isUp();
    }

    @Override
    public boolean isDefaultGateway() {
        return remote.isDefaultGateway();
    }

    @Override
    public void setDefaultGateway(String address) {
        remote.setDefaultGateway(address);
    }

    @Override
    public void delete() throws IOException {
        remote.delete();
    }

    @Override
    public void down() throws IOException {
        remote.down();
    }

    @Override
    public String getMac() {
        var mac = remote.getMac();
        return mac.equals("") ? null : mac;
    }

    @Override
    public int getMtu() {
        return remote.getMtu();
    }

    @Override
    public String name() {
        return remote.name();
    }

    @Override
    public String displayName() {
        return remote.displayName();
    }

    @Override
    public String nativeName() {
        return remote.nativeName();
    }

    @Override
    public String peer() {
        var peer = remote.peer();
        return peer.equals("") ? null : peer;
    }

    @Override
    public String table() {
        return remote.table();
    }

    @Override
    public void mtu(int mtu) {
        remote.mtu(mtu);
    }

    @Override
    public void up() throws IOException {
        remote.up();
    }

    @Override
    public boolean isLoopback() {
        return remote.isLoopback();
    }

    @Override
    public Optional<NetworkInterface> networkInterface() {
        return Optional.empty();
    }

    @Override
    public String shortName() {
        return remote.shortName();
    }

    @Override
    public boolean hasVirtualName() {
        return remote.hasVirtualName();
    }

}
