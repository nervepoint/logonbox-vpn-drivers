package com.logonbox.vpn.drivers.lib;

public abstract class AbstractSystemContext implements SystemContext {

    private SystemCommands commands;
    private NativeComponents nativeComponents;
    
    protected AbstractSystemContext() {
        commands = new ElevatableSystemCommands();
        nativeComponents = new NativeComponents();
    }

    @Override
    public final SystemCommands commands() {
        return commands;
    }

    @Override
    public final NativeComponents nativeComponents() {
        return nativeComponents;
    }

}
