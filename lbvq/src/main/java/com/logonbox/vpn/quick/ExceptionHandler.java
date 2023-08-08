package com.logonbox.vpn.quick;

import java.net.UnknownHostException;
import java.text.MessageFormat;

import picocli.CommandLine;
import picocli.CommandLine.Help.Ansi;
import picocli.CommandLine.IExecutionExceptionHandler;
import picocli.CommandLine.ParseResult;

public class ExceptionHandler implements IExecutionExceptionHandler {
	
	private final AbstractCommand cmd;

	public ExceptionHandler(AbstractCommand cmd) {
		this.cmd = cmd;
	}

	@Override
	public int handleExecutionException(Exception ex, CommandLine commandLine, ParseResult parseResult)
			throws Exception {
		var report = new StringBuilder();
		var msg = ex.getMessage() == null ? "An unknown error occured." : ex.getMessage();
		if(ex instanceof UnknownHostException) {
			msg = MessageFormat.format("Could not resolve hostname {0}: Name or service not known.", ex.getMessage());
		}
		report.append(Ansi.AUTO.string("@|red " + cmd.spec.commandLine().getCommandName() + ": " + msg + "|@"));
		report.append(System.lineSeparator());
		if(cmd.verboseExceptions()) {
			Throwable nex = ex;
			int indent = 0;
			while(nex != null) {
				if(indent > 0) {
					report.append(String.format("%" + ( 8 + ((indent - 1 )* 2) ) + "s", ""));
			        report.append(Ansi.AUTO.string("@|red " + (nex.getMessage() == null ? "No message." : nex.getMessage())+ "|@"));
					report.append(System.lineSeparator());
				}
				
				for(var el : nex.getStackTrace()) {
					report.append(String.format("%" + ( 8 + (indent * 2) ) + "s", ""));
					report.append("at ");
					if(el.getModuleName() != null) {
						report.append(el.getModuleName());
						report.append('/');
					}
                    report.append(Ansi.AUTO.string("@|yellow " + el.getClassName() + "." + el.getMethodName() + "|@"));
					if(el.getFileName() != null) {
						report.append('(');
						report.append(el.getFileName());
						if(el.getLineNumber() > -1) {
							report.append(':');
		                    report.append(Ansi.AUTO.string("@|yellow " + String.valueOf(el.getLineNumber()) + "|@"));
							report.append(')');
						}
					}
					report.append(System.lineSeparator());
				}
				indent++;
				nex = nex.getCause();
			}
		}
		System.err.print(report.toString());
		return 0;
	}

}
