package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class MethodFilter extends RequestFilter {
	
	public MethodFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"OPTIONS"});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if(onOffButton.isSelected()) {
			String requestMethod = requestInfo.getMethod().toLowerCase();
			for(String method : stringLiterals) {
				if(!method.trim().equals("") && requestMethod.equals(method.trim().toLowerCase())) {
					incrementFiltered();
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}