package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Excludes responses whose body contains any configured marker literal (or
 * regex, using the <code>re:</code> prefix). Useful to drop known noise such
 * as "login required", CAPTCHA walls, rate-limit pages or maintenance pages
 * that would otherwise generate identical SAME/SIMILAR rows. Opt-in; off by
 * default.
 */
public class ResponseMarkerFilter extends RequestFilter {

	public ResponseMarkerFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if (onOffButton.isSelected()) {
			if (response == null || responseInfo == null) {
				return false;
			}
			LiteralMatcher matcher = getLiteralMatcher();
			if (matcher.size() == 0) {
				return false;
			}
			String body;
			if(responseInfo.getBodyOffset() >= 0 && responseInfo.getBodyOffset() < response.length) {
				body = new String(java.util.Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length)).toLowerCase();
			}
			else {
				body = new String(response).toLowerCase();
			}
			if (matcher.anyMatches(body)) {
				incrementFiltered();
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}