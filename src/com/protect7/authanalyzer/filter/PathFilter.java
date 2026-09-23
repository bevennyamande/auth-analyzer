package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Filters requests whose URL path contains any configured literal, or matches
 * any configured regex. Prefix a literal with {@value RequestFilter#REGEX_PREFIX}
 * to treat it as a regular expression (e.g. <code>re:/admin/</code>).
 */
public class PathFilter extends RequestFilter {

	public PathFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if(onOffButton.isSelected() && requestInfo.getUrl().getPath() != null) {
			LiteralMatcher matcher = getLiteralMatcher();
			if(matcher.size() == 0) {
				return false;
			}
			String url = requestInfo.getUrl().getPath().toLowerCase();
			if(matcher.anyMatches(url)) {
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