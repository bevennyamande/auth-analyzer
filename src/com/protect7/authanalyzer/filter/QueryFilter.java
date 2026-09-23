package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Filters requests whose query string contains any configured literal, or
 * matches any configured regex. Prefix a literal with
 * {@value RequestFilter#REGEX_PREFIX} to treat it as a regular expression.
 */
public class QueryFilter extends RequestFilter {

	public QueryFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if(onOffButton.isSelected()) {
			if(requestInfo.getUrl().getQuery() != null) {
				LiteralMatcher matcher = getLiteralMatcher();
				if(matcher.size() == 0) {
					return false;
				}
				String query = requestInfo.getUrl().getQuery().toLowerCase();
				if(matcher.anyMatches(query)) {
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