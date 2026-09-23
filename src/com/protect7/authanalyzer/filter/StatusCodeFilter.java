package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Filters requests whose RESPONSE status code matches any configured pattern.
 * Supports three literal forms (comma separated):
 * <ul>
 * <li>Exact code: <code>304</code></li>
 * <li>Code class: <code>4xx</code> matches 400-499</li>
 * <li>Inclusive range: <code>500-599</code></li>
 * </ul>
 */
public class StatusCodeFilter extends RequestFilter {
	
	public StatusCodeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"304"});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if (onOffButton.isSelected() && responseInfo != null) {
			int statusCode = responseInfo.getStatusCode();
			for (String stringLiteral : stringLiterals) {
				if (stringLiteral.trim().equals("")) {
					continue;
				}
				String literal = stringLiteral.trim().toLowerCase();
				if (literal.matches("[1-9]xx")) {
					// Code class, e.g. "4xx" -> 400-499
					int classValue = Integer.parseInt(literal.substring(0, 1));
					if (statusCode / 100 == classValue) {
						incrementFiltered();
						return true;
					}
				}
				else if (literal.matches("[1-9][0-9][0-9]-[1-9][0-9][0-9]")) {
					// Inclusive range, e.g. "500-599"
					String[] bounds = literal.split("-");
					int lower = Integer.parseInt(bounds[0]);
					int upper = Integer.parseInt(bounds[1]);
					if (statusCode >= lower && statusCode <= upper) {
						incrementFiltered();
						return true;
					}
				}
				else if (literal.matches("[1-9][0-9][0-9]")) {
					// Exact code
					if (statusCode == Integer.parseInt(literal)) {
						incrementFiltered();
						return true;
					}
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