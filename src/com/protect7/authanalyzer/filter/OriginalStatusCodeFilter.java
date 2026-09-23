package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Filters requests whose ORIGINAL response did not return an allowed status
 * code. This aggressively reduces false positives: if the baseline (high
 * privilege) request already returned 403/404/405, the replayed responses are
 * pure noise and must not be shown as a potential bypass. Enabled by default,
 * only comparing responses that actually carry a successful (or allowed)
 * baseline status.
 *
 * Supported literal forms (comma separated):
 * <ul>
 * <li>Exact code: <code>200</code></li>
 * <li>Code class: <code>2xx</code> matches 200-299</li>
 * <li>Inclusive range: <code>200-299</code></li>
 * </ul>
 */
public class OriginalStatusCodeFilter extends RequestFilter {

	public OriginalStatusCodeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"200,201,202,203,204,205,206,300,301,302,303,304,305,307,308"});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if (onOffButton.isSelected()) {
			// No response available (e.g. drop-original mode or request-only
			// message) - the baseline is unknown, so do not filter it out.
			if (responseInfo == null) {
				return false;
			}
			int statusCode = responseInfo.getStatusCode();
			for (String stringLiteral : stringLiterals) {
				if (stringLiteral.trim().equals("")) {
					continue;
				}
				String literal = stringLiteral.trim().toLowerCase();
				if (literal.matches("[1-9]xx")) {
					if (statusCode / 100 == Integer.parseInt(literal.substring(0, 1))) {
						return false;
					}
				}
				else if (literal.matches("[1-9][0-9][0-9]-[1-9][0-9][0-9]")) {
					String[] bounds = literal.split("-");
					if (statusCode >= Integer.parseInt(bounds[0]) && statusCode <= Integer.parseInt(bounds[1])) {
						return false;
					}
				}
				else if (literal.matches("[1-9][0-9][0-9]") && statusCode == Integer.parseInt(literal)) {
					return false;
				}
			}
			incrementFiltered();
			return true;
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}