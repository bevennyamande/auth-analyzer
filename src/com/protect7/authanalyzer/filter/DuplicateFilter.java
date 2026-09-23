package com.protect7.authanalyzer.filter;

import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Excludes requests that are byte-identical (method + URL + full request
 * content) to a previously analyzed request within a bounded window. Prevents
 * the same endpoint from flooding the analysis queue when a page loads dozens
 * of identical static or duplicated requests. Opt-in; off by default.
 */
public class DuplicateFilter extends RequestFilter {

	private final LinkedHashMap<String, Boolean> seenRequests = new LinkedHashMap<String, Boolean>();
	private int maxEntries = 10000;

	public DuplicateFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {
		if (onOffButton.isSelected()) {
			byte[] requestBytes = request != null ? request : callbacks.getHelpers().buildHttpMessage(requestInfo.getHeaders(), new byte[0]);
			String key = requestInfo.getMethod() + "\n" + requestInfo.getUrl().toString() + "\n" + sha256Hex(requestBytes);
			synchronized (seenRequests) {
				if (seenRequests.containsKey(key)) {
					incrementFiltered();
					return true;
				}
				seenRequests.put(key, Boolean.TRUE);
				if (seenRequests.size() > maxEntries) {
					maxEntries = Math.max(100, com.protect7.authanalyzer.util.Setting.getValueAsInteger(
							com.protect7.authanalyzer.util.Setting.Item.DUPLICATE_FILTER_SIZE));
				}
				while (seenRequests.size() > maxEntries) {
					java.util.Iterator<Map.Entry<String, Boolean>> it = seenRequests.entrySet().iterator();
					if (it.hasNext()) {
						it.next();
						it.remove();
					}
				}
			}
		}
		return false;
	}

	private String sha256Hex(byte[] data) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(data);
			StringBuilder builder = new StringBuilder();
			for (byte b : hash) {
				builder.append(String.format("%02x", b & 0xff));
			}
			return builder.toString();
		} catch (Exception e) {
			return String.valueOf(data != null ? data.hashCode() : 0);
		}
	}

	public void clearSeenRequests() {
		synchronized (seenRequests) {
			seenRequests.clear();
		}
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}