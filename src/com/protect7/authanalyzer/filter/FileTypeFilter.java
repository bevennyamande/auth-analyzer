package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * Filters static / noise requests by file extension or MIME type. The URL
 * match requires a dot boundary (e.g. <code>.js</code>) so paths like
 * <code>/scripts</code> are not accidentally dropped. Both the stated and the
 * inferred MIME type are checked against each configured type.
 */
public class FileTypeFilter extends RequestFilter {
	
	public FileTypeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"js", "script", "css", "png", "jpg", "jpeg", "gif", "svg", "bmp", "woff", "icon", "ico", "map", "webp", "ttf", "otf", "eot", "mp4", "webm", "m4a", "mp3", "woff2", "mjs"});
	}
	
	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response) {		
		if(onOffButton.isSelected()) {
			String path = requestInfo.getUrl().getPath().toLowerCase();
			for(String fileType : stringLiterals) {
				String trimmedType = fileType.trim().toLowerCase();
				if(trimmedType.equals("")) {
					continue;
				}
				if(path.endsWith("." + trimmedType)) {
					incrementFiltered();
					return true;
				}
			}
			// MIME-type check (only makes sense once a response is available)
			if(responseInfo != null) {
				String statedMime = responseInfo.getStatedMimeType().toLowerCase();
				String inferredMime = responseInfo.getInferredMimeType().toLowerCase();
				for(String fileType : stringLiterals) {
					String trimmedType = fileType.trim().toLowerCase();
					if(trimmedType.equals("")) {
						continue;
					}
					if(statedMime.equals(trimmedType) || inferredMime.equals(trimmedType)) {
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