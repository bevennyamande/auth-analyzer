package com.protect7.authanalyzer.filter;

import java.awt.Color;
import javax.swing.SwingUtilities;
import java.util.regex.Pattern;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class RequestFilter {
	
	public static final String REGEX_PREFIX = "re:";
	
	protected HintCheckBox onOffButton = null;
	protected int amountOfFilteredRequests = 0;
	protected String[] stringLiterals = null;
	private String[] stringLiteralsLowerCased = null;
	private boolean[] literalIsRegex = null;
	private Pattern[] literalRegexPatterns = null;
	private final int filterIndex;
	private final String description;
	
	public RequestFilter(int filterIndex, String description) {
		this.filterIndex = filterIndex;
		this.description = description;
	}
	
	public void registerOnOffButton(HintCheckBox button) {
		onOffButton = button;
		onOffButton.putClientProperty("html.disable", null);
		onOffButton.setHint(getInfoText());
	}
	
	protected void incrementFiltered() {
		amountOfFilteredRequests++;
		if(onOffButton != null) {
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
					onOffButton.setText(textWihtoutFilterAmount + " (Filtered: " + amountOfFilteredRequests + ")");
					GenericHelper.uiUpdateAnimation(onOffButton, new Color(240, 110, 0));
				}
			});
		}
	}
	
	public void resetFilteredAmount() {
		amountOfFilteredRequests = 0;
		if(onOffButton != null) {
			String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
			onOffButton.setText(textWihtoutFilterAmount);
		}
	}
	
	public abstract boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo, byte[] request, byte[] response);

	public abstract boolean hasStringLiterals();
	
	public String[] getFilterStringLiterals() {
		return stringLiterals;
	}
	
	public void setFilterStringLiterals(String[] stringLiterals) {
		this.stringLiterals = stringLiterals;
		String[] literalsLower = new String[stringLiterals.length];
		boolean[] isRegex = new boolean[stringLiterals.length];
		Pattern[] patterns = new Pattern[stringLiterals.length];
		for(int i=0; i<stringLiterals.length; i++) {
			String literal = stringLiterals[i];
			isRegex[i] = literal.startsWith(REGEX_PREFIX);
			String raw = isRegex[i] ? literal.substring(REGEX_PREFIX.length()) : literal;
			literalsLower[i] = raw.toLowerCase();
			if(isRegex[i]) {
				try {
					patterns[i] = Pattern.compile(raw, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
				} catch (Exception e) {
					// Fall back to literal matching for invalid regex
					isRegex[i] = false;
					patterns[i] = null;
				}
			}
		}
		this.stringLiteralsLowerCased = literalsLower;
		this.literalIsRegex = isRegex;
		this.literalRegexPatterns = patterns;
		if(onOffButton != null) {
			onOffButton.setHint(getInfoText());
		}
	}
	
	/**
	 * Returns the pre-processed literals (regex prefix stripped, lower-cased,
	 * regex compiled). Filters wrapping a call should use these cached copies
	 * instead of parsing the literals on every request.
	 */
	protected LiteralMatcher getLiteralMatcher() {
		return new LiteralMatcher(stringLiteralsLowerCased, literalIsRegex, literalRegexPatterns);
	}
	
	/**
	 * Immutable snapshot of the compiled literals used by matching filters.
	 */
	protected static final class LiteralMatcher {
		private final String[] literalsLower;
		private final boolean[] isRegex;
		private final Pattern[] patterns;
		
		private LiteralMatcher(String[] literalsLower, boolean[] isRegex, Pattern[] patterns) {
			this.literalsLower = literalsLower;
			this.isRegex = isRegex;
			this.patterns = patterns;
		}
		
		public int size() {
			return literalsLower.length;
		}
		
		/**
		 * @return true if any literal or regex pattern matches the given
		 *         lower-cased input.
		 */
		public boolean anyMatches(String inputLowerCased) {
			for(int i=0; i<literalsLower.length; i++) {
				if(literalsLower[i].equals("")) {
					continue;
				}
				if(isRegex[i]) {
					if(patterns[i] != null && patterns[i].matcher(inputLowerCased).find()) {
						return true;
					}
				}
				else if(inputLowerCased.contains(literalsLower[i])) {
					return true;
				}
			}
			return false;
		}
	}
	
	public void setIsSelected(boolean selected) {
		onOffButton.setSelected(selected);
	}
	
	public String toJson() {
		String json = "{\"filterIndex\":"+filterIndex+",\"isSelected\":"+onOffButton.isSelected();
		if(!hasStringLiterals()) {
			json = json + "}";
		}
		else {
			json = json + ",\"stringLiterals\":[";
			for(int i=0; i<getFilterStringLiterals().length; i++) {
				if(i == getFilterStringLiterals().length-1) {
					json = json + "\""+getFilterStringLiterals()[i]+"\"";
				}
				else {
					json = json + "\""+getFilterStringLiterals()[i]+"\",";
				}
			}
			json = json + "]}";
		}
		return json;
	}
	
	public String getInfoText() {
		if (onOffButton != null) {
			if (hasStringLiterals()) {
				return "<html>" + getDescription() + "<br><strong><em>"
						+ GenericHelper.getArrayAsString(getFilterStringLiterals()) + "</em></strong></html>";
			} else {
				return getDescription();
			}
		}
		return "";
	}

	public int getFilterIndex() {
		return filterIndex;
	}

	public String getDescription() {
		return description;
	}
}