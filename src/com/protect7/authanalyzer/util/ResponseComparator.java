package com.protect7.authanalyzer.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;

import burp.IResponseInfo;

/**
 * Smart response comparison used to flag the BYPASS status of a repeated
 * request. Improves on the naive byte/length comparison by:
 *
 * <ul>
 * <li>Masking volatile values (UUIDs, JWTs, timestamps, hashes, token-like
 * JSON keys) before comparison to avoid false DIFFERENT on dynamic content.</li>
 * <li>Comparing JSON responses structurally.</li>
 * <li>Using a real content-similarity metric (Dice on lines / bigrams)
 * instead of raw length deviation for the SIMILAR status.</li>
 * <li>Recognizing login / expired-session pages and refusing to flag them as a
 * bypass.</li>
 * <li>Comparing the Location header on 3xx responses so a redirect to login is
 * never flagged SAME against a working redirect.</li>
 * </ul>
 */
public class ResponseComparator {

	private static final String MASKED = "~MASKED~";

	private ResponseComparator() {
	}

	public static class ComparisonResult {
		public final BypassConstants status;
		public final String infoText;
		public final boolean loginBounce;

		public ComparisonResult(BypassConstants status, String infoText, boolean loginBounce) {
			this.status = status;
			this.infoText = infoText;
			this.loginBounce = loginBounce;
		}
	}

	public static ComparisonResult compare(byte[] originalResponse, byte[] sessionResponse,
			IResponseInfo originalResponseInfo, IResponseInfo sessionResponseInfo) {
		int originalStatus = originalResponseInfo.getStatusCode();
		int sessionStatus = sessionResponseInfo.getStatusCode();

		String originalBody = bodyAsString(originalResponse, originalResponseInfo);
		String sessionBody = bodyAsString(sessionResponse, sessionResponseInfo);
		String originalHeaders = headersAsString(originalResponseInfo);
		String sessionHeaders = headersAsString(sessionResponseInfo);

		boolean normalize = Setting.getValueAsBoolean(Setting.Item.NORMALIZE_BEFORE_COMPARE);
		boolean respectSameCode = CurrentConfig.getCurrentConfig().isRespectResponseCodeForSameStatus();
		boolean respectSimilarCode = CurrentConfig.getCurrentConfig().isRespectResponseCodeForSimilarStatus();
		int threshold = Setting.getValueAsInteger(Setting.Item.SIMILARITY_THRESHOLD);

		// Login / expired-session detection: if the replayed response is a login
		// page but the original was not, this is a blocked request - never a bypass.
		boolean originalLoginLike = looksLikeLogin(originalBody, originalHeaders);
		boolean sessionLoginLike = looksLikeLogin(sessionBody, sessionHeaders);
		if (sessionLoginLike && !originalLoginLike) {
			return new ComparisonResult(BypassConstants.DIFFERENT,
					"Replay response looks like a login / expired-session page. Original was not.", true);
		}

		// Normalize (mask volatile values)
		String originalNorm = normalize ? applyMasks(originalBody) : originalBody;
		String sessionNorm = normalize ? applyMasks(sessionBody) : sessionBody;

		// 3xx redirect handling - the Location header decides, not the (often
		// empty) body. Redirecting to a login page is not a bypass.
		boolean originalRedirect = isRedirect(originalStatus);
		boolean sessionRedirect = isRedirect(sessionStatus);
		if (originalRedirect || sessionRedirect) {
			String originalLocation = getLocation(originalHeaders);
			String sessionLocation = getLocation(sessionHeaders);
			if (originalRedirect && !sessionRedirect) {
				return new ComparisonResult(BypassConstants.DIFFERENT,
						"Original redirected but session response did not (different access).", false);
			}
			if (!originalRedirect && sessionRedirect) {
				return new ComparisonResult(BypassConstants.DIFFERENT,
						"Session response redirects but original did not (e.g. replay bounced to login).", sessionLoginLike);
			}
			// Both are redirects - compare targets and status
			if (!bothNullOrEqual(originalLocation, sessionLocation)) {
				return new ComparisonResult(BypassConstants.DIFFERENT,
						"Redirect targets differ (e.g. original vs login redirect).", sessionLoginLike);
			}
			if (originalStatus == sessionStatus) {
				return new ComparisonResult(BypassConstants.SAME, null, false);
			}
			return new ComparisonResult(BypassConstants.SIMILAR,
					"Redirects to the same target but status codes differ.", false);
		}

		// SAME: identical normalized body (+ optional identical status code).
		// A bypass flag only makes sense when the baseline was actually
		// accessible - two identical 403/404 pages are not a bypass.
		if (isSuccess(originalStatus) && originalNorm.equals(sessionNorm)
				&& (originalStatus == sessionStatus || !respectSameCode)) {
			return new ComparisonResult(BypassConstants.SAME, null, false);
		}

		// SAME via structural JSON equality after masking volatile keys / values
		JsonElement originalJson = parseJsonLenient(originalNorm);
		JsonElement sessionJson = parseJsonLenient(sessionNorm);
		if (isSuccess(originalStatus) && originalJson != null && sessionJson != null
				&& (originalStatus == sessionStatus || !respectSameCode)
				&& jsonEquivalent(originalJson, sessionJson)) {
			return new ComparisonResult(BypassConstants.SAME, null, false);
		}

		// SIMILAR only makes sense against an accessible baseline. If the original
		// response itself was an error/denied page, similar-length noise is not a
		// potential bypass.
		if (!isSuccess(originalStatus)) {
			return new ComparisonResult(BypassConstants.DIFFERENT,
					"Original status " + originalStatus + " is not a success baseline.", sessionLoginLike);
		}

		if (originalStatus == sessionStatus || !respectSimilarCode) {
			double similarity = contentSimilarity(originalNorm, sessionNorm);
			if (similarity >= threshold / 100.0d) {
				return new ComparisonResult(BypassConstants.SIMILAR, null, false);
			}
		}
		return new ComparisonResult(BypassConstants.DIFFERENT, null, sessionLoginLike);
	}

	private static boolean bothNullOrEqual(String a, String b) {
		if (a == null && b == null) {
			return true;
		}
		if (a == null || b == null) {
			return false;
		}
		return a.trim().equalsIgnoreCase(b.trim());
	}

	private static boolean isRedirect(int status) {
		return status >= 300 && status <= 399;
	}

	public static boolean isSuccess(int status) {
		return status >= 200 && status <= 299;
	}

	private static String bodyAsString(byte[] response, IResponseInfo responseInfo) {
		return new String(Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length));
	}

	private static String headersAsString(IResponseInfo responseInfo) {
		StringBuilder builder = new StringBuilder();
		if (responseInfo.getHeaders() != null) {
			for (String header : responseInfo.getHeaders()) {
				builder.append(header).append("\n");
			}
		}
		return builder.toString();
	}

	private static String getLocation(String headers) {
		if (headers == null) {
			return null;
		}
		for (String line : headers.split("\n")) {
			if (line.toLowerCase().startsWith("location:")) {
				int index = line.indexOf(":");
				if (index != -1 && index + 1 < line.length()) {
					return line.substring(index + 1).trim();
				}
			}
		}
		return null;
	}

	private static boolean looksLikeLogin(String body, String headers) {
		String[] markers = Setting.getValueAsArray(Setting.Item.LOGIN_RESPONSE_MARKERS);
		String bodyLower = body.toLowerCase();
		for (String marker : markers) {
			if (!marker.trim().equals("")) {
				if (bodyLower.contains(marker.toLowerCase())) {
					return true;
				}
			}
		}
		String headersLower = headers.toLowerCase();
		for (String marker : markers) {
			if (!marker.trim().equals("")) {
				if (headersLower.contains(marker.toLowerCase())) {
					return true;
				}
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Volatile value masking
	// ------------------------------------------------------------------

	private static Pattern[] volatilePatterns = null;
	private static boolean volatilePatternsLoaded = false;

	public static void invalidateCaches() {
		volatilePatterns = null;
		volatilePatternsLoaded = false;
		volatileKeySet = null;
		volatileKeySetLoaded = false;
	}

	private static Pattern[] getVolatilePatterns() {
		if (!volatilePatternsLoaded) {
			ArrayList<Pattern> patternList = new ArrayList<Pattern>();
			String[] patterns = Setting.getValueAsArray(Setting.Item.MASK_PATTERNS);
			for (String pattern : patterns) {
				if (!pattern.trim().equals("")) {
					try {
						patternList.add(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
					} catch (Exception e) {
						burp.BurpExtender.callbacks
								.printError("Invalid mask pattern: '" + pattern + "' - " + e.getMessage());
					}
				}
			}
			volatilePatterns = patternList.toArray(new Pattern[patternList.size()]);
			volatilePatternsLoaded = true;
		}
		return volatilePatterns;
	}

	private static String applyMasks(String text) {
		String result = text;
		for (Pattern pattern : getVolatilePatterns()) {
			result = pattern.matcher(result).replaceAll(MASKED);
		}
		return result;
	}

	// ------------------------------------------------------------------
	// Structural JSON comparison
	// ------------------------------------------------------------------

	private static JsonElement parseJsonLenient(String text) {
		try {
			String trimmed = text.trim();
			if (trimmed.isEmpty() || !(trimmed.startsWith("{") || trimmed.startsWith("["))) {
				return null;
			}
			JsonReader reader = new JsonReader(new java.io.StringReader(text));
			reader.setLenient(true);
			JsonElement element = JsonParser.parseReader(reader);
			if (!element.isJsonObject() && !element.isJsonArray()) {
				return null;
			}
			return element;
		} catch (Exception e) {
			return null;
		}
	}

	private static Set<String> volatileKeySet = null;
	private static boolean volatileKeySetLoaded = false;

	private static Set<String> getVolatileKeySet() {
		if (!volatileKeySetLoaded) {
			HashSet<String> keys = new HashSet<String>();
			for (String key : Setting.getValueAsArray(Setting.Item.MASK_JSON_KEYS)) {
				if (!key.trim().equals("")) {
					keys.add(key.trim().toLowerCase());
				}
			}
			volatileKeySet = keys;
			volatileKeySetLoaded = true;
		}
		return volatileKeySet;
	}

	private static boolean jsonEquivalent(JsonElement original, JsonElement session) {
		String originalNorm = normalizeJsonElement(original);
		String sessionNorm = normalizeJsonElement(session);
		return originalNorm.equals(sessionNorm);
	}

	private static String normalizeJsonElement(JsonElement element) {
		if (element.isJsonObject()) {
			JsonObject object = element.getAsJsonObject();
			JsonObject normalized = new JsonObject();
			for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
				String key = entry.getKey();
				if (entry.getValue().isJsonObject() || entry.getValue().isJsonArray()) {
					normalized.add(key, JsonParser.parseString(normalizeJsonElement(entry.getValue())));
				} else {
					if (getVolatileKeySet().contains(key.toLowerCase())
							|| isVolatilePrimitive(entry.getValue())) {
						normalized.addProperty(key, MASKED);
					} else {
						normalized.add(key, entry.getValue());
					}
				}
			}
			return normalized.toString();
		}
		if (element.isJsonArray()) {
			com.google.gson.JsonArray array = new com.google.gson.JsonArray();
			for (JsonElement entry : element.getAsJsonArray()) {
				array.add(JsonParser.parseString(normalizeJsonElement(entry)));
			}
			return array.toString();
		}
		if (element.isJsonPrimitive() && isVolatilePrimitive(element)) {
			return new JsonPrimitive(MASKED).toString();
		}
		return element.toString();
	}

	private static boolean isVolatilePrimitive(JsonElement element) {
		if (!element.isJsonPrimitive()) {
			return false;
		}
		JsonPrimitive primitive = element.getAsJsonPrimitive();
		if (primitive.isNumber()) {
			String numericString = primitive.getAsString();
			// 13-digit epoch milliseconds and long hex-like numbers are volatile
			return numericString.matches("\\d{13}") || numericString.matches("[0-9a-fA-F]{32}[0-9a-fA-F]*");
		}
		if (primitive.isString()) {
			String value = primitive.getAsString();
			if (value.length() >= 24) {
				for (Pattern pattern : getVolatilePatterns()) {
					if (pattern.matcher(value).find()) {
						return true;
					}
				}
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Content similarity (Dice coefficient on lines / bigrams)
	// ------------------------------------------------------------------

	public static double contentSimilarity(String first, String second) {
		if (first.equals(second)) {
			return 1.0d;
		}
		if (first.isEmpty() || second.isEmpty()) {
			return 0.0d;
		}
		String[] firstLines = splitLines(first);
		String[] secondLines = splitLines(second);
		double lineSimilarity = diceLineSimilarity(firstLines, secondLines);
		if ((firstLines.length > 1 || secondLines.length > 1) && lineSimilarity > 0.0d) {
			return lineSimilarity;
		}
		// Single-line payloads (e.g. JSON, plain text) fall back to bigram similarity
		double minLengthDenominator = 2.0d * Math.min(first.length(), second.length())
				/ (double) (first.length() + second.length());
		if (minLengthDenominator < 0.05d) {
			return 0.0d;
		}
		return diceBigramSimilarity(first, second);
	}

	private static String[] splitLines(String text) {
		return text.split("\n");
	}

	private static double diceLineSimilarity(String[] first, String[] second) {
		Map<String, Integer> firstCounts = new HashMap<String, Integer>();
		Map<String, Integer> secondCounts = new HashMap<String, Integer>();
		for (String line : first) {
			countLine(firstCounts, line);
		}
		for (String line : second) {
			countLine(secondCounts, line);
		}
		int matched = 0;
		for (Map.Entry<String, Integer> entry : firstCounts.entrySet()) {
			Integer other = secondCounts.get(entry.getKey());
			if (other != null) {
				matched += Math.min(entry.getValue(), other);
			}
		}
		return (2.0d * matched) / (double) (first.length + second.length);
	}

	private static void countLine(Map<String, Integer> counts, String line) {
		Integer count = counts.get(line);
		counts.put(line, count == null ? 1 : count + 1);
	}

	private static double diceBigramSimilarity(String first, String second) {
		Set<String> firstBigrams = bigrams(first);
		Set<String> secondBigrams = bigrams(second);
		if (firstBigrams.isEmpty() || secondBigrams.isEmpty()) {
			return 0.0d;
		}
		int intersection = 0;
		for (String bigram : firstBigrams) {
			if (secondBigrams.contains(bigram)) {
				intersection++;
			}
		}
		return (2.0d * intersection) / (double) (firstBigrams.size() + secondBigrams.size());
	}

	private static Set<String> bigrams(String text) {
		HashSet<String> set = new HashSet<String>();
		if (text.length() < 2) {
			if (text.length() == 1) {
				set.add(text);
			}
			return set;
		}
		for (int i = 0; i < text.length() - 1; i++) {
			set.add(text.substring(i, i + 2));
		}
		return set;
	}
}