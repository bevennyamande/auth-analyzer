package com.protect7.authanalyzer.util;

import com.protect7.authanalyzer.entities.Range;

import burp.BurpExtender;

public class Setting {
	
	private final static String DELIMITER = ",";
	
	public static String[] getValueAsArray(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.ARRAY) {
			String[] values = value.split(DELIMITER);
			for(int i=0; i<values.length; i++) {
				values[i] = values[i].trim();
			}
			return values;
		}
		return new String[] {};
	}
	
	public static boolean getValueAsBoolean(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.BOOLEAN) {
			return Boolean.parseBoolean(value);
		}
		return false;
	}
	
	public static int getValueAsInteger(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.INTEGER) {
			return Integer.parseInt(value);
		}
		return -1;
	}
	
	public static String getValueAsString(Item settingsItem) {
		String value = getPersistentSetting(settingsItem.toString());
		if(value == null) {
			value = settingsItem.getDefaultValue();
		}
		return value;
	}
	
	public static void setValue(Item settingItem, String value) {
		BurpExtender.callbacks.saveExtensionSetting(settingItem.toString(), value);
		ResponseComparator.invalidateCaches();
	}
	
	/**
	 * Forces all lazily cached configuration (mask patterns, JSON keys) to reload
	 * on the write of any setting. 
	 */
	public static void refresh() {
		ResponseComparator.invalidateCaches();
	}
	
	private static String getPersistentSetting(String name) {
		if(BurpExtender.callbacks == null) {
			return null;
		}
		return BurpExtender.callbacks.loadExtensionSetting(name);
	}

	
	public enum Item {
		AUTOSET_PARAM_STATIC_PATTERNS("token,code,user,mail,pass,key,csrf,xsrf", 
				Type.ARRAY, "Static Patterns (for Automatically Set Parameters)", null),
		AUTOSET_PARAM_DYNAMIC_PATTERNS("viewstate,eventvalidation,requestverificationtoken", Type.ARRAY,
				"Dynamic Patterns (for Automatically Set Parameters)", null),
		NUMBER_OF_THREADS("5", Type.INTEGER, "Number of Threads (for Request Processing)", new Range(1,50)),
		DELAY_BETWEEN_REQUESTS("0", Type.INTEGER, "Delay between Requests in Milliseconds", new Range(0,60000)),
		ONLY_ONE_THREAD_IF_PROMT_FOR_INPUT("true", Type.BOOLEAN, 
				"One Thread if a Prompt for Input Parameter is present", null),
		APPLY_FILTER_ON_MANUAL_REPEAT("false", Type.BOOLEAN, 
				"Apply Filters on Manual Request Repetition", null),
		STATUS_SAME_RESPONSE_CODE("true", Type.BOOLEAN, 
				"Respect Response Code to flag with Status SAME", null),
		STATUS_SIMILAR_RESPONSE_CODE("true", Type.BOOLEAN, 
				"Respect Response Code to flag with Status SIMILAR", null),
		SIMILARITY_THRESHOLD("85", Type.INTEGER, 
				"Minimum content similarity (percent) required to flag SIMILAR", new Range(50,100)),
		NORMALIZE_BEFORE_COMPARE("true", Type.BOOLEAN, 
				"Mask volatile values (UUID, JWT, timestamps, hashes) before comparing responses", null),
		MASK_PATTERNS("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12},eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+,(?:\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*?)(?:Z|[+-]\\d{2}:?\\d{2})?,(?<!\\d)\\d{13}(?!\\d),[0-9a-fA-F]{32}[0-9a-fA-F]*", Type.ARRAY,
				"Regex patterns of volatile values masked before response comparison (comma separated)", null),
		MASK_JSON_KEYS("token,csrf,xsrf,nonce,requestId,request_id,request-id,traceId,trace_id,trace-id,spanId,span_id,jti,iat,exp,nbf,timestamp,createdAt,created_at,updatedAt,updated_at,expiresAt,expires_at,expiresIn,expires_in,sessionId,session_id", Type.ARRAY,
				"JSON keys whose values are masked before response comparison", null),
		LOGIN_RESPONSE_MARKERS("type=\"password\",type='password',forgot password,please log in,session expired,sign in to continue,/login,/signin", Type.ARRAY,
				"Response markers that indicate a login/expired-session page (blocks SAME/SIMILAR flagging)", null),
		SESSION_EXPIRY_THRESHOLD("5", Type.INTEGER, 
				"Consecutive auth-bounce responses before a session-expiry warning is raised", new Range(1,100)),
		AUTO_PAUSE_SESSION_ON_EXPIRY("true", Type.BOOLEAN, 
				"Automatically pause a session when expired-session is suspected", null),
		MAX_PENDING_REQUESTS("2000", Type.INTEGER, 
				"Max queued requests before new ones are dropped (backpressure)", new Range(100,100000)),
		DUPLICATE_FILTER_SIZE("10000", Type.INTEGER, 
				"Max remembered requests for the Exclude Duplicates filter", new Range(100,1000000));
		
		private final String defaultValue;
		private final Type type;
		private final String description;
		private final Range range;
		
		private Item(String defaultValue, Type type, String description, Range range) {
			this.defaultValue = defaultValue;
			this.type = type;
			this.description = description;
			this.range = range;
		}
		
		public String getDefaultValue() {
			return defaultValue;
		}
		
		public Type getType() {
			return type;
		}

		public String getDescription() {
			return description;
		}
		
		public Range getRange() {
			return range;
		}
	}
	
	public enum Type {
		ARRAY(), STRING(), INTEGER(), BOOLEAN();
	}	
}