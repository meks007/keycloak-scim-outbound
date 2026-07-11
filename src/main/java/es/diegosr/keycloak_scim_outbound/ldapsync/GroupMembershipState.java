package es.diegosr.keycloak_scim_outbound.ldapsync;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Membership state for LDAP-driven SCIM group synchronization.
 * State and pending flags are transient work records. Provisioned markers are durable
 * provenance records used to find remotely managed groups during scope cleanup.
 */
public record GroupMembershipState(String componentId, String userId, State state) {
    public static final String ATTRIBUTE_NAME = "scimGroupSync.membershipState";
    public static final String PENDING_ATTRIBUTE_NAME = "scimGroupSync.pending";
    public static final String PROVISIONED_ATTRIBUTE_NAME = "scimGroupSync.provisioned";

    public enum State { NEW_ADDED, NEW_DELETED, SENT }

    public String toValue() {
        return "{\"c\":\"" + esc(componentId) + "\",\"u\":\"" + esc(userId)
                + "\",\"s\":\"" + state.name() + "\"}";
    }

    public static String pendingValue(String componentId) { return componentId + ":1"; }
    public static String provisionedValue(String componentId) { return componentId + ":1"; }

    public static Optional<GroupMembershipState> parse(String value) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            String component = extractJsonField(value, "c");
            String user = extractJsonField(value, "u");
            String state = extractJsonField(value, "s");
            if (component == null || user == null || state == null) return Optional.empty();
            return Optional.of(new GroupMembershipState(component, user, State.valueOf(state)));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    public static Optional<GroupMembershipState> findForComponent(List<String> values, String componentId, String userId) {
        for (String raw : values) {
            Optional<GroupMembershipState> parsed = parse(raw);
            if (parsed.isPresent() && componentId.equals(parsed.get().componentId()) && userId.equals(parsed.get().userId())) {
                return parsed;
            }
        }
        return Optional.empty();
    }

    public static List<String> removeAllForComponent(List<String> values, String componentId) {
        List<String> result = new ArrayList<>();
        for (String raw : values) {
            Optional<GroupMembershipState> parsed = parse(raw);
            if (parsed.isEmpty() || !componentId.equals(parsed.get().componentId())) result.add(raw);
        }
        return result;
    }

    private static String extractJsonField(String json, String key) {
        String prefix = "\"" + key + "\":\"";
        int start = json.indexOf(prefix);
        if (start < 0) return null;
        start += prefix.length();
        int end = start;
        while (end < json.length()) {
            if (json.charAt(end) == '\\') { end += 2; continue; }
            if (json.charAt(end) == '"') break;
            end++;
        }
        return end >= json.length() ? null : unescape(json.substring(start, end));
    }

    private static String esc(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static String unescape(String value) {
        if (value == null || !value.contains("\\")) return value;
        StringBuilder result = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length()) {
                char next = value.charAt(++i);
                switch (next) {
                    case '"' -> result.append('"');
                    case '\\' -> result.append('\\');
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    default -> { result.append('\\'); result.append(next); }
                }
            } else result.append(c);
        }
        return result.toString();
    }
}
