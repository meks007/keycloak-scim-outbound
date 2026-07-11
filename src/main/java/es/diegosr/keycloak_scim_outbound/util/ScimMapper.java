package es.diegosr.keycloak_scim_outbound.util;

import org.keycloak.models.UserModel;

import java.util.List;

/** Builds SCIM v2 payloads from Keycloak models. */
public final class ScimMapper {
    public static final String REMOVE_FORM_RFC_PATH_FILTER = "RFC 7644 path filter";
    public static final String REMOVE_FORM_NON_RFC_VALUE_ARRAY = "Non-RFC value array";

    private ScimMapper() { }

    public static String buildCreateUser(UserModel user) {
        return buildCreateUser(user, user != null ? user.getUsername() : "");
    }

    public static String buildCreateUser(UserModel user, String scimUserName) {
        String given = esc(nvl(user != null ? user.getFirstName() : null));
        String family = esc(nvl(user != null ? user.getLastName() : null));
        String email = esc(nvl(user != null ? user.getEmail() : null));
        String username = esc(nvl(scimUserName));
        String externalId = esc(nvl(user != null ? user.getId() : null));
        String active = user != null && user.isEnabled() ? "true" : "false";
        return """
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
              "externalId": "%s",
              "userName": "%s",
              "name": { "givenName": "%s", "familyName": "%s" },
              "emails": [ { "value": "%s", "type": "work", "primary": true } ],
              "active": %s
            }
            """.formatted(externalId, username, given, family, email, active);
    }

    public static String buildPatchUser(UserModel user) {
        return buildPatchUser(user, null);
    }

    public static String buildPatchUser(UserModel user, String externalId) {
        String given = esc(nvl(user != null ? user.getFirstName() : null));
        String family = esc(nvl(user != null ? user.getLastName() : null));
        String email = esc(nvl(user != null ? user.getEmail() : null));
        String active = user != null && user.isEnabled() ? "true" : "false";
        String extId = esc(nvl(externalId));
        String prefix = extId.isEmpty() ? "" : "    {\"op\":\"add\",\"path\":\"externalId\",\"value\":\"" + extId + "\"},\n";
        return "{\n"
                + "  \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                + "  \"Operations\": [\n" + prefix
                + "    {\"op\":\"replace\",\"path\":\"name.givenName\",\"value\":\"" + given + "\"},\n"
                + "    {\"op\":\"replace\",\"path\":\"name.familyName\",\"value\":\"" + family + "\"},\n"
                + "    {\"op\":\"replace\",\"path\":\"emails[primary eq true].value\",\"value\":\"" + email + "\"},\n"
                + "    {\"op\":\"replace\",\"path\":\"active\",\"value\":" + active + "}\n"
                + "  ]\n}\n";
    }

    public static String buildDeactivatePatch() {
        return "{\n  \"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                + "  \"Operations\":[{\"op\":\"replace\",\"path\":\"active\",\"value\":false}]\n}\n";
    }

    public static String buildCreateGroup(String displayName, String externalId) {
        return "{\n  \"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\n"
                + "  \"externalId\":\"" + esc(nvl(externalId)) + "\",\n"
                + "  \"displayName\":\"" + esc(nvl(displayName)) + "\"\n}\n";
    }

    /** Builds a group member add or configured remove PatchOp payload. */
    public static String buildGroupMemberPatch(String op, String memberId, String removeForm) {
        String id = esc(nvl(memberId));
        if ("remove".equals(op) && REMOVE_FORM_RFC_PATH_FILTER.equals(removeForm)) {
            return "{\n  \"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                    + "  \"Operations\":[{\"op\":\"remove\",\"path\":\"members[value eq \\\"" + id + "\\\"]\"}]\n}\n";
        }
        String effectiveOp = "remove".equals(op) ? "remove" : "add";
        return "{\n  \"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                + "  \"Operations\":[{\"op\":\"" + effectiveOp + "\",\"path\":\"members\",\"value\":[{\"value\":\"" + id + "\"}]}]\n}\n";
    }

    public static String buildGroupMemberPatch(String op, String memberId) {
        return buildGroupMemberPatch(op, memberId, REMOVE_FORM_RFC_PATH_FILTER);
    }

    public static String buildGroupMemberReplace(List<String> scimUserIds) {
        StringBuilder members = new StringBuilder("[");
        if (scimUserIds != null) {
            for (String id : scimUserIds) {
                if (members.length() > 1) members.append(',');
                members.append("{\"value\":\"").append(esc(nvl(id))).append("\"}");
            }
        }
        members.append(']');
        return "{\n  \"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                + "  \"Operations\":[{\"op\":\"replace\",\"path\":\"members\",\"value\":" + members + "}]\n}\n";
    }

    public static String buildPatchGroupDisplayName(String newDisplayName) {
        return "{\n  \"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                + "  \"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + esc(nvl(newDisplayName)) + "\"}]\n}\n";
    }

    public static String esc(String value) {
        if (value == null) return "";
        StringBuilder result = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> { if (c < 0x20) result.append(String.format("\\u%04x", (int) c)); else result.append(c); }
            }
        }
        return result.toString();
    }

    public static String nvl(String value) { return value == null ? "" : value; }
}
