package es.diegosr.keycloak_scim_outbound.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Area 1 -- PATCH JSON generation.
 * Pure unit tests: no mocks, no Keycloak session needed.
 * ScimMapper is stateless and all methods are static.
 */
class ScimMapperTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    // -------------------------------------------------------------------------
    // Group member add
    // -------------------------------------------------------------------------

    @Test
    void add_containsCorrectOpPathAndValueArray() {
        String json = ScimMapper.buildGroupMemberPatch("add", "scim-user-1");

        assertTrue(json.contains("\"op\":\"add\""));
        assertTrue(json.contains("\"path\":\"members\""));
        assertTrue(json.contains("\"value\":[{\"value\":\"scim-user-1\"}]"));
        assertTrue(json.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
    }

    @Test
    void add_removeFormIsIgnored() {
        String rfcForm = ScimMapper.buildGroupMemberPatch(
                "add", "id-1", ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);
        String nonRfcForm = ScimMapper.buildGroupMemberPatch(
                "add", "id-1", ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY);

        assertEquals(rfcForm, nonRfcForm);
    }

    // -------------------------------------------------------------------------
    // Group member remove -- RFC 7644 path filter (default)
    // -------------------------------------------------------------------------

    @Test
    void remove_rfcPathFilter_usesFilterInPath_noValueArray() {
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", "scim-user-2", ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        assertTrue(json.contains("\"op\":\"remove\""));
        assertTrue(json.contains("members[value eq"));
        assertTrue(json.contains("scim-user-2"));
        assertFalse(json.contains("\"value\":["));
    }

    @Test
    void remove_defaultOverload_matchesExplicitRfcForm() {
        String explicit = ScimMapper.buildGroupMemberPatch(
                "remove", "scim-user-3", ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);
        String defaultForm = ScimMapper.buildGroupMemberPatch("remove", "scim-user-3");

        assertEquals(explicit, defaultForm);
    }

    /**
     * Plain ID (no special chars): JSON must parse and the decoded path must
     * contain the filter with the ID quoted correctly.
     *
     *   id = "asdf"
     *   expected decoded path: members[value eq "asdf"]
     */
    @Test
    void remove_rfcPathFilter_plainId_decodedPathIsCorrect() throws Exception {
        String id = "asdf";
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", id, ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        JsonNode op = JSON.readTree(json).at("/Operations/0");
        assertEquals("remove", op.get("op").asText());
        assertEquals("members[value eq \"asdf\"]", op.get("path").asText());
    }

    /**
     * ID containing a double-quote: the JSON must still parse cleanly and the
     * decoded path must contain the ID with the quote escaped at the SCIM filter
     * level (i.e. \" inside the filter literal).
     *
     *   id = "a\"sdf"  (Java literal: the ID contains one double-quote)
     *   expected decoded path: members[value eq "a\"sdf"]
     */
    @Test
    void remove_rfcPathFilter_idWithQuote_jsonParsesAndDecodedPathEscapesQuote()
            throws Exception {
        String id = "a\"sdf";
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", id, ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        // The raw JSON must be parseable (a single esc() would break the JSON here).
        JsonNode op = JSON.readTree(json).at("/Operations/0");
        assertEquals("remove", op.get("op").asText());

        // After JSON decoding, the path must contain the SCIM-escaped ID.
        String path = op.get("path").asText();
        assertTrue(path.startsWith("members[value eq \""),
                "path must open with members[value eq \"");
        // The decoded filter literal must contain \" (backslash + quote) not a raw ".
        assertTrue(path.contains("a\\\"sdf"),
                "quote in ID must be SCIM-escaped as \\\" inside the filter; got: " + path);
    }

    /**
     * ID containing a backslash: the decoded path must contain the ID with the
     * backslash escaped at the SCIM filter level (i.e. \\ inside the filter literal).
     *
     *   id = "a\\sdf"  (Java literal: the ID contains one backslash)
     *   expected decoded path: members[value eq "a\\sdf"]
     */
    @Test
    void remove_rfcPathFilter_idWithBackslash_jsonParsesAndDecodedPathEscapesBackslash()
            throws Exception {
        String id = "a\\sdf";
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", id, ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        JsonNode op = JSON.readTree(json).at("/Operations/0");
        assertEquals("remove", op.get("op").asText());

        String path = op.get("path").asText();
        assertTrue(path.contains("a\\\\sdf"),
                "backslash in ID must be SCIM-escaped as \\\\ inside the filter; got: " + path);
    }

    /**
     * ID containing both a double-quote and a backslash.
     *
     *   id = "a\"b\\c"  (Java literal: quote then backslash)
     *   expected decoded path: members[value eq "a\"b\\c"]
     */
    @Test
    void remove_rfcPathFilter_idWithQuoteAndBackslash_decodedPathEscapesBoth()
            throws Exception {
        String id = "a\"b\\c";
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", id, ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        JsonNode op = JSON.readTree(json).at("/Operations/0");
        String path = op.get("path").asText();
        assertTrue(path.contains("a\\\"b\\\\c"),
                "both special chars must be SCIM-escaped in the filter; got: " + path);
    }

    // -------------------------------------------------------------------------
    // Group member remove -- non-RFC value array
    // -------------------------------------------------------------------------

    @Test
    void remove_nonRfcValueArray_pathMembersWithValueArray() {
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", "scim-user-4", ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY);

        assertTrue(json.contains("\"op\":\"remove\""));
        assertTrue(json.contains("\"path\":\"members\""));
        assertTrue(json.contains("\"value\":[{\"value\":\"scim-user-4\"}]"));
    }

    /**
     * Non-RFC form with a quoted ID: the ID sits in a plain JSON string value
     * so a single esc() is sufficient; the JSON must parse and the decoded value
     * must equal the original ID.
     */
    @Test
    void remove_nonRfcValueArray_idWithQuote_decodedValueEqualsOriginalId()
            throws Exception {
        String id = "a\"sdf";
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", id, ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY);

        JsonNode op = JSON.readTree(json).at("/Operations/0");
        assertEquals("remove", op.get("op").asText());
        assertEquals(id, op.at("/value/0/value").asText(),
                "decoded member value must equal the original ID");
    }

    // -------------------------------------------------------------------------
    // Group member replace
    // -------------------------------------------------------------------------

    @Test
    void replace_multipleMembers_allIdsPresent() {
        String json = ScimMapper.buildGroupMemberReplace(List.of("id-a", "id-b", "id-c"));

        assertTrue(json.contains("\"op\":\"replace\""));
        assertTrue(json.contains("\"path\":\"members\""));
        assertTrue(json.contains("\"value\":\"id-a\""));
        assertTrue(json.contains("\"value\":\"id-b\""));
        assertTrue(json.contains("\"value\":\"id-c\""));
    }

    @Test
    void replace_emptyList_producesEmptyValueArray() {
        String json = ScimMapper.buildGroupMemberReplace(List.of());

        assertTrue(json.contains("\"op\":\"replace\""));
        assertTrue(json.contains("\"value\":[]"));
    }

    @Test
    void replace_specialCharsInId_escapedCorrectly() {
        String id = "id\\with\"special";
        String json = ScimMapper.buildGroupMemberReplace(List.of(id));

        assertFalse(json.contains("\"value\":\"" + id + "\""));
        assertTrue(json.contains("\\\\with"));
        assertTrue(json.contains("\\\"special"));
    }

    /**
     * Replace with a quoted ID: the decoded value must equal the original ID.
     */
    @Test
    void replace_idWithQuote_decodedValueEqualsOriginalId() throws Exception {
        String id = "a\"sdf";
        String json = ScimMapper.buildGroupMemberReplace(List.of(id));

        JsonNode op = JSON.readTree(json).at("/Operations/0");
        assertEquals(id, op.at("/value/0/value").asText(),
                "decoded member value must equal the original ID");
    }

    // -------------------------------------------------------------------------
    // Create group
    // -------------------------------------------------------------------------

    @Test
    void createGroup_containsSchemaExternalIdAndDisplayName() {
        String json = ScimMapper.buildCreateGroup("Engineering", "kc-group-uuid-1");

        assertTrue(json.contains("urn:ietf:params:scim:schemas:core:2.0:Group"));
        assertTrue(json.contains("\"externalId\": \"kc-group-uuid-1\""));
        assertTrue(json.contains("\"displayName\": \"Engineering\""));
    }

    // -------------------------------------------------------------------------
    // Add with special characters (value branch, single esc)
    // -------------------------------------------------------------------------

    @Test
    void add_specialCharsInMemberId_escapedCorrectly() {
        String id = "id-with-\"quote\"-and-\\backslash";
        String json = ScimMapper.buildGroupMemberPatch("add", id);

        assertFalse(json.contains("\"value\":\"" + id + "\""),
                "raw unescaped ID must not appear verbatim");
        assertTrue(json.contains("\\\"quote\\\""), "double-quote must be escaped");
        assertTrue(json.contains("\\\\backslash"), "backslash must be escaped");
    }

    /**
     * Add with a quoted ID: the decoded value must equal the original ID.
     */
    @Test
    void add_idWithQuote_decodedValueEqualsOriginalId() throws Exception {
        String id = "a\"sdf";
        String json = ScimMapper.buildGroupMemberPatch("add", id);

        JsonNode op = JSON.readTree(json).at("/Operations/0");
        assertEquals("add", op.get("op").asText());
        assertEquals(id, op.at("/value/0/value").asText(),
                "decoded member value must equal the original ID");
    }

    // -------------------------------------------------------------------------
    // Deactivate patch
    // -------------------------------------------------------------------------

    @Test
    void deactivatePatch_singleReplaceActiveFalse() {
        String json = ScimMapper.buildDeactivatePatch();

        assertTrue(json.contains("\"op\":\"replace\""));
        assertTrue(json.contains("\"path\":\"active\""));
        assertTrue(json.contains("\"value\":false"));
        assertEquals(1, countOccurrences(json, "\"op\":"),
                "must contain exactly one operation");
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private static int countOccurrences(String text, String sub) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(sub, idx)) >= 0) {
            count++;
            idx += sub.length();
        }
        return count;
    }
}
