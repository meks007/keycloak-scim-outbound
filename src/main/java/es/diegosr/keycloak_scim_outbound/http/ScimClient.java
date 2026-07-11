package es.diegosr.keycloak_scim_outbound.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Minimal SCIM v2 client with resource-specific Users and Groups APIs. */
public class ScimClient {
    public static final String LOOKUP_STRATEGY_EXTERNAL_ID_FIRST = "externalId first";
    public static final String LOOKUP_STRATEGY_NAME_ONLY = "name only";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http;
    private final String baseUrl;
    private final String bearer;
    private final Duration requestTimeout;
    private final int maxRetries;
    private final String lookupStrategy;

    public ScimClient(String baseUrl, String bearer) {
        this(baseUrl, bearer, LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, Duration.ofSeconds(8), 3);
    }

    public ScimClient(String baseUrl, String bearer, String lookupStrategy) {
        this(baseUrl, bearer, lookupStrategy, Duration.ofSeconds(8), 3);
    }

    public ScimClient(String baseUrl, String bearer, Duration timeout, int maxRetries) {
        this(baseUrl, bearer, LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, timeout, maxRetries);
    }

    public ScimClient(String baseUrl, String bearer, String lookupStrategy,
                      Duration timeout, int maxRetries) {
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.bearer = bearer;
        this.lookupStrategy = LOOKUP_STRATEGY_NAME_ONLY.equals(lookupStrategy)
                ? LOOKUP_STRATEGY_NAME_ONLY : LOOKUP_STRATEGY_EXTERNAL_ID_FIRST;
        this.requestTimeout = timeout != null ? timeout : Duration.ofSeconds(8);
        this.maxRetries = Math.max(0, maxRetries);
        this.http = HttpClient.newBuilder().connectTimeout(this.requestTimeout)
                .version(HttpClient.Version.HTTP_1_1).build();
    }

    public Users users() { return new Users(this); }
    public Groups groups() { return new Groups(this); }

    public boolean smokeTest() {
        try {
            HttpRequest req = baseRequestBuilder("/ServiceProviderConfig").GET().build();
            httpDebug("GET /ServiceProviderConfig (smokeTest) request: bearerPresent=%s", bearer != null && !bearer.isBlank());
            HttpResponse<String> res = sendWithRetries(req);
            httpDebug("GET /ServiceProviderConfig (smokeTest) response: status=%d body=%s", res.statusCode(), res.body());
            return is2xx(res.statusCode());
        } catch (Exception e) {
            httpErr("smokeTest failed: %s", e.getMessage());
            return false;
        }
    }

    public static final class Users {
        private final ScimClient client;
        private Users(ScimClient client) { this.client = client; }

        public Optional<JsonNode> get(String externalId, String userName) {
            if (!LOOKUP_STRATEGY_NAME_ONLY.equals(client.lookupStrategy) && notBlank(externalId)) {
                ScimListResponse response = client.getByFilter("/Users", "externalId", externalId, "Users.get externalId");
                if (response.isSingleResult()) return response.firstResource();
                if (response.totalResults() > 1) {
                    httpInfo("Users.get: externalId=%s returned %d results; falling back to userName.", externalId, response.totalResults());
                }
            }
            return notBlank(userName)
                    ? client.getByFilter("/Users", "userName", userName, "Users.get userName").firstResource()
                    : Optional.empty();
        }

        public Optional<String> resolveId(String externalId, String userName) { return id(get(externalId, userName)); }
        public boolean create(String jsonPayload) { return client.createResource("/Users", jsonPayload); }
        public boolean patch(String scimId, String jsonPatch) { return client.sendJson("PATCH", userPath(scimId), jsonPatch, 200, 204); }
        public boolean delete(String scimId) { return client.deleteResource(userPath(scimId)); }
    }

    public static final class Groups {
        private final ScimClient client;
        private Groups(ScimClient client) { this.client = client; }

        public Optional<JsonNode> get(String externalId, String displayName) {
            if (!LOOKUP_STRATEGY_NAME_ONLY.equals(client.lookupStrategy) && notBlank(externalId)) {
                ScimListResponse response = client.getByFilter("/Groups", "externalId", externalId, "Groups.get externalId");
                if (response.isSingleResult()) return response.firstResource();
                if (response.totalResults() > 1) {
                    httpInfo("Groups.get: externalId=%s returned %d results; falling back to displayName.", externalId, response.totalResults());
                }
            }
            return notBlank(displayName)
                    ? client.getByFilter("/Groups", "displayName", displayName, "Groups.get displayName").firstResource()
                    : Optional.empty();
        }

        public Optional<String> resolveId(String externalId, String displayName) { return id(get(externalId, displayName)); }

        public List<String> getMembers(String externalId, String displayName) {
            Optional<JsonNode> group = get(externalId, displayName);
            if (group.isEmpty()) return List.of();
            JsonNode members = group.get().path("members");
            if (!members.isArray() || members.isEmpty()) members = group.get().path("Members");
            if (!members.isArray() || members.isEmpty()) return List.of();
            List<String> ids = new ArrayList<>();
            for (JsonNode member : members) {
                JsonNode value = member.path("value");
                if (value.isTextual() && !value.asText().isBlank()) ids.add(value.asText());
            }
            return ids;
        }

        public boolean create(String jsonPayload) { return client.createResource("/Groups", jsonPayload); }
        public boolean patch(String scimId, String jsonPatch) { return client.sendJson("PATCH", groupPath(scimId), jsonPatch, 200, 204); }
        public boolean delete(String scimId) { return client.deleteResource(groupPath(scimId)); }
    }

    private ScimListResponse getByFilter(String resource, String attribute, String value, String operation) {
        if (!notBlank(value)) return ScimListResponse.empty();
        try {
            String query = "filter=" + urlEncode(attribute + " eq " + scimFilterString(value));
            String path = resource + "?" + query;
            HttpRequest req = baseRequestBuilder(path).GET().build();
            httpDebug("%s request: GET %s", operation, path);
            HttpResponse<String> res = sendWithRetries(req);
            httpDebug("%s response: status=%d body=%s", operation, res.statusCode(), res.body());
            if (is2xx(res.statusCode())) {
                ScimListResponse result = parseListResponse(res.body());
                httpInfo("GET %s -> %d totalResults=%d", path, res.statusCode(), result.totalResults());
                return result;
            }
            httpErr("GET %s -> %d %s", path, res.statusCode(), safeBody(res));
        } catch (Exception e) {
            httpErr("%s failed: %s", operation, e.getMessage());
        }
        return ScimListResponse.empty();
    }

    private boolean createResource(String resource, String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder(resource).header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload)).build();
            httpDebug("POST %s request body: %s", resource, jsonPayload);
            HttpResponse<String> res = sendWithRetries(req);
            httpDebug("POST %s response: status=%d body=%s", resource, res.statusCode(), res.body());
            if (res.statusCode() == 200 || res.statusCode() == 201) return true;
            if (res.statusCode() == 409) httpInfo("POST %s got 409 conflict: %s", resource, safeBody(res));
            else httpErr("POST %s -> %d %s", resource, res.statusCode(), safeBody(res));
        } catch (Exception e) {
            httpErr("POST %s failed: %s", resource, e.getMessage());
        }
        return false;
    }

    private boolean deleteResource(String path) {
        try {
            HttpRequest req = baseRequestBuilder(path).DELETE().build();
            httpDebug("DELETE %s request", path);
            HttpResponse<String> res = sendWithRetries(req);
            httpDebug("DELETE %s response: status=%d body=%s", path, res.statusCode(), res.body());
            boolean ok = res.statusCode() == 200 || res.statusCode() == 204 || res.statusCode() == 404;
            if (!ok) httpErr("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            httpErr("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    private boolean sendJson(String method, String path, String json, int... okCodes) {
        try {
            HttpRequest req = baseRequestBuilder(path).header("Content-Type", "application/scim+json")
                    .method(method, HttpRequest.BodyPublishers.ofString(json)).build();
            httpDebug("%s %s request body: %s", method, path, json);
            HttpResponse<String> res = sendWithRetries(req);
            httpDebug("%s %s response: status=%d body=%s", method, path, res.statusCode(), res.body());
            if (matches(res.statusCode(), okCodes)) return true;
            httpErr("%s %s -> %d %s", method, path, res.statusCode(), safeBody(res));
        } catch (Exception e) {
            httpErr("%s %s failed: %s", method, path, e.getMessage());
        }
        return false;
    }

    private static ScimListResponse parseListResponse(String body) throws Exception {
        if (body == null || body.isBlank()) return ScimListResponse.empty();
        JsonNode root = JSON.readTree(body);
        int total = root.path("totalResults").asInt(0);
        JsonNode resources = root.path("Resources");
        if (!resources.isArray() || resources.isEmpty()) resources = root.path("resources");
        return resources.isArray() && !resources.isEmpty()
                ? new ScimListResponse(total, Optional.of(resources.get(0)))
                : new ScimListResponse(total, Optional.empty());
    }

    private HttpRequest.Builder baseRequestBuilder(String path) {
        String url = baseUrl + (path.startsWith("/") ? path : "/" + path);
        return HttpRequest.newBuilder().uri(URI.create(url)).timeout(requestTimeout)
                .header("Authorization", "Bearer " + bearer).header("Accept", "application/scim+json")
                .header("User-Agent", "keycloak-scim-outbound/1.0");
    }

    private HttpResponse<String> sendWithRetries(HttpRequest req) throws Exception {
        int attempt = 0;
        long backoff = 250L;
        while (true) {
            attempt++;
            HttpResponse<String> res;
            try {
                res = http.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                httpDebug("Attempt %d for %s %s threw %s", attempt, req.method(), req.uri(), e.getMessage());
                if (attempt > maxRetries) throw e;
                sleep(backoff); backoff = Math.min(backoff * 2, 2000L); continue;
            }
            int status = res.statusCode();
            if (is2xx(status)) return res;
            if ((status == 429 || status >= 500 && status <= 599) && attempt <= maxRetries) {
                httpDebug("Attempt %d for %s %s got retryable status=%d, backing off %dms", attempt, req.method(), req.uri(), status, backoff);
                sleep(backoff); backoff = Math.min(backoff * 2, 2000L); continue;
            }
            return res;
        }
    }

    private static Optional<String> id(Optional<JsonNode> resource) {
        return resource.map(node -> node.path("id")).filter(JsonNode::isTextual)
                .map(JsonNode::asText).filter(ScimClient::notBlank);
    }
    private static boolean notBlank(String value) { return value != null && !value.isBlank(); }
    private static boolean is2xx(int code) { return code >= 200 && code < 300; }
    private static boolean matches(int code, int... expected) { for (int value : expected) if (code == value) return true; return false; }
    private static String trimTrailingSlash(String value) { return value != null && value.endsWith("/") ? value.substring(0, value.length() - 1) : value; }
    private static String userPath(String id) { return "/Users/" + urlEncode(id); }
    private static String groupPath(String id) { return "/Groups/" + urlEncode(id); }
    private static String urlEncode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); } }
    private static String safeBody(HttpResponse<String> res) { String body = res.body(); return body == null ? "" : body.length() > 400 ? body.substring(0, 400) + " ..." : body; }
    private static String scimFilterString(String value) { return "\"" + jsonEscape(value) + "\""; }
    private static String jsonEscape(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> { if (c < 0x20) escaped.append(String.format("\\u%04x", (int) c)); else escaped.append(c); }
            }
        }
        return escaped.toString();
    }
    private static String now() { return java.time.OffsetDateTime.now().toString(); }
    private static void httpInfo(String fmt, Object... args) { System.out.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }
    private static void httpErr(String fmt, Object... args) { System.err.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }
    private static void httpDebug(String fmt, Object... args) { System.out.printf("%s [keycloak-scim-outbound/HTTP] DEBUG %s%n", now(), String.format(fmt, args)); }

    private record ScimListResponse(int totalResults, Optional<JsonNode> firstResource) {
        private boolean isSingleResult() { return totalResults == 1 && firstResource.isPresent(); }
        private static ScimListResponse empty() { return new ScimListResponse(0, Optional.empty()); }
    }
}
