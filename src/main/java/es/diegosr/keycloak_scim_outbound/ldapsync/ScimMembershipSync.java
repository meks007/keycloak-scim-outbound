package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStoragePrivateUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/** Flushes LDAP-recorded user provisioning state to configured SCIM targets. */
public final class ScimMembershipSync {
    public static final String MODE_DELTA_ONLY = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
    public static final String MODE_FULL = "Full";
    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-SYNC]";

    private ScimMembershipSync() { }

    /** Processes pending changes. Add-only mode retains removals for a later full or deprovision delta sync. */
    public static void processPendingMembershipChanges(KeycloakSession session, RealmModel realm,
                                                       String componentIdFilter, String mode) {
        long start = System.currentTimeMillis();
        boolean flushDeletes = MODE_DELTA_DEPROVISION.equals(mode);
        List<ComponentModel> targets = targets(realm, componentIdFilter);
        int scanned = 0, pendingUsers = 0, adds = 0, removes = 0, failures = 0;

        for (ComponentModel target : targets) {
            Map<String, UserModel> candidates = new LinkedHashMap<>();
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm, MembershipState.PENDING_ATTRIBUTE_NAME,
                            MembershipState.pendingValue(target.getId()))
                    .forEach(user -> candidates.putIfAbsent(user.getId(), user));
            String base = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s has incomplete configuration; retaining %d pending entries.", target.getName(), candidates.size());
                failures += candidates.size();
                continue;
            }
            ScimClient client = client(target, base, token);

            for (UserModel user : candidates.values()) {
                scanned++;
                List<String> values = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList();
                List<String> updated = new ArrayList<>(values);
                boolean changed = false, hasPending = false;
                for (String raw : values) {
                    Optional<MembershipState> parsed = MembershipState.parse(raw);
                    if (parsed.isEmpty() || !target.getId().equals(parsed.get().componentId())
                            || parsed.get().state() == MembershipState.State.SENT) continue;
                    hasPending = true;
                    MembershipState entry = parsed.get();
                    String username = computeScimUserName(target, user);
                    if (username == null || username.isBlank()) { failures++; continue; }
                    try {
                        if (entry.state() == MembershipState.State.NEW_ADDED) {
                            if (upsertUser(target, client, user, username)) {
                                updated.remove(raw);
                                updated.add(new MembershipState(entry.componentId(), entry.groupId(), MembershipState.State.SENT).toValue());
                                changed = true; adds++;
                            } else failures++;
                        } else if (entry.state() == MembershipState.State.NEW_DELETED && flushDeletes) {
                            if (deprovisionUser(target, client, user.getId(), username)) {
                                updated.remove(raw); changed = true; removes++;
                            } else failures++;
                        }
                    } catch (Exception e) {
                        failures++;
                        err("Target=%s user=%s state=%s failed: %s", target.getName(), user.getUsername(), entry.state(), e.getMessage());
                    }
                }
                if (hasPending) pendingUsers++;
                if (changed) writeState(session, realm, user, updated);
                if (hasNoPendingForTarget(updated, target.getId())) clearPendingFlag(session, realm, user, target.getId());
            }
        }
        info("Pending user sync finished realm=%s mode=%s scanned=%d pendingUsers=%d adds=%d removes=%d failures=%d durationMs=%d",
                realm.getName(), mode, scanned, pendingUsers, adds, removes, failures, System.currentTimeMillis() - start);
    }

    /** Reconciles all members of the target filter group and removes former members. */
    public static void processFullUserSync(KeycloakSession session, RealmModel realm, String componentIdFilter) {
        long start = System.currentTimeMillis();
        int upserts = 0, deprovisions = 0, failures = 0;
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            String base = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            String filterName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (base == null || token == null || filterName == null || filterName.isBlank()) continue;
            Optional<org.keycloak.models.GroupModel> filter = session.groups()
                    .searchForGroupByNameStream(realm, filterName, true, null, null).findFirst();
            if (filter.isEmpty()) { err("Target=%s filter group %s was not found.", target.getName(), filterName); continue; }
            ScimClient client = client(target, base, token);
            Map<String, UserModel> members = new LinkedHashMap<>();
            session.users().getGroupMembersStream(realm, filter.get()).forEach(user -> members.put(user.getId(), user));
            for (UserModel user : members.values()) {
                String username = computeScimUserName(target, user);
                if (username == null || username.isBlank()) { failures++; continue; }
                if (upsertUser(target, client, user, username)) upserts++; else failures++;
            }
            String sentValue = new MembershipState(target.getId(), filter.get().getId(), MembershipState.State.SENT).toValue();
            List<UserModel> formerMembers = UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm, MembershipState.ATTRIBUTE_NAME, sentValue)
                    .filter(user -> !members.containsKey(user.getId())).collect(Collectors.toList());
            for (UserModel user : formerMembers) {
                if (deprovisionUser(target, client, user.getId(), computeScimUserName(target, user))) deprovisions++; else failures++;
            }
            List<UserModel> affected = new ArrayList<>(members.values());
            formerMembers.stream().filter(user -> !members.containsKey(user.getId())).forEach(affected::add);
            affected.forEach(user -> clearAllStateForTarget(session, realm, user, target.getId()));
        }
        info("Full user sync finished realm=%s upserts=%d deprovisions=%d failures=%d durationMs=%d",
                realm.getName(), upserts, deprovisions, failures, System.currentTimeMillis() - start);
    }

    static boolean upsertUser(ComponentModel target, ScimClient client, UserModel user, String username) {
        String externalId = user.getId();
        Optional<String> id = client.users().resolveId(externalId, username);
        if (id.isEmpty()) {
            if (client.users().create(ScimMapper.buildCreateUser(user, username))) return true;
            id = client.users().resolveId(externalId, username);
        }
        return id.map(value -> client.users().patch(value, ScimMapper.buildPatchUser(user, externalId))).orElse(false);
    }

    private static boolean deprovisionUser(ComponentModel target, ScimClient client, String externalId, String username) {
        Optional<String> id = client.users().resolveId(externalId, username);
        if (id.isEmpty()) return true;
        return "delete".equals(ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate"))
                ? client.users().delete(id.get()) : client.users().patch(id.get(), ScimMapper.buildDeactivatePatch());
    }

    private static ScimClient client(ComponentModel target, String base, String token) {
        return new ScimClient(base, token, ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST));
    }

    private static List<ComponentModel> targets(RealmModel realm, String componentId) {
        return realm.getComponentsStream().filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentId == null || componentId.equals(c.getId())).toList();
    }

    private static String computeScimUserName(ComponentModel target, UserModel user) {
        return switch (ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username")) {
            case "email" -> blankToNull(user.getEmail());
            case "attribute" -> {
                String attribute = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_UNAME_ATTR, null);
                yield attribute == null ? null : blankToNull(user.getFirstAttribute(attribute));
            }
            default -> user.getUsername();
        };
    }

    private static boolean hasNoPendingForTarget(List<String> values, String targetId) {
        return values.stream().map(MembershipState::parse).filter(Optional::isPresent).map(Optional::get)
                .noneMatch(state -> targetId.equals(state.componentId()) && state.state() != MembershipState.State.SENT);
    }

    private static void writeState(KeycloakSession session, RealmModel realm, UserModel user, List<String> values) {
        UserModel local = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
        if (local != null) local.setAttribute(MembershipState.ATTRIBUTE_NAME, values);
    }

    private static void clearPendingFlag(KeycloakSession session, RealmModel realm, UserModel user, String componentId) {
        UserModel local = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
        if (local == null) return;
        List<String> pending = new ArrayList<>(user.getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList());
        pending.remove(MembershipState.pendingValue(componentId));
        local.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, pending);
    }

    private static void clearAllStateForTarget(KeycloakSession session, RealmModel realm, UserModel user, String componentId) {
        UserModel local = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
        if (local == null) return;
        List<String> states = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList().stream()
                .filter(raw -> MembershipState.parse(raw).map(state -> !componentId.equals(state.componentId())).orElse(true)).toList();
        local.setAttribute(MembershipState.ATTRIBUTE_NAME, states);
        List<String> pending = new ArrayList<>(user.getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList());
        pending.remove(MembershipState.pendingValue(componentId));
        local.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, pending);
    }

    private static String blankToNull(String value) { return value == null || value.isBlank() ? null : value; }
    private static void info(String format, Object... args) { System.out.printf("%s %s INFO %s%n", java.time.OffsetDateTime.now(), LOG_TAG, String.format(format, args)); }
    private static void err(String format, Object... args) { System.err.printf("%s %s ERROR %s%n", java.time.OffsetDateTime.now(), LOG_TAG, String.format(format, args)); }
}
