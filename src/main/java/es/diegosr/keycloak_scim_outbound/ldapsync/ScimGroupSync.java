package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Flushes LDAP-recorded group membership changes to configured SCIM targets. */
public final class ScimGroupSync {
    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-GROUP-SYNC]";

    public static final String MODE_DELTA_ONLY = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
    public static final String MODE_FULL = "Full";

    private ScimGroupSync() { }

    public static void processPendingGroupMembershipChanges(KeycloakSession session,
                                                             RealmModel realm,
                                                             String componentIdFilter,
                                                             String mode) {
        long start = System.currentTimeMillis();
        boolean processRemovals = MODE_DELTA_DEPROVISION.equals(mode);
        debug("=== processPendingGroupMembershipChanges START realm=%s componentIdFilter=%s mode=%s ===",
                realm.getName(), displayFilter(componentIdFilter), mode);

        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!groupsEnabled(target)) {
                debug("Target=%s: group synchronization disabled. Skipping.", target.getName());
                continue;
            }
            ScimClient client = client(target);
            if (client == null) {
                err("Target=%s: incomplete base URL or token configuration. Skipping delta group sync.",
                        target.getName());
                continue;
            }
            List<GroupModel> groups = resolveInScopeGroups(session, realm, target);
            debug("Target=%s: %d in-scope group(s) found for delta processing.",
                    target.getName(), groups.size());

            for (GroupModel group : groups) {
                if (!group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME)
                        .anyMatch(GroupMembershipState.pendingValue(target.getId())::equals)) {
                    continue;
                }
                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
                    continue;
                }
                List<String> values = group.getAttributeStream(
                        GroupMembershipState.ATTRIBUTE_NAME).toList();
                List<String> updated = new ArrayList<>(values);
                boolean changed = false;

                for (String raw : values) {
                    Optional<GroupMembershipState> parsed = GroupMembershipState.parse(raw);
                    if (parsed.isEmpty()) {
                        debug("Target=%s group='%s': skipping unparsable state value '%s'.",
                                target.getName(), group.getName(), raw);
                        continue;
                    }
                    GroupMembershipState state = parsed.get();
                    if (!target.getId().equals(state.componentId())
                            || state.state() == GroupMembershipState.State.SENT) {
                        continue;
                    }
                    if (state.state() == GroupMembershipState.State.NEW_DELETED
                            && !processRemovals) {
                        debug("Target=%s group='%s' userId=%s: retaining NEW_DELETED in mode=%s.",
                                target.getName(), group.getName(), state.userId(), mode);
                        continue;
                    }

                    UserModel user = session.users().getUserById(realm, state.userId());
                    if (user == null) {
                        err("Target=%s group='%s': Keycloak user id=%s not found. State retained.",
                                target.getName(), group.getName(), state.userId());
                        continue;
                    }
                    if (state.state() == GroupMembershipState.State.NEW_ADDED
                            && !isUserInProvisioningScope(
                                    session, realm, target, user.getId())) {
                        err("Target=%s group='%s' user=%s: add skipped because user is outside "
                                        + "CFG_FILTER_GROUP. State retained.",
                                target.getName(), group.getName(), user.getUsername());
                        continue;
                    }
                    String scimUserName = computeScimUserName(target, user);
                    Optional<String> scimUserId = client.users().resolveId(
                            state.userId(), scimUserName);
                    if (scimUserId.isEmpty()) {
                        err("Target=%s group='%s' user=%s: SCIM user could not be resolved. State retained.",
                                target.getName(), group.getName(), user.getUsername());
                        continue;
                    }

                    String operation = state.state() == GroupMembershipState.State.NEW_ADDED
                            ? "add" : "remove";
                    String payload = state.state() == GroupMembershipState.State.NEW_ADDED
                            ? ScimMapper.buildGroupMemberPatch("add", scimUserId.get())
                            : ScimMapper.buildGroupMemberPatch(
                                    "remove", scimUserId.get(), removeForm(target));
                    debug("Calling group membership PATCH operation=%s group='%s' scimGroupId=%s "
                                    + "user=%s scimUserId=%s target=%s",
                            operation, group.getName(), scimGroupId.get(), user.getUsername(),
                            scimUserId.get(), target.getName());
                    boolean ok = client.groups().patch(scimGroupId.get(), payload);
                    if (!ok) {
                        err("Membership PATCH failed operation=%s group='%s' scimGroupId=%s "
                                        + "user=%s scimUserId=%s target=%s. State retained.",
                                operation, group.getName(), scimGroupId.get(), user.getUsername(),
                                scimUserId.get(), target.getName());
                        continue;
                    }
                    info("Membership PATCH succeeded operation=%s group='%s' user=%s target=%s.",
                            operation, group.getName(), user.getUsername(), target.getName());
                    markProvisioned(group, target.getId());
                    updated.remove(raw);
                    if (state.state() == GroupMembershipState.State.NEW_ADDED) {
                        updated.add(new GroupMembershipState(
                                state.componentId(), state.userId(),
                                GroupMembershipState.State.SENT).toValue());
                    }
                    changed = true;
                }
                if (changed) {
                    writeGroupState(group, target.getId(), updated);
                }
            }
            if (processRemovals) {
                crossCheckGroupMembers(session, realm, target, client, groups);
            }
        }
        info("=== processPendingGroupMembershipChanges DONE realm=%s componentIdFilter=%s "
                        + "mode=%s durationMs=%d ===",
                realm.getName(), displayFilter(componentIdFilter), mode,
                System.currentTimeMillis() - start);
    }

    public static void processFullGroupSync(KeycloakSession session, RealmModel realm,
                                            String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== processFullGroupSync START realm=%s componentIdFilter=%s ===",
                realm.getName(), displayFilter(componentIdFilter));

        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!groupsEnabled(target)) {
                continue;
            }
            ScimClient client = client(target);
            if (client == null) {
                err("Target=%s: incomplete base URL or token configuration. Skipping full group sync.",
                        target.getName());
                continue;
            }
            Optional<Set<String>> scopedUserIds = resolveScopedUserIds(session, realm, target);
            if (scopedUserIds.isEmpty()) {
                continue;
            }
            for (GroupModel group : resolveInScopeGroups(session, realm, target)) {
                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
                    continue;
                }
                List<String> memberIds = new ArrayList<>();
                session.users().getGroupMembersStream(realm, group).forEach(member -> {
                    if (!scopedUserIds.get().contains(member.getId())) {
                        return;
                    }
                    client.users().resolveId(member.getId(), computeScimUserName(target, member))
                            .ifPresentOrElse(memberIds::add,
                                    () -> err("Target=%s group='%s' user=%s: SCIM user unresolved; "
                                                    + "omitting from full replacement.",
                                            target.getName(), group.getName(), member.getUsername()));
                });
                debug("Calling full member replace group='%s' scimGroupId=%s target=%s memberCount=%d",
                        group.getName(), scimGroupId.get(), target.getName(), memberIds.size());
                if (client.groups().patch(scimGroupId.get(),
                        ScimMapper.buildGroupMemberReplace(memberIds))) {
                    info("Full member replace succeeded group='%s' target=%s memberCount=%d.",
                            group.getName(), target.getName(), memberIds.size());
                    markProvisioned(group, target.getId());
                    clearGroupState(group, target.getId());
                } else {
                    err("Full member replace failed group='%s' scimGroupId=%s target=%s. State retained.",
                            group.getName(), scimGroupId.get(), target.getName());
                }
            }
        }
        info("=== processFullGroupSync DONE realm=%s componentIdFilter=%s durationMs=%d ===",
                realm.getName(), displayFilter(componentIdFilter),
                System.currentTimeMillis() - start);
    }

    /** Removes remote members absent from Keycloak. Never adds members or creates groups. */
    private static void crossCheckGroupMembers(KeycloakSession session, RealmModel realm,
                                               ComponentModel target, ScimClient client,
                                               List<GroupModel> groups) {
        long start = System.currentTimeMillis();
        debug("=== crossCheckGroupMembers START realm=%s target=%s groupCount=%d ===",
                realm.getName(), target.getName(), groups.size());
        Optional<Set<String>> scopedUserIds = resolveScopedUserIds(session, realm, target);
        if (scopedUserIds.isEmpty()) {
            return;
        }

        for (GroupModel group : groups) {
            Optional<String> scimGroupId = client.groups().resolveId(
                    group.getId(), group.getName());
            if (scimGroupId.isEmpty()) {
                debug("Target=%s group='%s': SCIM group not found during cross-check. Skipping.",
                        target.getName(), group.getName());
                continue;
            }
            Set<String> localScimMemberIds = new HashSet<>();
            session.users().getGroupMembersStream(realm, group).forEach(member -> {
                if (!scopedUserIds.get().contains(member.getId())) {
                    return;
                }
                client.users().resolveId(member.getId(), computeScimUserName(target, member))
                        .ifPresentOrElse(localScimMemberIds::add,
                                () -> err("Target=%s group='%s' user=%s: SCIM user unresolved "
                                                + "during cross-check.",
                                        target.getName(), group.getName(), member.getUsername()));
            });
            for (String remoteId : client.groups().getMembers(group.getId(), group.getName())) {
                if (localScimMemberIds.contains(remoteId)) {
                    continue;
                }
                debug("Calling cross-check remove group='%s' scimGroupId=%s scimUserId=%s target=%s",
                        group.getName(), scimGroupId.get(), remoteId, target.getName());
                boolean ok = client.groups().patch(scimGroupId.get(),
                        ScimMapper.buildGroupMemberPatch(
                                "remove", remoteId, removeForm(target)));
                if (ok) {
                    info("Cross-check removed excess member group='%s' scimUserId=%s target=%s.",
                            group.getName(), remoteId, target.getName());
                    markProvisioned(group, target.getId());
                } else {
                    err("Cross-check remove failed group='%s' scimGroupId=%s scimUserId=%s "
                                    + "target=%s. Continuing.",
                            group.getName(), scimGroupId.get(), remoteId, target.getName());
                }
            }
        }
        info("=== crossCheckGroupMembers DONE realm=%s target=%s durationMs=%d ===",
                realm.getName(), target.getName(), System.currentTimeMillis() - start);
    }

    /** Deletes previously provisioned remote groups that no longer match the scope. */
    public static void deprovisionOutOfScopeGroups(KeycloakSession session, RealmModel realm,
                                                    String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== deprovisionOutOfScopeGroups START realm=%s componentIdFilter=%s ===",
                realm.getName(), displayFilter(componentIdFilter));
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!groupsEnabled(target)) {
                continue;
            }
            ScimClient client = client(target);
            if (client == null) {
                err("Target=%s: incomplete base URL or token configuration. Skipping deprovision sweep.",
                        target.getName());
                continue;
            }
            session.groups().getGroupsStream(realm)
                    .filter(group -> wasProvisionedBy(group, target.getId()))
                    .filter(group -> !isGroupInScope(target, group.getName()))
                    .forEach(group -> {
                        Optional<String> scimGroupId = client.groups().resolveId(
                                group.getId(), group.getName());
                        if (scimGroupId.isEmpty()) {
                            info("Target=%s group='%s': remote group already absent. "
                                            + "Clearing local bookkeeping.",
                                    target.getName(), group.getName());
                            clearAllBookkeeping(group, target.getId());
                            return;
                        }
                        debug("Calling group DELETE group='%s' scimGroupId=%s target=%s",
                                group.getName(), scimGroupId.get(), target.getName());
                        if (client.groups().delete(scimGroupId.get())) {
                            info("Deprovisioned group='%s' scimGroupId=%s target=%s.",
                                    group.getName(), scimGroupId.get(), target.getName());
                            clearAllBookkeeping(group, target.getId());
                        } else {
                            err("Group DELETE failed group='%s' scimGroupId=%s target=%s. "
                                            + "Bookkeeping retained for retry.",
                                    group.getName(), scimGroupId.get(), target.getName());
                        }
                    });
        }
        info("=== deprovisionOutOfScopeGroups DONE realm=%s componentIdFilter=%s durationMs=%d ===",
                realm.getName(), displayFilter(componentIdFilter),
                System.currentTimeMillis() - start);
    }

    /** Existing remote groups are not marked until a provisioning operation succeeds. */
    private static Optional<String> upsertScimGroup(ScimClient client,
                                                     ComponentModel target,
                                                     GroupModel group) {
        Optional<String> scimGroupId = client.groups().resolveId(
                group.getId(), group.getName());
        if (scimGroupId.isPresent()) {
            return scimGroupId;
        }
        info("Target=%s: SCIM group not found for KC group '%s' (id=%s). Auto-creating.",
                target.getName(), group.getName(), group.getId());
        if (!client.groups().create(
                ScimMapper.buildCreateGroup(group.getName(), group.getId()))) {
            err("Target=%s: failed to auto-create SCIM group '%s' (id=%s).",
                    target.getName(), group.getName(), group.getId());
            return Optional.empty();
        }
        scimGroupId = client.groups().resolveId(group.getId(), group.getName());
        if (scimGroupId.isPresent()) {
            markProvisioned(group, target.getId());
            info("Target=%s: auto-created SCIM group '%s' -> scimGroupId=%s.",
                    target.getName(), group.getName(), scimGroupId.get());
        } else {
            err("Target=%s: auto-created SCIM group '%s' but could not resolve its id.",
                    target.getName(), group.getName());
        }
        return scimGroupId;
    }

    static boolean isGroupInScope(ComponentModel target, String groupName) {
        if (groupName == null) {
            return false;
        }
        String regex = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        if (regex == null || regex.isBlank()) {
            String filterGroup = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            return groupName.equals(filterGroup);
        }
        return groupName.matches(regex);
    }

    private static List<GroupModel> resolveInScopeGroups(KeycloakSession session,
                                                          RealmModel realm,
                                                          ComponentModel target) {
        String regex = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        if (regex == null || regex.isBlank()) {
            String filterGroup = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroup == null || filterGroup.isBlank()) {
                return List.of();
            }
            return session.groups()
                    .searchForGroupByNameStream(realm, filterGroup, true, null, null)
                    .toList();
        }
        // Keycloak has no portable indexed group attribute search. Group counts are small.
        return session.groups().getGroupsStream(realm)
                .filter(group -> group.getName() != null
                        && group.getName().matches(regex))
                .toList();
    }

    /**
     * Returns empty when the configured boundary cannot be resolved. A present empty set
     * means the filter group exists but currently has no members.
     */
    private static Optional<Set<String>> resolveScopedUserIds(KeycloakSession session,
                                                               RealmModel realm,
                                                               ComponentModel target) {
        String filterGroup = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        if (filterGroup == null || filterGroup.isBlank()) {
            err("Target=%s: CFG_FILTER_GROUP is missing. Skipping group membership processing.",
                    target.getName());
            return Optional.empty();
        }
        Optional<GroupModel> group = session.groups().searchForGroupByNameStream(
                        realm, filterGroup, true, null, null)
                .findFirst();
        if (group.isEmpty()) {
            err("Target=%s: filter group '%s' not found in realm=%s. "
                            + "Skipping group membership processing.",
                    target.getName(), filterGroup, realm.getName());
            return Optional.empty();
        }
        Set<String> result = new HashSet<>();
        session.users().getGroupMembersStream(realm, group.get())
                .forEach(user -> result.add(user.getId()));
        debug("Target=%s: resolved %d user(s) in filter group '%s'.",
                target.getName(), result.size(), filterGroup);
        return Optional.of(result);
    }

    private static boolean isUserInProvisioningScope(KeycloakSession session,
                                                       RealmModel realm,
                                                       ComponentModel target,
                                                       String userId) {
        Optional<Set<String>> scopedUserIds = resolveScopedUserIds(session, realm, target);
        return scopedUserIds.isPresent() && scopedUserIds.get().contains(userId);
    }

    private static boolean wasProvisionedBy(GroupModel group, String componentId) {
        boolean provenance = group.getAttributeStream(
                        GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME)
                .anyMatch(GroupMembershipState.provisionedValue(componentId)::equals);
        boolean legacyState = group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME)
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(state -> componentId.equals(state.componentId()));
        return provenance || legacyState;
    }

    private static void writeGroupState(GroupModel group, String componentId,
                                        List<String> values) {
        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, values);
        boolean hasPending = values.stream()
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(state -> componentId.equals(state.componentId())
                        && state.state() != GroupMembershipState.State.SENT);
        List<String> pending = new ArrayList<>(group.getAttributeStream(
                GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        String flag = GroupMembershipState.pendingValue(componentId);
        if (hasPending && !pending.contains(flag)) {
            pending.add(flag);
        } else if (!hasPending) {
            pending.remove(flag);
        }
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, pending);
    }

    private static void markProvisioned(GroupModel group, String componentId) {
        List<String> values = new ArrayList<>(group.getAttributeStream(
                GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME).toList());
        String marker = GroupMembershipState.provisionedValue(componentId);
        if (!values.contains(marker)) {
            values.add(marker);
            group.setAttribute(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME, values);
        }
    }

    private static void clearGroupState(GroupModel group, String componentId) {
        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME,
                GroupMembershipState.removeAllForComponent(
                        group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList(),
                        componentId));
        List<String> pending = new ArrayList<>(group.getAttributeStream(
                GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        pending.remove(GroupMembershipState.pendingValue(componentId));
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, pending);
    }

    private static void clearAllBookkeeping(GroupModel group, String componentId) {
        clearGroupState(group, componentId);
        List<String> provenance = new ArrayList<>(group.getAttributeStream(
                GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME).toList());
        provenance.remove(GroupMembershipState.provisionedValue(componentId));
        group.setAttribute(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME, provenance);
    }

    private static List<ComponentModel> targets(RealmModel realm, String componentId) {
        return realm.getComponentsStream()
                .filter(component -> ScimTargetProviderFactory.ID.equals(
                        component.getProviderId()))
                .filter(component -> componentId == null
                        || componentId.equals(component.getId()))
                .toList();
    }

    private static boolean groupsEnabled(ComponentModel target) {
        return "true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"));
    }

    private static String removeForm(ComponentModel target) {
        return ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM,
                ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);
    }

    private static ScimClient client(ComponentModel target) {
        String base = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_BASE_URL, null);
        String token = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_TOKEN, null);
        if (base == null || token == null) {
            return null;
        }
        return new ScimClient(base, token, ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST));
    }

    private static String computeScimUserName(ComponentModel target, UserModel user) {
        String strategy = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username");
        if ("email".equals(strategy)) {
            return user.getEmail();
        }
        if ("attribute".equals(strategy)) {
            String attribute = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_UNAME_ATTR, null);
            return attribute == null ? null : user.getFirstAttribute(attribute);
        }
        return user.getUsername();
    }

    private static String displayFilter(String componentIdFilter) {
        return componentIdFilter == null ? "<all>" : componentIdFilter;
    }

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }

    private static void debug(String format, Object... args) {
        System.out.printf("%s %s DEBUG %s%n", now(), LOG_TAG, String.format(format, args));
    }

    private static void info(String format, Object... args) {
        System.out.printf("%s %s INFO %s%n", now(), LOG_TAG, String.format(format, args));
    }

    private static void err(String format, Object... args) {
        System.err.printf("%s %s ERROR %s%n", now(), LOG_TAG, String.format(format, args));
    }
}
