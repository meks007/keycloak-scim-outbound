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
    public static final String MODE_DELTA_ONLY = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
    public static final String MODE_FULL = "Full";

    private ScimGroupSync() { }

    public static void processPendingGroupMembershipChanges(KeycloakSession session,
                                                             RealmModel realm,
                                                             String componentIdFilter,
                                                             String mode) {
        boolean processRemovals = MODE_DELTA_DEPROVISION.equals(mode);
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!groupsEnabled(target)) {
                continue;
            }
            ScimClient client = client(target);
            if (client == null) {
                continue;
            }
            List<GroupModel> groups = resolveInScopeGroups(session, realm, target);
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
                        continue;
                    }
                    GroupMembershipState state = parsed.get();
                    if (!target.getId().equals(state.componentId())
                            || state.state() == GroupMembershipState.State.SENT) {
                        continue;
                    }
                    if (state.state() == GroupMembershipState.State.NEW_DELETED
                            && !processRemovals) {
                        continue;
                    }
                    UserModel user = session.users().getUserById(realm, state.userId());
                    String scimUserName = user == null ? null : computeScimUserName(target, user);
                    Optional<String> scimUserId = client.users().resolveId(
                            state.userId(), scimUserName);
                    if (scimUserId.isEmpty()) {
                        continue;
                    }
                    boolean ok;
                    if (state.state() == GroupMembershipState.State.NEW_ADDED) {
                        ok = client.groups().patch(scimGroupId.get(),
                                ScimMapper.buildGroupMemberPatch("add", scimUserId.get()));
                    } else {
                        ok = client.groups().patch(scimGroupId.get(),
                                ScimMapper.buildGroupMemberPatch(
                                        "remove", scimUserId.get(), removeForm(target)));
                    }
                    if (!ok) {
                        continue;
                    }
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
    }

    public static void processFullGroupSync(KeycloakSession session, RealmModel realm,
                                            String componentIdFilter) {
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!groupsEnabled(target)) {
                continue;
            }
            ScimClient client = client(target);
            if (client == null) {
                continue;
            }
            Set<String> scopedUserIds = resolveScopedUserIds(session, realm, target);
            for (GroupModel group : resolveInScopeGroups(session, realm, target)) {
                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
                    continue;
                }
                List<String> memberIds = new ArrayList<>();
                session.users().getGroupMembersStream(realm, group).forEach(member -> {
                    if (!scopedUserIds.isEmpty() && !scopedUserIds.contains(member.getId())) {
                        return;
                    }
                    client.users().resolveId(member.getId(), computeScimUserName(target, member))
                            .ifPresent(memberIds::add);
                });
                if (client.groups().patch(scimGroupId.get(),
                        ScimMapper.buildGroupMemberReplace(memberIds))) {
                    markProvisioned(group, target.getId());
                    clearGroupState(group, target.getId());
                }
            }
        }
    }

    /**
     * Removes remote members absent from Keycloak. This operation never adds members
     * and never creates or upserts a group.
     */
    private static void crossCheckGroupMembers(KeycloakSession session, RealmModel realm,
                                               ComponentModel target, ScimClient client,
                                               List<GroupModel> groups) {
        Set<String> scopedUserIds = resolveScopedUserIds(session, realm, target);
        for (GroupModel group : groups) {
            Optional<String> scimGroupId = client.groups().resolveId(
                    group.getId(), group.getName());
            if (scimGroupId.isEmpty()) {
                continue;
            }
            Set<String> localScimMemberIds = new HashSet<>();
            session.users().getGroupMembersStream(realm, group).forEach(member -> {
                if (!scopedUserIds.isEmpty() && !scopedUserIds.contains(member.getId())) {
                    return;
                }
                client.users().resolveId(member.getId(), computeScimUserName(target, member))
                        .ifPresent(localScimMemberIds::add);
            });
            for (String remoteId : client.groups().getMembers(group.getId(), group.getName())) {
                if (!localScimMemberIds.contains(remoteId)) {
                    client.groups().patch(scimGroupId.get(),
                            ScimMapper.buildGroupMemberPatch(
                                    "remove", remoteId, removeForm(target)));
                }
            }
        }
    }

    /**
     * Deletes remote groups previously provisioned by this target that no longer match
     * the configured scope. Failed deletes retain all state for the next retry.
     */
    public static void deprovisionOutOfScopeGroups(KeycloakSession session, RealmModel realm,
                                                    String componentIdFilter) {
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!groupsEnabled(target)) {
                continue;
            }
            ScimClient client = client(target);
            if (client == null) {
                continue;
            }
            session.groups().getGroupsStream(realm)
                    .filter(group -> wasProvisionedBy(group, target.getId()))
                    .filter(group -> !isGroupInScope(target, group.getName()))
                    .forEach(group -> {
                        Optional<String> scimGroupId = client.groups().resolveId(
                                group.getId(), group.getName());
                        if (scimGroupId.isEmpty()
                                || client.groups().delete(scimGroupId.get())) {
                            clearAllBookkeeping(group, target.getId());
                        }
                    });
        }
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
        if (!client.groups().create(
                ScimMapper.buildCreateGroup(group.getName(), group.getId()))) {
            return Optional.empty();
        }
        scimGroupId = client.groups().resolveId(group.getId(), group.getName());
        if (scimGroupId.isPresent()) {
            markProvisioned(group, target.getId());
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

    private static Set<String> resolveScopedUserIds(KeycloakSession session,
                                                     RealmModel realm,
                                                     ComponentModel target) {
        String filterGroup = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        if (filterGroup == null || filterGroup.isBlank()) {
            return Set.of();
        }
        Set<String> result = new HashSet<>();
        session.groups().searchForGroupByNameStream(
                        realm, filterGroup, true, null, null)
                .findFirst()
                .ifPresent(group -> session.users()
                        .getGroupMembersStream(realm, group)
                        .forEach(user -> result.add(user.getId())));
        return result;
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
}
