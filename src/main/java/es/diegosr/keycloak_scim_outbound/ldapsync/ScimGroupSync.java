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

/** LDAP-driven SCIM group synchronization. */
public final class ScimGroupSync {
    public static final String MODE_DELTA_ONLY = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
    public static final String MODE_FULL = "Full";

    private ScimGroupSync() { }

    public static void processPendingGroupMembershipChanges(KeycloakSession session, RealmModel realm,
                                                            String componentIdFilter, String mode) {
        boolean processRemovals = MODE_DELTA_DEPROVISION.equals(mode);
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!enabled(target)) continue;
            ScimClient client = client(target);
            if (client == null) continue;
            List<GroupModel> groups = inScopeGroups(session, realm, target);
            for (GroupModel group : groups) {
                if (!group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME)
                        .anyMatch(GroupMembershipState.pendingValue(target.getId())::equals)) continue;
                Optional<String> groupId = upsert(client, target, group);
                if (groupId.isEmpty()) continue;
                List<String> values = group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList();
                List<String> updated = new ArrayList<>(values);
                for (String raw : values) {
                    Optional<GroupMembershipState> result = GroupMembershipState.parse(raw);
                    if (result.isEmpty()) continue;
                    GroupMembershipState state = result.get();
                    if (!target.getId().equals(state.componentId()) || state.state() == GroupMembershipState.State.SENT) continue;
                    if (state.state() == GroupMembershipState.State.NEW_DELETED && !processRemovals) continue;
                    UserModel user = session.users().getUserById(realm, state.userId());
                    Optional<String> userId = client.users().resolveId(state.userId(), user == null ? null : userName(target, user));
                    if (userId.isEmpty()) continue;
                    boolean ok = state.state() == GroupMembershipState.State.NEW_ADDED
                            ? client.groups().patch(groupId.get(), ScimMapper.buildGroupMemberPatch("add", userId.get()))
                            : client.groups().patch(groupId.get(), ScimMapper.buildGroupMemberPatch("remove", userId.get(), removeForm(target)));
                    if (ok) {
                        updated.remove(raw);
                        if (state.state() == GroupMembershipState.State.NEW_ADDED) updated.add(new GroupMembershipState(state.componentId(), state.userId(), GroupMembershipState.State.SENT).toValue());
                        markProvisioned(group, target.getId());
                    }
                }
                writeState(group, target.getId(), updated);
            }
            if (processRemovals) crossCheck(session, realm, target, client, groups);
        }
    }

    public static void processFullGroupSync(KeycloakSession session, RealmModel realm, String componentIdFilter) {
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!enabled(target)) continue;
            ScimClient client = client(target);
            if (client == null) continue;
            Set<String> scope = scopedUsers(session, realm, target);
            for (GroupModel group : inScopeGroups(session, realm, target)) {
                Optional<String> groupId = upsert(client, target, group);
                if (groupId.isEmpty()) continue;
                List<String> memberIds = new ArrayList<>();
                session.users().getGroupMembersStream(realm, group).forEach(member -> {
                    if (scope.isEmpty() || scope.contains(member.getId())) client.users().resolveId(member.getId(), userName(target, member)).ifPresent(memberIds::add);
                });
                if (client.groups().patch(groupId.get(), ScimMapper.buildGroupMemberReplace(memberIds))) {
                    markProvisioned(group, target.getId());
                    clearState(group, target.getId());
                }
            }
        }
    }

    public static void deprovisionOutOfScopeGroups(KeycloakSession session, RealmModel realm, String componentIdFilter) {
        for (ComponentModel target : targets(realm, componentIdFilter)) {
            if (!enabled(target)) continue;
            ScimClient client = client(target);
            if (client == null) continue;
            session.groups().getGroupsStream(realm).filter(group -> managedBy(group, target.getId()))
                    .filter(group -> !isGroupInScope(target, group.getName())).forEach(group -> {
                        Optional<String> groupId = client.groups().resolveId(group.getId(), group.getName());
                        if (groupId.isEmpty() || client.groups().delete(groupId.get())) clearAllState(group, target.getId());
                    });
        }
    }

    private static void crossCheck(KeycloakSession session, RealmModel realm, ComponentModel target, ScimClient client, List<GroupModel> groups) {
        Set<String> scope = scopedUsers(session, realm, target);
        for (GroupModel group : groups) {
            Optional<String> groupId = client.groups().resolveId(group.getId(), group.getName());
            if (groupId.isEmpty()) continue;
            Set<String> local = new HashSet<>();
            session.users().getGroupMembersStream(realm, group).forEach(member -> {
                if (scope.isEmpty() || scope.contains(member.getId())) client.users().resolveId(member.getId(), userName(target, member)).ifPresent(local::add);
            });
            for (String remote : client.groups().getMembers(group.getId(), group.getName())) {
                if (!local.contains(remote)) client.groups().patch(groupId.get(), ScimMapper.buildGroupMemberPatch("remove", remote, removeForm(target)));
            }
        }
    }

    private static Optional<String> upsert(ScimClient client, ComponentModel target, GroupModel group) {
        Optional<String> id = client.groups().resolveId(group.getId(), group.getName());
        if (id.isPresent()) return id;
        if (!client.groups().create(ScimMapper.buildCreateGroup(group.getName(), group.getId()))) return Optional.empty();
        id = client.groups().resolveId(group.getId(), group.getName());
        id.ifPresent(value -> markProvisioned(group, target.getId()));
        return id;
    }

    static boolean isGroupInScope(ComponentModel target, String name) {
        if (name == null) return false;
        String regex = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        return regex == null || regex.isBlank()
                ? name.equals(ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null))
                : name.matches(regex);
    }

    private static List<GroupModel> inScopeGroups(KeycloakSession session, RealmModel realm, ComponentModel target) {
        String regex = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        if (regex == null || regex.isBlank()) {
            String name = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            return name == null || name.isBlank() ? List.of() : session.groups().searchForGroupByNameStream(realm, name, true, null, null).toList();
        }
        // Keycloak has no portable indexed group-attribute query; group counts are normally small.
        return session.groups().getGroupsStream(realm).filter(group -> group.getName() != null && group.getName().matches(regex)).toList();
    }

    private static Set<String> scopedUsers(KeycloakSession session, RealmModel realm, ComponentModel target) {
        String name = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        if (name == null || name.isBlank()) return Set.of();
        Set<String> ids = new HashSet<>();
        session.groups().searchForGroupByNameStream(realm, name, true, null, null).findFirst().ifPresent(group -> session.users().getGroupMembersStream(realm, group).forEach(user -> ids.add(user.getId())));
        return ids;
    }

    private static boolean managedBy(GroupModel group, String targetId) {
        return group.getAttributeStream(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME).anyMatch(GroupMembershipState.provisionedValue(targetId)::equals)
                || group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).map(GroupMembershipState::parse).filter(Optional::isPresent).map(Optional::get).anyMatch(state -> targetId.equals(state.componentId()));
    }

    private static void writeState(GroupModel group, String targetId, List<String> values) {
        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, values);
        boolean pending = values.stream().map(GroupMembershipState::parse).filter(Optional::isPresent).map(Optional::get).anyMatch(state -> targetId.equals(state.componentId()) && state.state() != GroupMembershipState.State.SENT);
        List<String> flags = new ArrayList<>(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        if (pending && !flags.contains(GroupMembershipState.pendingValue(targetId))) flags.add(GroupMembershipState.pendingValue(targetId));
        if (!pending) flags.remove(GroupMembershipState.pendingValue(targetId));
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, flags);
    }

    private static void markProvisioned(GroupModel group, String targetId) {
        List<String> values = new ArrayList<>(group.getAttributeStream(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME).toList());
        String marker = GroupMembershipState.provisionedValue(targetId);
        if (!values.contains(marker)) { values.add(marker); group.setAttribute(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME, values); }
    }

    private static void clearState(GroupModel group, String targetId) {
        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, GroupMembershipState.removeAllForComponent(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList(), targetId));
        List<String> flags = new ArrayList<>(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        flags.remove(GroupMembershipState.pendingValue(targetId));
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, flags);
    }

    private static void clearAllState(GroupModel group, String targetId) {
        clearState(group, targetId);
        List<String> markers = new ArrayList<>(group.getAttributeStream(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME).toList());
        markers.remove(GroupMembershipState.provisionedValue(targetId));
        group.setAttribute(GroupMembershipState.PROVISIONED_ATTRIBUTE_NAME, markers);
    }

    private static List<ComponentModel> targets(RealmModel realm, String targetId) { return realm.getComponentsStream().filter(component -> ScimTargetProviderFactory.ID.equals(component.getProviderId())).filter(component -> targetId == null || targetId.equals(component.getId())).toList(); }
    private static boolean enabled(ComponentModel target) { return "true".equalsIgnoreCase(ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false")); }
    private static String removeForm(ComponentModel target) { return ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM, ScimMapper.REMOVE_FORM_RFC_PATH_FILTER); }
    private static ScimClient client(ComponentModel target) { String base = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null), token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null); return base == null || token == null ? null : new ScimClient(base, token, ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY, ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST)); }
    private static String userName(ComponentModel target, UserModel user) { String strategy = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username"); return "email".equals(strategy) ? user.getEmail() : "attribute".equals(strategy) ? user.getFirstAttribute(ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_UNAME_ATTR, "")) : user.getUsername(); }
}
