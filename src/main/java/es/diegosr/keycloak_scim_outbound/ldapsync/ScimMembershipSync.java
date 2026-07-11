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

/**
 * Consumes the state written by LdapSyncNotifierMapper and pushes pending user
 * provisioning changes to the configured SCIM targets.
 *
 * Pending candidates are loaded from Keycloak local storage by the indexed pending
 * attribute. The aggregated user provider must not be used for this bookkeeping
 * attribute because federated providers do not know it.
 */
public final class ScimMembershipSync {

    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-SYNC]";

    public static final String MODE_DELTA_ONLY = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
    public static final String MODE_FULL = "Full";

    private ScimMembershipSync() { }

    /**
     * Delta flush for one or all targets. Add-only mode deliberately keeps
     * NEW_DELETED records and their pending flag for a later deprovision or full run.
     */
    public static void processPendingMembershipChanges(KeycloakSession session, RealmModel realm,
                                                        String componentIdFilter, String mode) {
        long start = System.currentTimeMillis();
        boolean flushDeletes = MODE_DELTA_DEPROVISION.equals(mode);
        debug("=== processPendingMembershipChanges START realm=%s componentIdFilter=%s mode=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter, mode);

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();

        if (targets.isEmpty()) {
            debug("No matching SCIM outbound targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int usersScanned = 0;
        int usersWithPending = 0;
        int pushedAdds = 0;
        int pushedRemoves = 0;
        int failures = 0;

        for (ComponentModel target : targets) {
            Map<String, UserModel> candidates = new LinkedHashMap<>();
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm,
                            MembershipState.PENDING_ATTRIBUTE_NAME,
                            MembershipState.pendingValue(target.getId()))
                    .forEach(user -> candidates.putIfAbsent(user.getId(), user));

            debug("Target=%s (id=%s): %d candidate user(s) flagged pending.",
                    target.getName(), target.getId(), candidates.size());

            String base = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete configuration (baseUrl/token). Skipping pending entries.",
                        target.getName());
                failures += candidates.size();
                continue;
            }

            ScimClient client = createClient(target, base, token);

            for (UserModel user : candidates.values()) {
                usersScanned++;
                List<String> values = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList();
                if (values.isEmpty()) {
                    clearPendingFlag(session, realm, user, target.getId());
                    continue;
                }

                List<String> updatedValues = new ArrayList<>(values);
                boolean userChanged = false;
                boolean hadPendingForThisUser = false;

                for (String rawValue : values) {
                    Optional<MembershipState> parsed = MembershipState.parse(rawValue);
                    if (parsed.isEmpty()) {
                        debug("Skipping unparsable attribute value '%s' for user=%s",
                                rawValue, user.getUsername());
                        continue;
                    }
                    MembershipState entry = parsed.get();
                    if (!entry.componentId().equals(target.getId())
                            || entry.state() == MembershipState.State.SENT) {
                        continue;
                    }

                    hadPendingForThisUser = true;
                    String scimUserName = computeScimUserName(target, user);
                    if (scimUserName == null || scimUserName.isBlank()) {
                        err("Could not resolve SCIM userName for user=%s target=%s. Skipping.",
                                user.getUsername(), target.getName());
                        failures++;
                        continue;
                    }

                    try {
                        if (entry.state() == MembershipState.State.NEW_ADDED) {
                            boolean ok = upsertUser(target, client, user, scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                updatedValues.add(new MembershipState(
                                        entry.componentId(), entry.groupId(),
                                        MembershipState.State.SENT).toValue());
                                userChanged = true;
                                pushedAdds++;
                                info("PUSHED ADD user=%s target=%s groupId=%s -> SENT",
                                        user.getUsername(), target.getName(), entry.groupId());
                            } else {
                                failures++;
                                err("FAILED ADD push for user=%s target=%s groupId=%s. Will retry.",
                                        user.getUsername(), target.getName(), entry.groupId());
                            }
                        } else if (entry.state() == MembershipState.State.NEW_DELETED) {
                            if (!flushDeletes) {
                                debug("Mode=%s: retaining NEW_DELETED user=%s target=%s groupId=%s",
                                        mode, user.getUsername(), target.getName(), entry.groupId());
                                continue;
                            }
                            boolean ok = deprovisionUser(
                                    target, client, user.getId(), scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                userChanged = true;
                                pushedRemoves++;
                                info("PUSHED REMOVE user=%s target=%s groupId=%s -> entry removed",
                                        user.getUsername(), target.getName(), entry.groupId());
                            } else {
                                failures++;
                                err("FAILED REMOVE push for user=%s target=%s groupId=%s. Will retry.",
                                        user.getUsername(), target.getName(), entry.groupId());
                            }
                        }
                    } catch (Exception e) {
                        failures++;
                        err("EXCEPTION processing user=%s target=%s groupId=%s state=%s: %s",
                                user.getUsername(), target.getName(), entry.groupId(),
                                entry.state(), e.getMessage());
                    }
                }

                if (hadPendingForThisUser) {
                    usersWithPending++;
                }
                if (userChanged) {
                    writeState(session, realm, user, updatedValues);
                }

                boolean stillPendingForTarget = updatedValues.stream()
                        .map(MembershipState::parse)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .anyMatch(state -> state.componentId().equals(target.getId())
                                && state.state() != MembershipState.State.SENT);
                if (!stillPendingForTarget) {
                    clearPendingFlag(session, realm, user, target.getId());
                }
            }
        }

        info("=== processPendingMembershipChanges DONE realm=%s componentIdFilter=%s mode=%s: "
                        + "usersScanned=%d usersWithPending=%d pushedAdds=%d "
                        + "pushedRemoves=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                mode, usersScanned, usersWithPending, pushedAdds, pushedRemoves,
                failures, System.currentTimeMillis() - start);
    }

    /**
     * Re-provisions all current members of CFG_FILTER_GROUP and deprovisions users
     * previously marked SENT who are no longer members. Successful processing clears
     * all state and pending records for this target on affected users.
     */
    public static void processFullUserSync(KeycloakSession session, RealmModel realm,
                                           String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== processFullUserSync START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();

        if (targets.isEmpty()) {
            debug("No matching SCIM outbound targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int usersUpserted = 0;
        int usersDeprovisioned = 0;
        int failures = 0;

        for (ComponentModel target : targets) {
            String base = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete configuration. Skipping full user sync.",
                        target.getName());
                continue;
            }

            String filterGroupName = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroupName == null || filterGroupName.isBlank()) {
                debug("Target=%s has no CFG_FILTER_GROUP. Skipping full user sync.",
                        target.getName());
                continue;
            }

            Optional<org.keycloak.models.GroupModel> filterGroupOpt = session.groups()
                    .searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .findFirst();
            if (filterGroupOpt.isEmpty()) {
                err("Target=%s: filter group '%s' not found in realm=%s. Skipping.",
                        target.getName(), filterGroupName, realm.getName());
                continue;
            }
            org.keycloak.models.GroupModel filterGroup = filterGroupOpt.get();
            ScimClient client = createClient(target, base, token);

            Map<String, UserModel> currentMembers = new LinkedHashMap<>();
            session.users().getGroupMembersStream(realm, filterGroup)
                    .forEach(user -> currentMembers.put(user.getId(), user));

            for (UserModel user : currentMembers.values()) {
                String scimUserName = computeScimUserName(target, user);
                if (scimUserName == null || scimUserName.isBlank()) {
                    err("Could not resolve SCIM userName for user=%s target=%s. Skipping.",
                            user.getUsername(), target.getName());
                    failures++;
                    continue;
                }
                try {
                    if (upsertUser(target, client, user, scimUserName)) {
                        usersUpserted++;
                        info("FULL UPSERT user=%s target=%s -> OK",
                                user.getUsername(), target.getName());
                    } else {
                        failures++;
                        err("FULL UPSERT FAILED user=%s target=%s.",
                                user.getUsername(), target.getName());
                    }
                } catch (Exception e) {
                    failures++;
                    err("FULL UPSERT EXCEPTION user=%s target=%s: %s",
                            user.getUsername(), target.getName(), e.getMessage());
                }
            }

            String sentValue = new MembershipState(
                    target.getId(), filterGroup.getId(), MembershipState.State.SENT).toValue();
            List<UserModel> previouslyProvisioned =
                    UserStoragePrivateUtil.userLocalStorage(session)
                            .searchForUserByUserAttributeStream(
                                    realm, MembershipState.ATTRIBUTE_NAME, sentValue)
                            .filter(user -> !currentMembers.containsKey(user.getId()))
                            .collect(Collectors.toList());

            for (UserModel user : previouslyProvisioned) {
                String scimUserName = computeScimUserName(target, user);
                try {
                    if (deprovisionUser(target, client, user.getId(), scimUserName)) {
                        usersDeprovisioned++;
                        info("FULL DEPROVISION user=%s target=%s -> OK",
                                user.getUsername(), target.getName());
                    } else {
                        failures++;
                        err("FULL DEPROVISION FAILED user=%s target=%s.",
                                user.getUsername(), target.getName());
                    }
                } catch (Exception e) {
                    failures++;
                    err("FULL DEPROVISION EXCEPTION user=%s target=%s: %s",
                            user.getUsername(), target.getName(), e.getMessage());
                }
            }

            List<UserModel> allAffected = new ArrayList<>(currentMembers.values());
            for (UserModel user : previouslyProvisioned) {
                if (!currentMembers.containsKey(user.getId())) {
                    allAffected.add(user);
                }
            }
            for (UserModel user : allAffected) {
                clearAllStateForTarget(session, realm, user, target.getId());
            }
        }

        info("=== processFullUserSync DONE realm=%s componentIdFilter=%s: "
                        + "usersUpserted=%d usersDeprovisioned=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                usersUpserted, usersDeprovisioned, failures,
                System.currentTimeMillis() - start);
    }

    private static ScimClient createClient(ComponentModel target, String base, String token) {
        String lookupStrategy = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);
        return new ScimClient(base, token, lookupStrategy);
    }

    private static void writeState(KeycloakSession session, RealmModel realm,
                                   UserModel user, List<String> updatedValues) {
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session)
                .getUserById(realm, user.getId());
        if (localUser != null) {
            localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedValues);
            debug("Updated state for user=%s through local storage.", user.getUsername());
        } else {
            err("Could not resolve local storage user for id=%s (username=%s).",
                    user.getId(), user.getUsername());
        }
    }

    private static void clearPendingFlag(KeycloakSession session, RealmModel realm,
                                         UserModel user, String componentId) {
        List<String> currentPending = user
                .getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList();
        String pendingValue = MembershipState.pendingValue(componentId);
        if (!currentPending.contains(pendingValue)) {
            return;
        }
        List<String> updatedPending = new ArrayList<>(currentPending);
        updatedPending.remove(pendingValue);
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session)
                .getUserById(realm, user.getId());
        if (localUser == null) {
            err("Could not resolve local storage user for id=%s; pending flag remains.",
                    user.getId());
            return;
        }
        localUser.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, updatedPending);
    }

    private static void clearAllStateForTarget(KeycloakSession session, RealmModel realm,
                                               UserModel user, String componentId) {
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session)
                .getUserById(realm, user.getId());
        if (localUser == null) {
            err("Could not resolve local storage user for id=%s; state clear skipped.",
                    user.getId());
            return;
        }

        List<String> updatedState = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME)
                .filter(raw -> MembershipState.parse(raw)
                        .map(state -> !state.componentId().equals(componentId))
                        .orElse(true))
                .collect(Collectors.toList());
        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedState);

        List<String> updatedPending = new ArrayList<>(user
                .getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList());
        updatedPending.remove(MembershipState.pendingValue(componentId));
        localUser.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, updatedPending);
    }

    private static String computeScimUserName(ComponentModel target, UserModel user) {
        String strategy = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username");
        return switch (strategy) {
            case "email" -> nullIfBlank(user.getEmail());
            case "attribute" -> {
                String attribute = ScimTargetProviderFactory.get(
                        target, ScimTargetProviderFactory.CFG_UNAME_ATTR, null);
                yield attribute == null
                        ? null
                        : nullIfBlank(user.getFirstAttribute(attribute));
            }
            default -> user.getUsername();
        };
    }

    private static String nullIfBlank(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    static boolean upsertUser(ComponentModel target, ScimClient scim,
                              UserModel user, String scimUserName) {
        String externalId = user.getId();
        Optional<String> existingId = resolveScimId(
                target, scim, externalId, scimUserName);
        if (existingId.isEmpty()) {
            boolean created = scim.users().create(
                    ScimMapper.buildCreateUser(user, scimUserName));
            if (created) {
                return true;
            }
            existingId = resolveScimId(target, scim, externalId, scimUserName);
            return existingId
                    .map(id -> scim.users().patch(
                            id, ScimMapper.buildPatchUser(user, externalId)))
                    .orElse(false);
        }
        return scim.users().patch(
                existingId.get(), ScimMapper.buildPatchUser(user, externalId));
    }

    private static boolean deprovisionUser(ComponentModel target, ScimClient scim,
                                           String externalId, String scimUserName) {
        Optional<String> id = resolveScimId(target, scim, externalId, scimUserName);
        if (id.isEmpty()) {
            debug("Deprovision NO-OP: user not found in SCIM "
                            + "(externalId=%s userName=%s)", externalId, scimUserName);
            return true;
        }
        String mode = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate");
        return "delete".equals(mode)
                ? scim.users().delete(id.get())
                : scim.users().patch(id.get(), ScimMapper.buildDeactivatePatch());
    }

    /** Lookup strategy is owned by the client resource API. */
    private static Optional<String> resolveScimId(ComponentModel target, ScimClient scim,
                                                   String externalId, String scimUserName) {
        return scim.users().resolveId(externalId, scimUserName);
    }

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }

    private static void debug(String format, Object... args) {
        System.out.printf("%s %s DEBUG %s%n",
                now(), LOG_TAG, String.format(format, args));
    }

    private static void info(String format, Object... args) {
        System.out.printf("%s %s INFO %s%n",
                now(), LOG_TAG, String.format(format, args));
    }

    private static void err(String format, Object... args) {
        System.err.printf("%s %s ERROR %s%n",
                now(), LOG_TAG, String.format(format, args));
    }
}
