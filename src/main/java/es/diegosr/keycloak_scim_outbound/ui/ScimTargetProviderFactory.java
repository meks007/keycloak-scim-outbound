package es.diegosr.keycloak_scim_outbound.ui;

import es.diegosr.keycloak_scim_outbound.ldapsync.ScimGroupSync;
import es.diegosr.keycloak_scim_outbound.ldapsync.ScimMembershipSync;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

import java.util.Date;
import java.util.List;

/** UI configuration and manual synchronization entry point for a SCIM target. */
public class ScimTargetProviderFactory
        implements UserStorageProviderFactory<ScimTargetProvider>, ImportSynchronization {

    private static final String LOG_TAG = "[keycloak-scim-outbound/MANUAL-SYNC]";

    public static final String ID = "keycloak-scim-outbound";
    public static final String CFG_BASE_URL = "baseUrl";
    public static final String CFG_TOKEN = "token";
    public static final String CFG_FILTER_GROUP = "filterGroup";
    public static final String CFG_UNAME_STRATEGY = "userNameStrategy";
    public static final String CFG_UNAME_ATTR = "userNameAttribute";
    public static final String CFG_DEPROVISION = "deprovisionAction";
    public static final String CFG_SYNC_GROUPS = "syncGroups";
    public static final String CFG_SYNC_GROUPS_FILTER = "syncGroupsFilter";
    public static final String CFG_LDAP_USER_PROV_MODE = "ldapUserProvMode";
    public static final String CFG_LDAP_GROUP_PROV_MODE = "ldapGroupProvMode";
    public static final String CFG_GROUP_MEMBER_REMOVE_FORM = "groupMemberRemoveForm";
    public static final String CFG_LOOKUP_STRATEGY = "lookupStrategy";

    public static final String LOOKUP_STRATEGY_EXTERNAL_ID_FIRST = "externalId first";
    public static final String LOOKUP_STRATEGY_NAME_ONLY = "name only";

    private static final List<ProviderConfigProperty> PROPS = List.of(
            property(ProviderConfigProperty.STRING_TYPE, CFG_BASE_URL,
                    "SCIM Base URL, including the SCIM v2 path.", true, "SCIM Base URL"),
            property(ProviderConfigProperty.PASSWORD, CFG_TOKEN,
                    "Bearer token used to authenticate against the SCIM target.", true, "SCIM Token"),
            property(ProviderConfigProperty.STRING_TYPE, CFG_FILTER_GROUP,
                    "Only users in this Keycloak group are provisioned.", false, "Filter Group"),
            listProperty(CFG_UNAME_STRATEGY,
                    "How to build SCIM userName.",
                    List.of("username", "email", "attribute"), "username"),
            property(ProviderConfigProperty.STRING_TYPE, CFG_UNAME_ATTR,
                    "User attribute used when userNameStrategy is attribute.", false,
                    "UserName Attribute"),
            listProperty(CFG_DEPROVISION,
                    "Deactivate or delete users that leave the provisioning scope.",
                    List.of("deactivate", "delete"), "deactivate"),
            listProperty(CFG_LOOKUP_STRATEGY,
                    "Resolve by externalId first with name fallback, or use name only.",
                    List.of(LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, LOOKUP_STRATEGY_NAME_ONLY),
                    LOOKUP_STRATEGY_EXTERNAL_ID_FIRST),
            property(ProviderConfigProperty.BOOLEAN_TYPE, CFG_SYNC_GROUPS,
                    "Enable SCIM /Groups synchronization.", false, "Sync Groups"),
            property(ProviderConfigProperty.STRING_TYPE, CFG_SYNC_GROUPS_FILTER,
                    "Java regex for group names. Empty means Filter Group only.", false,
                    "Sync Groups Filter"),
            listProperty(CFG_LDAP_USER_PROV_MODE,
                    "For changed-user sync: add-only retains removals; add and remove processes both; full reconciles the scope.",
                    List.of(ScimMembershipSync.MODE_DELTA_ONLY,
                            ScimMembershipSync.MODE_DELTA_DEPROVISION,
                            ScimMembershipSync.MODE_FULL),
                    ScimMembershipSync.MODE_DELTA_ONLY),
            listProperty(CFG_LDAP_GROUP_PROV_MODE,
                    "For changed-user sync: add-only, add and remove with cross-check, or full replacement.",
                    List.of(ScimGroupSync.MODE_DELTA_ONLY,
                            ScimGroupSync.MODE_DELTA_DEPROVISION,
                            ScimGroupSync.MODE_FULL),
                    ScimGroupSync.MODE_DELTA_ONLY),
            listProperty(CFG_GROUP_MEMBER_REMOVE_FORM,
                    "Payload form used to remove a member from a SCIM group.",
                    List.of(ScimMapper.REMOVE_FORM_RFC_PATH_FILTER,
                            ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY),
                    ScimMapper.REMOVE_FORM_RFC_PATH_FILTER)
    );

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPS;
    }

    @Override
    public ScimTargetProvider create(KeycloakSession session, ComponentModel model) {
        return new ScimTargetProvider(session, model);
    }

    @Override
    public String getId() {
        return ID;
    }

    public String getHelpText() {
        return "Push Keycloak users and optional groups to an external SCIM v2 endpoint.";
    }

    @Override
    public void init(org.keycloak.Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm,
                                      ComponentModel model)
            throws ComponentValidationException {
        require(model, CFG_BASE_URL, "SCIM Base URL is required");
        require(model, CFG_TOKEN, "SCIM token is required");
        String base = get(model, CFG_BASE_URL, "");
        if (!base.startsWith("http://") && !base.startsWith("https://")) {
            throw new ComponentValidationException(
                    "SCIM Base URL must start with http:// or https://");
        }
        String userNameStrategy = get(model, CFG_UNAME_STRATEGY, "username");
        if (!List.of("username", "email", "attribute").contains(userNameStrategy)) {
            throw new ComponentValidationException("Invalid userNameStrategy");
        }
        if ("attribute".equals(userNameStrategy)) {
            require(model, CFG_UNAME_ATTR,
                    "UserName Attribute is required for attribute strategy");
        }
        String deprovision = get(model, CFG_DEPROVISION, "deactivate");
        if (!List.of("deactivate", "delete").contains(deprovision)) {
            throw new ComponentValidationException("Invalid deprovisionAction");
        }
        String regex = get(model, CFG_SYNC_GROUPS_FILTER, null);
        if (regex != null && !regex.isBlank()) {
            try {
                java.util.regex.Pattern.compile(regex);
            } catch (java.util.regex.PatternSyntaxException e) {
                throw new ComponentValidationException(
                        "Sync Groups Filter is not a valid Java regex: " + e.getMessage());
            }
        }
    }

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory,
                                      String realmId, UserStorageProviderModel model) {
        info("Synchronize all triggered for target=%s realm=%s",
                model.getName(), realmId);
        return runSweep(sessionFactory, realmId, model, true);
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync,
                                           KeycloakSessionFactory sessionFactory,
                                           String realmId,
                                           UserStorageProviderModel model) {
        info("Synchronize changed triggered for target=%s realm=%s lastSync=%s",
                model.getName(), realmId, lastSync);
        return runSweep(sessionFactory, realmId, model, false);
    }

    private SynchronizationResult runSweep(KeycloakSessionFactory sessionFactory,
                                            String realmId, ComponentModel model,
                                            boolean fullSync) {
        long start = System.currentTimeMillis();
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    err("Realm not found for realmId=%s target=%s",
                            realmId, model.getName());
                    return;
                }
                session.getContext().setRealm(realm);

                String userMode = get(model, CFG_LDAP_USER_PROV_MODE,
                        ScimMembershipSync.MODE_DELTA_ONLY);
                if (fullSync || ScimMembershipSync.MODE_FULL.equals(userMode)) {
                    ScimMembershipSync.processFullUserSync(
                            session, realm, model.getId());
                } else {
                    ScimMembershipSync.processPendingMembershipChanges(
                            session, realm, model.getId(), userMode);
                }

                if ("true".equalsIgnoreCase(
                        get(model, CFG_SYNC_GROUPS, "false"))) {
                    String groupMode = get(model, CFG_LDAP_GROUP_PROV_MODE,
                            ScimGroupSync.MODE_DELTA_ONLY);
                    if (fullSync || ScimGroupSync.MODE_FULL.equals(groupMode)) {
                        ScimGroupSync.processFullGroupSync(
                                session, realm, model.getId());
                    } else {
                        ScimGroupSync.processPendingGroupMembershipChanges(
                                session, realm, model.getId(), groupMode);
                    }
                    ScimGroupSync.deprovisionOutOfScopeGroups(
                            session, realm, model.getId());
                }
            });
            info("Synchronization for target=%s completed in %dms",
                    model.getName(), System.currentTimeMillis() - start);
            return new SynchronizationResult();
        } catch (Exception e) {
            err("Synchronization for target=%s failed: %s",
                    model.getName(), e.getMessage());
            SynchronizationResult result = new SynchronizationResult();
            result.setFailed(1);
            return result;
        }
    }

    public static String get(ComponentModel model, String key, String fallback) {
        String value = model.getConfig().getFirst(key);
        return value == null ? fallback : value;
    }

    private static ProviderConfigProperty property(String type, String name,
                                                    String help, boolean required,
                                                    String label) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setType(type);
        property.setName(name);
        property.setLabel(label);
        property.setHelpText(help);
        property.setRequired(required);
        property.setSecret(ProviderConfigProperty.PASSWORD.equals(type));
        return property;
    }

    private static ProviderConfigProperty listProperty(String name, String help,
                                                        List<String> options,
                                                        String defaultValue) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setName(name);
        property.setLabel(name);
        property.setHelpText(help);
        property.setOptions(options);
        property.setDefaultValue(defaultValue);
        property.setRequired(true);
        return property;
    }

    private static void require(ComponentModel model, String key, String message)
            throws ComponentValidationException {
        String value = get(model, key, null);
        if (value == null || value.isBlank()) {
            throw new ComponentValidationException(message);
        }
    }

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
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
