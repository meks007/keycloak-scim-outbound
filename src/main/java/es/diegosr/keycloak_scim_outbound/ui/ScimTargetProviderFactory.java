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

/** SCIM target configuration and manual LDAP synchronization trigger. */
public class ScimTargetProviderFactory implements UserStorageProviderFactory<ScimTargetProvider>, ImportSynchronization {
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
            prop(ProviderConfigProperty.STRING_TYPE, CFG_BASE_URL, "SCIM Base URL, including the SCIM v2 path.", true, "SCIM Base URL"),
            prop(ProviderConfigProperty.PASSWORD, CFG_TOKEN, "Bearer token for the SCIM target.", true, "SCIM Token"),
            prop(ProviderConfigProperty.STRING_TYPE, CFG_FILTER_GROUP, "Only members of this Keycloak group are provisioned.", false, "Filter Group"),
            list(CFG_UNAME_STRATEGY, "SCIM userName source.", List.of("username", "email", "attribute"), "username"),
            prop(ProviderConfigProperty.STRING_TYPE, CFG_UNAME_ATTR, "User attribute used when userName source is attribute.", false, "UserName Attribute"),
            list(CFG_DEPROVISION, "Action when a user leaves provisioning scope.", List.of("deactivate", "delete"), "deactivate"),
            list(CFG_LOOKUP_STRATEGY, "How SCIM resources are resolved.", List.of(LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, LOOKUP_STRATEGY_NAME_ONLY), LOOKUP_STRATEGY_EXTERNAL_ID_FIRST),
            prop(ProviderConfigProperty.BOOLEAN_TYPE, CFG_SYNC_GROUPS, "Enable SCIM group synchronization.", false, "Sync Groups"),
            prop(ProviderConfigProperty.STRING_TYPE, CFG_SYNC_GROUPS_FILTER, "Java regex for groups synchronized through LDAP. Empty means Filter Group only.", false, "Sync Groups Filter"),
            list(CFG_LDAP_USER_PROV_MODE, "Synchronize changed users: add-only keeps pending removals; add and remove processes both; full replaces the user scope.", List.of(ScimMembershipSync.MODE_DELTA_ONLY, ScimMembershipSync.MODE_DELTA_DEPROVISION, ScimMembershipSync.MODE_FULL), ScimMembershipSync.MODE_DELTA_ONLY),
            list(CFG_LDAP_GROUP_PROV_MODE, "Synchronize changed users group mode.", List.of(ScimGroupSync.MODE_DELTA_ONLY, ScimGroupSync.MODE_DELTA_DEPROVISION, ScimGroupSync.MODE_FULL), ScimGroupSync.MODE_DELTA_ONLY),
            list(CFG_GROUP_MEMBER_REMOVE_FORM, "SCIM PATCH member removal payload.", List.of(ScimMapper.REMOVE_FORM_RFC_PATH_FILTER, ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY), ScimMapper.REMOVE_FORM_RFC_PATH_FILTER)
    );

    @Override public List<ProviderConfigProperty> getConfigProperties() { return PROPS; }
    @Override public ScimTargetProvider create(KeycloakSession session, ComponentModel model) { return new ScimTargetProvider(session, model); }
    @Override public String getId() { return ID; }
    public String getHelpText() { return "Push Keycloak users and optional groups to an external SCIM v2 endpoint."; }
    @Override public void init(org.keycloak.Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        require(model, CFG_BASE_URL, "SCIM Base URL is required");
        require(model, CFG_TOKEN, "SCIM token is required");
        String base = get(model, CFG_BASE_URL, "");
        if (!base.startsWith("http://") && !base.startsWith("https://")) throw new ComponentValidationException("SCIM Base URL must start with http:// or https://");
        String userNameStrategy = get(model, CFG_UNAME_STRATEGY, "username");
        if (!List.of("username", "email", "attribute").contains(userNameStrategy)) throw new ComponentValidationException("Invalid userNameStrategy");
        if ("attribute".equals(userNameStrategy)) require(model, CFG_UNAME_ATTR, "UserName Attribute is required for attribute strategy");
        if (!List.of("deactivate", "delete").contains(get(model, CFG_DEPROVISION, "deactivate"))) throw new ComponentValidationException("Invalid deprovisionAction");
        String regex = get(model, CFG_SYNC_GROUPS_FILTER, null);
        if (regex != null && !regex.isBlank()) try { java.util.regex.Pattern.compile(regex); } catch (java.util.regex.PatternSyntaxException e) { throw new ComponentValidationException("Sync Groups Filter is not a valid Java regex: " + e.getMessage()); }
    }

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        return runSweep(sessionFactory, realmId, model, true);
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        return runSweep(sessionFactory, realmId, model, false);
    }

    private SynchronizationResult runSweep(KeycloakSessionFactory factory, String realmId, ComponentModel model, boolean full) {
        try {
            KeycloakModelUtils.runJobInTransaction(factory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) return;
                session.getContext().setRealm(realm);
                String userMode = full ? ScimMembershipSync.MODE_FULL : get(model, CFG_LDAP_USER_PROV_MODE, ScimMembershipSync.MODE_DELTA_ONLY);
                if (ScimMembershipSync.MODE_FULL.equals(userMode)) ScimMembershipSync.processFullUserSync(session, realm, model.getId());
                else ScimMembershipSync.processPendingMembershipChanges(session, realm, model.getId(), userMode);
                if ("true".equalsIgnoreCase(get(model, CFG_SYNC_GROUPS, "false"))) {
                    String groupMode = full ? ScimGroupSync.MODE_FULL : get(model, CFG_LDAP_GROUP_PROV_MODE, ScimGroupSync.MODE_DELTA_ONLY);
                    if (ScimGroupSync.MODE_FULL.equals(groupMode)) ScimGroupSync.processFullGroupSync(session, realm, model.getId());
                    else ScimGroupSync.processPendingGroupMembershipChanges(session, realm, model.getId(), groupMode);
                    ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, model.getId());
                }
            });
            return new SynchronizationResult();
        } catch (Exception e) {
            SynchronizationResult failed = new SynchronizationResult();
            failed.setFailed(1);
            return failed;
        }
    }

    public static String get(ComponentModel model, String key, String fallback) { String value = model.getConfig().getFirst(key); return value == null ? fallback : value; }
    private static ProviderConfigProperty prop(String type, String name, String help, boolean required, String label) { ProviderConfigProperty property = new ProviderConfigProperty(); property.setType(type); property.setName(name); property.setLabel(label); property.setHelpText(help); property.setRequired(required); property.setSecret(ProviderConfigProperty.PASSWORD.equals(type)); return property; }
    private static ProviderConfigProperty list(String name, String help, List<String> options, String defaultValue) { ProviderConfigProperty property = new ProviderConfigProperty(); property.setType(ProviderConfigProperty.LIST_TYPE); property.setName(name); property.setLabel(name); property.setHelpText(help); property.setOptions(options); property.setDefaultValue(defaultValue); property.setRequired(true); return property; }
    private static void require(ComponentModel model, String key, String message) throws ComponentValidationException { if (get(model, key, null) == null || get(model, key, "").isBlank()) throw new ComponentValidationException(message); }
}
