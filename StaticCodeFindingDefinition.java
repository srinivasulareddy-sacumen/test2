package com.brinqa.connectors.github.models;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JavaType;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.ObjectClassInfoMetaData;
import org.identityconnectors.framework.common.objects.ObjectClassInfoMetaDataBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.PredefinedTags;

import com.brinqa.connectors.common.HandlerWrapper;
import com.brinqa.connectors.github.api.apps.Installation;
import com.brinqa.connectors.github.api.codescanning.CodeScanningAlert;
import com.brinqa.connectors.github.api.graphql.Repository;
import com.brinqa.connectors.model.ModelNames;
import com.brinqa.connectors.github.GitHubConnector;

import static com.brinqa.connectors.github.GitHubConnector.checkResponse;
import static com.brinqa.connectors.model.AttributeInfos.CATEGORIES;
import static com.brinqa.connectors.model.AttributeInfos.DESCRIPTION;
import static com.brinqa.connectors.model.AttributeInfos.NAME;
import static com.brinqa.connectors.model.AttributeInfos.SEVERITY;
import static com.brinqa.connectors.model.AttributeInfos.SOURCE_SEVERITY;
import static com.brinqa.connectors.model.AttributeInfos.TAGS;
import static com.brinqa.connectors.model.AttributeInfos.UID;
import static com.brinqa.connectors.model.ModelUtil.normalizeFindingSeverity;
import static org.identityconnectors.common.CollectionUtil.newSet;

public class StaticCodeFindingDefinition extends BaseStaticCodeFindingDefinitionModel {

    public static final String OBJECT_TYPE = "Code Scanning Alert";
    public static final ObjectClass OBJECT_CLASS = new ObjectClass(OBJECT_TYPE);

    protected final AttributeInfo RULE_SECURITY_SEVERITY = new AttributeInfoBuilder("RULE_SECURITY_SEVERITY").setTitle("Rule security severity").setType(String.class).build();
    protected final AttributeInfo SEVERITY_SCORE = new AttributeInfoBuilder("SEVERITY_SCORE").setTitle("Severity score").setType(String.class).build();

    @Override
    public ObjectClassInfoMetaData schemaMetaData() {
        return new ObjectClassInfoMetaDataBuilder()
            .setTarget(ModelNames.STATIC_CODE_FINDING_DEFINITION)
            .addTag(PredefinedTags.REQUIRED)
            .addIdentifier(UID)
            .setTitle(OBJECT_TYPE) // for display only
            .build();
    }

    @Override
    public ObjectClassInfo schema() {
        AttributeInfo[] attributeInfo = new AttributeInfo[]{
            UID,
            SEVERITY,
            SOURCE_SEVERITY,
            SEVERITY_SCORE,
            DESCRIPTION,
            NAME,
            RULE_SECURITY_SEVERITY,
            CATEGORIES,
            TAGS
        };

        ObjectClassInfoBuilder bld = new ObjectClassInfoBuilder();
        bld.setType(OBJECT_TYPE);
        bld.setOrder(2);

        // add static attributes
        bld.addAllAttributeInfo(newSet(attributeInfo));

        return bld.build();
    }

    public StaticCodeFindingDefinition(GitHubConnector connector) {
        super(connector);
    }

    public void sync(final Instant since, final HandlerWrapper handler, final OperationOptions opts) {
        long lastUpdated = Instant.now().toEpochMilli();
        List<Installation> installations = getOrgInstallations();
        for (Installation installation : installations) {
            if (installation.isOrganizationAccount()) {
                for (Repository repo : getRepositories(installation)) {
                    if (hasCodeScanningAnalysis(installation, repo)) {
                        syncCodeScanningAlerts(installation, repo, since, opts, codeScanningAlert -> {
                            ConnectorObject co = buildConnectorObject(installation, repo, codeScanningAlert);
                            return handler.handle(co, lastUpdated);
                        });
                    }
                }
            }
        }
    }

    private boolean handleAlerts(final Installation installation, final Repository repo, List<CodeScanningAlert> alerts, final HandlerWrapper handler, final long lastUpdated) {
        for (CodeScanningAlert alert : alerts) {
            ConnectorObject co = buildConnectorObject(installation, repo, alert);
            if (!handler.handle(co, lastUpdated)) {
                return false;
            }
        }
        return true;
    }

    public static ConnectorObject buildConnectorObject(final Installation installation, final Repository repo, final CodeScanningAlert alert) {
        ConnectorObjectBuilder bld = new ConnectorObjectBuilder();
        bld.setObjectClass(OBJECT_CLASS);

        alert.rule().ifPresent(rule -> {
            String uid = rule.id();

            bld.setUid(uid);
            bld.setName(uid);

            addAttribute(bld, UID, uid);
            rule.severity().ifPresent(val -> addAttribute(bld, SEVERITY, normalizeFindingSeverity(val)));
            rule.severity().ifPresent(val -> addAttribute(bld, SOURCE_SEVERITY, val));
            //rule.severity().ifPresent(val -> addAttribute(bld, SEVERITY_SCORE, val));
            rule.description().ifPresent(val -> addAttribute(bld, DESCRIPTION, val));
            rule.name().ifPresent(val -> addAttribute(bld, NAME, val));
            //rule.security_severity_level().ifPresent(val -> addAttribute(bld, RULE_SECURITY_SEVERITY, val));
            addAttribute(bld, TAGS, rule.tags());
        });

        return bld.build();
    }
}
