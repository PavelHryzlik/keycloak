package org.keycloak.broker.saml;

import org.keycloak.broker.provider.DefaultDataMarshaller;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.protocol.ArtifactResponseType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.parsers.saml.EidasSAMLParser;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLResponseWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class EidasSAMLDataMarshaller extends DefaultDataMarshaller {

    @Override
    public String serialize(Object obj) {

        // Lame impl, but hopefully sufficient for now. See if something better is needed...
        if (obj.getClass().getName().startsWith("org.keycloak.dom.saml")) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            try {
                if (obj instanceof ResponseType) {
                    ResponseType responseType = (ResponseType) obj;
                    SAMLResponseWriter samlWriter = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(responseType);
                } else if (obj instanceof AssertionType) {
                    AssertionType assertion = (AssertionType) obj;
                    SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(assertion);
                } else if (obj instanceof AuthnStatementType) {
                    AuthnStatementType authnStatement = (AuthnStatementType) obj;
                    SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(authnStatement, true);
                } else if (obj instanceof ArtifactResponseType) {
                    ArtifactResponseType artifactResponseType = (ArtifactResponseType) obj;
                    SAMLResponseWriter samlWriter = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(artifactResponseType);
                } else {
                    throw new IllegalArgumentException("Don't know how to serialize object of type " + obj.getClass().getName());
                }
            } catch (ProcessingException pe) {
                throw new RuntimeException(pe);
            }

            return new String(bos.toByteArray(), GeneralConstants.SAML_CHARSET);
        } else {
            return super.serialize(obj);
        }
    }

    @Override
    public <T> T deserialize(String serialized, Class<T> clazz) {
        if (clazz.getName().startsWith("org.keycloak.dom.saml")) {
            String xmlString = serialized;

            try {
                if (clazz.equals(ResponseType.class) || clazz.equals(AssertionType.class) || clazz.equals(AuthnStatementType.class) || clazz.equals(ArtifactResponseType.class)) {
                    byte[] bytes = xmlString.getBytes(GeneralConstants.SAML_CHARSET);
                    InputStream is = new ByteArrayInputStream(bytes);
                    Object respType = EidasSAMLParser.getInstance().parse(is);
                    return clazz.cast(respType);
                } else {
                    throw new IllegalArgumentException("Don't know how to deserialize object of type " + clazz.getName());
                }
            } catch (ParsingException pe) {
                throw new RuntimeException(pe);
            }

        } else {
            return super.deserialize(serialized, clazz);
        }
    }
}