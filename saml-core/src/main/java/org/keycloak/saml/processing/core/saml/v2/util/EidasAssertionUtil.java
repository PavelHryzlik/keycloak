package org.keycloak.saml.processing.core.saml.v2.util;

import java.security.PrivateKey;

import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.parsers.saml.EidasSAMLParser;
import org.keycloak.saml.processing.core.util.JAXPValidationUtil;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Collections;
import java.util.Objects;

public class EidasAssertionUtil {

	public static Element decryptAssertion(ResponseType responseType, PrivateKey privateKey)
			throws ParsingException, ProcessingException, ConfigurationException {
		return decryptAssertion(responseType, encryptedData -> Collections.singletonList(privateKey));
	}

    /**
     * This method modifies the given responseType, and replaces the encrypted assertion with a decrypted version.
     *
     * @param responseType a response containing an encrypted assertion
     * @param decryptionKeyLocator locator of keys suitable for decrypting encrypted element
     *
     * @return the assertion element as it was decrypted. This can be used in signature verification.
     */
    public static Element decryptAssertion(ResponseType responseType, XMLEncryptionUtil.DecryptionKeyLocator decryptionKeyLocator) throws ParsingException, ProcessingException, ConfigurationException {
        Element enc = responseType.getAssertions().stream()
                .map(ResponseType.RTChoiceType::getEncryptedAssertion)
                .filter(Objects::nonNull)
                .findFirst()
                .map(EncryptedElementType::getEncryptedElement)
                .orElseThrow(() -> new ProcessingException("No encrypted assertion found."));

        String oldID = enc.getAttribute(JBossSAMLConstants.ID.get());
        Document newDoc = DocumentUtil.createDocument();
        Node importedNode = newDoc.importNode(enc, true);
        newDoc.appendChild(importedNode);

        Element decryptedDocumentElement = XMLEncryptionUtil.decryptElementInDocument(newDoc, decryptionKeyLocator);
        EidasSAMLParser parser = EidasSAMLParser.getInstance();

        JAXPValidationUtil.checkSchemaValidation(decryptedDocumentElement);
        AssertionType assertion = (AssertionType) parser.parse(parser.createEventReader(DocumentUtil
                .getNodeAsStream(decryptedDocumentElement)));

        responseType.replaceAssertion(oldID, new ResponseType.RTChoiceType(assertion));

        return decryptedDocumentElement;
       
    }
}