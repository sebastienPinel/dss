/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import static javax.xml.crypto.dsig.XMLSignature.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSManifest;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class handles the specifics of the detached XML signature.
 */
class DetachedSignatureBuilder extends XAdESSignatureBuilder {

	private static final Logger logger = LoggerFactory.getLogger(DetachedSignatureBuilder.class);

	/**
	 * The default constructor for DetachedSignatureBuilder.<br>
	 * The detached signature uses by default the exclusive method of
	 * canonicalization.
	 *
	 * @param params
	 *            The set of parameters relating to the structure and process of
	 *            the creation or extension of the electronic signature.
	 * @param origDoc
	 *            The original document to sign.
	 * @param certificateVerifier
	 */
	public DetachedSignatureBuilder(final XAdESSignatureParameters params, final DSSDocument origDoc,
			final CertificateVerifier certificateVerifier) {
		super(params, origDoc, certificateVerifier);
		setCanonicalizationMethods(params, CanonicalizationMethod.EXCLUSIVE);
	}

	@Override
	protected Document buildRootDocumentDom() {
		if (params.getRootDocument() != null) {
			return params.getRootDocument();
		}
		return DSSXMLUtils.buildDOM();
	}

	@Override
	protected Node getParentNodeOfSignature() {
		if (params.getRootDocument() != null) {
			return documentDom.getDocumentElement();
		}
		return documentDom;
	}

	@Override
	protected List<DSSReference> createDefaultReferences() {

		final List<DSSReference> references = new ArrayList<DSSReference>();

		DSSDocument currentDetachedDocument = detachedDocument;
		do {
			final String fileURI = currentDetachedDocument.getName() != null ? currentDetachedDocument.getName() : "";
			// <ds:Reference Id="detached-ref-id" URI="xml_example.xml">
			final DSSReference reference = new DSSReference();
			reference.setId("xades-" + deterministicId + "-manifest-reference");
			reference.setUri("#xades-" + deterministicId + "-manifest");
			reference.setType("http://www.w3.org/2000/09/xmldsig#Manifest");
			// reference.setUri(fileURI);
			reference.setContents(currentDetachedDocument);
			// reference.setContents(manifestDom);
			reference.setDigestMethodAlgorithm(params.getDigestAlgorithm());

			final List<DSSTransform> dssTransformList = new ArrayList<DSSTransform>();

			// Canonicalization is the last operation, its better to operate the
			// canonicalization on the smaller
			// document
			DSSTransform dssTransform = new DSSTransform();
			dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
			dssTransformList.add(dssTransform);

			reference.setTransforms(dssTransformList);

			references.add(reference);
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
		return references;
	}

	/**
	 * Preconditions: - The reference data is XML - The last transformation is
	 * canonicalization.
	 *
	 * @param reference
	 *            {@code DSSReference} to be transformed
	 * @return {@code DSSDocument} containing transformed reference's data
	 */
	@Override
	protected DSSDocument transformReference(final DSSReference reference) {
		try {
			Canonicalizer canonicalizer = Canonicalizer.getInstance(reference.getTransforms().get(0).getAlgorithm());
			return new InMemoryDocument(canonicalizer.canonicalize(DSSUtils.toByteArray(reference.getContents())));
		} catch (InvalidCanonicalizerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CanonicalizationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DSSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return reference.getContents();
	}

	private static boolean isXPointer(final String uri) {
		final boolean xPointer = uri.startsWith("#xpointer(") || uri.startsWith("#xmlns(");
		return xPointer;
	}

	@Override
	protected void incorporateManifest() throws DSSException {
		DSSDocument currentDetachedDocument = detachedDocument;
		int referenceIndex = 1;

		// <ds:Object>
		final Element objectDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLNS, DS_OBJECT);

		do {
			final DSSManifest dssManifest = new DSSManifest();
			dssManifest.setId("xades-" + deterministicId + "-manifest");
			final String fileURI = currentDetachedDocument.getName() != null ? currentDetachedDocument.getName() : "";

			final Element manifestDom = DSSXMLUtils.addElement(documentDom, objectDom, XMLNS, DS_MANIFEST);
			manifestDom.setAttribute(ID, dssManifest.getId());

			final DSSReference dssReference = new DSSReference();
			dssReference.setType(currentDetachedDocument.getMimeType().getMimeTypeString());
			dssReference.setUri(fileURI);
			dssReference.setContents(currentDetachedDocument);
			dssReference.setDigestMethodAlgorithm(params.getDigestAlgorithm());

			final Element referenceDom = DSSXMLUtils.addElement(documentDom, manifestDom, XMLNS, DS_REFERENCE);

			final String uri = dssReference.getUri();
			referenceDom.setAttribute(URI, uri);
			referenceDom.setAttribute(TYPE, dssReference.getType());

			final List<DSSTransform> dssTransforms = new ArrayList<DSSTransform>();

			DSSTransform dssTransformTemp = new DSSTransform();
			dssTransformTemp.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
			dssTransforms.add(dssTransformTemp);

			dssReference.setTransforms(dssTransforms);

			if (dssTransforms != null) { // Detached signature may not have
											// transformations

				final Element transformsDom = DSSXMLUtils.addElement(documentDom, referenceDom, XMLNS, DS_TRANSFORMS);
				for (final DSSTransform dssTransform : dssTransforms) {

					final Element transformDom = DSSXMLUtils
							.addElement(documentDom, transformsDom, XMLNS, DS_TRANSFORM);
					createTransform(documentDom, dssTransform, transformDom);
				}
			}
			// <ds:DigestMethod
			// Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
			final DigestAlgorithm digestAlgorithm = dssReference.getDigestMethodAlgorithm();
			incorporateDigestMethod(referenceDom, digestAlgorithm);

			final DSSDocument canonicalizedDocument = transformReference(dssReference);
			if (logger.isTraceEnabled()) {
				logger.trace("Reference canonicalization method  -->" + signedInfoCanonicalizationMethod);
			}
			incorporateDigestValue(referenceDom, digestAlgorithm, canonicalizedDocument);

			DSSDocument manifestDoc = new InMemoryDocument(DSSXMLUtils.serializeNode(manifestDom));
			params.getReferences().get(0).setContents(manifestDoc);

			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);

	}

}