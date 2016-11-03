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
package eu.europa.esig.dss.xades;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;

/**
 * TODO
 */
public class DSSManifest {

	private String id;

	private DSSDocument contents;

	private List<DSSReference> references;

	/**
	 * The default constructor
	 */
	public DSSManifest() {
	}

	public DSSManifest(final DSSManifest manifest) {
		id = manifest.id;
		contents = manifest.contents;
		if (manifest.references != null && !manifest.references.isEmpty()) {
			references = new ArrayList<DSSReference>();
			for (final DSSReference transform : manifest.references) {
				references.add(transform);
			}
		}
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public List<DSSReference> getReferences() {
		return references;
	}

	public void setReferences(List<DSSReference> references) {
		this.references = references;
	}

	public DSSDocument getContents() {
		return contents;
	}

	public void setContents(DSSDocument contents) {
		this.contents = contents;
	}

	@Override
	public String toString() {
		return "DSSManifest{" + "id='" + id + '\'' + ", contents="
				+ (contents != null ? contents.toString() : contents) + ", references=" + references + '}';
	}
}
