package com.crivano.demoiselle.rest.server;

import com.crivano.blucservice.api.BlueCrystalContext;
import com.crivano.blucservice.api.IBlueCrystal.IAttachPost;

public class AttachPost implements IAttachPost {

	@Override
	public String getContext() {
		return "demoiselle-attach";
	}

	@Override
	public void run(Request req, Response resp, BlueCrystalContext ctx) throws Exception {
		throw new Exception("not implemented");
	}
}