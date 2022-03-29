package com.crivano.demoiselle.rest.server;

import com.crivano.blucservice.api.IBlueCrystal.AttachPostRequest;
import com.crivano.blucservice.api.IBlueCrystal.AttachPostResponse;
import com.crivano.blucservice.api.IBlueCrystal.IAttachPost;

public class AttachPost implements IAttachPost {

	@Override
	public String getContext() {
		return "demoiselle-attach";
	}

	@Override
	public void run(AttachPostRequest req, AttachPostResponse resp) throws Exception {
		throw new Exception("not implemented");
	}
}