package com.crivano.deimoselle.rest.server;

import com.crivano.blucservice.api.IBlueCrystal.EnvelopePostRequest;
import com.crivano.blucservice.api.IBlueCrystal.EnvelopePostResponse;
import com.crivano.blucservice.api.IBlueCrystal.IEnvelopePost;

public class EnvelopePost implements IEnvelopePost {

	@Override
	public String getContext() {
		return "deimoselle-envelope";
	}

	@Override
	public void run(EnvelopePostRequest req, EnvelopePostResponse resp) throws Exception {
		throw new Exception("not implemented");
	}
}