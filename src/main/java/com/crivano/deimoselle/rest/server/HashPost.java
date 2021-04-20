package com.crivano.deimoselle.rest.server;

import com.crivano.blucservice.api.IBlueCrystal.HashPostRequest;
import com.crivano.blucservice.api.IBlueCrystal.HashPostResponse;
import com.crivano.blucservice.api.IBlueCrystal.IHashPost;

public class HashPost implements IHashPost {

	@Override
	public String getContext() {
		return "deimoselle-hash";
	}

	@Override
	public void run(HashPostRequest req, HashPostResponse resp) throws Exception {
		throw new Exception("not implemented");
	}
}
