package com.crivano.demoiselle.rest.server;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;

import com.crivano.blucservice.api.IBlueCrystal.CertificatePostRequest;
import com.crivano.blucservice.api.IBlueCrystal.CertificatePostResponse;
import com.crivano.blucservice.api.IBlueCrystal.HashPostRequest;
import com.crivano.blucservice.api.IBlueCrystal.HashPostResponse;
import com.crivano.blucservice.api.IBlueCrystal.IHashPost;

public class HashPost implements IHashPost {

	@Override
	public String getContext() {
		return "demoiselle-hash";
	}

	@Override
	public void run(HashPostRequest req, HashPostResponse resp) throws Exception {
		if (!("AD-RB".equals(req.policy) || "PKCS#7".equals(req.policy)))
			throw new Exception("Parameter 'policy' should be either 'AD-RB' or 'PKCS#7'");

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(req.certificate);
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

		Policies policy = Policies.AD_RB_CADES_2_3;
		resp.hash = DemoiselleHelper.produceSignedAttributes(cert, req.sha256, SignerAlgorithmEnum.SHA256withRSA,
				policy, req.time);

		CertificatePostRequest certReq = new CertificatePostRequest();
		CertificatePostResponse certResp = new CertificatePostResponse();
		certReq.certificate = req.certificate;
		CertificatePost.certDetails(certReq, certResp);
		resp.certdetails = certResp.certdetails;
		resp.cn = certResp.cn;

		PolicyFactory policyFactory = PolicyFactory.getInstance();
		org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy sp = policyFactory.loadPolicy(policy);

		sp.getSignPolicyInfo().getSignPolicyIdentifier().getValue();

		resp.policyoid = sp.getSignPolicyInfo().getSignPolicyIdentifier().getValue();
		String policyName = ValidatePost.recuperarNomePolitica(resp.policyoid);
		resp.policy = policyName.split(" ")[0];
		resp.policyversion = policyName.split(" ")[1].replace("v", "");
	}
}
