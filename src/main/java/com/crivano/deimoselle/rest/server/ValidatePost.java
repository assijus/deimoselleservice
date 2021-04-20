package com.crivano.deimoselle.rest.server;

import java.util.List;

import org.demoiselle.signer.core.extension.CertificateExtra;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;

import com.crivano.blucservice.api.IBlueCrystal.CertDetails;
import com.crivano.blucservice.api.IBlueCrystal.IValidatePost;
import com.crivano.blucservice.api.IBlueCrystal.ValidatePostRequest;
import com.crivano.blucservice.api.IBlueCrystal.ValidatePostResponse;
import com.crivano.swaggerservlet.ISwaggerCacheableMethod;
import com.crivano.swaggerservlet.SwaggerException;

public class ValidatePost implements IValidatePost, ISwaggerCacheableMethod {

	@Override
	public String getContext() {
		return "deimoselle-validate";
	}

	@Override
	public void run(ValidatePostRequest req, ValidatePostResponse resp) throws Exception {
		// Date dtSign = javax.xml.bind.DatatypeConverter.parseDateTime(time)
		// .getTime();

		// Produce response

		CAdESChecker checker = new CAdESChecker();
		List<SignatureInformations> signaturesInfo = checker.checkSignatureByHash(
				SignerAlgorithmEnum.SHA256withRSA.getOIDAlgorithmHash(), req.sha256, req.envelope);

		SignatureInformations si = signaturesInfo.get(0);

		CertificateExtra ce = new CertificateExtra(si.getIcpBrasilcertificate().getX509Certificate());

		resp.cn = si.getIcpBrasilcertificate().getName();
		resp.policyoid = si.getSignaturePolicy().getSignPolicyInfo().getSignPolicyIdentifier().getValue();
		String policy = recuperarNomePolitica(resp.policyoid);
		resp.policy = policy.split(" ")[0];
		resp.policyversion = policy.split(" ")[1].replace("v", "");
		if (si.getValidatorErrors() != null && si.getValidatorErrors().size() > 0)
			resp.errormsg = si.getValidatorErrors().get(0);
		resp.status = resp.errormsg == null ? "GOOD" : "INVALID_SIGN";
		resp.certdetails = new CertDetails();
		resp.certdetails.cpf0 = ce.getOID_2_16_76_1_3_1().getCPF();
		if (ce.isCertificatePF())
			resp.certdetails.birth_date0 = ce.getOID_2_16_76_1_3_1().getBirthDate();
		if (ce.isCertificatePJ())
			resp.certdetails.cnpj0 = ce.getOID_2_16_76_1_3_3().getCNPJ();
		resp.certdetails.san_email0 = ce.getEmail();
		if (resp.errormsg != null)
			throw new SwaggerException(resp.errormsg, 400, null, req, resp, "validando assinatura");
	}

	public static String recuperarNomePolitica(String politica) {
		switch (politica) {
		case "2.16.76.1.7.1.1.1":
			return "AD-RB v1.0";
		case "2.16.76.1.7.1.2.1":
			return "AD-RT v1.0";
		case "2.16.76.1.7.1.3.1":
			return "AD-RV v1.0";
		case "2.16.76.1.7.1.4.1":
			return "AD-RC v1.0";
		case "2.16.76.1.7.1.5.1":
			return "AD-RA v1.0";

		case "2.16.76.1.7.1.1.2.1":
			return "AD-RB v2.1";
		case "2.16.76.1.7.1.2.2.1":
			return "AD-RT v2.1";
		case "2.16.76.1.7.1.3.2.1":
			return "AD-RV v2.1";
		case "2.16.76.1.7.1.4.2.1":
			return "AD-RC v2.1";
		case "2.16.76.1.7.1.5.2.1":
			return "AD-RA v2.1";

		case "2.16.76.1.7.1.1.2.3":
			return "AD-RB v2.3";
		case "2.16.76.1.7.1.2.2.3":
			return "AD-RT v2.3";
		case "2.16.76.1.7.1.3.2.3":
			return "AD-RV v2.3";
		case "2.16.76.1.7.1.4.2.3":
			return "AD-RC v2.3";
		case "2.16.76.1.7.1.5.2.3":
			return "AD-RA v2.3";
		}
		return politica;
	}
}
