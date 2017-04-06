package org.cryptomator.x509generator;

public class CertificateGenerationException extends SelfSignedX509CertificateException {

	CertificateGenerationException(Throwable cause) {
		super(cause);
	}

}
