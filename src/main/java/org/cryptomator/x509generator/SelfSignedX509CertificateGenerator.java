package org.cryptomator.x509generator;

import static java.lang.System.currentTimeMillis;
import static java.math.BigInteger.ONE;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

class SelfSignedX509CertificateGenerator {

	private static final String SIGNATURE_AND_DIGEST_ALGORITHM_NAME = "SHA256withRSA";
	private static final long MILLISECONDS_PER_DAY = 24L * 60 * 60 * 1000; // ms
	private static final int KEY_SIZE = 2048;

	private final AsymmetricCipherKeyPair keyPair;
	private final X509CertificateHolder certificate;
	private final long validityInMilliseconds;

	public SelfSignedX509CertificateGenerator(SecureRandom secureRandom, X500Name issuerAndSubjectName, int validityInDays) {
		keyPair = generateKeyPair(secureRandom);
		certificate = generateCertificate(issuerAndSubjectName);
		validityInMilliseconds = validityInDays * MILLISECONDS_PER_DAY;
	}

	public AsymmetricKeyParameter getPrivateKey() {
		return keyPair.getPrivate();
	}

	public X509CertificateHolder getCertificate() {
		return certificate;
	}

	private AsymmetricCipherKeyPair generateKeyPair(SecureRandom secureRandom) {
		RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
		generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), secureRandom, KEY_SIZE, 112));
		return generator.generateKeyPair();
	}

	private X509CertificateHolder generateCertificate(X500Name issuerAndSubjectName) {
		return new X509v3CertificateBuilder( //
				issuerAndSubjectName, //
				serialNumber(), //
				validFrom(), validTo(), //
				issuerAndSubjectName, //
				publicKeyInfo()) //
						.build(signer());
	}

	private SubjectPublicKeyInfo publicKeyInfo() {
		try {
			return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic());
		} catch (IOException e) {
			throw new CertificateGenerationException(e);
		}
	}

	private BigInteger serialNumber() {
		return ONE;
	}

	private Date validFrom() {
		return new Date();
	}

	private Date validTo() {
		return new Date(currentTimeMillis() + validityInMilliseconds);
	}

	private ContentSigner signer() {
		AlgorithmIdentifier signingAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_AND_DIGEST_ALGORITHM_NAME);
		AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signingAlgorithm);
		try {
			return new BcRSAContentSignerBuilder(signingAlgorithm, digestAlgorithm).build(keyPair.getPrivate());
		} catch (OperatorCreationException e) {
			throw new CertificateGenerationException(e);
		}
	}

}
