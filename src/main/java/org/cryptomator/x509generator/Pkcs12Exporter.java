package org.cryptomator.x509generator;

import static java.util.Arrays.fill;
import static org.bouncycastle.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;

class Pkcs12Exporter {

	private final X509CertificateHolder certificate;
	private final AsymmetricKeyParameter privateKey;
	private final SubjectKeyIdentifier publicKeyId;

	public Pkcs12Exporter(X509CertificateHolder certificate, AsymmetricKeyParameter privateKey) {
		this.certificate = certificate;
		this.privateKey = privateKey;
		this.publicKeyId = publicKeyId();
	}

	private SubjectKeyIdentifier publicKeyId() {
		try {
			return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(certificate.getSubjectPublicKeyInfo());
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateExportException(e);
		}
	}

	public byte[] asBytes(CharSequence password) {
		char[] passwordChars = new char[0];
		try {
			passwordChars = passwordAsCharArray(password);
			return asBytes(passwordChars);
		} finally {
			fill(passwordChars, '\0');
		}
	}

	private byte[] asBytes(char[] passwordChars) {
		try {
			return new PKCS12PfxPduBuilder() //
					.addData(createCertificateBag()) //
					.addData(createKeyBag(passwordChars)) //
					.build(sha1MacCalculator(), passwordChars) //
					.getEncoded(ASN1Encoding.DL);
		} catch (OperatorCreationException | IOException | PKCSException e) {
			throw new CertificateExportException(e);
		}
	}

	private PKCS12SafeBag createCertificateBag() throws IOException {
		return new PKCS12SafeBagBuilder(certificate) //
				.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, publicKeyId) //
				.build();
	}

	private PKCS12SafeBag createKeyBag(char[] passwordChars) throws OperatorCreationException, IOException {
		return new PKCS12SafeBagBuilder(createPrivateKeyInfo(privateKey), keyOutputEncryptor(passwordChars)) //
				.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, publicKeyId) //
				.build();
	}

	private BcPKCS12MacCalculatorBuilder sha1MacCalculator() {
		return new BcPKCS12MacCalculatorBuilder().setIterationCount(2048);
	}

	private char[] passwordAsCharArray(CharSequence password) {
		char[] result = new char[password.length()];
		for (int i = 0; i < result.length; i++) {
			result[i] = password.charAt(i);
		}
		return result;
	}

	private OutputEncryptor keyOutputEncryptor(char[] passwordChars) throws OperatorCreationException {
		return new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, new CBCBlockCipher(new DESedeEngine())) //
				.setIterationCount(2048) //
				.build(passwordChars);
	}

}
