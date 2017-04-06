package org.cryptomator.x509generator;

import static org.bouncycastle.asn1.x500.style.BCStyle.CN;
import static org.bouncycastle.asn1.x500.style.BCStyle.O;

import java.security.SecureRandom;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SelfSignedX509Certificate {

	public static Builder selfSignedX509Certificate() {
		return new Builder();
	}

	private final X509CertificateHolder certificate;
	private final AsymmetricKeyParameter privateKey;

	private SelfSignedX509Certificate(Builder builder) {
		SelfSignedX509CertificateGenerator generator = certificateGeneratorFrom(builder);
		this.certificate = generator.getCertificate();
		this.privateKey = generator.getPrivateKey();
	}

	private SelfSignedX509CertificateGenerator certificateGeneratorFrom(Builder builder) {
		return new SelfSignedX509CertificateGenerator( //
				builder.secureRandom, //
				issuerAndSubjectName(builder), //
				builder.validityInDays);
	}

	private X500Name issuerAndSubjectName(Builder builder) {
		X500NameBuilder x500Name = new X500NameBuilder().addRDN(CN, builder.commonName);
		builder.organisation.ifPresent(organisation -> x500Name.addRDN(O, organisation));
		return x500Name.build();
	}

	public byte[] asPkcs12(CharSequence password) {
		return new Pkcs12Exporter(certificate, privateKey).asBytes(password);
	}

	public static class Builder {

		private Optional<String> organisation = Optional.empty();
		private int validityInDays = 365;
		private String commonName;
		private SecureRandom secureRandom;

		private Builder() {
		}

		public Builder withCommonName(String commonName) {
			this.commonName = commonName;
			return this;
		}

		public Builder withValidityPeriodInDays(int days) {
			if (days < 1) {
				throw new IllegalArgumentException("Days must not be < 1");
			}
			this.validityInDays = days;
			return this;
		}

		public Builder withOrganisation(String organisation) {
			if (!organisation.isEmpty()) {
				this.organisation = Optional.of(organisation);
			}
			return this;
		}

		public Builder withSecureRandom(SecureRandom secureRandom) {
			this.secureRandom = secureRandom;
			return this;
		}

		public SelfSignedX509Certificate generate() throws SelfSignedX509CertificateException {
			validate();
			return new SelfSignedX509Certificate(this);
		}

		public byte[] asPkcs12(CharSequence password) throws SelfSignedX509CertificateException {
			return generate().asPkcs12(password);
		}

		private void validate() {
			if (commonName == null) {
				throw new IllegalStateException("commonName is required");
			}
			if (secureRandom == null) {
				throw new IllegalStateException("secureRandom is required");
			}
		}

	}

}
