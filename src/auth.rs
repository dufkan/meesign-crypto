use std::{error::Error, str::FromStr};

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use x509_cert::der::Encode;
use x509_cert::{
    builder::{Builder, RequestBuilder},
    name::Name,
};

pub fn gen_key_with_csr(name: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let key = SigningKey::random(&mut OsRng);
    let key_der = key.to_pkcs8_der()?.as_bytes().to_vec();

    let subject = Name::from_str(&format!("CN={name}"))?;
    let builder = RequestBuilder::new(subject, &key)?;
    let csr = builder.build::<DerSignature>()?;
    let csr_der = csr.to_der()?;

    Ok((key_der, csr_der))
}

pub fn cert_key_to_pkcs12(key_der: &[u8], cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let ca_der = None;
    let password = "";
    let pfx = p12::PFX::new(cert_der, key_der, ca_der, password, "meesign auth key")
        .ok_or("Error creating PKCS #12")?;
    Ok(pfx.to_der())
}
