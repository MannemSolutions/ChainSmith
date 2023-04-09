extern crate rcgen;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnValue, IsCa};

mod tls_subject;
mod tls_objects;
//use crate::tls_subject::TlsSubject;

fn main() {
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];
    let mut params = CertificateParams::new(subject_alt_names);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(3));
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, DnValue::PrintableString("chainsmith".to_string()));


    let cert = Certificate::from_params(params).unwrap();

    // The certificate is now valid for localhost and the domain "hello.world.example"
    println!("{}", cert.serialize_pem().unwrap());
    println!("{}", cert.serialize_private_key_pem());
    println!("Hello, world!");
}

