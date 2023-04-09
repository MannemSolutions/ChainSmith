extern crate rcgen;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnValue, IsCa, DnType};

use crate::tls_subject::TlsSubject;

pub struct TlsCa {
    subject_alternate_name: Vec<String>,
    dn: DistinguishedName,
    cert: Option<Certificate>,
    pem: String,
    key: String,
}

impl TlsCa {
    pub fn new() -> TlsCa {
        let san = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
        TlsCa{
            subject_alternate_name: san,
            dn: DistinguishedName::new(),
            cert: None,
            pem: "".to_string(),
            key: "".to_string(),
        }
    }
    pub fn with_san(mut self, san: Vec<String>) -> TlsCa {
        self.subject_alternate_name = san;
        self
    }
    pub fn with_dn(mut self, subj: &str) -> TlsCa {
        let dn = TlsSubject::from_string(subj).as_distinguished_name();
        for (dn_type, dn_value) in dn.iter() {
            self.dn.push(dn_type.clone(), dn_value.clone());
        }
        self
    }
    fn get_cn(&self) -> Option<String> {
        match self.dn.get(&DnType::CommonName) {
            Some(DnValue::PrintableString(common_name)) |
            Some(DnValue::Utf8String(common_name)) => Some(common_name.clone()),
            Some(DnValue::TeletexString(bytes)) |
            Some(DnValue::UniversalString(bytes)) |
            Some(DnValue::BmpString(bytes)) => Some(String::from_utf8_lossy(bytes).to_string()),
            _ => None,
        }
    }
    pub fn gen_cert(mut self) -> TlsCa {
        if self.cert.is_some() {
            return self
        }
        if self.subject_alternate_name.len() == 0 {
            self.subject_alternate_name.push(
                self.get_cn().unwrap_or("NoCommonName".to_string()));
        }
        let mut params = CertificateParams::new(self.subject_alternate_name.clone());
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(1));
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, DnValue::PrintableString("chainsmith".to_string()));
        match Certificate::from_params(params) {
            Ok(cert) => {
                self.pem = cert.serialize_pem().unwrap_or("".to_string());
                self.key = cert.serialize_private_key_pem();
                self.cert = Some(cert);
            },
            Err(err) =>
                println!("Error generating cert: {}", err),
        };
        self
    }
    pub fn get_cert(&self) -> Option<String> {
        let pem = self.pem.clone();
        match pem.as_str() {
            "" => None,
            _ => Some(pem),

        }
    }

    fn get_key(&self) -> Option<String> {
        let key = self.key.clone();
        match key.as_str() {
            "" => None,
            _ => Some(key),

        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_line(lines: &str) -> String {
        lines.lines().next().unwrap_or("").to_string()
    }
    #[test]
    fn test_ca() {
        let ca = TlsCa::new()
            .with_dn("/C=US/ST=Utah/L=Lehi/O=Your Company, Inc./OU=IT/CN=yourdomain.com")
            .with_san(vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()])
            .gen_cert();

        assert_eq!("-----BEGIN CERTIFICATE-----".to_string(),
                   first_line(ca.get_cert().unwrap_or("???".to_string()).as_str()));
        assert_eq!("-----BEGIN PRIVATE KEY-----".to_string(),
                   first_line(ca.get_key().unwrap_or("???".to_string()).as_str()));

    }
}
