extern crate rcgen;

use rcgen::{DistinguishedName, DnType, DnValue};
use std::borrow::Borrow;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TlsSubject {
    kv: HashMap<String, String>,
}

fn dn_type_from_key(key: &str) -> Option<DnType> {
    match key {
        "C" =>  Some(rcgen::DnType::CountryName),
        "CN" => Some(rcgen::DnType::CommonName),
        "L" =>  Some(rcgen::DnType::LocalityName),
        "ST" => Some(rcgen::DnType::StateOrProvinceName),
        "O" =>  Some(rcgen::DnType::OrganizationName),
        "OU" => Some(rcgen::DnType::OrganizationalUnitName),
        _ => None,
    }
}

impl TlsSubject {
    pub fn from_string(from: &str) -> TlsSubject {
        let mut subject = TlsSubject::new();
        let split = from.split("/");
        for s in split {
            if let Some((key, value)) = s.split_once("=") {
                subject.set_value(key, value)
            }
        }
        subject
    }
    /*
    pub fn copy(&self) -> TlsSubject {
        let mut kv: HashMap<String, String> = HashMap::new();
        for (k, v) in self.kv.borrow() {
            kv.insert(k.to_string(), v.to_string());
        }
        TlsSubject {kv}
    }
    */
    pub fn new() -> TlsSubject {
        TlsSubject {
            kv: HashMap::new()
        }
    }
    pub fn to_string(&self) -> String {
        let mut vec = Vec::new();
        vec.push("".to_string());
        for (k, v) in self.clone().kv {
            vec.push(format!("{0}={1}", k, v))
        }
        vec.sort();
        vec.join("/")
    }
    fn set_value(&mut self, key: &str, value: &str) {
        self.kv.insert(key.to_string(), value.to_string());
    }
    fn get_value(&self, key: &str, default: &str) -> String {
        match self.kv.get_key_value(key) {
            Some(kv) => {
                let (k, v) = kv;
                if key.eq(k) {
                    return v.to_string();
                }
            }
            None => return default.to_string(),
        }
        default.to_string()
    }
    pub fn as_distinguished_name(&self) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        for (key, value) in self.kv.borrow() {
            match dn_type_from_key(key.as_str()) {
                Some(dn_type) => {
                    dn.push(dn_type, DnValue::PrintableString(value.to_string()))
                },
                None =>
                    println!("Skipping unknown DistinguishedName {}", key),
            };
        }
        dn
    }
    }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_subject() {
        let subject_as_string = "/C=US/CN=yourdomain.com/L=Lehi/O=Your Company, Inc./OU=IT/ST=Utah";
        let subject = TlsSubject::from_string(subject_as_string);
        assert_eq!(subject.get_value("C", "UNKNOWN"), "US");
        assert_eq!(subject.get_value("O", "UNKNOWN"), "Your Company, Inc.");
        assert_eq!(subject.get_value("OU", "UNKNOWN"), "IT");
        assert_eq!(subject.to_string(), subject_as_string);
        assert!(subject
                .as_distinguished_name()
                .get(&DnType::LocalityName)
                .is_some());
        assert!(subject
                .as_distinguished_name()
                .get(&DnType::LocalityName)
                .unwrap()
                .eq(&DnValue::PrintableString("Lehi".to_string()))
                );
    }
}
