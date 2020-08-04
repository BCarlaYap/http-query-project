use curl::easy::{Form, HttpVersion};
use std::io::{Error, ErrorKind};

use ipaddress::IPAddress;
use log::{debug, error};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5 {
    pub address: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl Socks5 {
    pub fn get_url(&self) -> String { format!("socks5h://{}", self.address) }

    pub fn count(&self) -> usize {
        let mut count_bytes: usize = 5;

        if let Some(user) = &self.user {
            count_bytes = count_bytes + 5 + user.len();
        }

        if let Some(pass) = &self.password {
            count_bytes = count_bytes + pass.len();
        }

        count_bytes = count_bytes + 11;

        match IPAddress::parse(&self.address) {
            Ok(ip_addr) => {
                if ip_addr.is_ipv4() {
                    debug!("address {} is an ipv4", &self.address);
                    count_bytes = count_bytes + 4 * 2;
                } else if ip_addr.is_ipv6() {
                    debug!("address {} is an ipv6", &self.address);
                    count_bytes = count_bytes + 16 * 2;
                }
            }

            Err(_) => {
                debug!("address {} is a domain name", &self.address);
                count_bytes = count_bytes + 2 + self.address.len() * 2;
            }
        }
        count_bytes
    }
}



#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestType {
    POST,
    GET,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostType {
    FORM(Vec<(String, bytes::Bytes)>),
    CUSTOM(bytes::Bytes),
}

impl PostType {
    pub fn create_form(&self) -> Result<Form, Error> {
        match self {
            PostType::FORM(key_value) => {
                let mut form = Form::new();
                for (key, value) in key_value.iter() {
                    form.part(key).contents(value.as_ref());
                }
                Ok(form)
            }
            PostType::CUSTOM(_) => {
                error!("Cannot create a form from a custom post field.");
                Err(Error::new(ErrorKind::InvalidInput, "cannot create form for Custom."))
            }
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolVersion {
    HttpAny,
    Http10,
    Http11,
    Http20,
    Http2TLS,
    Http2PriorKnowledge,
}

impl ProtocolVersion {
    pub fn get_curl_version(&self) -> HttpVersion {
        match self {
            ProtocolVersion::HttpAny => HttpVersion::Any,
            ProtocolVersion::Http10 => HttpVersion::V10,
            ProtocolVersion::Http11 => HttpVersion::V11,
            ProtocolVersion::Http20 => HttpVersion::V2,
            ProtocolVersion::Http2TLS => HttpVersion::V2TLS,
            ProtocolVersion::Http2PriorKnowledge => HttpVersion::V2PriorKnowledge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn create_form_success() {
        let post_fields = vec![("key1".to_string(), Bytes::from_static(b"value1"))];

        let mut x = PostType::FORM(post_fields);
        let form = x.create_form();

        assert_eq!(form.is_ok(), true);
    }

    #[test]
    fn sock5_count_success() {
        let mut socks5 =
            Socks5 { address: "1.2.3.4".to_string(), port: 40, user: None, password: None };
        assert_eq!(socks5.count(), 24);

        socks5.address = "localhost".to_string();
        assert_eq!(socks5.count(), 36);


        socks5.user = Some("user".to_string());
        socks5.password = Some("pass".to_string());
        assert_eq!(socks5.count(), 49);
    }
}
