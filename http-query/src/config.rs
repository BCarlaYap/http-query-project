use crate::models::{PostType, ProtocolVersion, RequestType, Socks5};

use bytes::Bytes;
use curl::easy::List;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub domain: String,
    pub user_agent: String,
    pub request: RequestType,
    pub data_limit: usize,

    verbose: bool,
    keep_alive: bool,
    timeout: Duration,
    max_redirections: u32,
    protocol: ProtocolVersion,
    custom_headers: Vec<(String, String)>,

    cookies: Option<String>,

    username: Option<String>,
    password: Option<String>,
    custom_ip: Option<String>,
    path: Option<String>,

    doh_url: Option<String>,
    socks5_proxy: Option<Socks5>,

    post_fields: Option<PostType>,
}

impl Config {
    pub fn new(
        domain: String,
        user_agent: String,
        request: RequestType,
        data_limit: usize,
    ) -> Config {
        Config {
            domain,
            user_agent,
            request,
            data_limit,
            path: None,
            custom_headers: vec![],
            protocol: ProtocolVersion::HttpAny,
            keep_alive: false,
            timeout: Duration::new(5, 0),
            max_redirections: 3,
            socks5_proxy: None,
            doh_url: None,
            custom_ip: None,
            username: None,
            password: None,
            cookies: None,
            post_fields: None,
            verbose: false,
        }
    }

    pub fn verbose(&mut self, enable: bool) { self.verbose = enable }

    pub fn set_keep_alive(&mut self, v: bool) { self.keep_alive = v; }

    pub fn set_timeout(&mut self, duration: Duration) { self.timeout = duration; }

    pub fn set_max_redirections(&mut self, v: u32) { self.max_redirections = v; }

    pub fn set_protocol(&mut self, version: ProtocolVersion) { self.protocol = version; }

    pub fn add_custom_header(&mut self, key: String, value: String) {
        self.custom_headers.push((key, value));
    }

    pub fn set_cookies(&mut self, cookies: String) { self.cookies = Some(cookies); }

    pub fn set_username(&mut self, username: String) { self.username = Some(username) }

    pub fn set_password(&mut self, password: String) { self.password = Some(password); }

    pub fn set_custom_ip(&mut self, ip: String) { self.custom_ip = Some(ip); }

    pub fn set_path(&mut self, path: String) { self.path = Some(path); }

    pub fn set_doh_url(&mut self, url: String) { self.doh_url = Some(url); }

    pub fn set_socks5(&mut self, socks5: Socks5) { self.socks5_proxy = Some(socks5); }

    pub fn add_post_field(&mut self, key: String, value: &[u8]) {
        let new_vec = match self.post_fields.clone() {
            Some(PostType::FORM(mut v)) => {
                &v.push((key, Bytes::from(value)));
                v.clone()
            }
            _ => vec![(key, Bytes::from(value))],
        };

        self.post_fields = Some(PostType::FORM(new_vec));
    }

    pub fn add_post_fields_raw(&mut self, raw_body: &[u8]) {
        self.post_fields = Some(PostType::CUSTOM(Bytes::from(raw_body)));
    }

    pub fn is_verbose(&self) -> bool { self.verbose }

    pub fn is_keep_alive(&self) -> bool { self.keep_alive }

    pub fn timeout(&self) -> Duration { self.timeout.clone() }

    pub fn max_redirections(&self) -> u32 { self.max_redirections }

    pub fn protocol(&self) -> &ProtocolVersion { &self.protocol }

    pub fn custom_header(&self) -> &Vec<(String, String)> { &self.custom_headers }

    pub fn custom_header_as_list(&self) -> Result<List, curl::Error> {
        let mut custom_header_list = List::new();
        for (key, value) in self.custom_headers.iter() {
            custom_header_list.append(format!("{}: {}", key, value).as_str())?;
        }

        Ok(custom_header_list)
    }

    pub fn cookies(&self) -> Option<&String> { self.cookies.as_ref() }

    pub fn username(&self) -> Option<&String> { self.username.as_ref() }

    pub fn password(&self) -> Option<&String> { self.password.as_ref() }

    pub fn custom_ip(&self) -> Option<&String> { self.custom_ip.as_ref() }

    pub fn path(&self) -> Option<&String> { self.path.as_ref() }

    pub fn doh_url(&self) -> Option<&String> { self.doh_url.as_ref() }

    pub fn socks5(&self) -> &Option<Socks5> { &self.socks5_proxy }

    pub fn post_fields(&self) -> &Option<PostType> { &self.post_fields }
}
