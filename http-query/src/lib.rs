pub mod config;
pub mod models;
pub mod handler;

use crate::{
    config::Config,
    handler::ResponseHandler,
    models::{PostType, RequestType},
};
use curl::easy::{Easy2, List, ProxyType};
use log::*;

use std::{
    io::{Error, ErrorKind},
    ops::Deref,
};
use std::net::TcpListener;
use std::sync::Arc;


///  Extracts ip addresses of domain and calculates how much bytes the request consumed.
///  This is only when DoH(DNS over Https) url is set in the config.
pub async fn resolve_ip(cfg_b: &Config) -> Result<(usize, Option<Vec<String>>), Error> {
    if cfg_b.doh_url().is_none() {
        return Err(Error::new(ErrorKind::NotFound, "doh url not set in config"));
    }
    let handler2 = ResponseHandler::new(cfg_b.data_limit, cfg_b.is_verbose());

    let mut easy2 = Easy2::new(handler2);

    easy2.get(true)?;
    easy2.verbose(true)?;
    easy2.tcp_nodelay(true)?;

    easy2.http_version(cfg_b.protocol().get_curl_version())?;

    let url = format!("{}?name={}&type=A", cfg_b.doh_url().unwrap(), &cfg_b.domain);
    easy2.url(url.as_str())?;

    let mut list = List::new();
    list.append("Accept: application/dns-json")?;
    easy2.http_headers(list)?;

    easy2
        .perform()
        .map(|_| {
            let contents = easy2.get_ref();
            let json_response: serde_json::Value = serde_json::from_slice(&contents.response_body)
                .expect("dns response not convertible to json.");

            let ans_value = json_response["Answer"].as_array().map(|j_arr| {
                let res: Vec<String> = j_arr
                    .into_iter()
                    .filter_map(|j_value| {
                        let data_type = j_value["type"].as_u64().unwrap();
                        if data_type == 1 {
                            j_value["data"].as_str().map(|str| str.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                res
            });
            (contents.calculated_size(), ans_value)
        })
        .map_err(|e| {
            warn!("failed to resolve: {:?}", e.code());
            Error::new(ErrorKind::Interrupted, e.description())
        })
}

/// The actual conversion of the config to easy2 of rust-curl.
/// Where the actual curl is performed.
/// Only http_process_query(...) can call this function.
async fn process_request(
    cfg: &Config,
    domain_ips: Option<Vec<String>>,
    xtra_calculated_size: usize,
) -> Result<ResponseHandler, Error> {
    let mut handler = ResponseHandler::new(cfg.data_limit, cfg.is_verbose());
    handler.add_calculated_size(xtra_calculated_size);

    let mut easy2 = Easy2::new(handler);

    //verbose is always true, because the the calculation of size happens in the handler's debug.
    //check fn debug(..) of ResponseHandler's implementation
    easy2.verbose(true)?;
    easy2.tcp_nodelay(true)?;
    easy2.timeout(cfg.timeout())?;
    easy2.useragent(cfg.user_agent.as_str())?;
    easy2.tcp_keepalive(cfg.is_keep_alive())?;
    easy2.max_redirections(cfg.max_redirections())?;
    easy2.http_version(cfg.protocol().get_curl_version())?;


    //if custom_ip provided, use that; else use the domain_ips provided from DoH.
    let mut list = List::new();
    if cfg.custom_ip().is_some() {
        let custom_ip = cfg.custom_ip().unwrap();
        list.append(format!("{}:443:{}", cfg.domain.clone(), custom_ip).as_str()).unwrap();
        easy2.resolve(list)?;
    } else if domain_ips.is_some() {
        for dom_ip in domain_ips.unwrap().iter() {
            list.append(format!("{}:443:{}", cfg.domain.clone(), dom_ip).as_str()).unwrap();
        }
        easy2.resolve(list)?;
    }

    //append the domain with https, to create the url.
    let request_url = format!("https://{}", cfg.domain);
    easy2.url(request_url.as_str())?;

    let custom_headers = cfg.custom_header_as_list()?;
    easy2.http_headers(custom_headers)?;

    //set from either GET or POST
    match cfg.request {
        RequestType::GET => easy2.get(true)?,
        RequestType::POST => {
            easy2.post(true)?;
            match &cfg.post_fields() {
                Some(PostType::CUSTOM(b)) => easy2.post_fields_copy(b.deref())?,
                Some(post_type_form) => {
                    let form = post_type_form.create_form()?;
                    easy2.httppost(form)?;
                }
                None => {}
            }
        }
    };

    if let Some(x) = cfg.username() {
        easy2.username(x.as_str())?;
    }

    if let Some(x) = cfg.password() {
        easy2.password(x.as_str())?;
    }

    if let Some(x) = cfg.socks5() {
        easy2.proxy(x.get_url().as_str())?;
        easy2.proxy_port(x.port)?;

        if let Some(user) = &x.user {
            easy2.proxy_username(user.as_str())?;
        }

        if let Some(pass) = &x.password {
            easy2.proxy_password(pass.as_str())?;
        }
        easy2.proxy_type(ProxyType::Socks5)?;
    }

    if let Some(x) = cfg.cookies() {
        easy2.cookie(x.as_str())?;
    }

    easy2
        .perform()
        .map(|_| {
            let contents: &ResponseHandler = easy2.get_ref();
            contents.to_owned()
        })
        .map_err(|e| {
            let contents: &ResponseHandler = easy2.get_ref();

            if e.code() == 23 && contents.calculated_size() > contents.data_limit {
                Error::new(ErrorKind::Other, "exceeded data limit")
            } else {
                Error::new(ErrorKind::ConnectionAborted, e.description())
            }
        })
}


/// Processes http requests.
/// Returns either the ResponseHandler (holding the response header and body) or an error.
pub async fn http_process_query(cfg: Config) -> Result<ResponseHandler, Error> {
    //check for DoH(DNS over Https)
    let (calculated_size, dom_ip_list_opt) = if cfg.custom_ip().is_none() && cfg.doh_url().is_some()
    {
        resolve_ip(&cfg).await?
    } else {
        (usize::MIN, None)
    };

    //update the calculated size coming from DoH
    let mut extra_calculated_size = calculated_size;

    //add to calculated size if socks is provided.
    if let Some(socks5) = cfg.socks5() {
        extra_calculated_size = extra_calculated_size + socks5.count();
    }

    process_request(&cfg, dom_ip_list_opt, extra_calculated_size).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProtocolVersion, Socks5};


    use futures::{future, executor::block_on};
    use std::time::Duration;

    #[test]
    fn resolve_ip_success() {
        let mut x =
            Config::new("google.com".to_string(), "panteum".to_string(), RequestType::GET, 10000);
        x.set_doh_url("https://cloudflare-dns.com/dns-query".to_string());
        x.verbose(true);

        block_on(async move {
            let resolve_res = resolve_ip(&x).await;

            match resolve_res {
                Ok((size, ip_addr_opt)) => {
                    println!("carla size: {}", size);
                    assert_eq!(ip_addr_opt.is_some(), true);
                }
                Err(e) => {
                    warn!("Error occurred: {:?}", e);
                    assert!(false);
                }
            };
        });
    }

    #[test]
    /// should fail, if the dns url is not valid
    fn resolve_ip_failed() {
        let mut cfg =
            Config::new("openai.com".to_string(), "panteum".to_string(), RequestType::GET, 10000);
        cfg.set_doh_url("https://cloudflare-dns-wrong.com/dns-query".to_string());
        cfg.verbose(true);

        block_on(async move {
            let resolve_res = resolve_ip(&cfg).await;
            assert_eq!(resolve_res.is_err(), true);

            match resolve_res {
                Ok(_) => assert!(false),
                Err(e) => assert_eq!(e.to_string(), "Couldn't resolve host name"),
            };
        })
    }

    #[test]
    fn http_process_query_get_one() {

        block_on(async move {
                    let mut cfg =
                        Config::new("google.com".to_string(), "panteum".to_string(), RequestType::GET, 1000000);
                    //cfg.set_path("/about".to_string());
                    cfg.set_protocol(ProtocolVersion::Http20);
                    // cfg.set_socks5(Socks5 {
                    //     address: "173.44.37.82".to_string(),
                    //     port: 1085,
                    //     user: None,
                    //     password: None,
                    // });
                    cfg.set_socks5(Socks5 {
                        address: "127.0.0.1".to_string(),
                        port: 1339,
                        user: None,
                        password: None //Some("mypassword".to_string()),
                    });
                    cfg.verbose(true);

                    match http_process_query(cfg).await {
                        Ok(r) => {
                            println!("CARLA CARLA HEADER SIZE: {}", &r.response_header.len());
                            println!(
                                "CARLA CARLA HEADER: {:?}",
                                String::from_utf8_lossy(&r.response_header)
                            );

                            println!("CARLA CARLA BODY SIZE: {}", &r.response_body.len());
                            println!("CARLA CARLA TOTAL: {}", &r.calculated_size());
                            assert!(true);
                        }
                        Err(e) => {
                            // let err_desc = format!("{:?}", e.to_string());
                            // assert_eq!(err_desc, "\"exceeded data limit\"");
                        }
                    }
        })
    }

    #[test]
    fn http_process_query_get_many() {
        block_on(async move {
            let domains_query = vec![
                "youtube.com",
                "en.wikipedia.org",
                "twitter.com",
                "facebook.com",
                "amazon.com",
                "yelp.com",
                "reddit.com",
                "imdb.com",
                "pinterest.com",
                "tripadvisor.com",
                "instagram.com",
                "walmart.com",
                "craigslist.org",
                "ebay.com",
                "linkedin.com",
                "play.google.com",
                "etsy.com",
                "indeed.com",
                "apple.com",
                "espn.com",
                "nytimes.com",
                "google.com",
                "yandex.ru",
                "yahoo.co.jp",
                "ok.ru",
                "bit.ly",
                "baidu.com",
                "vk.com",
                "rottentomatoes.com",
                "irs.gov",
                "netflix.com",
                "roblox.com",
                "dailymail.co.uk",
                "speedtest.net",
                "live.com",
                "zoom.us",
                "worldometers.info",
                "stackoverflow.com",
                "naver.com",
                "amazon.co.jp",
                "google.co.in",
                "msn.com",
                "wsj.com",
                "bing.com",
                "twitch.com",
                "paypal.com",
                "huffpost.com",
                "techradar.com",
                "hulu.com",
                "quora.com",
            ]
            .iter()
            .map(|dom| {
                let mut cfg =
                    Config::new(dom.to_string(), "panteum".to_string(), RequestType::GET, 640000);
                cfg.set_protocol(ProtocolVersion::Http20);

                http_process_query(cfg)
            })
            .collect::<Vec<_>>();

            match future::try_join_all(domains_query).await {
                Ok(vec_handlers) => {
                    for resp_hand in vec_handlers {
                        assert_eq!(resp_hand.response_header.is_empty(), false);
                        assert!(&resp_hand.calculated_size() <= &resp_hand.data_limit);
                    }
                }
                Err(e) => {
                    warn!("Failed: {:?}", e);
                    assert!(false);
                }
            }
        })
    }

    #[test]
    fn http_process_query_post() {
        let mut cfg = Config::new(
            "fakerestapi.azurewebsites.net".to_string(),
            "panteum".to_string(),
            RequestType::POST,
            100000,
        );
        cfg.set_path("/api/users".to_string());

        cfg.add_post_fields_raw(
            b"{
        \"ID\": 0,
        \"UserName\": \"Lorem Ipsum\",
        \"Password\": \"Pass\"
        }",
        );

        cfg.set_socks5(Socks5 {
            address: "173.44.37.82".to_string(),
            port: 1085,
            user: None,
            password: None,
        });


        cfg.set_doh_url("https://cloudflare-dnS.com/dns-query".to_string());
        cfg.verbose(true);

        block_on(async move {
            match http_process_query(cfg).await {
                Ok(res) => {
                    debug!("response header: {}", String::from_utf8_lossy(&res.response_header));

                    debug!("response body: {}", String::from_utf8_lossy(&res.response_body));

                    assert_eq!(res.response_header.is_empty(), false);
                    assert_eq!(res.response_body.is_empty(), false);
                    assert!(res.calculated_size() <= res.data_limit);
                }
                Err(e) => {
                    error!("{:?}", e.to_string());
                    assert!(false);
                }
            }
        })
    }

    #[test]
    fn http_process_query_timeout() {
        let mut cfg = Config::new(
            "world.taobao.com".to_string(),
            "panteum".to_string(),
            RequestType::GET,
            100000,
        );
        cfg.set_timeout(Duration::from_millis(1));
        cfg.verbose(true);

        block_on(async move {
            match http_process_query(cfg).await {
                Ok(res) => assert!(false),
                Err(e) => {
                    let err_desc = format!("{:?}", e.to_string());
                    assert_eq!(err_desc, "\"Timeout was reached\"");
                }
            }
        })
    }

    #[test]
    fn http_process_query_data_exceeded() {
        let mut cfg =
            Config::new("smetana.net".to_string(), "panteum".to_string(), RequestType::GET, 100000);
        cfg.verbose(true);

        block_on(async move {
            match http_process_query(cfg).await {
                Ok(_) => assert!(false),
                Err(e) => {
                    let err_desc = format!("{:?}", e.to_string());
                    assert_eq!(err_desc, "\"exceeded data limit\"");
                }
            }
        })
    }
}
