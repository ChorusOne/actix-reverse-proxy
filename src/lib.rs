//! Reverse proxy specifically for purposes of using a node dev server with the backend
//!
//! Based on:
//! <https://github.com/DoumanAsh/actix-reverse-proxy>
//! <https://golang.org/src/net/http/httputil/reverseproxy.go>
//! <https://github.com/felipenoris/actix-reverse-proxy>

extern crate actix_web;

use actix_web::http::header::{HeaderMap, HeaderName};
use actix_web::web::Bytes;
use actix_web::{HttpRequest, HttpResponse};

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

lazy_static::lazy_static! {
    static ref HEADER_X_FORWARDED_FOR: HeaderName = HeaderName::from_lowercase(b"x-forwarded-for").unwrap();

    static ref HOP_BY_HOP_HEADERS: Vec<HeaderName> = vec![
        HeaderName::from_lowercase(b"connection").unwrap(),
        HeaderName::from_lowercase(b"proxy-connection").unwrap(),
        HeaderName::from_lowercase(b"keep-alive").unwrap(),
        HeaderName::from_lowercase(b"proxy-authenticate").unwrap(),
        HeaderName::from_lowercase(b"proxy-authorization").unwrap(),
        HeaderName::from_lowercase(b"te").unwrap(),
        HeaderName::from_lowercase(b"trailer").unwrap(),
        HeaderName::from_lowercase(b"transfer-encoding").unwrap(),
        HeaderName::from_lowercase(b"upgrade").unwrap(),
    ];

    static ref HEADER_TE: HeaderName = HeaderName::from_lowercase(b"te").unwrap();

    static ref HEADER_CONNECTION: HeaderName = HeaderName::from_lowercase(b"connection").unwrap();
}

static DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct ReverseProxy<'a> {
    forward_host: &'a str,
    timeout: Duration,
    response_size: usize
}

fn add_client_ip(fwd_header_value: &mut String, client_addr: SocketAddr) {
    if !fwd_header_value.is_empty() {
        fwd_header_value.push_str(", ");
    }

    let client_ip_str = &format!("{}", client_addr.ip());
    fwd_header_value.push_str(client_ip_str);
}

fn remove_connection_headers(headers: &mut HeaderMap) {
    let header_connection = &(*HEADER_CONNECTION);

    let connection_headers: HashSet<HeaderName> = headers
        .get_all(header_connection)
        .map(|v| HeaderName::from_bytes(v.as_bytes()).unwrap())
        .collect();
    for h in connection_headers {
        headers.remove(h);
    }
}

fn remove_request_hop_by_hop_headers(headers: &mut HeaderMap) {
    for h in HOP_BY_HOP_HEADERS.iter() {
        match headers.get(h) {
            Some(v) => {
                if v == "" || (h == *HEADER_TE && v == "trailers") {
                    continue;
                }
                headers.remove(h);
            }
            None => continue,
        }
    }
}

impl<'a> ReverseProxy<'a> {
    pub fn new(forward_host: &'a str) -> ReverseProxy<'a> {
        ReverseProxy {
            forward_host,
            timeout: DEFAULT_TIMEOUT,
            response_size: 2 * 1024 * 1024,
        }
    }

    pub fn timeout(mut self, duration: Duration) -> ReverseProxy<'a> {
        self.timeout = duration;
        self
    }

    pub fn response_size(mut self, response_size: usize) -> ReverseProxy<'a> {
        self.response_size = response_size;
        self
    }

    fn x_forwarded_for_value(&self, req: &HttpRequest) -> String {
        let mut result = String::new();

        for (key, value) in req.headers() {
            if key == *HEADER_X_FORWARDED_FOR {
                result.push_str(value.to_str().unwrap());
                break;
            }
        }

        // adds client IP address
        // to x-forwarded-for header
        // if it's available
        if let Some(peer_addr) = req.peer_addr() {
            add_client_ip(&mut result, peer_addr);
        }

        result
    }

    fn forward_uri(&self, path: &str, req: &HttpRequest) -> String {
        let forward_host: &str = self.forward_host;

        let forward_uri = match req.uri().query() {
            Some(query) => format!("{}{}?{}", forward_host, path, query),
            None => format!("{}{}", forward_host, path),
        };

        forward_uri
    }

    pub async fn forward(&self,
        req: &HttpRequest,
        body: Bytes,
    ) -> Result<actix_web::HttpResponse, actix_web::error::Error> {
        self.forward_path(req, req.uri().path(), body).await
    }

    pub async fn forward_path(
        &self,
        req: &HttpRequest,
        forward_path: &str,
        body: Bytes,
    ) -> Result<actix_web::HttpResponse, actix_web::error::Error> {
        let client = awc::Client::new();

        // set headers from the client instead of default headers
        let mut forward_req = client
            .request_from(self.forward_uri(forward_path, &req).as_str(), req.head())
            .insert_header((
                HEADER_X_FORWARDED_FOR.clone(),
                self.x_forwarded_for_value(&req),
            ))
            .insert_header_if_none((actix_web::http::header::USER_AGENT, ""));

        remove_connection_headers(forward_req.headers_mut());
        remove_request_hop_by_hop_headers(forward_req.headers_mut());

        tracing::debug!("#### REVERSE PROXY REQUEST HEADERS");
        for (key, value) in forward_req.headers() {
            tracing::debug!("[{:?}] = {:?}", key, value);
        }

        let mut resp = forward_req
            .timeout(self.timeout)
            .send_body(body)
            .await
            .map_err(|e| actix_web::error::ErrorBadGateway(e))?;

        let mut back_rsp = HttpResponse::build(resp.status());

        let header_connection = &(*HEADER_CONNECTION);

        let mut connection_headers: HashSet<HeaderName> = resp
            .headers()
            .get_all(header_connection)
            .map(|v| HeaderName::from_bytes(v.as_bytes()).unwrap())
            .collect();
        connection_headers.insert(HeaderName::from_lowercase(b"content-encoding").unwrap());
        // copy headers
        tracing::debug!("#### REVERSE PROXY RESPONSE HEADERS");
        for (key, value) in resp.headers() {
            if !HOP_BY_HOP_HEADERS.contains(key) && !connection_headers.contains(key) {
                back_rsp.append_header((key.clone(), value.clone()));
                tracing::debug!("[{:?}] = {:?}", key, value);
            }
        }
        let resp_body = resp.body().limit(self.response_size).await?;
        Ok(back_rsp.body(resp_body))
    }
}
