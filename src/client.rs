use std::{future::Future, pin::Pin};

use futures_util::StreamExt;
use http::Response;
use oauth2::{AsyncHttpClient, HttpRequest, HttpResponse};
use wasm_streams::ReadableStream;
use web_sys::{js_sys::Uint8Array, wasm_bindgen::JsCast};
use worker::{Fetch, RequestInit, RequestRedirect};

pub struct WorkerClient {}

impl WorkerClient {
    pub fn new() -> Self {
        Self {}
    }
}

impl<'c> AsyncHttpClient<'c> for WorkerClient {
    type Error = worker::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>>>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let mut init = RequestInit::new();

            let modified_init = init
                .with_method(match request.method() {
                    &http::Method::POST => worker::Method::Post,
                    _ => unreachable!(),
                })
                .with_headers(request.headers().into())
                .with_body(Some(
                    String::from_utf8(request.body().to_vec()).unwrap().into(),
                ))
                // Simulate similar protections against SSRF
                .with_redirect(RequestRedirect::Manual);

            let request =
                worker::Request::new_with_init(&request.uri().to_string(), modified_init)?;

            let response = Fetch::Request(request).send().await?;
            let worker_http_resp: worker::HttpResponse = response.try_into()?;

            let (parts, body) = worker_http_resp.into_parts();
            let body_stream = body.into_inner().unwrap();

            let reader = ReadableStream::from_raw(body_stream);
            let mut rust_stream = reader.into_stream();

            let mut bytes: Vec<u8> = vec![];

            while let Some(Ok(chunk)) = rust_stream.next().await {
                let uint8_array = chunk.unchecked_into::<Uint8Array>();
                let uint8_vec = uint8_array.to_vec();
                bytes.extend(uint8_vec.into_iter());
            }

            Ok(Response::from_parts(parts, bytes))
        })
    }
}
