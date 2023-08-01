use anyhow::{Context, Ok};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use serde::{Deserialize, Serialize};

pub async fn post<U, Req: Serialize, Resp>(
    uri: U,
    request: Req,
) -> anyhow::Result<(StatusCode, Resp)>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
    for<'de> Resp: Deserialize<'de>,
{
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&request).context("failed to serialize the request body")?,
        ))
        .context("failed to build the request")?;

    let client = Client::new();
    let response = client
        .request(req)
        .await
        .context("failed to send the request")?;
    let status = response.status();

    let data = hyper::body::to_bytes(response)
        .await
        .context("failed to read the response body")?;
    let response: Resp =
        serde_json::from_slice(&data).context("failed to deserialize the response body")?;

    Ok((status, response))
}
