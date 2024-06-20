use anyhow::Context;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::{Account, AccountId};

pub async fn vote_join(
    accounts: Vec<Account>,
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> anyhow::Result<()> {
    let vote_futures = accounts
        .iter()
        .map(|account| {
            tracing::info!(
                "{} voting for new participant: {}",
                account.id(),
                account_id
            );
            account
                .call(mpc_contract, "vote_join")
                .args_json(serde_json::json!({
                    "candidate_account_id": account_id
                }))
                .transact()
        })
        .collect::<Vec<_>>();

    futures::future::join_all(vote_futures)
        .await
        .iter()
        .for_each(|result| {
            assert!(result.as_ref().unwrap().failures().is_empty());
        });

    Ok(())
}

pub async fn vote_leave(
    accounts: Vec<Account>,
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> Vec<Result<ExecutionFinalResult, near_workspaces::error::Error>> {
    let vote_futures = accounts
        .iter()
        .filter(|account| account.id() != account_id)
        .map(|account| {
            account
                .call(mpc_contract, "vote_leave")
                .args_json(serde_json::json!({
                    "kick": account_id
                }))
                .transact()
        })
        .collect::<Vec<_>>();

    futures::future::join_all(vote_futures).await
}

pub async fn get<U>(uri: U) -> anyhow::Result<StatusCode>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
{
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::empty())
        .context("failed to build the request")?;

    let client = Client::new();
    let response = client
        .request(req)
        .await
        .context("failed to send the request")?;
    Ok(response.status())
}

/// Request an unused port from the OS.
pub async fn pick_unused_port() -> anyhow::Result<u16> {
    // Port 0 means the OS gives us an unused port
    // Important to use localhost as using 0.0.0.0 leads to users getting brief firewall popups to
    // allow inbound connections on macOS
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

pub async fn ping_until_ok(addr: &str, timeout: u64) -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(timeout), async {
        loop {
            match get(addr).await {
                Ok(status) if status == StatusCode::OK => break,
                _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            }
        }
    })
    .await?;
    Ok(())
}
