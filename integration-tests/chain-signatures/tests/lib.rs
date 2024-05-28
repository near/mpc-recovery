mod actions;
mod cases;

use crate::actions::wait_for;

use anyhow::anyhow;
use futures::future::BoxFuture;
use glob::glob;
use integration_tests_chain_signatures::containers::DockerClient;
use integration_tests_chain_signatures::utils::{vote_join, vote_leave};
use integration_tests_chain_signatures::{run, MultichainConfig, Nodes};
use near_jsonrpc_client::JsonRpcClient;

use near_workspaces::{Account, AccountId};

use std::fs;
use std::str::FromStr;

pub struct MultichainTestContext<'a> {
    nodes: Nodes<'a>,
    rpc_client: near_fetch::Client,
    jsonrpc_client: JsonRpcClient,
    http_client: reqwest::Client,
    cfg: MultichainConfig,
}

impl MultichainTestContext<'_> {
    pub async fn participant_accounts(&self) -> anyhow::Result<Vec<Account>> {
        let node_accounts: Vec<Account> = self.nodes.near_accounts();
        let state = wait_for::running_mpc(self, None).await?;
        let participant_ids = state.participants.keys().collect::<Vec<_>>();
        let participant_accounts: Vec<Account> = participant_ids
            .iter()
            .map(|id| near_workspaces::types::AccountId::from_str(id.as_ref()).unwrap())
            .map(|id| {
                node_accounts
                    .iter()
                    .find(|a| a.id() == &id)
                    .unwrap()
                    .clone()
            })
            .collect();
        Ok(participant_accounts)
    }

    pub async fn add_participant(&mut self) -> anyhow::Result<()> {
        let state = wait_for::running_mpc(self, None).await?;

        let new_node_account = self.nodes.ctx().worker.dev_create_account().await?;
        tracing::info!("Adding a new participant: {}", new_node_account.id());
        self.nodes
            .start_node(
                new_node_account.id(),
                new_node_account.secret_key(),
                &self.cfg,
            )
            .await?;

        // Wait for new node to add itself as a candidate
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // T number of participants should vote
        let participants = self.participant_accounts().await?;
        let voting_participants = participants
            .iter()
            .take(state.threshold)
            .cloned()
            .collect::<Vec<_>>();
        assert!(vote_join(
            voting_participants,
            self.nodes.ctx().mpc_contract.id(),
            new_node_account.id()
        )
        .await
        .is_ok());

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        assert_eq!(new_state.participants.len(), state.participants.len() + 1);
        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        Ok(())
    }

    pub async fn remove_participant(
        &mut self,
        leaving_account_id: Option<&AccountId>,
    ) -> anyhow::Result<()> {
        let state = wait_for::running_mpc(self, None).await?;
        let participant_accounts = self.participant_accounts().await?;
        let leaving_account_id =
            leaving_account_id.unwrap_or_else(|| participant_accounts.last().unwrap().id());
        tracing::info!("Removing participant: {}", leaving_account_id);

        let voting_accounts = participant_accounts
            .iter()
            .filter(|account| account.id() != leaving_account_id)
            .take(state.threshold)
            .cloned()
            .collect::<Vec<Account>>();

        let results = vote_leave(
            voting_accounts,
            self.nodes.ctx().mpc_contract.id(),
            leaving_account_id,
        )
        .await;

        // Check if any result has failures, and return early with an error if so
        if results
            .iter()
            .any(|result| !result.as_ref().unwrap().failures().is_empty())
        {
            return Err(anyhow!("Failed to vote_leave"));
        }

        let new_state = wait_for::running_mpc(self, Some(state.epoch + 1)).await?;
        assert_eq!(state.participants.len(), new_state.participants.len() + 1);

        assert_eq!(
            state.public_key, new_state.public_key,
            "public key must stay the same"
        );

        self.nodes.kill_node(leaving_account_id).await.unwrap();
        Ok(())
    }
}

pub async fn with_multichain_nodes<F>(cfg: MultichainConfig, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(MultichainTestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker_client = DockerClient::default();
    let nodes = run(cfg.clone(), &docker_client).await?;

    let sk_local_path = nodes.ctx().storage_options.sk_share_local_path.clone();

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&nodes.ctx().lake_indexer.rpc_host_address);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());
    let result = f(MultichainTestContext {
        nodes,
        rpc_client,
        jsonrpc_client,
        http_client: reqwest::Client::default(),
        cfg,
    })
    .await;
    clear_local_sk_shares(sk_local_path).await?;

    result
}

pub async fn clear_local_sk_shares(sk_local_path: Option<String>) -> anyhow::Result<()> {
    if let Some(sk_share_local_path) = sk_local_path {
        let pattern = format!("{sk_share_local_path}*");
        for entry in glob(&pattern).expect("Failed to read glob pattern") {
            match entry {
                Ok(path) => {
                    if path.is_file() {
                        if let Err(e) = fs::remove_file(&path) {
                            eprintln!("Failed to delete file {:?}: {}", path.display(), e);
                        }
                    }
                }
                Err(e) => eprintln!("{:?}", e),
            }
        }
    }
    Ok(())
}
