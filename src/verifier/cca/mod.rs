// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Context, Result};
extern crate serde;
use super::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use reqwest::{Client, Method};

const VERIFIER_ADDR: &str = "VERIFIER_ADDR";
const DEFAULT_VERIFIER_ADDR: &str = "localhost:3300";

#[derive(Debug, Default)]
pub struct CCA {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RealmToken {
	cca_realm_personalization_value:  String,
    cca_realm_initial_measurement: String
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Evidence {
	//platform_token: PlatformToken,
	cca_realm_delegated_token:    RealmToken,
}

#[allow(unused_variables)]
#[async_trait]
impl Verifier for CCA {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        // NOTE: the proxy to verifier is started on localhost with port 3300, the proxy will sign the evidence and forward the evidence to cca verifier,
        // it's veraison at the moment.
        let host_url = std::env::var(VERIFIER_ADDR).unwrap_or_else(|_| DEFAULT_VERIFIER_ADDR.to_string());
        let tee_evidence = serde_json::from_str::<String>(&attestation.tee_evidence).context("Deserialize evidence failed.")?;

        let url = format!("http://{:}/veraison/proxy", host_url);
        let client = Client::new();
        let req = client.request(Method::POST, &url).body(tee_evidence);

        // marshall the evidence to a json struct
        // parse the result to the final tcb claim which will be used for rvps.
        // /go/src/github.com/veraison/services/scheme/cca-ssd-platform/evidence_handler.go

        let res = req.send().await?;
        if !res.status().is_success(){
            return Err(anyhow!("Fail to validate tee_evidence, status: {}", res.status().as_str()));
        }

        let body = res.bytes().await?;

        let v = body.to_vec();
        let s = String::from_utf8_lossy(&v);
        println!("response: {} ", s);

        println!("update evidence: {}", attestation.tee_evidence);

        let evidence: String= serde_json::from_str(&attestation.tee_evidence).map_err(|_| anyhow!("Deserialize tee_evidence failed"))?;
        //let evidence = attestation.tee_evidence.to_string();
        let claim = serde_json::from_str::<Evidence>(&evidence).context("Deserialize realm token failed.")?;

        let claims_map = json!({
            "svn": claim
        });

        println!("check it here: {} ", claims_map);
        Ok(claims_map as TeeEvidenceParsedClaim)
    }
}

// some testcase here is needed
