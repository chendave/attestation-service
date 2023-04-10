// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Context, Result};
extern crate serde;
use super::*;
use async_trait::async_trait;
use serde_json::json;
use reqwest::{Client, Method};

#[derive(Debug, Default)]
pub struct CCA {}

#[allow(unused_variables)]
#[async_trait]
impl Verifier for CCA {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        // NOTE: the proxy is started on localhost with port 3300, the proxy will sign the evidence and forward the evidence to cca verifier, it's veraison at the moment.
        let host_url = "localhost:3300";
        let tee_evidence = serde_json::from_str::<String>(&attestation.tee_evidence)
            .context("Deserialize Quote failed.")?;

        let url = format!("http://{:}/veraison/proxy", host_url);
        let client = Client::new();
        let req = client.request(Method::POST, &url).body(tee_evidence);

        let res = req.send().await?;
        if !res.status().is_success(){
            return Err(anyhow!("fail to validate tee_evidence, status: {}", res.status().as_str()));
        }

        let body = res.bytes().await?;

        let v = body.to_vec();
        let s = String::from_utf8_lossy(&v);
        println!("response: {} ", s);

        //parse_tee_evidence(&tee_evidence)
        let claims_map = json!({
            "svn": "demo"
        });
        Ok(claims_map as TeeEvidenceParsedClaim)
    }
}
