use anyhow::Result;
use attestation_service::{AttestationService as Service, Tee};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::as_api::attestation_service_server::{AttestationService, AttestationServiceServer};
use crate::as_api::{AttestationRequest, AttestationResponse, Tee as GrpcTee};

use crate::rvps_api::reference_value_provider_service_server::{
    ReferenceValueProviderService, ReferenceValueProviderServiceServer,
};

use crate::rvps_api::{
    ReferenceValueQueryRequest, ReferenceValueQueryResponse, ReferenceValueRegisterRequest,
    ReferenceValueRegisterResponse,
};

const DEFAULT_SOCK: &str = "127.0.0.1:3000";

fn to_kbs_tee(tee: GrpcTee) -> Tee {
    match tee {
        GrpcTee::Sev => Tee::Sev,
        GrpcTee::Sgx => Tee::Sgx,
        GrpcTee::Snp => Tee::Snp,
        GrpcTee::Tdx => Tee::Tdx,
    }
}

pub struct AttestationServer {
    attestation_service: Arc<RwLock<Service>>,
}

impl AttestationServer {
    pub async fn new(rvps_addr: Option<&str>) -> Result<Self> {
        let service = match rvps_addr {
            Some(addr) => {
                info!("Connect to remote RVPS [{addr}] (Proxy Mode)");
                Service::new_with_rvps_proxy(addr).await?
            }
            None => {
                info!("Start a local RVPS (Server mode)");
                Service::new()?
            }
        };

        Ok(Self {
            attestation_service: Arc::new(RwLock::new(service)),
        })
    }
}

#[tonic::async_trait]
impl AttestationService for AttestationServer {
    async fn attestation_evaluate(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let request: AttestationRequest = request.into_inner();

        debug!("Evidence: {}", &request.evidence);

        let attestation_results = self
            .attestation_service
            .read()
            .await
            .evaluate(
                to_kbs_tee(
                    GrpcTee::from_i32(request.tee)
                        .ok_or_else(|| Status::aborted(format!("Invalid TEE {}", request.tee)))?,
                ),
                &request.nonce,
                &request.evidence,
            )
            .await
            .map_err(|e| Status::aborted(format!("Attestation: {e}")))?;

        let results = serde_json::to_string(&attestation_results)
            .map_err(|e| Status::aborted(format!("Parse attestation results: {e}")))?;

        debug!("Attestation Results: {}", &results);

        let res = AttestationResponse {
            attestation_results: results,
        };
        Ok(Response::new(res))
    }
}

#[tonic::async_trait]
impl ReferenceValueProviderService for AttestationServer {
    async fn query_reference_value(
        &self,
        _request: Request<ReferenceValueQueryRequest>,
    ) -> Result<Response<ReferenceValueQueryResponse>, Status> {
        let status = Status::aborted(format!(
            "Cannot query reference values using RVPS as a submodule in AS."
        ));

        Err(status)
    }

    async fn register_reference_value(
        &self,
        request: Request<ReferenceValueRegisterRequest>,
    ) -> Result<Response<ReferenceValueRegisterResponse>, Status> {
        let request = request.into_inner();

        info!("registry reference value: {}", request.message);

        let message = serde_json::from_str(&request.message)
            .map_err(|e| Status::aborted(format!("Parse message: {e}")))?;
        self.attestation_service
            .write()
            .await
            .registry_reference_value(message)
            .await
            .map_err(|e| Status::aborted(format!("Register reference value: {e}")))?;

        let res = ReferenceValueRegisterResponse {};
        Ok(Response::new(res))
    }
}

pub async fn start(socket: Option<&str>, rvps_addr: Option<&str>) -> Result<()> {
    let socket = socket.unwrap_or(DEFAULT_SOCK).parse()?;
    info!("Listen socket: {}", &socket);

    let attestation_server = AttestationServer::new(rvps_addr).await?;

    Server::builder()
        .add_service(AttestationServiceServer::new(attestation_server))
        .serve(socket)
        .await?;
    Ok(())
}
