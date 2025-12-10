use modnet_runtime::WASM_BINARY;
use sc_service::{ChainType, Properties};
use sc_telemetry::TelemetryEndpoints;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

pub fn development_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("Development")
    .with_id("dev")
    .with_chain_type(ChainType::Development)
    .with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
    .build())
}

pub fn modnet_testnet_chain_spec() -> Result<ChainSpec, String> {
    // Chain properties
    let mut props = Properties::new();
    props.insert("tokenSymbol".into(), "MODNET".into());
    props.insert("tokenDecimals".into(), 12.into());
    props.insert("ss58Format".into(), 42.into());

    // Telemetry endpoint provided by user (ngrok). Substrate expects wss:// and /submit/ path.
    let telemetry = TelemetryEndpoints::new(vec![
        (
            "wss://telemetry-comai.ngrok.dev/submit/".to_string(),
            0,
        ),
    ]).expect("Telemetry endpoint vector must be non-empty");

    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("Modnet Testnet")
    .with_id("modnet-testnet")
    .with_chain_type(ChainType::Live)
    .with_protocol_id("modnet-testnet")
    .with_properties(props)
    .with_telemetry_endpoints(telemetry)
    .with_genesis_config_preset_name("modnet_testnet")
    .build())
}

pub fn local_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("Local Testnet")
    .with_id("local_testnet")
    .with_chain_type(ChainType::Local)
    .with_genesis_config_preset_name(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET)
    .build())
}
