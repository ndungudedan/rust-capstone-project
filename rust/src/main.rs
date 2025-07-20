#![allow(unused)]
use bitcoin::hex::DisplayHex;
use bitcoincore_rpc::bitcoin::{Address, Amount, BlockHash, Network};
use bitcoincore_rpc::json::GetWalletInfoResult;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::Write;

// Node access params
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port
const RPC_USER: &str = "alice";
const RPC_PASS: &str = "password";

// You can use calls not provided in RPC lib API using the generic `call` function.
// An example of using the `send` RPC call, which doesn't have exposed API.
// You can also use serde_json `Deserialize` derivation to capture the returned json result.
fn send(rpc: &Client, addr: &str) -> bitcoincore_rpc::Result<String> {
    let args = [
        json!([{addr : 100 }]), // recipient address
        json!(null),            // conf target
        json!(null),            // estimate mode
        json!(null),            // fee rate in sats/vb
        json!(null),            // Empty option object
    ];

    #[derive(Deserialize)]
    struct SendResult {
        complete: bool,
        txid: String,
    }
    let send_result = rpc.call::<SendResult>("send", &args)?;
    assert!(send_result.complete);
    Ok(send_result.txid)
}

fn main() -> bitcoincore_rpc::Result<()> {
    println!("Connecting to Bitcoin Core RPC client");

    // Connect to Bitcoin Core RPC
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    println!("Connected to Bitcoin Core RPC client");

    // Get blockchain info
    let blockchain_info = rpc.get_blockchain_info()?;
    println!("Blockchain Info: {:?}", blockchain_info);

    // Create/Load the wallets, named 'Miner' and 'Trader'. Have logic to optionally create/load them if they do not exist or not loaded already.
    let miner_wallet_info = create_and_or_load_wallet(&rpc, "Miner")?;
    println!("Miner wallet info: {:?}", miner_wallet_info);
    let miner_rpc = wallet_rpc(&rpc, "Miner")?;
    let miner_rpc_info = miner_rpc.get_wallet_info()?;
    println!("Miner wallet info: {:?}", miner_rpc_info);

    // Generate spendable balances in the Miner wallet. How many blocks needs to be mined?
    let miner_address = generate_wallet_address(&miner_rpc, "Miner", "Mining Reward")?;
    let miner_address_info = miner_rpc.get_address_info(&miner_address)?;
    println!("Miner address info: {:?}", miner_address_info);

    // To get a positive balance, we need to mine more than 100 blocks.
    // This is because in regtest, the first 100 blocks are not confirmed. The rewards are not spendable and are tagged as immature.
    // Mining multiple blocks confirms the previous block transactions thus our coinbase transaction balance also gets confirmed.
    let _ = mine_blocks(&miner_rpc, &miner_address, 100)?;
    let _ = mine_blocks(&miner_rpc, &miner_address, 100)?;
    let miner_wallet_info = miner_rpc.get_wallet_info()?;
    println!("Miner wallet info: {:?}", miner_wallet_info);

    // Load Trader wallet and generate a new address
    let trader_wallet_info = create_and_or_load_wallet(&rpc, "Trader")?;
    println!("Trader wallet info: {:?}", trader_wallet_info);
    let trader_rpc = wallet_rpc(&rpc, "Trader")?;
    let trader_rpc_info = trader_rpc.get_wallet_info()?;
    println!("Trader wallet info: {:?}", trader_rpc_info);
    let trader_address = generate_wallet_address(&trader_rpc, "Trader", "Received")?;
    println!("Trader address: {:?}", trader_address);

    // Send 20 BTC from Miner to Trader
    println!("Sending 20 BTC from Miner to Trader");
    let amount = Amount::from_btc(20.0).expect("Failed to parse amount");
    let txid = miner_rpc.send_to_address(&trader_address, amount, None, None, None, None, None, None)?;
    println!("Transaction ID: {:?}", txid);

    // Get unconfirmed transaction info from mempool
    let tx_info = miner_rpc.get_mempool_entry(&txid)?;
    println!("Unconfirmed Transaction info: {:?}", tx_info);

    // Mine 1 block to confirm the transaction
    let _ = mine_blocks(&miner_rpc, &miner_address, 1)?;

    // Extract all required transaction details
    let tx_result = miner_rpc.get_transaction(&txid, None)?;
    let tx_data = tx_result.transaction().unwrap();
    let tx_info = miner_rpc.decode_raw_transaction(&tx_data, None)?;
    let tx_wallet_info = tx_result.info;
    
    println!("--------------------------------********************--------------------------------");
    println!("Transaction info: {:?}", tx_info);
    println!("--------------------------------********************--------------------------------");
    println!("Transaction wallet info: {:?}", tx_wallet_info);
    println!("--------------------------------********************--------------------------------");

    // Extract transaction details from the decoded transaction
    let tx_id = tx_data.txid();
    let tx_fees = tx_result.fee;
    let tx_block_height = tx_wallet_info.blockheight.unwrap_or(0);
    let tx_block_hash = tx_wallet_info.blockhash.expect("Block hash not found");
    
    // Parse the decoded transaction to extract input/output details
    let vin = &tx_info.vin;
    let vout = &tx_info.vout;
    
    // Debug: Print transaction structure
    println!("Number of inputs: {}", vin.len());
    println!("Number of outputs: {}", vout.len());
    for (i, input) in vin.iter().enumerate() {
        println!("Input {}: {:?}", i, input);
    }
    for (i, output) in vout.iter().enumerate() {
        println!("Output {}: {:?}", i, output);
        println!("Output {} address: {:?}", i, output.script_pub_key.address);
        println!("Output {} value: {:?}", i, output.value);
    }
    println!("--------------------------------********************--------------------------------");
    
    // Calculate total input amount from all inputs
    let mut total_input_amount = Amount::ZERO;
    let mut miner_input_address = String::new();
    
    // Use the first input for the address (they should all be from the miner)
    let first_input = &vin[0];
    let prev_tx = first_input.txid.as_ref().unwrap();
    let vout_index = first_input.vout.unwrap();
    
    // Get the previous transaction to find the miner's input address
    let prev_tx_result = miner_rpc.get_transaction(prev_tx, None)?;
    let prev_tx_data = prev_tx_result.transaction().unwrap();
    let prev_tx_info = miner_rpc.decode_raw_transaction(&prev_tx_data, None)?;
    let prev_vout = &prev_tx_info.vout;
    let prev_output = &prev_vout[vout_index as usize];
    
    // Get the address from the first input
    miner_input_address = if let Some(addr) = &prev_output.script_pub_key.address {
        addr.clone().require_network(Network::Regtest).unwrap().to_string()
    } else {
        "Unknown".to_string()
    };
    

    // Calculate total input amount from all inputs
    for input in vin {
        if let (Some(txid), Some(vout_idx)) = (input.txid.as_ref(), input.vout) {
            let input_tx_result = miner_rpc.get_transaction(txid, None)?;
            let input_tx_data = input_tx_result.transaction().unwrap();
            let input_tx_info = miner_rpc.decode_raw_transaction(&input_tx_data, None)?;
            let input_vout = &input_tx_info.vout;
            let input_output = &input_vout[vout_idx as usize];
            total_input_amount += input_output.value;
        }
    }
    
    let miner_input_amount = total_input_amount;
    
    // Extract output details - handle case where there might be only one output
    let trader_output = &vout[0]; // First output (20 BTC to trader)
    
    let trader_output_address = if let Some(addr) = &trader_output.script_pub_key.address {
        addr.clone().require_network(Network::Regtest).unwrap().to_string()
    } else {
        "Unknown".to_string()
    };
    let trader_output_amount = trader_output.value;
    
    // Handle change output - might not exist if exact amount was sent
    let (miner_change_address, miner_change_amount) = if vout.len() > 1 {
        let miner_change_output = &vout[1]; // Second output (change back to miner)
        let change_address = if let Some(addr) = &miner_change_output.script_pub_key.address {
            addr.clone().require_network(Network::Regtest).unwrap().to_string()
        } else {
            "Unknown".to_string()
        };
        (change_address, miner_change_output.value)
    } else {
        // No change output - use the same address as input but with 0 amount
        (miner_input_address.clone(), Amount::ZERO)
    };


    // Write the data to ../out.txt in the specified format given in readme.md
    let mut file = File::create("../out.txt")?;
    file.write_all(format!("{}\n", tx_id).as_bytes())?;
    file.write_all(format!("{}\n", miner_input_address).as_bytes())?;
    file.write_all(format!("{}\n", miner_input_amount).as_bytes())?;
    file.write_all(format!("{}\n", trader_output_address).as_bytes())?;
    file.write_all(format!("{}\n", trader_output_amount).as_bytes())?;
    file.write_all(format!("{}\n", miner_change_address).as_bytes())?;
    file.write_all(format!("{}\n", miner_change_amount).as_bytes())?;
    file.write_all(format!("{}\n", tx_fees.unwrap_or_default().to_btc()).as_bytes())?;
    file.write_all(format!("{}\n", tx_block_height).as_bytes())?;
    file.write_all(format!("{}\n", tx_block_hash).as_bytes())?;

    Ok(())
}

fn create_and_or_load_wallet(
    rpc: &Client,
    wallet_name: &str,
) -> bitcoincore_rpc::Result<()> {

    let wallets_dir = rpc.list_wallet_dir()?;
    println!("Wallets directory: {:?}", wallets_dir);
    if(!wallets_dir.contains(&wallet_name.to_string())) {
        println!("Wallet not found, creating wallet: {:?}", wallet_name);
        rpc.create_wallet(wallet_name, Some(false), None, None, None)?;
    }

    println!("----Listing wallets----");
    let wallets = rpc.list_wallets()?;
    println!("Wallets: {:?}", wallets);
    if (!wallets.contains(&wallet_name.to_string())) {
        println!("No loaded wallets found, loading wallet: {:?}", wallet_name);
        rpc.load_wallet(wallet_name)?;
    }
    println!("--------------------------------********************--------------------------------");
    Ok(())
}

fn generate_wallet_address(
    rpc: &Client,
    wallet_name: &str,
    label: &str,
) -> bitcoincore_rpc::Result<Address> {
    println!("Generating address for wallet: {:?} with label: {:?}", wallet_name, label);
    
    let address = rpc.get_new_address(Some(label), None)?;
    let address = address
        .require_network(Network::Regtest)
        .expect("Failed to get address");
    println!("Generated address for wallet: {:?} is {:?}", wallet_name, address);
    println!("--------------------------------********************--------------------------------");
    Ok(address)
}

fn mine_blocks(rpc: &Client, address: &Address, num_blocks: u64) -> bitcoincore_rpc::Result<()> {
    println!("Mining {} blocks to address: {:?}", num_blocks, address);
    let block_hash = rpc.generate_to_address(num_blocks, address)?;
    println!("Block hash: {:?}", block_hash);
    println!("--------------------------------********************--------------------------------");
    Ok(())
}

fn wallet_rpc(rpc: &Client, wallet_name: &str) -> bitcoincore_rpc::Result<Client> {
    let wallet_rpc = Client::new(
        &format!("{}/wallet/{}", RPC_URL, wallet_name),
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;
    println!("--------------------------------********************--------------------------------");
    Ok(wallet_rpc)
}