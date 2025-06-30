use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use bs58;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer, Signature},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn generate_keypair() -> impl Responder {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(KeypairResponse { pubkey, secret }),
        error: None,
    })
}

async fn create_token(data: web::Json<CreateTokenRequest>) -> impl Responder {
    let mint_authority = match Pubkey::from_str(&data.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint authority public key".to_string()),
            });
        }
    };

    let mint = match Pubkey::from_str(&data.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint public key".to_string()),
            });
        }
    };

    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        data.decimals,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .into_iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: spl_token::id().to_string(),
            accounts,
            instruction_data: bs58::encode(instruction.data).into_string(),
        }),
        error: None,
    })
}

async fn mint_token(data: web::Json<MintTokenRequest>) -> impl Responder {
    let mint = match Pubkey::from_str(&data.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            });
        }
    };

    let destination = match Pubkey::from_str(&data.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            });
        }
    };

    let authority = match Pubkey::from_str(&data.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority address".to_string()),
            });
        }
    };

    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        data.amount,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .into_iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: spl_token::id().to_string(),
            accounts,
            instruction_data: bs58::encode(instruction.data).into_string(),
        }),
        error: None,
    })
}

async fn sign_message(data: web::Json<SignMessageRequest>) -> impl Responder {
    if data.message.is_empty() || data.secret.is_empty() {
        return HttpResponse::Ok().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    let secret_bytes = match bs58::decode(&data.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key".to_string()),
            });
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key format".to_string()),
            });
        }
    };

    let message = data.message.as_bytes();
    let signature = keypair.sign_message(message);
    let signature_b64 = bs58::encode(signature.as_ref()).into_string();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: signature_b64,
            public_key: keypair.pubkey().to_string(),
            message: data.message.clone(),
        }),
        error: None,
    })
}

async fn verify_message(data: web::Json<VerifyMessageRequest>) -> impl Responder {
    if data.message.is_empty() || data.signature.is_empty() || data.pubkey.is_empty() {
        return HttpResponse::Ok().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    let pubkey = match Pubkey::from_str(&data.pubkey) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key".to_string()),
            });
        }
    };

    let signature_bytes = match bs58::decode(&data.signature).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature format".to_string()),
            });
        }
    };

    if signature_bytes.len() != 64 {
        return HttpResponse::Ok().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Invalid signature length".to_string()),
        });
    }

    let signature_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Failed to convert signature bytes".to_string()),
            });
        }
    };

    let signature = Signature::from(signature_array);

    let valid = signature.verify(&pubkey.to_bytes(), data.message.as_bytes());

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(VerifyMessageResponse {
            valid,
            message: data.message.clone(),
            pubkey: data.pubkey.clone(),
        }),
        error: None,
    })
}

async fn send_sol(data: web::Json<SendSolRequest>) -> impl Responder {
    let from = match Pubkey::from_str(&data.from) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid sender address".to_string()),
            });
        }
    };

    let to = match Pubkey::from_str(&data.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid recipient address".to_string()),
            });
        }
    };

    if data.lamports == 0 {
        return HttpResponse::Ok().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Lamports must be greater than zero".to_string()),
        });
    }

    let instruction = system_instruction::transfer(&from, &to, data.lamports);

    let accounts = instruction
        .accounts
        .into_iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: solana_sdk::system_program::id().to_string(),
            accounts,
            instruction_data: bs58::encode(instruction.data).into_string(),
        }),
        error: None,
    })
}

async fn send_token(data: web::Json<SendTokenRequest>) -> impl Responder {
    let destination = match Pubkey::from_str(&data.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            });
        }
    };

    let mint = match Pubkey::from_str(&data.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            });
        }
    };

    let owner = match Pubkey::from_str(&data.owner) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner address".to_string()),
            });
        }
    };

    if data.amount == 0 {
        return HttpResponse::Ok().json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than zero".to_string()),
        });
    }

    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &spl_associated_token_account::get_associated_token_address(&owner, &mint),
        &destination,
        &owner,
        &[],
        data.amount,
    )
    .unwrap();

    let accounts = instruction
        .accounts
        .into_iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: spl_token::id().to_string(),
            accounts,
            instruction_data: bs58::encode(instruction.data).into_string(),
        }),
        error: None,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("0.0.0.0:{}", port);
    println!("Starting server on {}", bind_address);
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(&bind_address)?
    .run()
    .await
}
