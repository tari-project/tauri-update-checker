use anyhow;
use base64::decode;
use base64::Engine;
use futures_util::StreamExt;
use minisign_verify::{PublicKey, Signature};
use reqwest::blocking::get;
use reqwest::header::CONTENT_LENGTH;
use reqwest::{ClientBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::str::from_utf8;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Deserialize, Debug)]
struct Release {
    url: String,
    signature: String,
}

#[derive(Deserialize, Debug)]
struct Platforms {
    #[serde(rename = "linux-x86_64")]
    linux_x86_64: Release,
    #[serde(rename = "darwin-aarch64")]
    darwin_aarch64: Option<Release>,
    #[serde(rename = "darwin-x86_64")]
    darwin_x86_64: Option<Release>,

    #[serde(rename = "windows-x86_64")]
    windows_x86_64: Option<Release>,
}

#[derive(Deserialize, Debug)]
struct Manifest {
    platforms: Platforms,
}

fn save_to_file(path: &str, data: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    dbg!("hello");
    // Sample JSON string (you would typically read this from a file)
    let json_data = include_str!("../updater.json");
    let pub_key = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEYxNUJBOEFEQkQ4RjJBMjYKUldRbUtvKzlyYWhiOFJIUmFFditENVV3d3hRbjNlZm1DMi9aMjluRUpVdHhQTytadTV3ODN3bUMK";

    dbg!("d");
    // Parse the JSON data
    let manifest: Manifest = serde_json::from_str(json_data).expect("bad json");

    let mut platforms = vec![];
    platforms.push(("linux_x86_64", &manifest.platforms.linux_x86_64));
    if let Some(x) = &manifest.platforms.darwin_aarch64 {
        platforms.push(("darwin_aarch64", x));
    }

    if let Some(x) = &manifest.platforms.darwin_x86_64 {
        platforms.push(("darwin_x86_64", x));
    }
    if let Some(x) = &manifest.platforms.windows_x86_64 {
        platforms.push(("windows_x86_64", x));
    }
    let mut num_tested = 0;
    let mut num_ok = 0;
    // Iterate over each platform
    for (key, release) in &platforms {
        let file_path = format!("{}.tar.gz", key); // Set file path
        println!("Downloading {} from {}", key, release.url);

        // Download the file
        match tauri_download_fn(&release.url, &release.signature, pub_key).await {
            Ok(()) => {
                num_ok += 1;
            }
            Err(e) => {
                eprintln!("Failed: {}", &release.url);
            }
        };
        num_tested += 1;

        // let signature = &release.signature;
        // verify_signature(data, signature);
    }

    println!("All files downloaded {}/{} ok", num_ok, num_tested);
}

async fn tauri_download_fn(url: &str, signature: &str, pub_key: &str) -> Result<(), anyhow::Error> {
    // Create our request
    let response = reqwest::Client::new().get(url).send().await?;
    // if let Some(timeout) = self.timeout {
    //   req = req.timeout(timeout);
    // }

    // #[cfg(feature = "tracing")]
    // tracing::info!("Downloading update");
    // let response = client.send(req).await?;

    // make sure it's success
    // if !response.status().is_success() {
    // return Err(Error::Network(format!(
    // "Download request failed with status: {}",
    // response.status()
    // )));
    // }

    let content_length: Option<u64> = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());

    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();

    let buffer = Arc::new(RwLock::new(Vec::with_capacity(
        content_length.unwrap_or(1000) as usize,
    )));
    let buffer2 = buffer.clone();
    let task = async move {
        let mut total = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let bytes = chunk.as_ref().to_vec();
            total += bytes.len();
            println!("chunk size: {} / {}", total, content_length.unwrap());
            // on_chunk(bytes.len(), content_length);
            let mut lock = buffer2.write().await;
            lock.extend(bytes);
        }
        Result::<_, anyhow::Error>::Ok(())
    };

    task.await?;

    let r = buffer.read().await;
    println!("Checking signature for {}", url);
    match verify_signature(&r, &signature, &pub_key) {
        Ok(b) => {
            if b {
                println!("Signature valid");
            } else {
                println!("Signature invalid");
            }
        }
        Err(e) => {
            eprintln!("SIGNATURE ERROR: {}", e.to_string());
            return Err(e);
        }
    }
    println!("signature ok");
    Ok(())
}

pub fn verify_signature(
    data: &[u8],
    release_signature: &str,
    pub_key: &str,
) -> Result<bool, anyhow::Error> {
    // we need to convert the pub key
    let pub_key_decoded = base64_to_string(pub_key)?;
    let public_key = PublicKey::decode(&pub_key_decoded)?;
    let signature_base64_decoded = base64_to_string(release_signature)?;
    let signature = Signature::decode(&signature_base64_decoded)?;

    // Validate signature or bail out
    public_key.verify(data, &signature, true)?;
    Ok(true)
}

fn base64_to_string(base64_string: &str) -> Result<String, anyhow::Error> {
    let decoded_string = &base64::engine::general_purpose::STANDARD.decode(base64_string)?;
    let result = from_utf8(decoded_string).expect("bad utf8").to_string();
    Ok(result)
}
