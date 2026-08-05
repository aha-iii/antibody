//! 发版工具：将明文 pack 目录加密为 `.sealed` 交付物。
//!
//! ```bash
//! export NERVE_PACK_SEAL_KEY_B64="$(openssl rand -base64 32)"
//! cargo run -p nerve-antibody-pack --bin seal-pack -- packs/baseline dist/baseline.sealed
//! ```

use base64::Engine;
use nerve_antibody_pack::seal_pack_dir;
use std::env;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: seal-pack <pack_dir> <output.sealed> [--key-file path]");
        eprintln!("  key: NERVE_PACK_SEAL_KEY_B64 (32-byte AES key, base64) or --key-file");
        std::process::exit(1);
    }
    let pack_dir = PathBuf::from(&args[1]);
    let output = PathBuf::from(&args[2]);
    let key = read_key(&args[3..]).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    seal_pack_dir(&pack_dir, &output, &key).unwrap_or_else(|e| {
        eprintln!("seal failed: {e}");
        std::process::exit(1);
    });
    println!("sealed {} -> {}", pack_dir.display(), output.display());
}

fn read_key(args: &[String]) -> Result<[u8; 32], String> {
    if let Some(i) = args.iter().position(|a| a == "--key-file") {
        let path = args
            .get(i + 1)
            .ok_or_else(|| "--key-file requires path".to_string())?;
        let raw = std::fs::read(path).map_err(|e| format!("read key file: {e}"))?;
        return decode_key(&raw);
    }
    let b64 = env::var("NERVE_PACK_SEAL_KEY_B64")
        .map_err(|_| "set NERVE_PACK_SEAL_KEY_B64 or pass --key-file".to_string())?;
    decode_key(b64.trim().as_bytes())
}

fn decode_key(raw: &[u8]) -> Result<[u8; 32], String> {
    let text = std::str::from_utf8(raw).map_err(|_| "key must be utf8 base64".to_string())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| format!("invalid base64 key: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("key must be 32 bytes, got {}", bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
