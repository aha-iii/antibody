//! AES-256-GCM 加密规则包（客户侧仅见 `.sealed` 二进制，无明文 YAML）。

use crate::error::PackError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const MAGIC: &[u8; 9] = b"NWPKSEAL1";
const FORMAT_VERSION: u8 = 1;

/// 解密后的临时目录守卫；Drop 时自动清理。
pub struct SealedExtractGuard {
    _dir: TempDir,
    pub root: PathBuf,
}

/// 是否为 sealed 包路径（`.sealed` 后缀或 magic 头）。
pub fn is_sealed_path(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("sealed"))
        .unwrap_or(false)
    {
        return path.is_file();
    }
    if !path.is_file() {
        return false;
    }
    let mut head = [0u8; 9];
    if let Ok(mut f) = fs::File::open(path) {
        if f.read_exact(&mut head).is_ok() {
            return head == *MAGIC;
        }
    }
    false
}

/// 开发模式：允许加载明文 pack 目录（测试 / 内部 dashboard）。
pub fn dev_plain_pack_allowed() -> bool {
    if cfg!(test) {
        return true;
    }
    matches!(
        std::env::var("NERVE_NATIVE_DEV_PACK").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// 将明文 pack 目录加密写入 `.sealed` 文件。
pub fn seal_pack_dir(
    pack_dir: impl AsRef<Path>,
    output: impl AsRef<Path>,
    key: &[u8; 32],
) -> Result<(), PackError> {
    let pack_dir = pack_dir.as_ref();
    if !pack_dir.join("pack.toml").is_file() {
        return Err(PackError::Msg(format!(
            "pack.toml not found under {}",
            pack_dir.display()
        )));
    }
    let manifest: crate::manifest::PackManifest = toml::from_str(&fs::read_to_string(
        pack_dir.join("pack.toml"),
    )?)?;
    let tar_bytes = tar_directory(pack_dir)?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PackError::Msg(format!("invalid seal key: {e}")))?;
    let payload = cipher
        .encrypt(Nonce::from_slice(&nonce), tar_bytes.as_ref())
        .map_err(|e| PackError::Msg(format!("seal encrypt failed: {e}")))?;

    let pack_id = manifest.id.as_bytes();
    let pack_version = manifest.version.as_bytes();
    if pack_id.len() > u16::MAX as usize || pack_version.len() > u16::MAX as usize {
        return Err(PackError::Msg("pack id/version too long".into()));
    }

    let out_path = output.as_ref();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(out_path)?;
    f.write_all(MAGIC)?;
    f.write_all(&[FORMAT_VERSION])?;
    f.write_all(&(pack_id.len() as u16).to_be_bytes())?;
    f.write_all(pack_id)?;
    f.write_all(&(pack_version.len() as u16).to_be_bytes())?;
    f.write_all(pack_version)?;
    f.write_all(&nonce)?;
    f.write_all(&payload)?;
    f.flush()?;
    Ok(())
}

/// 解密 sealed 包到临时目录。
pub fn extract_sealed(
    sealed_path: impl AsRef<Path>,
    key: &[u8; 32],
) -> Result<SealedExtractGuard, PackError> {
    let sealed_path = sealed_path.as_ref();
    let data = fs::read(sealed_path)?;
    if data.len() < MAGIC.len() + 1 + 4 + 12 {
        return Err(PackError::Msg("sealed pack too short".into()));
    }
    if &data[..MAGIC.len()] != MAGIC {
        return Err(PackError::Msg("invalid sealed pack magic".into()));
    }
    let mut off = MAGIC.len();
    let fmt = data[off];
    off += 1;
    if fmt != FORMAT_VERSION {
        return Err(PackError::Msg(format!("unsupported sealed format {fmt}")));
    }
    let id_len = read_u16_be(&data, &mut off)? as usize;
    let pack_id = read_slice(&data, &mut off, id_len)?;
    let ver_len = read_u16_be(&data, &mut off)? as usize;
    let pack_version = read_slice(&data, &mut off, ver_len)?;
    let nonce = read_slice(&data, &mut off, 12)?;
    let ciphertext = &data[off..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PackError::Msg(format!("invalid decrypt key: {e}")))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| PackError::Msg("sealed pack decrypt failed (wrong key or tampered)".into()))?;
    if plain.is_empty() {
        return Err(PackError::Msg("sealed pack decrypted to empty tar".into()));
    }

    let tmp = tempfile::Builder::new()
        .prefix("nw-native-pack-")
        .tempdir()
        .map_err(PackError::Io)?;
    untar_directory(&plain, tmp.path())?;
    if !tmp.path().join("pack.toml").is_file() {
        return Err(PackError::Msg(format!(
            "sealed pack {}@{} missing pack.toml after extract",
            std::str::from_utf8(pack_id).unwrap_or("?"),
            std::str::from_utf8(pack_version).unwrap_or("?")
        )));
    }
    Ok(SealedExtractGuard {
        root: tmp.path().to_path_buf(),
        _dir: tmp,
    })
}

fn read_u16_be(data: &[u8], off: &mut usize) -> Result<u16, PackError> {
    if *off + 2 > data.len() {
        return Err(PackError::Msg("truncated sealed header".into()));
    }
    let v = u16::from_be_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_slice<'a>(data: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], PackError> {
    if *off + len > data.len() {
        return Err(PackError::Msg("truncated sealed header".into()));
    }
    let s = &data[*off..*off + len];
    *off += len;
    Ok(s)
}

fn tar_directory(root: &Path) -> Result<Vec<u8>, PackError> {
    let mut files = Vec::new();
    collect_pack_files(root, root, &mut files)?;
    files.sort_by(|a, b| a.1.cmp(&b.1));
    let mut buf = Vec::new();
    {
        let mut ar = tar::Builder::new(&mut buf);
        for (abs, rel) in files {
            let data = fs::read(&abs)?;
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_path(&name).map_err(|e| PackError::Msg(e.to_string()))?;
            header.set_cksum();
            ar.append_data(&mut header, &name, &*data)?;
        }
        ar.finish()?;
    }
    if buf.is_empty() {
        return Err(PackError::Msg("sealed tar archive empty".into()));
    }
    Ok(buf)
}

fn collect_pack_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<(), PackError> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let path = ent.path();
        if path.is_dir() {
            collect_pack_files(root, &path, out)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| PackError::Msg(format!("pack path: {e}")))?
                .to_path_buf();
            out.push((path, rel));
        }
    }
    Ok(())
}

fn untar_directory(data: &[u8], dest: &Path) -> Result<(), PackError> {
    let mut ar = tar::Archive::new(data);
    ar.unpack(dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn roundtrip_seal_extract() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/demo");
        if !root.join("pack.toml").is_file() {
            return;
        }
        let key = [7u8; 32];
        let sealed = tempfile::NamedTempFile::new().unwrap();
        seal_pack_dir(&root, sealed.path(), &key).unwrap();
        assert!(is_sealed_path(sealed.path()));
        let guard = extract_sealed(sealed.path(), &key).unwrap();
        assert!(guard.root.join("pack.toml").is_file());
        let pack = crate::NativePack::load(&guard.root).unwrap();
        assert_eq!(pack.id(), "demo");
    }

    #[test]
    fn baseline_sealed_roundtrip_preserves_rules() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        if !root.join("pack.toml").is_file() {
            return;
        }
        let sample = root.join("rules/00-allow/allow-adobe-activityi-cat.yaml");
        if !sample.is_file() {
            return;
        }
        let key = [9u8; 32];
        let sealed = tempfile::NamedTempFile::new().unwrap();
        seal_pack_dir(&root, sealed.path(), &key).unwrap();
        let guard = extract_sealed(sealed.path(), &key).unwrap();
        let extracted = guard.root.join("rules/00-allow/allow-adobe-activityi-cat.yaml");
        let orig = fs::read(&sample).unwrap();
        let got = fs::read(&extracted).unwrap();
        assert_eq!(orig, got, "sealed extract must preserve rule bytes");
        let pack = crate::NativePack::load(&guard.root).unwrap();
        assert_eq!(pack.id(), "baseline");
        assert!(pack.rules.len() >= 100);
    }
}
