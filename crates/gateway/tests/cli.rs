//! 공개 CLI의 실제 초기화·발급·정책·회수·비밀 비출력을 검증한다.
use anyhow::{Result, ensure};
use std::{path::Path, process::Command};
fn invoke(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtp-gateway"))
        .args(args)
        .output()?;
    ensure!(
        output.status.success(),
        "CLI 실패: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        !String::from_utf8_lossy(&output.stdout).contains("PRIVATE KEY"),
        "개인키 표준출력 금지"
    );
    Ok(output.stdout)
}
#[test]
fn cli만으로_장치와_정책_관리() -> Result<()> {
    let mut random = [0; 8];
    mtp_transport::random(&mut random)?;
    let root = std::env::temp_dir().join(format!("mtp-cli-{}", hex::encode(random)));
    let result = (|| {
        let dir = root.to_str().unwrap();
        invoke(&[
            "init",
            "--root",
            dir,
            "--host",
            "127.0.0.1",
            "--outer-sni",
            "www.example.com",
            "--server-name",
            "gateway.example.com",
            "--dns-server",
            "127.0.0.1:53",
        ])?;
        invoke(&[
            "client", "issue", "--root", dir, "--id", "desktop", "--owner", "alice",
        ])?;
        let list: serde_json::Value =
            serde_json::from_slice(&invoke(&["client", "list", "--root", dir])?)?;
        ensure!(list.as_array().is_some_and(|x| x.len() == 1), "장치 목록");
        let mut policy: serde_json::Value = serde_json::from_slice(&invoke(&[
            "user", "show", "--root", dir, "--owner", "alice",
        ])?)?;
        ensure!(
            policy["connections"] == 32 && policy["udp_per_second"] == 10000,
            "높은 기본 정책"
        );
        policy["enabled"] = false.into();
        let file = root.join("policy.json");
        std::fs::write(&file, serde_json::to_vec(&policy)?)?;
        invoke(&[
            "user",
            "set",
            "--root",
            dir,
            "--owner",
            "alice",
            "--policy",
            file.to_str().unwrap(),
        ])?;
        let saved: serde_json::Value = serde_json::from_slice(&invoke(&[
            "user", "show", "--root", dir, "--owner", "alice",
        ])?)?;
        ensure!(saved["enabled"] == false, "정책 적용");
        invoke(&["access", "--root", dir, "--enabled", "false"])?;
        invoke(&["client", "revoke", "--root", dir, "--id", "desktop"])?;
        let list: serde_json::Value =
            serde_json::from_slice(&invoke(&["client", "list", "--root", dir])?)?;
        ensure!(list[0]["enabled"] == false, "장치 폐기");
        let help = invoke(&["--help"])?;
        ensure!(
            !String::from_utf8_lossy(&help).contains("manage"),
            "웹 관리 API 명령 없음"
        );
        Ok(())
    })();
    if Path::new(&root).exists() {
        std::fs::remove_dir_all(root)?;
    }
    result
}
