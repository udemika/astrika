use flate2::write::GzEncoder;
use flate2::Compression;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn compress_asset(src: &str, dst_name: &str, out_dir: &Path) {
    println!("cargo:rerun-if-changed={}", src);
    let data = fs::read(src).unwrap_or_else(|e| panic!("failed to read {}: {}", src, e));
    let mut enc = GzEncoder::new(Vec::with_capacity(data.len() / 3), Compression::best());
    enc.write_all(&data).expect("gzip write failed");
    let gz = enc.finish().expect("gzip finish failed");
    fs::write(out_dir.join(dst_name), gz).expect("failed to write gz asset");
}

fn main() {
    let out_dir = Path::new(&env::var("OUT_DIR").expect("OUT_DIR missing")).to_path_buf();
    compress_asset("www/index.html", "index.html.gz", &out_dir);
    compress_asset("www/mod.js", "mod.js.gz", &out_dir);
    compress_asset("www/account.html", "account.html.gz", &out_dir);
    println!("cargo:rerun-if-changed=www/favicon.png");
    let fav = fs::read("www/favicon.png").expect("failed to read www/favicon.png");
    fs::write(out_dir.join("favicon.png"), fav).expect("failed to write favicon.png");
}
