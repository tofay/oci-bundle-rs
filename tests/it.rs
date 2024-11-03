use oci_bundle::unpack;
use ocidir::cap_std::ambient_authority;
use ocidir::cap_std::fs::Dir;
use ocidir::oci_spec::image::{ImageManifest, Platform};
use ocidir::OciDir;
use std::fs;
use std::path::{Path, PathBuf};
use test_temp_dir::TestTempDir;

fn create_and_unpack(layers: &[&str], temp_dir: &TestTempDir, root: &Path) {
    let oci_path = temp_dir.as_path_untracked().join("oci");

    if oci_path.exists() {
        fs::remove_dir_all(&oci_path).unwrap();
    }

    fs::create_dir(&oci_path).unwrap();
    let oci_dir =
        OciDir::ensure(&Dir::open_ambient_dir(oci_path, ambient_authority()).unwrap()).unwrap();

    let mut manifest = ocidir::new_empty_manifest().build().unwrap();
    let mut config = ocidir::oci_spec::image::ImageConfigurationBuilder::default()
        .build()
        .unwrap();

    for layer_name in layers {
        let mut tar = oci_dir.create_layer(None).unwrap();
        tar.append_dir_all(
            ".",
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join(layer_name),
        )
        .unwrap();
        let layer = tar.into_inner().unwrap().complete().unwrap();
        oci_dir.push_layer(&mut manifest, &mut config, layer, layer_name, None);
    }

    let manifest_descriptor = oci_dir
        .insert_manifest_and_config(manifest, config, None, Platform::default())
        .unwrap();

    let manifest =
        ImageManifest::from_reader(oci_dir.read_blob(&manifest_descriptor).unwrap()).unwrap();

    unpack(&manifest, &oci_dir, root).unwrap();
}

#[test]
fn test_multi_layer() {
    let _ = simple_logger::init_with_env();
    let temp_dir = test_temp_dir::TestTempDir::from_complete_item_path(&format!(
        "it::{}",
        std::thread::current().name().unwrap()
    ));
    let root = temp_dir.as_path_untracked().join("root");
    let rootfs = root.join("rootfs");
    create_and_unpack(&["0", "1"], &temp_dir, &root);

    assert!(rootfs.join("a/b/c/foo").exists());
    assert!(rootfs.join("a/b/c/bar").exists());
}

#[test]
fn test_opaque_whiteout() {
    let _ = simple_logger::init_with_env();
    let temp_dir = test_temp_dir::TestTempDir::from_complete_item_path(&format!(
        "it::{}",
        std::thread::current().name().unwrap()
    ));
    let root = temp_dir.as_path_untracked().join("root");
    let rootfs = root.join("rootfs");
    create_and_unpack(&["0", "2"], &temp_dir, &root);

    assert!(!rootfs.join("a/b/c/foo").exists());
    assert!(!rootfs.join("a/b/c/bar").exists());
    assert!(!rootfs.join("a/.wh..wh..opq").exists());
    assert!(rootfs.join("a").exists());
}

#[test]
fn test_regular_whiteout() {
    let _ = simple_logger::init_with_env();
    let temp_dir = test_temp_dir::TestTempDir::from_complete_item_path(&format!(
        "it::{}",
        std::thread::current().name().unwrap()
    ));
    let root = temp_dir.as_path_untracked().join("root");
    let rootfs = root.join("rootfs");

    create_and_unpack(&["0", "3"], &temp_dir, &root);

    assert!(!rootfs.join("a/b/c/bar").exists());
    assert!(rootfs.join("a/b/c").exists());

    create_and_unpack(&["0", "3", "1"], &temp_dir, &root);

    assert!(!rootfs.join("a/b/c/bar").exists());
    assert!(rootfs.join("a/b/c").exists());
    assert!(rootfs.join("a/b/c/foo").exists());
}

/*
TODO: use https://github.com/alexcrichton/tar-rs/pull/382 when released
to create a test for xattr
#[test]
fn test_xattr() {
    simple_logger::init_with_env().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path().join("root");

    create_and_unpack(&["capability"], &temp_dir, &root);

    assert!(rootfs.join("a/b/c/bar").exists());

    let mut xattrs = xattr::list(root.join("a/b/c/bar")).unwrap();
    println!("Extended attributes:");
    for attr in xattrs {
        println!(" - {:?}", attr);
    }

    assert!(!rootfs.join("a/b/c").exists());
}*/
