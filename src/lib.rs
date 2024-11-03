use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use ocidir::cap_std::ambient_authority;
use ocidir::cap_std::fs::Dir;
use ocidir::oci_spec::image::{ImageConfiguration, ImageManifest, MediaType};
use ocidir::oci_spec::runtime::{ProcessBuilder, UserBuilder};
use ocidir::OciDir;
use sha256_reader::Sha256Reader;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self};
use std::io::{self};
use std::path::{Path, PathBuf};
use tar::Archive;
use users::{get_user_by_name, get_user_by_uid, get_group_by_name, get_group_by_gid, get_groups};

mod sha256_reader;

/// Unpacks the layers of an OCI image into a directory
/// # Arguments
/// * `manifest` - The manifest of the image
/// * `oci_dir` - The OCI directory containing the image
/// * `root` - The directory to unpack the image into. It will be created if it doesn't exist
pub fn unpack(manifest: &ImageManifest, oci_dir: &OciDir, bundle: &Path) -> Result<()> {
    if bundle.exists() {
        fs::remove_dir_all(bundle).context("Failed to remove existing bundle directory")?;
    }
    let rootfs = bundle.join("rootfs");
    fs::create_dir_all(&rootfs).context("Failed to create rootfs directory")?;

    // Load image configuration so we can verify layer diff IDs
    let image_config = ImageConfiguration::from_reader(oci_dir.read_blob(manifest.config())?)?;

    let layers = manifest.layers();
    let diff_ids = image_config.rootfs().diff_ids();

    if layers.len() != diff_ids.len() {
        bail!(
            "Mismatch between number of layers and diff IDs: {} != {}",
            layers.len(),
            diff_ids.len()
        );
    }

    for (descriptor, expected_diff_id) in manifest.layers().iter().zip(diff_ids.iter()) {
        match descriptor.media_type() {
            MediaType::ImageLayerGzip => {
                let mut archive = Archive::new(Sha256Reader::new(GzDecoder::new(
                    Sha256Reader::new(oci_dir.read_blob(descriptor)?),
                )));
                extract_layer(&mut archive, &rootfs)?;
                // Note that the diff_id is the uncompressed digest, which is the first digest...
                let (discovered_diff_id, gz_decoder) = archive.into_inner().finish()?;
                if format!("sha256:{discovered_diff_id}") != *expected_diff_id {
                    bail!(
                        "Diff ID mismatch. Expected diff ID {}. Discovered diff ID {}",
                        expected_diff_id,
                        discovered_diff_id,
                    );
                }

                // ...and the overall layer digest is the second digest
                let (discovered_digest, _) = gz_decoder.into_inner().finish()?;
                if descriptor.digest().digest() != discovered_digest {
                    bail!(
                        "Layer digest mismatch. Expected digest {}. Discovered digest {}",
                        descriptor.digest().digest(),
                        discovered_digest,
                    );
                }
            }
            _ => {
                bail!("Unsupported media type: {}", descriptor.media_type());
            }
        }
    }

    // convert manifest config per https://github.com/opencontainers/image-spec/blob/main/conversion.md#verbatim-fields
    let image_config = ImageConfiguration::from_reader(oci_dir.read_blob(manifest.config())?)?;
    let runtime_config = create_runtime_config(&image_config)?;
    runtime_config.save(bundle.join("config.json"))?;
    Ok(())
}

fn extract_layer<R: io::Read>(archive: &mut Archive<R>, root: &Path) -> Result<()> {
    // Use cap_std::fs to do deletions as an extra protection against deleting outside the root
    // We also skip entries with ".." in them to avoid traversing outside the root
    let root_dir = Dir::open_ambient_dir(root, ambient_authority())?;

    archive.set_overwrite(true);
    archive.set_preserve_mtime(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(true);

    // Keep track of files added this layer, as if we encounter a whiteout file
    // whose target is also added in this layer then we mustn't remove it.
    let mut files = Vec::new();

    // Add directories at the end at the end. See [0] for details.
    //
    // [0]: <https://github.com/alexcrichton/tar-rs/issues/242>
    let mut dirs = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        log::trace!("Found archive entry {}", path.display());

        if entry.header().entry_type().is_dir() {
            log::trace!("Entry is directory");
            dirs.push(entry);
            continue;
        } else if let Some(file_name) = path.file_name() {
            // Ignore paths with ".." in them, to avoid traversing outside the root
            if path.components().any(|c| c.as_os_str() == OsStr::new("..")) {
                log::warn!("Ignoring path with '..'");
                continue;
            }

            let slice = file_name.as_encoded_bytes();
            // Handle whiteouts
            if slice.len() > 4 && slice[0..4] == *b".wh." {
                log::trace!("Detected whiteout");
                if slice == b".wh..wh..opq" {
                    log::trace!("Opaque whiteout");
                    let dir_to_clear = path
                        .parent()
                        .map(|p| root.join(p))
                        .unwrap_or(root.to_path_buf());
                    // Delete all entries in the directory, except those added this layer!
                    for entry in fs::read_dir(&dir_to_clear)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() {
                            log::trace!("Examining directory {}", path.display());
                            // Retain any files and their parents that were added in this layer
                            for sub_entry in walkdir::WalkDir::new(&path) {
                                let sub_entry = sub_entry?;
                                let sub_path = sub_entry.path();
                                // Delete this path only if it, nor its ancestors, were added this layer
                                if !files
                                    .iter()
                                    .any(|p| p == sub_path || sub_path.ancestors().any(|a| a == p))
                                {
                                    if sub_path.is_dir() {
                                        log::trace!("Removing directory {}", sub_path.display());
                                        root_dir.remove_dir_all(sub_path.strip_prefix(root)?)?;
                                    } else {
                                        log::trace!("Removing file {}", sub_path.display());
                                        root_dir.remove_file(sub_path.strip_prefix(root)?)?;
                                    }
                                }
                            }
                        } else if !files.contains(&path) {
                            log::trace!("Removing file {}", path.display());
                            root_dir.remove_file(&path)?;
                        }
                    }
                } else {
                    log::trace!("Regular whiteout");
                    // SAFETY: we checked above that the first 4 bytes of slice are b".wh."
                    let file_name = unsafe { OsStr::from_encoded_bytes_unchecked(&slice[4..]) };

                    let file_to_remove = path
                        .parent()
                        .map(|p| p.join(file_name))
                        .unwrap_or(PathBuf::from(file_name));

                    if root_dir.exists(&file_to_remove) {
                        log::trace!("Removing file {}", file_to_remove.display());
                        root_dir.remove_file(&file_to_remove)?;
                    }
                }
            } else {
                // Non-whiteout file
                files.push(path.to_path_buf());
                entry.unpack_in(root)?;
            }
        }
    }

    dirs.sort_by(|a, b| b.path_bytes().cmp(&a.path_bytes()));
    for mut dir in dirs {
        dir.unpack_in(root)?;
    }

    Ok(())
}

fn create_runtime_config(
    image_config: &ImageConfiguration,
) -> Result<ocidir::oci_spec::runtime::Spec, anyhow::Error> {
    let mut runtime_config = ocidir::oci_spec::runtime::SpecBuilder::default().build()?;
    let mut annotations = HashMap::new();
    annotations.insert(
        "org.opencontainers.image.os".to_string(),
        image_config.os().to_string(),
    );
    annotations.insert(
        "org.opencontainers.image.architecture".to_string(),
        image_config.architecture().to_string(),
    );
    if let Some(variant) = image_config.variant() {
        annotations.insert(
            "org.opencontainers.image.variant".to_string(),
            variant.clone(),
        );
    }
    if let Some(os_version) = image_config.os_version() {
        annotations.insert(
            "org.opencontainers.image.os.version".to_string(),
            os_version.clone(),
        );
    }
    if let Some(os_features) = image_config.os_features() {
        annotations.insert(
            "org.opencontainers.image.os.features".to_string(),
            os_features.join(","),
        );
    }
    if let Some(author) = image_config.author() {
        annotations.insert(
            "org.opencontainers.image.author".to_string(),
            author.clone(),
        );
    }
    if let Some(created) = image_config.created() {
        annotations.insert(
            "org.opencontainers.image.created".to_string(),
            created.to_string(),
        );
    }
    if let Some(config) = image_config.config() {
        let mut process = ProcessBuilder::default().build().unwrap();

        if let Some(dir) = config.working_dir() {
            process.set_cwd(PathBuf::from(dir));
        }

        match (config.entrypoint(), config.cmd()) {
            (None, None) => {}
            (None, Some(cmd)) => {
                process.set_args(Some(cmd.clone()));
            }
            (Some(entrypoint), None) => {
                process.set_args(Some(entrypoint.clone()));
            }
            (Some(entrypoint), Some(cmd)) => {
                let mut args = entrypoint.clone();
                args.append(&mut cmd.clone());
                process.set_args(Some(args));
            }
        }

        process.set_env(config.env().clone());

        if let Some(user) = config.user() {
            let user_parts: Vec<&str> = user.split(':').collect();
            let (uid, gid) = match user_parts.as_slice() {
                [user] => resolve_user(user)?,
                [user, group] => (resolve_user(user)?.0, resolve_group(group)?),
                _ => bail!("Invalid user format in Config.User"),
            };

            let additional_gids = if user_parts.len() == 1 {
                resolve_additional_gids(uid)?
            } else {
                Vec::new()
            };

            process.set_user(Some(
                UserBuilder::default()
                    .uid(uid)
                    .gid(gid)
                    .additional_gids(additional_gids)
                    .build()?,
            ));
        }

        runtime_config.set_process(Some(process));

        if let Some(stop_signal) = config.stop_signal() {
            annotations.insert(
                "org.opencontainers.image.stopSignal".to_string(),
                stop_signal.clone(),
            );
        }

        // Config.Labels takes precedence over other annotations, so set that last
        if let Some(labels) = config.labels() {
            annotations.extend(labels.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
    }
    runtime_config.set_annotations(Some(annotations));
    Ok(runtime_config)
}

fn resolve_user(user: &str) -> Result<(u32, u32)> {
    if let Ok(uid) = user.parse::<u32>() {
        let user = get_user_by_uid(uid).ok_or_else(|| anyhow::anyhow!("User ID {} not found", uid))?;
        Ok((user.uid(), user.primary_group_id()))
    } else {
        let user = get_user_by_name(user).ok_or_else(|| anyhow::anyhow!("User {} not found", user))?;
        Ok((user.uid(), user.primary_group_id()))
    }
}

fn resolve_group(group: &str) -> Result<u32> {
    if let Ok(gid) = group.parse::<u32>() {
        get_group_by_gid(gid).ok_or_else(|| anyhow::anyhow!("Group ID {} not found", gid))?;
        Ok(gid)
    } else {
        let group = get_group_by_name(group).ok_or_else(|| anyhow::anyhow!("Group {} not found", group))?;
        Ok(group.gid())
    }
}

fn resolve_additional_gids(uid: u32) -> Result<Vec<u32>> {
    let user = get_user_by_uid(uid).ok_or_else(|| anyhow::anyhow!("User ID {} not found", uid))?;
    let groups = get_groups().filter(|g| g.members().contains(&user.name())).map(|g| g.gid()).collect();
    Ok(groups)
}
