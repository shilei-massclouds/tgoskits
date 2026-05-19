use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, bail};
use ostool::ToolConfig;

use crate::{
    arceos::{self, ArceOS},
    context::{AppContext, axbuild_tmp_dir, workspace_root_path},
};

const OVERLAY_DIR_NAME: &str = "arceos-ex-workspace";
const DEFAULT_ARCH: &str = "riscv64";
const DEFAULT_TEST_GROUP: &str = "std";
const OVERLAY_MANIFEST_ENV: &str = "AXBUILD_WORKSPACE_MANIFEST";
const DEFAULT_PLATFORM_ENV: &str = "AXBUILD_DEFAULT_PLATFORM_PACKAGE_RISCV64";
const GENERIC_PLATFORM_PACKAGE: &str = "ax-plat-riscv64-generic-ex";

pub struct ArceOSEx {
    arceos: ArceOS,
    _overlay: OverlayWorkspace,
}

impl ArceOSEx {
    pub fn new() -> anyhow::Result<Self> {
        let workspace_root = workspace_root_path()?;
        let overlay = OverlayWorkspace::prepare(&workspace_root)?;
        // SAFETY: axbuild is a single-command CLI. The variables are set before
        // any arceos-ex Cargo metadata cache is initialized and remain scoped to
        // this process.
        unsafe {
            env::set_var(OVERLAY_MANIFEST_ENV, overlay.manifest_path());
            env::set_var(DEFAULT_PLATFORM_ENV, GENERIC_PLATFORM_PACKAGE);
        }
        let app = AppContext::new_with_tool_config(ToolConfig {
            manifest: Some(overlay.manifest_path().to_path_buf()),
            ..ToolConfig::default()
        })?;
        Ok(Self {
            arceos: ArceOS::from_app(app),
            _overlay: overlay,
        })
    }

    pub async fn execute(&mut self, command: arceos::Command) -> anyhow::Result<()> {
        self.arceos.execute(normalize_command(command)?).await
    }
}

fn normalize_command(command: arceos::Command) -> anyhow::Result<arceos::Command> {
    match command {
        arceos::Command::Build(mut args) => {
            normalize_build_args(&mut args)?;
            Ok(arceos::Command::Build(args))
        }
        arceos::Command::Qemu(mut args) => {
            normalize_build_args(&mut args.build)?;
            Ok(arceos::Command::Qemu(args))
        }
        arceos::Command::Uboot(mut args) => {
            normalize_build_args(&mut args.build)?;
            Ok(arceos::Command::Uboot(args))
        }
        arceos::Command::Test(mut args) => {
            normalize_test_args(&mut args)?;
            Ok(arceos::Command::Test(args))
        }
    }
}

fn normalize_build_args(args: &mut arceos::ArgsBuild) -> anyhow::Result<()> {
    if args.arch.is_none() && args.target.is_none() {
        args.arch = Some(DEFAULT_ARCH.to_string());
    }
    ensure_riscv64_target(args.arch.as_deref(), args.target.as_deref())?;
    Ok(())
}

fn normalize_test_args(args: &mut arceos::test::ArgsTest) -> anyhow::Result<()> {
    match &mut args.command {
        arceos::test::TestCommand::Qemu(qemu) => {
            if qemu.arch.is_none() && qemu.target.is_none() && !qemu.list {
                qemu.arch = Some(DEFAULT_ARCH.to_string());
            }
            ensure_riscv64_target(qemu.arch.as_deref(), qemu.target.as_deref())?;
            if qemu.test_group.is_none() && !qemu.only_c && !qemu.only_rust {
                qemu.test_group = Some(DEFAULT_TEST_GROUP.to_string());
            }
        }
    }
    Ok(())
}

fn ensure_riscv64_target(arch: Option<&str>, target: Option<&str>) -> anyhow::Result<()> {
    if let Some(arch) = arch
        && arch != DEFAULT_ARCH
    {
        bail!("arceos-ex supports only `{DEFAULT_ARCH}` arch, not `{arch}`");
    }
    if let Some(target) = target
        && !target.starts_with("riscv64")
    {
        bail!("arceos-ex supports only RISC-V64 targets, not `{target}`");
    }
    Ok(())
}

struct OverlayWorkspace {
    manifest_path: PathBuf,
}

impl OverlayWorkspace {
    fn prepare(workspace_root: &Path) -> anyhow::Result<Self> {
        let overlay_root = axbuild_tmp_dir(workspace_root).join(OVERLAY_DIR_NAME);
        reset_dir(&overlay_root)?;
        for entry in [
            ".cargo",
            "components",
            "drivers",
            "os",
            "platform",
            "scripts",
            "test-suit",
            "xtask",
        ] {
            link_dir(workspace_root, &overlay_root, entry)?;
        }
        write_overlay_manifest(workspace_root, &overlay_root)?;
        Ok(Self {
            manifest_path: overlay_root.join("Cargo.toml"),
        })
    }

    fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }
}

fn reset_dir(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

fn link_dir(workspace_root: &Path, overlay_root: &Path, name: &str) -> anyhow::Result<()> {
    let source = workspace_root.join(name);
    if !source.exists() {
        return Ok(());
    }
    let target = overlay_root.join(name);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &target).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            target.display(),
            source.display()
        )
    })?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&source, &target).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            target.display(),
            source.display()
        )
    })?;
    Ok(())
}

fn write_overlay_manifest(workspace_root: &Path, overlay_root: &Path) -> anyhow::Result<()> {
    let source = workspace_root.join("Cargo.toml");
    let content = fs::read_to_string(&source)
        .with_context(|| format!("failed to read {}", source.display()))?;
    let mut manifest: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", source.display()))?;
    patch_workspace_members(&mut manifest)?;
    patch_workspace_dependencies(&mut manifest)?;
    let rendered =
        toml::to_string_pretty(&manifest).context("failed to render overlay manifest")?;
    let output = overlay_root.join("Cargo.toml");
    fs::write(&output, rendered).with_context(|| format!("failed to write {}", output.display()))
}

fn patch_workspace_members(manifest: &mut toml::Value) -> anyhow::Result<()> {
    let members = manifest
        .get_mut("workspace")
        .and_then(toml::Value::as_table_mut)
        .and_then(|workspace| workspace.get_mut("members"))
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| anyhow!("workspace.members is missing from root Cargo.toml"))?;
    for member in [
        "os/arceos_ex/modules/axhal",
        "os/arceos_ex/modules/axruntime",
        "components/axplat_crates/platforms/axplat-riscv64-generic-ex",
    ] {
        if !members.iter().any(|value| value.as_str() == Some(member)) {
            members.push(toml::Value::String(member.to_string()));
        }
    }
    Ok(())
}

fn patch_workspace_dependencies(manifest: &mut toml::Value) -> anyhow::Result<()> {
    let dependencies = manifest
        .get_mut("workspace")
        .and_then(toml::Value::as_table_mut)
        .and_then(|workspace| workspace.get_mut("dependencies"))
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("workspace.dependencies is missing from root Cargo.toml"))?;

    dependencies.insert(
        "ax-hal".to_string(),
        path_dependency_with_package("ax-hal-ex", "0.1.0", "os/arceos_ex/modules/axhal"),
    );
    dependencies.insert(
        "ax-runtime".to_string(),
        path_dependency_with_package("ax-runtime-ex", "0.1.0", "os/arceos_ex/modules/axruntime"),
    );
    dependencies.insert(
        "ax-plat-riscv64-qemu-virt".to_string(),
        path_dependency_with_package(
            GENERIC_PLATFORM_PACKAGE,
            "0.1.0",
            "components/axplat_crates/platforms/axplat-riscv64-generic-ex",
        ),
    );
    dependencies.insert(
        GENERIC_PLATFORM_PACKAGE.to_string(),
        path_dependency(
            "0.1.0",
            "components/axplat_crates/platforms/axplat-riscv64-generic-ex",
        ),
    );
    Ok(())
}

fn path_dependency(version: &str, path: &str) -> toml::Value {
    let mut table = toml::Table::new();
    table.insert(
        "version".to_string(),
        toml::Value::String(version.to_string()),
    );
    table.insert("path".to_string(), toml::Value::String(path.to_string()));
    toml::Value::Table(table)
}

fn path_dependency_with_package(package: &str, version: &str, path: &str) -> toml::Value {
    let mut table = match path_dependency(version, path) {
        toml::Value::Table(table) => table,
        _ => unreachable!(),
    };
    table.insert(
        "package".to_string(),
        toml::Value::String(package.to_string()),
    );
    toml::Value::Table(table)
}
