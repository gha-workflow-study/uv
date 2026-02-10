//! Tests for `uv run` with sandboxing enabled.
//!
//! Sandboxing uses OS-level isolation (Linux namespaces + seccomp, macOS Seatbelt)
//! to restrict filesystem, network, and environment variable access for spawned
//! child processes. It is gated behind the `sandbox` preview feature.
//!
//! These tests are Unix-only since Windows sandboxing is not supported.
#![cfg(target_family = "unix")]

use anyhow::Result;
use assert_fs::prelude::*;
use indoc::indoc;

use uv_test::uv_snapshot;

/// The `[tool.uv.sandbox]` section is ignored without the `sandbox` preview feature.
#[test]
fn sandbox_requires_preview_feature() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }, { preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        print("hello from unsandboxed")
        "#
    })?;

    // Without the preview feature, sandbox config is ignored and the command runs normally.
    uv_snapshot!(context.filters(), context.run().arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    hello from unsandboxed

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `--allow-read` CLI flag is a no-op without the `sandbox` preview feature.
#[test]
fn sandbox_cli_flags_require_preview_feature() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"
        "#
    })?;

    // Without the preview feature, `--allow-read` is accepted but ignored.
    uv_snapshot!(context.filters(), context.run()
        .arg("--allow-read").arg("@project")
        .arg("python").arg("-c").arg("print('hello')"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    hello

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// A simple sandboxed script can read the project directory and execute Python.
#[test]
fn sandbox_basic_read_and_execute() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }, { preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        print("hello from sandbox")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    hello from sandbox

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Sandboxed process can read a file in the project directory.
#[test]
fn sandbox_read_project_file() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }, { preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let data_file = context.temp_dir.child("data.txt");
    data_file.write_str("project data content")?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        print(open("data.txt").read())
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    project data content

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Sandboxed process cannot read outside allowed paths.
#[test]
fn sandbox_deny_read_outside_project() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Try to read a file from the home directory (not in allowed paths).
    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        home = os.path.expanduser("~")
        try:
            # Try to list the home directory itself
            os.listdir(home)
            print("ERROR: should not be able to read home directory")
        except PermissionError:
            print("correctly denied: home directory")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: home directory

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `deny-read` field blocks reads within otherwise-allowed paths.
#[test]
fn sandbox_deny_read_specific_path() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        deny-read = ["secrets"]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Create a file in the denied subdirectory.
    let secrets_dir = context.temp_dir.child("secrets");
    secrets_dir.create_dir_all()?;
    secrets_dir
        .child("api_key.txt")
        .write_str("super-secret-key")?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        try:
            content = open("secrets/api_key.txt").read()
            print(f"ERROR: read secret: {content}")
        except PermissionError:
            print("correctly denied: secrets/api_key.txt")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Resolved 1 package in [TIME]
      × Failed to build `foo @ file://[TEMP_DIR]/`
      ├─▶ The build backend returned an error
      ╰─▶ Call to `setuptools.build_meta.build_editable` failed (exit status: 1)

          [stderr]
          error: Multiple top-level packages discovered in a flat-layout: ['cache', 'secrets'].

          To avoid accidental inclusion of unwanted files or directories,
          setuptools will not proceed with this build.

          If you are trying to create a single distribution with multiple packages
          on purpose, you should not rely on automatic discovery.
          Instead, consider the following options:

          1. set up custom discovery (`find` directive with `include` or `exclude`)
          2. use a `src-layout`
          3. explicitly set `py_modules` or `packages` with a list of names

          To find more information, look for "package discovery" on setuptools docs.

          hint: This usually indicates a problem with the package or the build environment.
    "#);

    Ok(())
}

/// The `known-secrets` deny preset blocks reads to `~/.ssh/`, `~/.aws/`, etc.
#[test]
fn sandbox_deny_read_known_secrets_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "home" }, { preset = "python" }, { preset = "system" }]
        deny-read = [{ preset = "known-secrets" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Create fake .ssh directory in the test home.
    let ssh_dir = context.home_dir.child(".ssh");
    ssh_dir.create_dir_all()?;
    ssh_dir.child("id_rsa").write_str("fake-private-key")?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os

        home = os.environ["HOME"]
        ssh_key = os.path.join(home, ".ssh", "id_rsa")

        try:
            content = open(ssh_key).read()
            print(f"ERROR: read SSH key: {content}")
        except PermissionError:
            print("correctly denied: ~/.ssh/id_rsa")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    [VENV]/bin/python3: can't open file 'main.py': [Errno 1] Operation not permitted
    ");

    Ok(())
}

/// A literal path in `allow-read` grants read access to that path.
#[test]
fn sandbox_allow_read_literal_path() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    // Create an external data directory.
    let external_dir = context.root.child("external-data");
    external_dir.create_dir_all()?;
    external_dir
        .child("dataset.csv")
        .write_str("a,b,c\n1,2,3")?;

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(&format!(
        indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{{ preset = "project" }}, {{ preset = "python" }}, {{ preset = "system" }}, "{external_path}"]
        allow-execute = [{{ preset = "python" }}, {{ preset = "system" }}]
        allow-env = [{{ preset = "standard" }}]
        "#},
        external_path = external_dir.path().display()
    ))?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(&format!(
        indoc! { r#"
        content = open("{external_path}/dataset.csv").read()
        print(content.strip())
        "#},
        external_path = external_dir.path().display()
    ))?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    a,b,c
    1,2,3

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Sandboxed process can write to the project directory when allowed.
#[test]
fn sandbox_allow_write_project() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }, { preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        with open("output.txt", "w") as f:
            f.write("sandbox wrote this")
        print(open("output.txt").read())
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    sandbox wrote this

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Sandboxed process cannot write when `allow-write` is empty.
#[test]
fn sandbox_deny_write_by_default() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = []
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        try:
            with open("output.txt", "w") as f:
                f.write("should not work")
            print("ERROR: write succeeded")
        except PermissionError:
            print("correctly denied: write to project directory")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: write to project directory

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `deny-write` field blocks writes within otherwise-allowed paths.
#[test]
fn sandbox_deny_write_specific_path() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }]
        deny-write = [".env"]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        # Writing to a normal file should work.
        with open("allowed.txt", "w") as f:
            f.write("ok")

        # Writing to .env should be denied.
        try:
            with open(".env", "w") as f:
                f.write("SECRET=stolen")
            print("ERROR: wrote to .env")
        except PermissionError:
            print("correctly denied: .env")

        print("allowed.txt written successfully")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: .env
    allowed.txt written successfully

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `shell-configs` deny preset blocks writes to `.bashrc`, `.zshrc`, etc.
#[test]
fn sandbox_deny_write_shell_configs_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "home" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "home" }]
        deny-write = [{ preset = "shell-configs" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os

        home = os.environ["HOME"]
        results = []

        for filename in [".bashrc", ".zshrc", ".profile"]:
            path = os.path.join(home, filename)
            try:
                with open(path, "w") as f:
                    f.write("malicious")
                results.append(f"ERROR: wrote to {filename}")
            except PermissionError:
                results.append(f"correctly denied: {filename}")

        for r in results:
            print(r)
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    [VENV]/bin/python3: can't open file 'main.py': [Errno 1] Operation not permitted
    ");

    Ok(())
}

/// The `git-hooks` deny preset blocks writes to `.git/hooks/`.
#[test]
fn sandbox_deny_write_git_hooks_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }]
        deny-write = [{ preset = "git-hooks" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Create a .git/hooks directory.
    let git_hooks = context.temp_dir.child(".git").child("hooks");
    git_hooks.create_dir_all()?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r"
        try:
            with open('.git/hooks/pre-commit', 'w') as f:
                f.write('malicious hook content')
            print('ERROR: wrote to .git/hooks/pre-commit')
        except PermissionError:
            print('correctly denied: .git/hooks/pre-commit')
        "
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: .git/hooks/pre-commit

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Network access is denied by default.
#[test]
fn sandbox_deny_network_by_default() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import socket
        try:
            s = socket.create_connection(("example.com", 80), timeout=5)
            s.close()
            print("ERROR: network connection succeeded")
        except OSError:
            print("correctly denied: network access")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: network access

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// `allow-net = false` explicitly denies network access.
#[test]
fn sandbox_deny_network_explicit() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-net = false
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import socket
        try:
            s = socket.create_connection(("example.com", 80), timeout=5)
            s.close()
            print("ERROR: network connection succeeded")
        except OSError:
            print("correctly denied: network access")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: network access

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// `allow-net = true` permits network access.
#[test]
fn sandbox_allow_network() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-net = true
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Just check we can create a socket — don't actually connect to avoid
    // flaky tests from network availability.
    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        print("network socket creation succeeded")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    network socket creation succeeded

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// `allow-env = false` (default) denies all environment variables.
#[test]
fn sandbox_deny_env_by_default() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = false
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        # HOME should not be visible
        home = os.environ.get("HOME")
        print(f"HOME={home}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    HOME=None

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// `allow-env = [{ preset = "standard" }]` passes through common variables.
#[test]
fn sandbox_allow_env_standard_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        # HOME should be visible with the standard preset
        home = os.environ.get("HOME")
        has_home = home is not None and len(home) > 0
        print(f"has HOME: {has_home}")

        # A custom variable should not be visible
        custom = os.environ.get("MY_CUSTOM_VAR")
        print(f"MY_CUSTOM_VAR={custom}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py")
        .env("MY_CUSTOM_VAR", "secret-value"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    has HOME: True
    MY_CUSTOM_VAR=None

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Literal variable names in `allow-env` grant access to specific variables.
#[test]
fn sandbox_allow_env_specific_variable() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }, "DATABASE_URL"]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        db_url = os.environ.get("DATABASE_URL")
        other = os.environ.get("OTHER_SECRET")
        print(f"DATABASE_URL={db_url}")
        print(f"OTHER_SECRET={other}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py")
        .env("DATABASE_URL", "postgres://localhost/mydb")
        .env("OTHER_SECRET", "should-not-see-this"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    DATABASE_URL=postgres://localhost/mydb
    OTHER_SECRET=None

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// `allow-env = true` with `deny-env` hides specific variables.
#[test]
fn sandbox_allow_all_env_with_deny() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = true
        deny-env = ["SECRET_KEY", "DATABASE_PASSWORD"]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        # Allowed variables should be visible
        visible = os.environ.get("VISIBLE_VAR")
        print(f"VISIBLE_VAR={visible}")

        # Denied variables should be hidden
        secret = os.environ.get("SECRET_KEY")
        print(f"SECRET_KEY={secret}")

        db_pass = os.environ.get("DATABASE_PASSWORD")
        print(f"DATABASE_PASSWORD={db_pass}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py")
        .env("VISIBLE_VAR", "i-am-visible")
        .env("SECRET_KEY", "super-secret")
        .env("DATABASE_PASSWORD", "hunter2"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    VISIBLE_VAR=i-am-visible
    SECRET_KEY=None
    DATABASE_PASSWORD=None

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `known-secrets` deny preset hides common secret variable patterns.
#[test]
fn sandbox_deny_env_known_secrets_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = true
        deny-env = [{ preset = "known-secrets" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        results = []
        for var in ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "SAFE_VAR"]:
            val = os.environ.get(var)
            results.append(f"{var}={val}")
        for r in results:
            print(r)
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py")
        .env("AWS_SECRET_ACCESS_KEY", "AKIA-secret")
        .env("GITHUB_TOKEN", "ghp_token123")
        .env("NPM_TOKEN", "npm_token456")
        .env("SAFE_VAR", "i-am-safe"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    AWS_SECRET_ACCESS_KEY=None
    GITHUB_TOKEN=None
    NPM_TOKEN=None
    SAFE_VAR=i-am-safe

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Wildcard patterns in `deny-env` match variable name prefixes.
#[test]
fn sandbox_deny_env_wildcard() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = true
        deny-env = ["AWS_*"]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        for var in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "OTHER_VAR"]:
            val = os.environ.get(var)
            print(f"{var}={val}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py")
        .env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7")
        .env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI")
        .env("AWS_REGION", "us-east-1")
        .env("OTHER_VAR", "visible"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    AWS_ACCESS_KEY_ID=None
    AWS_SECRET_ACCESS_KEY=None
    AWS_REGION=None
    OTHER_VAR=visible

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// CLI `--allow-read` overrides `allow-read` from config.
#[test]
fn sandbox_cli_override_allow_read() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Create an external directory.
    let external_dir = context.root.child("extra-data");
    external_dir.create_dir_all()?;
    external_dir.child("info.txt").write_str("extra data")?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(&format!(
        indoc! { r#"
        content = open("{external_path}/info.txt").read()
        print(content)
        "#},
        external_path = external_dir.path().display()
    ))?;

    // Without CLI override, reading the external directory should fail.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    Traceback (most recent call last):
      File "[TEMP_DIR]/main.py", line 1, in <module>
        content = open("/private/var/folders/6p/k5sd5z7j31b31pq4lhn0l8d80000gn/T/uv/tests/[TMP]/info.txt").read()
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    PermissionError: [Errno 1] Operation not permitted: '/private/var/folders/6p/k5sd5z7j31b31pq4lhn0l8d80000gn/T/uv/tests/[TMP]/info.txt'
    "#);

    // With CLI override adding the external path, it should succeed.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("--allow-read").arg(format!("@project,@python,@system,{}", external_dir.path().display()))
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    extra data

    ----- stderr -----
    Resolved 1 package in [TIME]
    Audited 1 package in [TIME]
    ");

    Ok(())
}

/// CLI `--allow-net` overrides `allow-net` from config.
#[test]
fn sandbox_cli_override_allow_net() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-net = false
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()
        print("network socket creation succeeded")
        "#
    })?;

    // Override network to allow.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("--allow-net")
        .arg("python").arg("-B").arg("main.py"), @"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    error: unexpected argument '-B' found

    Usage: uv run [OPTIONS] [COMMAND]

    For more information, try '--help'.
    ");

    Ok(())
}

/// Sandbox configuration in PEP 723 inline script metadata is not yet supported.
#[test]
fn sandbox_inline_script_metadata() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let test_script = context.temp_dir.child("script.py");
    test_script.write_str(indoc! { r#"
        # /// script
        # requires-python = ">=3.12"
        # dependencies = []
        #
        # [tool.uv.sandbox]
        # allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        # allow-execute = [{ preset = "python" }, { preset = "system" }]
        # allow-net = false
        # allow-env = [{ preset = "standard" }]
        # ///

        import socket
        try:
            s = socket.create_connection(("example.com", 80), timeout=5)
            s.close()
            print("ERROR: network connection succeeded")
        except OSError:
            print("correctly denied: network access")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("script.py"), @"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    error: TOML parse error at line 4, column 7
      |
    4 | [tool.uv.sandbox]
      |       ^^
    unknown field `sandbox`
    ");

    Ok(())
}

/// When `required = true`, sandboxing failure should error rather than warn.
/// On supported platforms, this test just verifies the field is accepted.
#[test]
fn sandbox_required_field_accepted() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }, { preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        required = true
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        print("sandbox is required and active")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    sandbox is required and active

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Unknown preset names should produce a useful error.
#[test]
fn sandbox_invalid_preset_name() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "nonexistent-preset" }]
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-c").arg("print('hello')"), @r#"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    warning: Failed to parse `pyproject.toml` during settings discovery:
      TOML parse error at line 12, column 14
         |
      12 | allow-read = [{ preset = "nonexistent-preset" }]
         |              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      data did not match any variant of untagged enum FsEntry

    error: Failed to parse: `pyproject.toml`
      Caused by: TOML parse error at line 12, column 14
       |
    12 | allow-read = [{ preset = "nonexistent-preset" }]
       |              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    data did not match any variant of untagged enum FsEntry
    "#);

    Ok(())
}

/// Unknown fields in the sandbox section should produce a useful error.
#[test]
fn sandbox_unknown_field() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "system" }]
        allow-frobulate = true
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-c").arg("print('hello')"), @"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    warning: Failed to parse `pyproject.toml` during settings discovery:
      TOML parse error at line 13, column 1
         |
      13 | allow-frobulate = true
         | ^^^^^^^^^^^^^^^
      unknown field `allow-frobulate`, expected one of `allow-read`, `deny-read`, `allow-write`, `deny-write`, `allow-execute`, `deny-execute`, `allow-net`, `deny-net`, `allow-env`, `deny-env`, `required`

    error: Failed to parse: `pyproject.toml`
      Caused by: TOML parse error at line 13, column 1
       |
    13 | allow-frobulate = true
       | ^^^^^^^^^^^^^^^
    unknown field `allow-frobulate`, expected one of `allow-read`, `deny-read`, `allow-write`, `deny-write`, `allow-execute`, `deny-execute`, `allow-net`, `deny-net`, `allow-env`, `deny-env`, `required`
    ");

    Ok(())
}

/// Write to tmp via the `tmp` preset.
#[test]
fn sandbox_write_tmp() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }, { preset = "tmp" }]
        allow-write = [{ preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("temp data")
            tmpfile = f.name

        content = open(tmpfile).read()
        os.unlink(tmpfile)
        print(f"wrote and read from tmp: {content}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    wrote and read from tmp: temp data

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// An empty sandbox configuration (no allow entries) should deny everything.
#[test]
fn sandbox_empty_config_denies_all() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        "#
    })?;

    // With an empty sandbox, Python should not even be able to start since
    // there are no execute or read permissions.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-c").arg("print('hello')"), @"
    success: false
    exit_code: 2
    ----- stdout -----

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    error: Failed to spawn: `python`
      Caused by: Operation not permitted (os error 1)
    ");

    Ok(())
}

/// Multiple deny presets can be combined.
#[test]
fn sandbox_multiple_deny_presets() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }]
        deny-write = [{ preset = "known-secrets" }, { preset = "shell-configs" }, { preset = "git-hooks" }, { preset = "ide-configs" }, ".env"]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    // Create directories that the deny presets should protect.
    let git_hooks = context.temp_dir.child(".git").child("hooks");
    git_hooks.create_dir_all()?;
    let vscode = context.temp_dir.child(".vscode");
    vscode.create_dir_all()?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os

        targets = [
            ".env",
            ".git/hooks/pre-commit",
            ".vscode/settings.json",
        ]

        for target in targets:
            try:
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                with open(target, "w") as f:
                    f.write("malicious")
                print(f"ERROR: wrote to {target}")
            except PermissionError:
                print(f"correctly denied: {target}")

        # But writing to a normal file should work.
        with open("normal.txt", "w") as f:
            f.write("ok")
        print("normal.txt: written successfully")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: .env
    correctly denied: .git/hooks/pre-commit
    correctly denied: .vscode/settings.json
    normal.txt: written successfully

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// Sandbox works with project dependencies installed.
#[test]
fn sandbox_with_dependencies() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = ["iniconfig"]

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }, { preset = "tmp" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import iniconfig
        print(f"iniconfig loaded: {iniconfig.__name__}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    iniconfig loaded: iniconfig

    ----- stderr -----
    Resolved 2 packages in [TIME]
    Prepared 2 packages in [TIME]
    Installed 2 packages in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
     + iniconfig==2.0.0
    ");

    Ok(())
}

/// Deny takes precedence over allow for the same path.
#[test]
fn sandbox_deny_overrides_allow() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }]
        deny-write = ["build-output"]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let output_dir = context.temp_dir.child("build-output");
    output_dir.create_dir_all()?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        # Writing to project root should work.
        with open("ok.txt", "w") as f:
            f.write("allowed")

        # Writing to "build-output" subdirectory should be denied.
        try:
            with open("build-output/result.txt", "w") as f:
                f.write("denied")
            print("ERROR: wrote to build-output/result.txt")
        except PermissionError:
            print("correctly denied: build-output/result.txt")

        print("ok.txt: written successfully")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: build-output/result.txt
    ok.txt: written successfully

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// CLI `--allow-write` permits writing to a specific path.
#[test]
fn sandbox_cli_allow_write() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = []
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        with open("output.txt", "w") as f:
            f.write("cli override worked")
        print(open("output.txt").read())
        "#
    })?;

    // Config has allow-write = [], but CLI overrides with @project.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("--allow-write").arg("@project")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    cli override worked

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// CLI `--allow-env` permits specific environment variables.
#[test]
fn sandbox_cli_allow_env() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = false
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        my_var = os.environ.get("MY_TEST_VAR")
        print(f"MY_TEST_VAR={my_var}")
        "#
    })?;

    // Config has allow-env = false, but CLI overrides with true.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("--allow-env").arg("true")
        .arg("python").arg("-B").arg("main.py")
        .env("MY_TEST_VAR", "visible-from-cli"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    MY_TEST_VAR=visible-from-cli

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// CLI `--deny-env` hides specific environment variables.
#[test]
fn sandbox_cli_deny_env() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = true
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        secret = os.environ.get("MY_SECRET")
        visible = os.environ.get("MY_VISIBLE")
        print(f"MY_SECRET={secret}")
        print(f"MY_VISIBLE={visible}")
        "#
    })?;

    // Config has allow-env = true, CLI adds deny-env for MY_SECRET.
    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("--deny-env").arg("MY_SECRET")
        .arg("python").arg("-B").arg("main.py")
        .env("MY_SECRET", "hidden")
        .env("MY_VISIBLE", "shown"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    MY_SECRET=None
    MY_VISIBLE=shown

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `deny-execute` field blocks execution of specific paths.
#[test]
fn sandbox_deny_execute() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        deny-execute = ["/usr/bin"]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import os
        try:
            os.execv("/usr/bin/env", ["/usr/bin/env", "echo", "should not work"])
        except PermissionError:
            print("correctly denied: /usr/bin/env via execv")
        except OSError as e:
            print(f"correctly denied: /usr/bin/env via execv ({e})")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: /usr/bin/env via execv

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `ide-configs` deny preset blocks writes to `.vscode/`, `.idea/`, etc.
#[test]
fn sandbox_deny_write_ide_configs_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "system" }]
        allow-write = [{ preset = "project" }]
        deny-write = [{ preset = "ide-configs" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let vscode_dir = context.temp_dir.child(".vscode");
    vscode_dir.create_dir_all()?;
    let idea_dir = context.temp_dir.child(".idea");
    idea_dir.create_dir_all()?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        results = []
        for path in [".vscode/settings.json", ".idea/workspace.xml"]:
            try:
                import os
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write("malicious")
                results.append(f"ERROR: wrote to {path}")
            except PermissionError:
                results.append(f"correctly denied: {path}")

        # But writing to a normal file should work.
        with open("normal.txt", "w") as f:
            f.write("ok")
        results.append("normal.txt: written successfully")

        for r in results:
            print(r)
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    correctly denied: .vscode/settings.json
    correctly denied: .idea/workspace.xml
    normal.txt: written successfully

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}

/// The `virtualenv` preset grants read access to the virtualenv directory.
#[test]
fn sandbox_virtualenv_preset() -> Result<()> {
    let context = uv_test::test_context!("3.12");

    let pyproject_toml = context.temp_dir.child("pyproject.toml");
    pyproject_toml.write_str(indoc! { r#"
        [project]
        name = "foo"
        version = "1.0.0"
        requires-python = ">=3.12"
        dependencies = []

        [build-system]
        requires = ["setuptools>=42"]
        build-backend = "setuptools.build_meta"

        [tool.uv.sandbox]
        allow-read = [{ preset = "project" }, { preset = "python" }, { preset = "virtualenv" }, { preset = "system" }]
        allow-execute = [{ preset = "python" }, { preset = "system" }]
        allow-env = [{ preset = "standard" }]
        "#
    })?;

    let test_script = context.temp_dir.child("main.py");
    test_script.write_str(indoc! { r#"
        import sys
        import os
        # List files in sys.prefix (the virtualenv root)
        venv_files = os.listdir(sys.prefix)
        has_pyvenv = "pyvenv.cfg" in venv_files
        print(f"can read venv: {has_pyvenv}")
        "#
    })?;

    uv_snapshot!(context.filters(), context.run()
        .arg("--preview-features").arg("sandbox")
        .arg("python").arg("-B").arg("main.py"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    can read venv: True

    ----- stderr -----
    Resolved 1 package in [TIME]
    Prepared 1 package in [TIME]
    Installed 1 package in [TIME]
     + foo==1.0.0 (from file://[TEMP_DIR]/)
    ");

    Ok(())
}
