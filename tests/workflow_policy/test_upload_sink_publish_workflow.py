"""Policy tests for the isolated immutable HTTPS upload-sink image."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-upload-sink.yml"
EXPECTED_ACTIONS = {
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
}


class UploadSinkPublishWorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.uses = re.findall(r"^\s*uses:\s*([^\s#]+)", cls.text, flags=re.MULTILINE)

    def test_is_manual_only_and_bounded(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\n  workflow_dispatch:\s*$")
        self.assertNotRegex(self.text, r"(?m)^  (?:push|pull_request|pull_request_target|schedule):")
        self.assertRegex(self.text, r"(?m)^    timeout-minutes: 15$")

    def test_actions_are_immutable_and_no_cache_is_used(self) -> None:
        self.assertEqual(set(self.uses), EXPECTED_ACTIONS)
        for action in self.uses:
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("actions/cache", self.text)

    def test_permissions_are_limited_to_source_read_and_package_publish(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n  packages: write$")
        self.assertNotRegex(self.text, r"(?im)^\s+[a-z-]+:\s*(?:write|admin)$.*(?:actions|contents|issues|pull-requests)")

    def test_source_toolchain_and_image_tag_are_pinned(self) -> None:
        self.assertIn('ref: ${{ github.sha }}', self.text)
        self.assertIn("GO_VERSION: '1.24.6'", self.text)
        self.assertIn("test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"", self.text)
        self.assertIn("GOPROXY: 'off'", self.text)
        self.assertIn("GOTOOLCHAIN: 'local'", self.text)
        self.assertIn("--tag \"$image_tag\"", self.text)
        self.assertIn('image_tag="$IMAGE_NAME:$GITHUB_SHA"', self.text)
        self.assertNotIn(":latest", self.text)
        self.assertIn("--platform linux/amd64", self.text)

    def test_build_emits_registry_provenance_and_checks_digest(self) -> None:
        self.assertIn("--push", self.text)
        self.assertIn("--provenance=mode=max", self.text)
        self.assertIn("--sbom=true", self.text)
        self.assertIn("--metadata-file", self.text)
        self.assertIn('metadata.get("containerimage.digest")', self.text)
        self.assertIn('metadata.get("buildx.build.provenance")', self.text)
        self.assertRegex(self.text, r"sha256:\[0-9a-f\]\{64\}")
        self.assertIn("image_ref", self.text)

    def test_built_container_smoke_mounts_secret_and_sends_one_mebibyte(self) -> None:
        self.assertIn("Build container and run non-root upload smoke test", self.text)
        self.assertIn("--load", self.text)
        self.assertIn("--env PORT=18080", self.text)
        self.assertIn("/etc/secrets/upload-path:ro", self.text)
        self.assertIn("--path-file=/etc/secrets/upload-path", self.text)
        self.assertIn('sudo chmod 0440 "$smoke_dir/upload-path"', self.text)
        self.assertIn("test \"$image_user\" = \"65532:1000\"", self.text)
        self.assertIn("head -c 1048576 /dev/zero", self.text)
        self.assertIn("%{size_upload} %{http_code}", self.text)
        self.assertIn('test "$upload_result" = "1048576 204"', self.text)

    def test_pushed_digest_is_run_headless_with_the_same_contract(self) -> None:
        self.assertIn('docker image inspect "$image_ref" --format \'{{.Config.User}}\'', self.text)
        self.assertIn('docker image inspect "$image_ref" --format \'{{json .Config.Entrypoint}}\'', self.text)
        self.assertIn('test "$pulled_image_user" = "65532:1000"', self.text)
        self.assertIn("test \"$pulled_entrypoint\" = '[\"/upload-sink\"]'", self.text)
        self.assertIn("--env PORT=18081", self.text)
        self.assertIn("--publish 127.0.0.1:18081:18081", self.text)
        self.assertIn('sudo chmod 0440 "$pulled_smoke_dir/upload-path"', self.text)
        self.assertIn('test "$pulled_upload_result" = "1048576 204"', self.text)
        self.assertIn('docker image rm "$image_ref"', self.text)

    def test_external_visibility_and_render_variable_gates_are_documented(self) -> None:
        readme = (ROOT / "server" / "upload_sink" / "README.md").read_text(encoding="utf-8")
        self.assertIn("make the", readme)
        self.assertIn("GHCR package public", readme)
        self.assertIn("does not change", readme)
        self.assertIn("package visibility", readme)
        self.assertIn("RENDER_SINK_IMAGE_PATH", readme)
        self.assertIn("RENDER_SINK_IMAGE_DIGEST", readme)
        self.assertIn("protected", readme)

    def test_anonymous_digest_pull_happens_after_logout_and_inspects_manifest(self) -> None:
        logout = self.text.index("docker logout ghcr.io")
        pull = self.text.index('docker pull --platform linux/amd64 "$image_ref"')
        inspect = self.text.index('docker buildx imagetools inspect "$image_ref"')
        push = self.text.index("--push")
        self.assertGreater(logout, push)
        self.assertGreater(pull, logout)
        self.assertGreater(inspect, pull)

    def test_token_is_used_only_for_ghcr_login_and_no_secret_is_persisted(self) -> None:
        self.assertIn("packages: write", self.text)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", self.text)
        self.assertIn("docker login ghcr.io --username \"$GITHUB_ACTOR\" --password-stdin", self.text)
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("docker save", self.text)
        self.assertNotIn("profile", self.text.lower())
        self.assertNotRegex(self.text, r"(?m)^\s*set -x\s*$")

    def test_upload_sink_source_is_self_contained_and_minimal(self) -> None:
        source = ROOT / "server" / "upload_sink"
        self.assertTrue((source / "go.mod").is_file())
        self.assertTrue((source / "Dockerfile").is_file())
        self.assertTrue((source / ".dockerignore").is_file())
        dockerfile = (source / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(dockerfile, r"(?m)^FROM scratch$")
        self.assertRegex(dockerfile, r"(?m)^USER 65532:1000$")
        self.assertIn('ENTRYPOINT ["/upload-sink"]', dockerfile)
        self.assertNotIn("VOLUME", dockerfile.upper())
        main = (source / "main.go").read_text(encoding="utf-8")
        self.assertIn('UploadPathFilePath = "/etc/secrets/upload-path"', main)
        self.assertIn('strings.HasPrefix(args[0], "--path-file=")', main)
        self.assertIn("loadUploadPathFile", main)
        self.assertIn("syscall.O_NOFOLLOW", main)
        self.assertIn("file.Stat()", main)
        self.assertNotIn("os.Lstat", main)

    def test_server_diagnostics_are_not_suppressed(self) -> None:
        main = (ROOT / "server" / "upload_sink" / "main.go").read_text(encoding="utf-8")
        self.assertNotIn("io.Discard", main)
        self.assertNotIn("safeDiagnosticWriter", main)
        self.assertIn("log.New(os.Stderr", main)
        self.assertIn("os.Stderr", main)
        self.assertIn('fmt.Errorf("could not listen on PORT: %w", err)', main)
        self.assertIn('fmt.Errorf("upload sink shutdown failed: %w", err)', main)


if __name__ == "__main__":
    unittest.main()
