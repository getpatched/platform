# Isolated public APT preview

The preview channel tests repository delivery with a harmless package named `getpatched-preview-smoke`. It uses only `preview.getpatched.dev`, the `getpatched-apt-preview` R2 bucket, and a dedicated signing key. The preview Worker is read-only and serves only Focal indexes, the preview key, and this package's source and binary files. Every workflow run and attempt has an immutable path under `/runs/<run-id>/<attempt>/`; a later run cannot replace indexes used by an earlier signed `InRelease`. The workflow never writes to production or sponsor storage and never creates a production release record.

## Cloudflare and GitHub setup

The GitHub Actions environment `getpatched-apt-preview` is restricted to `main`. The dedicated `getpatched-apt-preview` R2 bucket has been created and is empty with public access disabled. The preview signing key and fingerprint are configured in the GitHub environment. Before dispatching the preview workflow, the Cloudflare owner must:

1. Create the `getpatched-apt-preview` Worker and bind only that bucket as `PREVIEW`. Attach the custom domain `preview.getpatched.dev` to this Worker. Chrome is currently at Cloudflare’s Hello World creation wizard for this Worker; do not deploy its default code or expose an unintended `workers.dev` endpoint. Do not reuse `getpatched-release-gateway`, `getpatched-release-staging`, `repo.getpatched.dev`, or `early.getpatched.dev`.
2. Create a dedicated Cloudflare API token for the preview Worker, scoped to Worker Editor. If the token must add or change its custom domain during deploy, grant Workers Routes Write only for the `getpatched.dev` zone. The initial creation of a new Worker requires Workers Admin; create the Worker and domain through the Cloudflare owner dashboard first so CI does not need that broader role.
3. Create R2 S3 API credentials with Object Read & Write access scoped only to `getpatched-apt-preview`.
4. Add these values to the protected GitHub environment; never add them to repository or organization-wide secrets:

The preview-only RSA-3072 signing key has already been generated, stored owner-only in the local Authstore, and added as an environment secret; its fingerprint is also set as an environment variable. Keep the key separate from production and sponsor signing material. A confirmation is required immediately before creating Cloudflare credentials in the dashboard because that action creates security-sensitive access; specify the permissions and preview-bucket scope at that time.

   | Type | Name | Value |
   | --- | --- | --- |
   | Secret | `CLOUDFLARE_PREVIEW_DEPLOY_TOKEN` | Dedicated Worker deployment token |
   | Secret | `CLOUDFLARE_PREVIEW_ACCOUNT_ID` | Cloudflare account ID |
   | Secret | `GETPATCHED_PREVIEW_R2_ACCESS_KEY_ID` | Bucket-scoped R2 access key ID |
   | Secret | `GETPATCHED_PREVIEW_R2_SECRET_ACCESS_KEY` | Bucket-scoped R2 secret access key |
   | Secret | `GETPATCHED_PREVIEW_SIGNING_KEY_ARMORED` | Preview-only private signing key |
   | Variable | `GETPATCHED_PREVIEW_R2_ENDPOINT` | `https://<account-id>.r2.cloudflarestorage.com` |
   | Variable | `GETPATCHED_PREVIEW_SIGNING_FINGERPRINT` | Full fingerprint of the preview signing key |

Cloudflare documents that a Worker custom domain requires an active zone and a Worker, and that Wrangler can configure the domain in its routes configuration. R2 S3 credentials can be limited to Object Read & Write for selected buckets. See [Workers Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/), [Workers permissions](https://developers.cloudflare.com/workers/authorization/workers/), and [R2 S3 credentials](https://developers.cloudflare.com/r2/get-started/s3/).

## Run and verify

The `Publish isolated preview APT smoke package` workflow has a `pull_request` build-only path and a manual `workflow_dispatch` path on `main`. The manual path builds a per-run version of the test package, deploys the preview Worker, signs `Release` and `InRelease` with the preview key, uploads artifacts to that attempt's unique bucket prefix, then uploads its `InRelease` last. A clean Ubuntu Focal client checks the key fingerprint and signature, installs the exact package version, runs its command, and retrieves the source package with `apt-get source` from the same run-specific repository URL. The immutable URL is emitted from the run's `GETPATCHED_PREVIEW_REPOSITORY_BASE` value.

Do not use the synthetic smoke package as evidence that the affected libarchive binary is publicly available. Resume matching-package consumer scouting only after the relevant Focal amd64 binary package has been safely published and is accessible.
