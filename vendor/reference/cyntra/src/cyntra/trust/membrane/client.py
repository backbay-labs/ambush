"""
HTTP client for membrane service.

Provides methods for:
- Publishing runs (upload + attest)
- Uploading artifacts to IPFS
- Creating attestations
- Verifying attestations
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .config import get_membrane_timeout, get_membrane_url
from .receipt import RunReceipt, generate_receipt

logger = logging.getLogger(__name__)


@dataclass
class PublishResult:
    """Result of publishing a run."""

    cid: str
    attestation_uid: str
    explorer_url: str | None = None
    ipfs_gateway_url: str | None = None


@dataclass
class VerifyResult:
    """Result of verifying an attestation."""

    valid: bool
    receipt: dict | None = None
    attested_at: str | None = None
    attester: str | None = None
    error: str | None = None


class MembraneError(Exception):
    """Error from membrane service."""

    def __init__(self, message: str, code: str | None = None, details: str | None = None):
        super().__init__(message)
        self.code = code
        self.details = details


class MembraneClient:
    """
    HTTP client for membrane service.

    Example:
        client = MembraneClient()

        # Publish a run
        result = client.publish("/path/to/run")
        print(f"CID: {result.cid}")
        print(f"Attestation: {result.attestation_uid}")

        # Verify an attestation
        verify = client.verify(result.attestation_uid)
        if verify.valid:
            print(f"Valid! Attested at {verify.attested_at}")
    """

    def __init__(self, base_url: str | None = None, timeout: float | None = None):
        """
        Initialize membrane client.

        Args:
            base_url: Membrane service URL (default: from env or localhost:7331)
            timeout: Request timeout in seconds (default: from env or 30)
        """
        self.base_url = (base_url or get_membrane_url()).rstrip("/")
        self.timeout = timeout or get_membrane_timeout()
        self._session = None

    def _get_session(self):
        """Get or create HTTP session."""
        if self._session is None:
            try:
                import httpx

                self._session = httpx.Client(timeout=self.timeout)
            except ImportError as err:
                raise ImportError(
                    "httpx is required for membrane client. Install with: pip install httpx"
                ) from err
        return self._session

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make HTTP request to membrane service."""
        session = self._get_session()
        url = f"{self.base_url}{path}"

        try:
            response = session.request(method, url, **kwargs)
        except Exception as e:
            raise MembraneError(
                f"Failed to connect to membrane service at {self.base_url}: {e}",
                code="CONNECTION_FAILED",
            ) from e

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise MembraneError(
                f"Invalid JSON response from membrane: {response.text[:200]}",
                code="INVALID_RESPONSE",
            ) from e

        if not response.is_success:
            raise MembraneError(
                data.get("error", f"Request failed with status {response.status_code}"),
                code=data.get("code"),
                details=str(data.get("details")),
            )

        return data

    def health(self) -> dict:
        """
        Check membrane service health.

        Returns:
            Health status dict with version and uptime
        """
        return self._request("GET", "/")

    def is_running(self) -> bool:
        """Check if membrane service is running."""
        try:
            self.health()
            return True
        except MembraneError:
            return False

    def publish(self, run_dir: str | Path) -> PublishResult:
        """
        Publish a run to IPFS and create attestation.

        This is the main method for publishing completed runs.
        It uploads all artifacts to IPFS and creates an EAS attestation.

        Args:
            run_dir: Path to run directory containing receipt.json

        Returns:
            PublishResult with CID and attestation UID
        """
        run_dir = Path(run_dir).resolve()

        # Ensure receipt.json exists
        receipt_path = run_dir / "receipt.json"
        if not receipt_path.exists():
            # Generate receipt if not present
            logger.info(f"Generating receipt for {run_dir}")
            receipt = generate_receipt(run_dir)
            receipt.save(receipt_path)

        data = self._request("POST", "/publish", json={"runDir": str(run_dir)})

        return PublishResult(
            cid=data["cid"],
            attestation_uid=data["attestationUid"],
            explorer_url=data.get("explorerUrl"),
            ipfs_gateway_url=data.get("ipfsGatewayUrl"),
        )

    def upload(self, artifacts_dir: str | Path) -> tuple[str, str]:
        """
        Upload a directory to IPFS.

        Args:
            artifacts_dir: Path to directory to upload

        Returns:
            Tuple of (cid, gateway_url)
        """
        artifacts_dir = Path(artifacts_dir).resolve()
        data = self._request("POST", "/upload", json={"artifactsDir": str(artifacts_dir)})
        return data["cid"], data.get("gatewayUrl", "")

    def attest(self, receipt: RunReceipt, cid: str) -> tuple[str, str]:
        """
        Create an EAS attestation for a receipt.

        Args:
            receipt: RunReceipt to attest
            cid: IPFS CID of the artifacts

        Returns:
            Tuple of (attestation_uid, signature)
        """
        data = self._request(
            "POST",
            "/attest",
            json={
                "receipt": receipt.to_dict(),
                "cid": cid,
            },
        )
        return data["attestationUid"], data.get("signature", "")

    def verify(self, attestation_uid: str) -> VerifyResult:
        """
        Verify an attestation.

        Args:
            attestation_uid: EAS attestation UID to verify

        Returns:
            VerifyResult with validity and attestation details
        """
        try:
            data = self._request("GET", f"/verify/{attestation_uid}")
            return VerifyResult(
                valid=data.get("valid", False),
                receipt=data.get("receipt"),
                attested_at=data.get("attestedAt"),
                attester=data.get("attester"),
            )
        except MembraneError as e:
            return VerifyResult(valid=False, error=str(e))

    # ==================== ENS Integration ====================

    def resolve_universe(self, ens_name: str, chain: str = "mainnet") -> dict:
        """
        Resolve a universe ENS name.

        Args:
            ens_name: ENS name (e.g., "outora.fab.eth" or "library.outora.fab.eth")
            chain: Network ("mainnet" or "sepolia")

        Returns:
            Resolution with contentHash, ipfsCid, address, resolver
        """
        return self._request("GET", f"/ens/resolve/{ens_name}?chain={chain}")

    def fetch_universe_metadata(self, ens_name: str, chain: str = "mainnet") -> dict:
        """
        Fetch universe metadata from IPFS via ENS.

        Args:
            ens_name: Universe ENS name
            chain: Network ("mainnet" or "sepolia")

        Returns:
            Resolution and metadata dict
        """
        return self._request("GET", f"/ens/universe/{ens_name}?chain={chain}")

    def parse_universe_name(self, name: str) -> dict:
        """
        Parse a universe ENS name into components.

        Args:
            name: Full ENS name

        Returns:
            Parsed components (world, universe, domain, isWorld, etc.)
        """
        return self._request("POST", "/ens/parse", json={"name": name})

    def get_ens_records(self, name: str, keys: list | None = None, chain: str = "mainnet") -> dict:
        """
        Get text records for an ENS name.

        Args:
            name: ENS name
            keys: List of record keys (default: description, url, com.twitter, com.github)
            chain: Network

        Returns:
            Dict of record key -> value
        """
        params = f"chain={chain}"
        if keys:
            params += f"&keys={','.join(keys)}"
        return self._request("GET", f"/ens/records/{name}?{params}")

    # ==================== Tableland Integration ====================

    def get_tableland_status(self) -> dict:
        """
        Get Tableland table configuration status.

        Returns:
            Status with configured bool and tables dict
        """
        return self._request("GET", "/tableland/status")

    def query_runs_by_world(
        self, world_id: str, limit: int = 50, passed_only: bool = False
    ) -> dict:
        """
        Query run records for a world.

        Args:
            world_id: World identifier
            limit: Max results
            passed_only: Only return passing runs

        Returns:
            Dict with runs array and count
        """
        params = f"limit={limit}"
        if passed_only:
            params += "&passed=true"
        return self._request("GET", f"/tableland/runs/world/{world_id}?{params}")

    def query_run_by_attestation(self, attestation_uid: str) -> dict:
        """
        Query a run by its attestation UID.

        Args:
            attestation_uid: EAS attestation UID

        Returns:
            Run record
        """
        return self._request("GET", f"/tableland/runs/attestation/{attestation_uid}")

    def get_latest_frontier(self, world_id: str) -> dict:
        """
        Get the latest Pareto frontier for a world.

        Args:
            world_id: World identifier

        Returns:
            Frontier record with generation and paretoFront
        """
        return self._request("GET", f"/tableland/frontiers/{world_id}")

    def update_frontier(
        self, world_id: str, generation: int, pareto_front: str, updated_at: int
    ) -> dict:
        """
        Update the Pareto frontier for a world.

        Args:
            world_id: World identifier
            generation: Generation number
            pareto_front: JSON-encoded Pareto front data
            updated_at: Timestamp

        Returns:
            Success status
        """
        return self._request(
            "POST",
            "/tableland/frontiers",
            json={
                "worldId": world_id,
                "generation": generation,
                "paretoFront": pareto_front,
                "updatedAt": updated_at,
            },
        )

    def query_patterns(self, min_confidence: float = 0.7, limit: int = 20) -> dict:
        """
        Query high-confidence patterns.

        Args:
            min_confidence: Minimum confidence threshold
            limit: Max results

        Returns:
            Dict with patterns array and count
        """
        return self._request(
            "GET", f"/tableland/patterns?minConfidence={min_confidence}&limit={limit}"
        )

    def index_run(self, run_record: dict) -> dict:
        """
        Index a run in Tableland.

        Args:
            run_record: Run record dict with runId, worldId, commitHash, etc.

        Returns:
            Success status
        """
        return self._request("POST", "/tableland/runs", json=run_record)

    # ==================== Lit Protocol Integration ====================

    def get_lit_status(self) -> dict:
        """
        Check Lit Protocol connection status.

        Returns:
            Status with connected bool and network
        """
        return self._request("GET", "/lit/status")

    def encrypt_with_lit(
        self,
        data: str,
        conditions: list,
        combine_with: str = "or",
        chain: str = "base-sepolia",
    ) -> dict:
        """
        Encrypt data with Lit Protocol access conditions.

        Args:
            data: String data to encrypt
            conditions: List of access condition dicts
            combine_with: How to combine conditions ("and" or "or")
            chain: Chain for conditions

        Returns:
            Encrypted data with ciphertext and hash
        """
        return self._request(
            "POST",
            "/lit/encrypt",
            json={
                "data": data,
                "conditions": conditions,
                "combineWith": combine_with,
                "chain": chain,
            },
        )

    def decrypt_with_lit(self, encrypted_data: dict, auth_sig: dict) -> dict:
        """
        Decrypt data using Lit Protocol.

        Args:
            encrypted_data: Encrypted data from encrypt_with_lit
            auth_sig: Wallet signature for auth

        Returns:
            Decrypted data
        """
        return self._request(
            "POST",
            "/lit/decrypt",
            json={"encryptedData": encrypted_data, "authSig": auth_sig},
        )

    def check_lit_access(
        self,
        conditions: list,
        auth_sig: dict,
        combine_with: str = "or",
        chain: str = "base-sepolia",
    ) -> dict:
        """
        Check if a user meets access conditions.

        Args:
            conditions: Access conditions to check
            auth_sig: Wallet signature for auth
            combine_with: How to combine conditions
            chain: Chain for conditions

        Returns:
            Dict with hasAccess bool
        """
        return self._request(
            "POST",
            "/lit/check-access",
            json={
                "conditions": conditions,
                "authSig": auth_sig,
                "combineWith": combine_with,
                "chain": chain,
            },
        )

    def build_access_conditions(self, conditions: list, combine_with: str = "or") -> dict:
        """
        Build access conditions without encrypting (for preview).

        Args:
            conditions: List of condition dicts
            combine_with: How to combine ("and" or "or")

        Returns:
            Built access control conditions
        """
        return self._request(
            "POST",
            "/lit/conditions/build",
            json={"conditions": conditions, "combineWith": combine_with},
        )

    # ==================== Bacalhau Integration ====================

    def get_bacalhau_status(self, network: str = "testnet") -> dict:
        """
        Check Bacalhau connection status.

        Args:
            network: Network ("mainnet", "testnet", "local")

        Returns:
            Status with connected bool and apiKeyConfigured
        """
        return self._request("GET", f"/bacalhau/status?network={network}")

    def submit_gate_job(
        self,
        asset_cid: str,
        gate_config_cid: str,
        world_id: str,
        gate_name: str | None = None,
        network: str = "testnet",
    ) -> dict:
        """
        Submit a quality gate evaluation job.

        Args:
            asset_cid: IPFS CID of asset to evaluate
            gate_config_cid: IPFS CID of gate config
            world_id: World identifier
            gate_name: Optional gate name
            network: Bacalhau network

        Returns:
            Job submission result with jobId
        """
        payload = {
            "assetCid": asset_cid,
            "gateConfigCid": gate_config_cid,
            "worldId": world_id,
        }
        if gate_name:
            payload["gateName"] = gate_name

        return self._request("POST", f"/bacalhau/jobs/gate?network={network}", json=payload)

    def submit_render_job(
        self,
        blend_file_cid: str,
        camera: str,
        resolution: dict,
        samples: int | None = None,
        frame: int | None = None,
        network: str = "testnet",
    ) -> dict:
        """
        Submit a Blender render job.

        Args:
            blend_file_cid: IPFS CID of .blend file
            camera: Camera name
            resolution: Dict with width and height
            samples: Optional render samples
            frame: Optional frame number
            network: Bacalhau network

        Returns:
            Job submission result with jobId
        """
        payload = {
            "blendFileCid": blend_file_cid,
            "camera": camera,
            "resolution": resolution,
        }
        if samples:
            payload["samples"] = samples
        if frame:
            payload["frame"] = frame

        return self._request("POST", f"/bacalhau/jobs/render?network={network}", json=payload)

    def submit_critic_job(
        self,
        renders_cid: str,
        critic_config_cid: str,
        world_id: str,
        network: str = "testnet",
    ) -> dict:
        """
        Submit a critic evaluation job.

        Args:
            renders_cid: IPFS CID of rendered images
            critic_config_cid: IPFS CID of critic config
            world_id: World identifier
            network: Bacalhau network

        Returns:
            Job submission result with jobId
        """
        return self._request(
            "POST",
            f"/bacalhau/jobs/critic?network={network}",
            json={
                "rendersCid": renders_cid,
                "criticConfigCid": critic_config_cid,
                "worldId": world_id,
            },
        )

    def run_gate_pipeline(
        self,
        asset_cid: str,
        gate_config_cid: str,
        critic_config_cid: str,
        lookdev_cid: str,
        world_id: str,
        network: str = "testnet",
    ) -> dict:
        """
        Run complete gate pipeline (render → critics → gate).

        Args:
            asset_cid: IPFS CID of asset
            gate_config_cid: IPFS CID of gate config
            critic_config_cid: IPFS CID of critic config
            lookdev_cid: IPFS CID of lookdev scene
            world_id: World identifier
            network: Bacalhau network

        Returns:
            Pipeline result with CIDs and passed status
        """
        return self._request(
            "POST",
            f"/bacalhau/pipeline?network={network}",
            json={
                "assetCid": asset_cid,
                "gateConfigCid": gate_config_cid,
                "criticConfigCid": critic_config_cid,
                "lookdevCid": lookdev_cid,
                "worldId": world_id,
            },
        )

    def get_bacalhau_job_status(self, job_id: str, network: str = "testnet") -> dict:
        """
        Get status of a Bacalhau job.

        Args:
            job_id: Job identifier
            network: Bacalhau network

        Returns:
            Job status
        """
        return self._request("GET", f"/bacalhau/jobs/{job_id}?network={network}")

    def get_bacalhau_job_outputs(self, job_id: str, network: str = "testnet") -> dict:
        """
        Get outputs from a completed Bacalhau job.

        Args:
            job_id: Job identifier
            network: Bacalhau network

        Returns:
            Job outputs with IPFS CIDs
        """
        return self._request("GET", f"/bacalhau/jobs/{job_id}/outputs?network={network}")

    def wait_for_bacalhau_job(
        self, job_id: str, timeout: int = 600000, network: str = "testnet"
    ) -> dict:
        """
        Wait for a Bacalhau job to complete.

        Args:
            job_id: Job identifier
            timeout: Timeout in milliseconds
            network: Bacalhau network

        Returns:
            Final job status
        """
        return self._request(
            "POST",
            f"/bacalhau/jobs/{job_id}/wait?network={network}&timeout={timeout}",
        )

    def cancel_bacalhau_job(self, job_id: str, network: str = "testnet") -> dict:
        """
        Cancel a running Bacalhau job.

        Args:
            job_id: Job identifier
            network: Bacalhau network

        Returns:
            Cancellation result
        """
        return self._request("DELETE", f"/bacalhau/jobs/{job_id}?network={network}")

    def close(self):
        """Close HTTP session."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
