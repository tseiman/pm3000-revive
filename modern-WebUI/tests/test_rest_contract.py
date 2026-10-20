#!/usr/bin/env python3
"""Contract gates for the deliberately narrow PM3000 REST API v1."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "api" / "openapi-v1.json"


class RestV1ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text())

    def test_exposes_only_the_approved_routes_and_methods(self) -> None:
        paths = self.contract["paths"]
        self.assertEqual(
            {
                "/api/v1/health",
                "/api/v1/outlets",
                "/api/v1/outlets/{outletId}",
                "/api/v1/outlets/{outletId}/actions",
                "/api/v1/tokens",
                "/api/v1/tokens/{tokenId}",
                "/api/v1/tokens/{tokenId}/disable",
                "/api/v1/tokens/{tokenId}/enable",
            },
            set(paths),
        )
        self.assertEqual({"get"}, set(paths["/api/v1/health"]))
        self.assertEqual({"get"}, set(paths["/api/v1/outlets"]))
        self.assertEqual({"get", "parameters"}, set(paths["/api/v1/outlets/{outletId}"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/outlets/{outletId}/actions"]))
        self.assertEqual({"get", "post"}, set(paths["/api/v1/tokens"]))
        self.assertEqual({"delete", "parameters"}, set(paths["/api/v1/tokens/{tokenId}"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/tokens/{tokenId}/disable"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/tokens/{tokenId}/enable"]))

    def test_token_administration_is_closed_admin_only_and_never_reaches_avtrans(self) -> None:
        paths = self.contract["paths"]
        operations = [
            paths["/api/v1/tokens"]["get"],
            paths["/api/v1/tokens"]["post"],
            paths["/api/v1/tokens/{tokenId}"]["delete"],
            paths["/api/v1/tokens/{tokenId}/disable"]["post"],
            paths["/api/v1/tokens/{tokenId}/enable"]["post"],
        ]
        for operation in operations:
            with self.subTest(operation=operation["operationId"]):
                self.assertEqual([{"bearerAuth": []}], operation["security"])
                self.assertEqual("admin", operation["x-required-scope"])
                self.assertEqual(
                    "token-store-only-no-backend-request",
                    operation["x-stage3-behavior"],
                )
                self.assertNotIn("x-backend-template", operation)

        schemas = self.contract["components"]["schemas"]
        create = schemas["TokenCreateRequest"]
        self.assertFalse(create["additionalProperties"])
        self.assertEqual(["label", "scope"], create["required"])
        self.assertEqual(["read", "control", "admin"], schemas["TokenScope"]["enum"])
        self.assertTrue(create["properties"]["outlets"]["uniqueItems"])
        self.assertEqual(256, create["properties"]["outlets"]["maxItems"])

        metadata = schemas["TokenMetadata"]
        self.assertFalse(metadata["additionalProperties"])
        self.assertNotIn("digest", metadata["properties"])
        self.assertNotIn("token", metadata["properties"])
        self.assertIn("token", schemas["TokenCreated"]["properties"])
        issued_token = schemas["TokenCreated"]["properties"]["token"]
        self.assertTrue(issued_token["readOnly"])
        self.assertNotIn("writeOnly", issued_token)

        create_operation = paths["/api/v1/tokens"]["post"]
        self.assertEqual(
            "#/components/schemas/TokenCreateRequest",
            create_operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        )
        self.assertEqual(
            "#/components/responses/TokenCreated",
            create_operation["responses"]["201"]["$ref"],
        )
        self.assertEqual(
            "#/components/schemas/TokenCreated",
            self.contract["components"]["responses"]["TokenCreated"]["content"]["application/json"]["schema"]["$ref"],
        )
        self.assertNotIn("/api/v1/tokens/bootstrap", paths)

    def test_uses_opaque_outlet_ids_and_fixed_read_templates(self) -> None:
        schemas = self.contract["components"]["schemas"]
        outlet_id = schemas["OutletId"]
        self.assertEqual("string", outlet_id["type"])
        self.assertEqual(22, outlet_id["minLength"])
        self.assertEqual(22, outlet_id["maxLength"])
        self.assertEqual("^[A-Za-z0-9_-]{22}$", outlet_id["pattern"])

        operations = {
            self.contract["paths"]["/api/v1/outlets"]["get"]["x-backend-template"],
            self.contract["paths"]["/api/v1/outlets/{outletId}"]["get"]["x-backend-template"],
        }
        self.assertEqual(
            {
                "action=get;path=units.topology;projection=outlet-list",
                "action=get;path=units.topology;projection=outlet-detail",
            },
            operations,
        )
        collection = self.contract["paths"]["/api/v1/outlets"]["get"]
        detail = self.contract["paths"]["/api/v1/outlets/{outletId}"]["get"]
        action = self.contract["paths"]["/api/v1/outlets/{outletId}/actions"]["post"]
        self.assertEqual("read", collection["x-required-scope"])
        self.assertEqual("filter-collection", collection["x-outlet-allowlist-behavior"])
        self.assertEqual("read", detail["x-required-scope"])
        self.assertEqual("require-membership", detail["x-outlet-allowlist-behavior"])
        self.assertEqual("control", action["x-required-scope"])
        self.assertEqual("require-membership", action["x-outlet-allowlist-behavior"])

    def test_opaque_identifiers_are_domain_separated_and_have_fixed_vectors(self) -> None:
        schemas = self.contract["components"]["schemas"]
        self.assertEqual(
            "#/components/schemas/PduId",
            schemas["Outlet"]["properties"]["pduId"]["$ref"],
        )
        self.assertEqual(schemas["OutletId"]["pattern"], schemas["PduId"]["pattern"])

        derivation = self.contract["x-identifier-derivation"]
        self.assertEqual("sha256-base64url-prefix", derivation["algorithm"])
        self.assertEqual(22, derivation["outputCharacters"])
        self.assertEqual("unsigned-big-endian-32-bit-length", derivation["inventoryLengthEncoding"])
        self.assertEqual(
            {
                "outlet": "706d333030302d726573742d7631006f75746c657400",
                "pdu": "706d333030302d726573742d76310070647500",
                "inventory": "706d333030302d726573742d763100696e76656e746f727900",
            },
            derivation["domainPrefixHex"],
        )
        self.assertEqual(
            {
                "outlet:SYNTHETIC_OUTLET_1": "XDmSGmQaZ6o7iRBWKUnpVg",
                "pdu:SYNTHETIC_PDU_1": "niRcjzKfdPHmzgYMv2BzfB",
                "inventory:SYNTHETIC_OUTLET_1,SYNTHETIC_OUTLET_2": "3Nsqnx4t6hGoJs5d-ahRdd",
            },
            derivation["testVectors"],
        )

    def test_action_shape_is_closed_and_stage2_never_dispatches_it(self) -> None:
        operation = self.contract["paths"]["/api/v1/outlets/{outletId}/actions"]["post"]
        self.assertEqual("reject-without-backend-request", operation["x-stage2-behavior"])
        self.assertEqual(1024, operation["x-max-body-bytes"])
        self.assertNotIn("x-backend-template", operation)
        self.assertEqual(
            {"400", "401", "403", "404", "409", "413", "415", "503"},
            set(operation["responses"]),
        )
        self.assertFalse(any(status.startswith("2") for status in operation["responses"]))

        schema = self.contract["components"]["schemas"]["OutletActionRequest"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(["action", "inventoryRevision"], schema["required"])
        self.assertEqual(["on", "off", "cycle"], schema["properties"]["action"]["enum"])
        self.assertEqual(2, schema["maxProperties"])

    def test_objects_and_errors_reject_unknown_fields(self) -> None:
        schemas = self.contract["components"]["schemas"]
        for name in (
            "Health",
            "Outlet",
            "OutletCollection",
            "OutletActionRequest",
            "TokenCreateRequest",
            "TokenMetadata",
            "TokenCreated",
            "TokenCollection",
            "ApiError",
        ):
            with self.subTest(schema=name):
                self.assertEqual("object", schemas[name]["type"])
                self.assertFalse(schemas[name]["additionalProperties"])

        self.assertEqual(["on", "off", "unknown"], schemas["OutletState"]["enum"])
        self.assertEqual(
            [
                "bad_request",
                "unauthorized",
                "forbidden",
                "not_found",
                "method_not_allowed",
                "not_acceptable",
                "unsupported_media_type",
                "payload_too_large",
                "inventory_stale",
                "backend_unavailable",
                "backend_protocol_error",
                "action_disabled",
                "action_outcome_unknown",
                "internal_error",
                "last_administrator",
                "token_limit_reached",
                "token_store_unavailable",
            ],
            schemas["ErrorCode"]["enum"],
        )

    def test_non_health_routes_require_bearer_authentication(self) -> None:
        self.assertEqual([], self.contract["paths"]["/api/v1/health"]["get"]["security"])
        for path, method in (
            ("/api/v1/outlets", "get"),
            ("/api/v1/outlets/{outletId}", "get"),
            ("/api/v1/outlets/{outletId}/actions", "post"),
            ("/api/v1/tokens", "get"),
            ("/api/v1/tokens", "post"),
            ("/api/v1/tokens/{tokenId}", "delete"),
            ("/api/v1/tokens/{tokenId}/disable", "post"),
            ("/api/v1/tokens/{tokenId}/enable", "post"),
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    [{"bearerAuth": []}],
                    self.contract["paths"][path][method]["security"],
                )

    def test_every_response_disables_caching_and_content_sniffing(self) -> None:
        responses = list(self.contract["components"]["responses"].items())
        for path_item in self.contract["paths"].values():
            for method, operation in path_item.items():
                if method == "parameters":
                    continue
                for status, response in operation["responses"].items():
                    if "$ref" not in response:
                        responses.append((f"{operation['operationId']}:{status}", response))

        def resolve_header(header):
            reference = header.get("$ref")
            if reference is None:
                return header
            prefix = "#/components/headers/"
            self.assertTrue(str(reference).startswith(prefix))
            return self.contract["components"]["headers"][str(reference)[len(prefix):]]

        for name, response in responses:
            with self.subTest(response=name):
                headers = response["headers"]
                cache_control = resolve_header(headers["Cache-Control"])
                content_options = resolve_header(headers["X-Content-Type-Options"])
                self.assertEqual("no-store", cache_control["schema"]["const"])
                self.assertEqual("nosniff", content_options["schema"]["const"])

    def test_contract_has_no_generic_backend_or_dangerous_operations(self) -> None:
        serialized = json.dumps(self.contract, sort_keys=True).lower()
        for forbidden in (
            "backendpath",
            "rawxml",
            "factorydef",
            "factory default",
            "firmware upgrade",
            "rebootpdu",
            "reset hardware",
            "/pdus/{",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

        self.assertIsNone(re.search(r'"additionalProperties"\s*:\s*true', serialized))


if __name__ == "__main__":
    unittest.main()
