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
                "/api/v1/outlets/actions",
                "/api/v1/outlets/{outletId}",
                "/api/v1/outlets/{outletId}/actions",
                "/api/v1/pdus",
                "/api/v1/pdus/{pduId}/actions",
                "/api/v1/tokens",
                "/api/v1/tokens/{tokenId}",
                "/api/v1/tokens/{tokenId}/disable",
                "/api/v1/tokens/{tokenId}/enable",
                "/api/v1/session",
                "/api/v1/session/password",
                "/api/v1/settings/security/dsview",
                "/api/v1/settings/authentication/nis",
                "/api/v1/settings/help-language",
                "/api/v1/settings/data-buffering",
                "/api/v1/settings/appliance-logging",
                "/api/v1/settings/time-zone",
                "/api/v1/system/information",
                "/api/v1/system/usage/memory",
                "/api/v1/system/usage/flash",
                "/api/v1/monitoring/network/devices",
                "/api/v1/monitoring/network/routes/ipv4",
                "/api/v1/monitoring/network/routes/ipv6",
                "/api/v1/monitoring/serial-ports",
            },
            set(paths),
        )
        self.assertEqual({"get"}, set(paths["/api/v1/health"]))
        self.assertEqual({"get"}, set(paths["/api/v1/outlets"]))
        self.assertEqual({"post"}, set(paths["/api/v1/outlets/actions"]))
        self.assertEqual({"get", "parameters"}, set(paths["/api/v1/outlets/{outletId}"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/outlets/{outletId}/actions"]))
        self.assertEqual({"get"}, set(paths["/api/v1/pdus"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/pdus/{pduId}/actions"]))
        self.assertEqual({"get", "post"}, set(paths["/api/v1/tokens"]))
        self.assertEqual({"delete", "parameters"}, set(paths["/api/v1/tokens/{tokenId}"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/tokens/{tokenId}/disable"]))
        self.assertEqual({"post", "parameters"}, set(paths["/api/v1/tokens/{tokenId}/enable"]))
        self.assertEqual({"post", "get", "delete"}, set(paths["/api/v1/session"]))
        self.assertEqual({"post"}, set(paths["/api/v1/session/password"]))
        self.assertEqual({"get", "put"}, set(paths["/api/v1/settings/security/dsview"]))
        self.assertEqual({"get", "put"}, set(paths["/api/v1/settings/authentication/nis"]))
        self.assertEqual({"get", "put"}, set(paths["/api/v1/settings/help-language"]))
        self.assertEqual({"get", "put"}, set(paths["/api/v1/settings/data-buffering"]))
        self.assertEqual({"get", "put"}, set(paths["/api/v1/settings/appliance-logging"]))
        self.assertEqual({"get", "put"}, set(paths["/api/v1/settings/time-zone"]))
        for route in (
            "/api/v1/system/information",
            "/api/v1/system/usage/memory",
            "/api/v1/system/usage/flash",
            "/api/v1/monitoring/network/devices",
            "/api/v1/monitoring/network/routes/ipv4",
            "/api/v1/monitoring/network/routes/ipv6",
            "/api/v1/monitoring/serial-ports",
        ):
            with self.subTest(route=route):
                self.assertEqual({"get"}, set(paths[route]))

    def test_all_operation_security_requirements_reference_defined_schemes(self) -> None:
        schemes = set(self.contract["components"]["securitySchemes"])
        for path, item in self.contract["paths"].items():
            for method, operation in item.items():
                if method == "parameters":
                    continue
                for requirement in operation.get("security", []):
                    with self.subTest(path=path, method=method):
                        self.assertLessEqual(set(requirement), schemes)

    def test_dsview_setting_is_a_closed_session_only_boolean_resource(self) -> None:
        route = self.contract["paths"]["/api/v1/settings/security/dsview"]
        self.assertEqual([{"cookieAuth": []}], route["get"]["security"])
        self.assertEqual([{"cookieAuth": []}], route["put"]["security"])
        self.assertIn("502", route["get"]["responses"])
        self.assertEqual(
            "#/components/responses/BackendProtocolError",
            route["get"]["responses"]["502"]["$ref"],
        )
        nis_get = self.contract["paths"]["/api/v1/settings/authentication/nis"]["get"]
        self.assertEqual(
            "#/components/responses/BackendProtocolError",
            nis_get["responses"]["502"]["$ref"],
        )
        schema = self.contract["components"]["schemas"]["DsviewSecuritySetting"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(["allowDSView"], schema["required"])
        self.assertEqual("boolean", schema["properties"]["allowDSView"]["type"])
        self.assertEqual(
            {"204", "400", "401", "403", "405", "413", "415", "503"},
            set(route["put"]["responses"]),
        )

    def test_revisioned_settings_are_closed_cookie_only_full_replacements(self) -> None:
        paths = self.contract["paths"]
        schemas = self.contract["components"]["schemas"]
        cases = {
            "/api/v1/settings/help-language": (
                "units.applianceSettings.help",
                "configuration.appliance.language:w",
                "HelpLanguageSetting",
                "HelpLanguageReplacement",
                {"applianceLanguage", "url", "allowedLanguages", "revision"},
                {"applianceLanguage", "url"},
            ),
            "/api/v1/settings/data-buffering": (
                "units.event_notification.global_settings_databuffering",
                "configuration.event-notify:w",
                "DataBufferingSetting",
                "DataBufferingReplacement",
                {"localSize", "localSegments", "nfsServer", "nfsPath", "nfsSize", "nfsSegments", "syslogFacility", "revision"},
                {"localSize", "localSegments", "nfsServer", "nfsPath", "nfsSize", "nfsSegments", "syslogFacility"},
            ),
        }
        for path, (nav_path, capability, read_schema, write_schema, read_fields, write_fields) in cases.items():
            with self.subTest(path=path):
                route = paths[path]
                for operation in route.values():
                    self.assertEqual([{"cookieAuth": []}], operation["security"])
                    self.assertTrue(operation["x-bearer-rejected"])
                    self.assertEqual(nav_path, operation["x-required-nav-path"])
                    self.assertEqual(capability, operation["x-required-write-capability"])
                get = route["get"]
                put = route["put"]
                self.assertEqual(
                    f"#/components/schemas/{read_schema}",
                    get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                )
                self.assertEqual(
                    "#/components/headers/StrongETag",
                    get["responses"]["200"]["headers"]["ETag"]["$ref"],
                )
                self.assertEqual(
                    f"#/components/schemas/{write_schema}",
                    put["requestBody"]["content"]["application/json"]["schema"]["$ref"],
                )
                if_match = next(item for item in put["parameters"] if item["name"] == "If-Match")
                self.assertTrue(if_match["required"])
                self.assertEqual("header", if_match["in"])
                self.assertEqual("#/components/schemas/StrongRevision", if_match["schema"]["$ref"])
                self.assertTrue(put["x-csrf-required"])
                self.assertTrue(put["x-full-replacement"])
                self.assertEqual("exact-read-back-of-all-submitted-fields", put["x-success-confirmation"])
                self.assertEqual(
                    "#/components/responses/SettingWriteUnconfirmed",
                    put["responses"]["503"]["$ref"],
                )
                self.assertEqual(
                    {"204", "400", "401", "403", "405", "412", "413", "415", "428", "502", "503"},
                    set(put["responses"]),
                )
                for name, fields in ((read_schema, read_fields), (write_schema, write_fields)):
                    schema = schemas[name]
                    self.assertFalse(schema["additionalProperties"])
                    self.assertEqual(fields, set(schema["required"]))
                    self.assertEqual(fields, set(schema["properties"]))

        self.assertEqual(
            ["LOG_LOCAL0", "LOG_LOCAL1", "LOG_LOCAL2", "LOG_LOCAL3", "LOG_LOCAL4", "LOG_LOCAL5"],
            schemas["SyslogFacility"]["enum"],
        )
        self.assertEqual('^"[0-9a-f]{64}"$', schemas["StrongRevision"]["pattern"])
        xml_text_pattern = "^[^\\u0000-\\u001F\\uFFFE\\uFFFF]*$"
        help_text_pattern = "^[^\\u0000-\\u0020\\u007F\\uFFFE\\uFFFF]+$"
        for schema_name in ("HelpLanguageReplacement", "HelpLanguageSetting"):
            self.assertEqual(help_text_pattern, schemas[schema_name]["properties"]["url"]["pattern"])
            self.assertEqual(xml_text_pattern, schemas[schema_name]["properties"]["applianceLanguage"].get("pattern"))
        self.assertEqual(
            xml_text_pattern,
            schemas["HelpLanguageSetting"]["properties"]["allowedLanguages"]["items"]["pattern"],
        )
        for schema_name in ("DataBufferingReplacement", "DataBufferingSetting"):
            self.assertEqual(xml_text_pattern, schemas[schema_name]["properties"]["nfsPath"]["pattern"])
        for field in ("oldPassword", "newPassword", "confirmation"):
            self.assertEqual("^[ -~]+$", schemas["PasswordChangeRequest"]["properties"][field]["pattern"])

    def test_appliance_logging_is_a_closed_conditional_revisioned_setting(self) -> None:
        route = self.contract["paths"]["/api/v1/settings/appliance-logging"]
        schemas = self.contract["components"]["schemas"]
        for operation in route.values():
            self.assertEqual([{"cookieAuth": []}], operation["security"])
            self.assertTrue(operation["x-bearer-rejected"])
            self.assertEqual("units.event_notification.sessions", operation["x-required-nav-path"])
            self.assertEqual("configuration.event-notify:w", operation["x-required-write-capability"])
        put = route["put"]
        self.assertFalse(put["x-full-replacement"])
        self.assertTrue(put["x-csrf-required"])
        self.assertEqual(
            "exact-read-back-of-active-writes-and-preserved-inactive-fields",
            put["x-success-confirmation"],
        )
        self.assertEqual(
            "#/components/schemas/ApplianceLoggingReplacement",
            put["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        )
        setting = schemas["ApplianceLoggingSetting"]
        self.assertFalse(setting["additionalProperties"])
        self.assertEqual(
            {"sessionLoggingEnabled", "destination", "timestampEnabled", "alertsEnabled", "alertStrings", "allowedDestinations", "revision"},
            set(setting["required"]),
        )
        self.assertEqual(["local", "nfs", "syslog", "dsview"], setting["properties"]["destination"]["enum"])
        alerts = setting["properties"]["alertStrings"]
        self.assertEqual((10, 10), (alerts["minItems"], alerts["maxItems"]))
        self.assertEqual(64, alerts["items"]["x-max-utf8-bytes"])
        variants = schemas["ApplianceLoggingReplacement"]["oneOf"]
        self.assertEqual(3, len(variants))
        for variant, required, enabled, alerts_enabled in (
            (variants[0], {"sessionLoggingEnabled"}, False, None),
            (variants[1], {"sessionLoggingEnabled", "destination", "timestampEnabled", "alertsEnabled"}, True, False),
            (variants[2], {"sessionLoggingEnabled", "destination", "timestampEnabled", "alertsEnabled", "alertStrings"}, True, True),
        ):
            self.assertFalse(variant["additionalProperties"])
            self.assertEqual(required, set(variant["required"]))
            self.assertEqual(required, set(variant["properties"]))
            self.assertIs(enabled, variant["properties"]["sessionLoggingEnabled"]["const"])
            if alerts_enabled is not None:
                self.assertIs(alerts_enabled, variant["properties"]["alertsEnabled"]["const"])

    def test_time_zone_is_closed_conditional_and_runtime_choice_bounded(self) -> None:
        route = self.contract["paths"]["/api/v1/settings/time-zone"]
        schemas = self.contract["components"]["schemas"]
        for operation in route.values():
            self.assertEqual([{"cookieAuth": []}], operation["security"])
            self.assertTrue(operation["x-bearer-rejected"])
            self.assertEqual("units.applianceSettings.date_and_time.time_zone", operation["x-required-nav-path"])
            self.assertEqual("management.date:w", operation["x-required-write-capability"])
        self.assertFalse(route["put"]["x-full-replacement"])
        self.assertEqual(
            "#/components/schemas/TimeZoneReplacement",
            route["put"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        )
        setting = schemas["TimeZoneSetting"]
        self.assertFalse(setting["additionalProperties"])
        self.assertEqual({"mode", "predefined", "custom", "revision"}, set(setting["required"]))
        choices = setting["properties"]["predefined"]["properties"]["choices"]
        self.assertEqual((1, 521), (choices["minItems"], choices["maxItems"]))
        self.assertTrue(choices["uniqueItems"])
        variants = schemas["TimeZoneReplacement"]["oneOf"]
        self.assertEqual(3, len(variants))
        self.assertEqual(
            {
                "#/components/schemas/TimeZonePredefinedReplacement",
                "#/components/schemas/TimeZoneCustomNoDstReplacement",
                "#/components/schemas/TimeZoneCustomDstReplacement",
            },
            {variant["$ref"] for variant in variants},
        )
        for name in ("TimeZonePredefinedReplacement", "TimeZoneCustomNoDstReplacement", "TimeZoneCustomDstReplacement"):
            self.assertFalse(schemas[name]["additionalProperties"])
        self.assertIn("not-runtime-filesystem-effects", route["put"]["x-success-confirmation"])

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
                self.assertEqual([{"bearerAuth": []}, {"cookieAuth": []}], operation["security"])
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

    def test_power_action_contracts_are_closed_and_dispatched_through_fixed_templates(self) -> None:
        operation = self.contract["paths"]["/api/v1/outlets/{outletId}/actions"]["post"]
        self.assertEqual(1024, operation["x-max-body-bytes"])
        self.assertEqual(
            "path=units.topology;table=topologyTable;actions=on:targPowerOn,off:targPowerOff,cycle:targCycle;target=fresh-server-resolved-array-id",
            operation["x-backend-template"],
        )
        self.assertEqual("firmware-derived-fixed-dispatch", operation["x-action-contract-status"])
        self.assertEqual(
            {"204", "400", "401", "403", "404", "409", "413", "415", "503"},
            set(operation["responses"]),
        )

        pdu = self.contract["paths"]["/api/v1/pdus/{pduId}/actions"]["post"]
        self.assertEqual(
            "path=units.powermanagement.pdu_management;table=pdu_devices_table;actions=on,off,cycle;target=fresh-server-resolved-array-id",
            pdu["x-backend-template"],
        )
        self.assertEqual("firmware-derived-fixed-dispatch", pdu["x-action-contract-status"])
        self.assertTrue(pdu["x-csrf-required-for-cookie-auth"])
        self.assertEqual("#/components/schemas/PduActionRequest",
                         pdu["requestBody"]["content"]["application/json"]["schema"]["$ref"])
        self.assertEqual("#/components/responses/ActionUnavailable",
                         pdu["responses"]["503"]["$ref"])

        schema = self.contract["components"]["schemas"]["OutletActionRequest"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(["action"], schema["required"])
        self.assertEqual(["on", "off", "cycle"], schema["properties"]["action"]["enum"])
        self.assertEqual(2, schema["maxProperties"])
        pdu_schema = self.contract["components"]["schemas"]["PduActionRequest"]
        self.assertEqual(["action", "inventoryRevision"], pdu_schema["required"])
        self.assertEqual(2, pdu_schema["minProperties"])

        selector_operation = self.contract["paths"]["/api/v1/outlets/actions"]["post"]
        self.assertEqual("control", selector_operation["x-required-scope"])
        self.assertEqual("resolve-selector-then-require-id-membership",
                         selector_operation["x-outlet-allowlist-behavior"])
        self.assertEqual("#/components/responses/OutletSelectorConflict",
                         selector_operation["responses"]["409"]["$ref"])
        self.assertEqual("#/components/responses/ActionUnavailable",
                         selector_operation["responses"]["503"]["$ref"])
        selector = self.contract["components"]["schemas"]["OutletSelectorActionRequest"]
        self.assertFalse(selector["additionalProperties"])
        self.assertEqual(["outlet", "action"], selector["required"])
        self.assertEqual(3, selector["maxProperties"])
        self.assertIn("inventoryRevision", selector["properties"])

    def test_objects_and_errors_reject_unknown_fields(self) -> None:
        schemas = self.contract["components"]["schemas"]
        for name in (
            "Health",
            "Outlet",
            "OutletCollection",
            "OutletActionRequest",
            "OutletSelectorActionRequest",
            "PduActionRequest",
            "Pdu",
            "PduCollection",
            "PasswordChangeRequest",
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
                "csrf_rejected",
                "precondition_required",
                "revision_changed",
                "not_found",
                "method_not_allowed",
                "not_acceptable",
                "unsupported_media_type",
                "payload_too_large",
                "inventory_changed",
                "outlet_name_ambiguous",
                "backend_unavailable",
                "backend_protocol_error",
                "action_outcome_unknown",
                "session_store_unavailable",
                "logout_incomplete",
                "internal_error",
                "last_administrator",
                "token_limit_reached",
                "token_store_unavailable",
            ],
            schemas["ErrorCode"]["enum"],
        )

    def test_api_supports_external_bearer_and_separate_web_sessions(self) -> None:
        self.assertEqual([], self.contract["paths"]["/api/v1/health"]["get"]["security"])
        for path, method in (
            ("/api/v1/outlets", "get"),
            ("/api/v1/outlets/actions", "post"),
            ("/api/v1/outlets/{outletId}", "get"),
            ("/api/v1/outlets/{outletId}/actions", "post"),
            ("/api/v1/pdus", "get"),
            ("/api/v1/pdus/{pduId}/actions", "post"),
            ("/api/v1/tokens", "get"),
            ("/api/v1/tokens", "post"),
            ("/api/v1/tokens/{tokenId}", "delete"),
            ("/api/v1/tokens/{tokenId}/disable", "post"),
            ("/api/v1/tokens/{tokenId}/enable", "post"),
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    [{"bearerAuth": []}, {"cookieAuth": []}],
                    self.contract["paths"][path][method]["security"],
                )
        session = self.contract["paths"]["/api/v1/session"]
        self.assertEqual([], session["post"]["security"])
        self.assertEqual([{"cookieAuth": []}], session["get"]["security"])
        self.assertEqual([{"cookieAuth": []}], session["delete"]["security"])
        password_operation = self.contract["paths"]["/api/v1/session/password"]["post"]
        self.assertEqual([{"cookieAuth": []}], password_operation["security"])
        self.assertEqual(2048, password_operation["x-max-body-bytes"])

        def response_code(operation, status: str) -> str:
            response_ref = operation["responses"][status]["$ref"].split("/")[-1]
            response = self.contract["components"]["responses"][response_ref]
            schema_ref = response["content"]["application/json"]["schema"]["$ref"].split("/")[-1]
            schema = self.contract["components"]["schemas"][schema_ref]
            return schema["properties"]["code"]["const"]

        self.assertEqual({"201", "400", "401", "413", "415", "503"}, set(session["post"]["responses"]))
        self.assertEqual(1024, session["post"]["x-max-body-bytes"])
        self.assertEqual(
            "#/components/schemas/SessionCreateRequest",
            session["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        )
        for operation, status in ((session["post"], "201"), (session["get"], "200")):
            response_ref = operation["responses"][status]["$ref"].split("/")[-1]
            response = self.contract["components"]["responses"][response_ref]
            self.assertEqual(
                "#/components/schemas/Session",
                response["content"]["application/json"]["schema"]["$ref"],
            )
            self.assertIn("Set-Cookie", response["headers"])
            self.assertEqual(
                "#/components/headers/ActiveSessionCookie",
                response["headers"]["Set-Cookie"]["$ref"],
            )

        self.assertEqual("bad_request", response_code(session["post"], "400"))
        self.assertEqual("unauthorized", response_code(session["post"], "401"))
        self.assertEqual("payload_too_large", response_code(session["post"], "413"))
        self.assertEqual("unsupported_media_type", response_code(session["post"], "415"))
        self.assertEqual("session_store_unavailable", response_code(session["post"], "503"))
        self.assertEqual({"204", "401", "403", "503"}, set(session["delete"]["responses"]))
        self.assertEqual("unauthorized", response_code(session["get"], "401"))
        self.assertEqual("unauthorized", response_code(session["delete"], "401"))
        self.assertEqual("csrf_rejected", response_code(session["delete"], "403"))
        self.assertEqual("logout_incomplete", response_code(session["delete"], "503"))
        for status in ("204", "503"):
            response_ref = session["delete"]["responses"][status]["$ref"].split("/")[-1]
            response = self.contract["components"]["responses"][response_ref]
            self.assertIn("Set-Cookie", response["headers"])
            self.assertEqual(
                "#/components/headers/ExpiredSessionCookie",
                response["headers"]["Set-Cookie"]["$ref"],
            )
        headers = self.contract["components"]["headers"]
        self.assertEqual(
            r"^pm3000_session=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900$",
            headers["ActiveSessionCookie"]["schema"]["pattern"],
        )
        self.assertEqual(
            r"^pm3000_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0$",
            headers["ExpiredSessionCookie"]["schema"]["pattern"],
        )
        logout_ref = session["delete"]["responses"]["503"]["$ref"].split("/")[-1]
        logout_description = self.contract["components"]["responses"][logout_ref]["description"]
        self.assertIn("omitted when local deletion fails", logout_description)
        self.assertIn("expired when local deletion succeeds", logout_description)

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

    def test_session_only_read_routes_reject_bearer_and_have_closed_schemas(self) -> None:
        paths = self.contract["paths"]
        schemas = self.contract["components"]["schemas"]
        routes = {
            "/api/v1/system/information": ("getSystemInformation", "units.applianceSettings.information", "SystemInformation"),
            "/api/v1/system/usage/memory": ("getMemoryUsage", "units.applianceSettings.usage.memory", "MemoryUsage"),
            "/api/v1/system/usage/flash": ("getFlashUsage", "units.applianceSettings.usage.flashUsage", "FlashUsage"),
            "/api/v1/monitoring/network/devices": ("getNetworkDevices", "units.monitoring.networkmon.monitoringDevice", "NetworkDevices"),
            "/api/v1/monitoring/network/routes/ipv4": ("getIpv4Routes", "units.monitoring.networkmon.monitoringIpv4RouteTable", "Ipv4Routes"),
            "/api/v1/monitoring/network/routes/ipv6": ("getIpv6Routes", "units.monitoring.networkmon.monitoringIpv6RouteTable", "Ipv6Routes"),
            "/api/v1/monitoring/serial-ports": ("getSerialPorts", "units.monitoring.serialstatistics", "SerialPorts"),
        }
        for path, (op_id, nav_path, schema_name) in routes.items():
            with self.subTest(route=path):
                operation = paths[path]["get"]
                self.assertEqual(op_id, operation["operationId"])
                self.assertTrue(operation["x-bearer-rejected"])
                self.assertEqual([{"cookieAuth": []}], operation["security"])
                self.assertEqual(nav_path, operation["x-required-nav-path"])
                self.assertIn("401", operation["responses"])
                self.assertIn("403", operation["responses"])
                self.assertIn("502", operation["responses"])
                self.assertIn("503", operation["responses"])
                self.assertEqual(
                    f"#/components/schemas/{schema_name}",
                    operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                )
                self.assertIn(schema_name, schemas)
                self.assertFalse(schemas[schema_name]["additionalProperties"])

        collection_properties = {
            "MemoryUsage": "rows",
            "FlashUsage": "rows",
            "NetworkDevices": "devices",
            "Ipv4Routes": "routes",
            "Ipv6Routes": "routes",
            "SerialPorts": "ports",
        }
        for schema_name, property_name in collection_properties.items():
            with self.subTest(collection=schema_name):
                self.assertEqual(
                    25,
                    schemas[schema_name]["properties"][property_name]["maxItems"],
                )

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
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

        self.assertIsNone(re.search(r'"additionalProperties"\s*:\s*true', serialized))


if __name__ == "__main__":
    unittest.main()
