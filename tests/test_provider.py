from importlib.metadata import version
import json

import pytest
import responses
from responses import matchers
from octodns.zone import Zone
from octodns.record import Record

from octodns_infomaniak import (
    BASE_API_URL,
    InfomaniakProvider,
    InfomaniakClientBadRequest,
    InfomaniakClientUnauthorized,
    InfomaniakClientForbidden,
    InfomaniakClientNotFound,
)

TOKEN = "token"


def test_http_error():
    zone_name = "example.test."
    provider = InfomaniakProvider("infomaniak", "token")

    # 400
    with responses.RequestsMock() as mock:
        mock.get(f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records", status=400)

        with pytest.raises(InfomaniakClientBadRequest):
            zone = Zone(zone_name, [])
            provider.populate(zone)

    # 401
    with responses.RequestsMock() as mock:
        mock.get(f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records", status=401)

        with pytest.raises(InfomaniakClientUnauthorized):
            zone = Zone(zone_name, [])
            provider.populate(zone)

    # 403
    with responses.RequestsMock() as mock:
        mock.get(f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records", status=403)

        with pytest.raises(InfomaniakClientForbidden):
            zone = Zone(zone_name, [])
            provider.populate(zone)

    # 404
    with responses.RequestsMock() as mock:
        mock.get(f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records", status=404)

        with pytest.raises(InfomaniakClientNotFound):
            zone = Zone(zone_name, [])
            provider.populate(zone)


def test_populate_empty_zone():
    zone_name = "example.test."
    provider = InfomaniakProvider("infomaniak", "token")

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/empty_example.test.json") as f:
            mock.get(
                f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records",
                status=200,
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "User-Agent": f"octodns/{version('octodns')} octodns-infomaniak/{version('octodns-infomaniak')}",
                },
                json=json.loads(f.read()),
            )

        zone = Zone(zone_name, [])
        provider.populate(zone)
        assert 0 == len(zone.records)
        assert set() == zone.records


def test_populate_zone():
    zone_name = "example.test."
    provider = InfomaniakProvider("infomaniak", "token")

    wanted = Zone(zone_name, [])
    wanted.add_record(
        Record.new(
            wanted,
            "",
            {
                "ttl": 3600,
                "type": "NS",
                "value": ["ns1.example2.test.", "ns2.example2.test."],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {"ttl": 3600, "type": "A", "value": ["192.0.2.1", "192.0.2.4"]},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {"ttl": 300, "type": "AAAA", "value": ["2001:db8::3", "2001:db8::7"]},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "",
            {
                "ttl": 3600,
                "type": "CAA",
                "value": [
                    {"flags": 0, "tag": "issue", "value": "sectigo.com"},
                    {"flags": 1, "tag": "issuewild", "value": "letsencrypt.org"},
                    {
                        "flags": 2,
                        "tag": "iodef",
                        "value": "mailto:security@example.test",
                    },
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test2",
            {"ttl": 3600, "type": "CNAME", "value": "test.example.test."},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {
                "ttl": 3600,
                "type": "DS",
                "value": [
                    {
                        "algorithm": 15,
                        "digest": "23711321F987CC6583E92DF0890718C42",
                        "digest_type": 1,
                        "key_tag": 2371,
                    }
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "mail",
            {
                "ttl": 3600,
                "type": "MX",
                "value": [
                    {
                        "priority": 10,
                        "exchange": "mail.example.test.",
                    }
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test6",
            {"ttl": 3600, "type": "NS", "value": ["test.example.test."]},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "_imap._tcp",
            {
                "ttl": 3600,
                "type": "SRV",
                "value": [
                    {
                        "priority": 10,
                        "weight": 0,
                        "port": 8000,
                        "target": "test.example.test.",
                    }
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {
                "ttl": 3600,
                "type": "SSHFP",
                "value": [
                    {
                        "algorithm": 4,
                        "fingerprint_type": 2,
                        "fingerprint": "A9759105BF5A6BDE1555CF2D30E2049B3E63DC81C899DC5C1DEC28CD02A9E88F",
                    }
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "_dmarc",
            {
                "ttl": 3600,
                "type": "TXT",
                "value": [
                    "v=DMARC1\\; p=reject\\; aspf=s\\; adkim=s\\; rua=mailto:security@example.test\\; ruf=mailto:security@example.test\\;"
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {
                "ttl": 3600,
                "type": "TLSA",
                "value": [
                    {
                        "certificate_usage": 0,
                        "selector": 0,
                        "matching_type": 1,
                        "certificate_association_data": "2B8C10F47DE35F59C834305E5DFDB6C549DA57A79DF470728B3A67CAB99256C1",
                    }
                ],
            },
        )
    )

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/get_example.test.json") as f:
            mock.get(
                f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records",
                status=200,
                json=json.loads(f.read()),
            )

        expected = Zone(zone_name, [])
        provider.populate(expected)
        assert 12 == len(expected.records)
        assert expected.records == wanted.records


def test_apply_full_zone():
    zone_name = "example.test."
    provider = InfomaniakProvider("infomaniak", "token")

    expected = Zone(zone_name, [])
    expected.add_record(
        Record.new(
            expected,
            "",
            {
                "ttl": 3600,
                "type": "NS",
                "value": ["ns1.example2.test.", "ns2.example2.test."],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {"ttl": 3600, "type": "A", "value": ["192.0.2.1", "192.0.2.4"]},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {"ttl": 300, "type": "AAAA", "value": ["2001:db8::3", "2001:db8::7"]},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "",
            {
                "ttl": 3600,
                "type": "CAA",
                "value": [
                    {"flags": 0, "tag": "issue", "value": "sectigo.com"},
                    {"flags": 1, "tag": "issuewild", "value": "letsencrypt.org"},
                    {
                        "flags": 2,
                        "tag": "iodef",
                        "value": "mailto:security@example.test",
                    },
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test2",
            {"ttl": 3600, "type": "CNAME", "value": "test.example.test."},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {
                "ttl": 3600,
                "type": "DS",
                "value": [
                    {
                        "algorithm": 15,
                        "digest": "23711321F987CC6583E92DF0890718C42",
                        "digest_type": 1,
                        "key_tag": 2371,
                    }
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "mail",
            {
                "ttl": 3600,
                "type": "MX",
                "value": [
                    {
                        "priority": 10,
                        "exchange": "mail.example.test.",
                    }
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test6",
            {"ttl": 3600, "type": "NS", "value": ["test.example.test."]},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "_imap._tcp",
            {
                "ttl": 3600,
                "type": "SRV",
                "value": [
                    {
                        "priority": 10,
                        "weight": 0,
                        "port": 8000,
                        "target": "test.example.test.",
                    }
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {
                "ttl": 3600,
                "type": "SSHFP",
                "value": [
                    {
                        "algorithm": 4,
                        "fingerprint_type": 2,
                        "fingerprint": "A9759105BF5A6BDE1555CF2D30E2049B3E63DC81C899DC5C1DEC28CD02A9E88F",
                    }
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "_dmarc",
            {
                "ttl": 3600,
                "type": "TXT",
                "value": [
                    "v=DMARC1\\; p=reject\\; aspf=s\\; adkim=s\\; rua=mailto:security@example.test\\; ruf=mailto:security@example.test\\;"
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {
                "ttl": 3600,
                "type": "TLSA",
                "value": [
                    {
                        "certificate_usage": 0,
                        "selector": 0,
                        "matching_type": 1,
                        "certificate_association_data": "2B8C10F47DE35F59C834305E5DFDB6C549DA57A79DF470728B3A67CAB99256C1",
                    }
                ],
            },
        )
    )

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/empty_example.test.json") as f:
            mock.get(
                f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records",
                status=200,
                json=json.loads(f.read()),
            )

        with open("tests/fixtures/post_example.test.json") as f:
            datas = json.loads(f.read())
            for data in datas:
                mock.post(
                    f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records",
                    status=201,
                    match=[matchers.json_params_matcher(data)],
                    json={},
                )

        plan = provider.plan(expected)
        assert 12 == len(plan.changes)
        apply = provider.apply(plan)
        assert 12 == apply
        assert plan.exists


def test_apply_update_zone():
    zone_name = "example2.test."
    provider = InfomaniakProvider("infomaniak", "token")

    expected = Zone(zone_name, [])
    expected.add_record(
        Record.new(
            expected,
            "",
            {
                "ttl": 3600,
                "type": "NS",
                "value": ["ns1.example2.test.", "ns3.example2.test."],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "_imap._tcp",
            {
                "type": "SRV",
                "ttl": 3600,
                "value": {
                    "priority": "10",
                    "weight": "0",
                    "port": "8001",
                    "target": "test.example2.test.",
                },
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {"ttl": 3600, "type": "A", "value": ["192.0.2.1"]},
        )
    )

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/get_example2.test.json") as f:
            mock.get(
                f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records",
                status=200,
                json=json.loads(f.read()),
            )

        with open("tests/fixtures/post_example2.test.json") as f:
            datas = json.loads(f.read())
            for data in datas:
                mock.post(
                    f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records",
                    status=201,
                    match=[matchers.json_params_matcher(data)],
                    json={},
                )

        with open("tests/fixtures/delete_example2.test.json") as f:
            datas = json.loads(f.read())
            for data in datas:
                mock.delete(
                    f"{BASE_API_URL}zones/{zone_name.rstrip('.')}/records/{data}",
                    status=200,
                    json={},
                )

        plan = provider.plan(expected)
        assert 4 == len(plan.changes)
        apply = provider.apply(plan)
        assert 4 == apply
        assert plan.exists
