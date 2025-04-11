from typing import Any, Iterator
from importlib.metadata import version
import logging
from collections import defaultdict

from requests import Session
from octodns.zone import Zone
from octodns.record import Record
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider


BASE_API_URL = "https://api.infomaniak.com/2/"


class InfomaniakClientException(ProviderException):
    pass


class InfomaniakProviderException(ProviderException):
    pass


class InfomaniakClientBadRequest(InfomaniakClientException):
    def __init__(self):
        super().__init__("Bad request")


class InfomaniakClientUnauthorized(InfomaniakClientException):
    def __init__(self):
        super().__init__("Unauthorized")


class InfomaniakClientForbidden(InfomaniakClientException):
    def __init__(self):
        super().__init__("Forbidden")


class InfomaniakClientNotFound(InfomaniakClientException):
    def __init__(self):
        super().__init__("Not found")


class InfomaniakClient(object):
    def __init__(self, token: str):
        session = Session()
        session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "User-Agent": f"octodns/{version('octodns')} octodns-infomaniak/{version(__package__)}",
            }
        )
        self._session = session
        self.endpoint = BASE_API_URL

    def _request(self, method: str, path: str, params=None, data=None) -> Any:
        url = f"{self.endpoint}{path}"
        r = self._session.request(method, url, params=params, json=data)

        if r.status_code == 400:
            raise InfomaniakClientBadRequest()
        elif r.status_code == 401:
            raise InfomaniakClientUnauthorized()
        elif r.status_code == 403:
            raise InfomaniakClientForbidden()
        elif r.status_code == 404:
            raise InfomaniakClientNotFound()

        r.raise_for_status()

        return r.json()

    def get_records(self, zone: str) -> list[dict[str, str]]:
        path = f"zones/{zone}/records"
        return self._request("GET", path)["data"]

    def post_record(self, zone: str, data):
        path = f"zones/{zone}/records"
        self._request("POST", path, data=data)

    def delete_record(self, zone: str, record):
        path = f"zones/{zone}/records/{record}"
        self._request("DELETE", path)


class InfomaniakProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS_POOL_VALUE_STATUS = False
    SUPPORTS = set(
        (
            "A",
            "AAAA",
            "CAA",
            "CNAME",
            "DS",
            "MX",
            "NS",
            "SRV",
            "SSHFP",
            "TLSA",
            "TXT",
        )
    )

    def __init__(self, id: str, token: str, *args, **kwargs):
        self.log = logging.getLogger(f"InfomaniakProvider[{id}]")
        self.log.debug("__init__: id=%s, token=***", id)
        super().__init__(id, *args, **kwargs)
        self._client = InfomaniakClient(token)

        self._zone_records = {}

    def _get_zone_without_trailling_dot(self, zone: str) -> str:
        return zone.rstrip(".")

    def _get_fqdn(self, name: str) -> str:
        return name if name.endswith(".") else f"{name}."

    def _get_record_name(self, record_name: str) -> str:
        return record_name if record_name else "."

    def populate(self, zone: Zone, target: bool = False, lenient: bool = False) -> bool:
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))

        for record in self.zone_records(zone):
            _type = record["type"]
            _name = record["source"]

            if _type not in self.SUPPORTS:
                self.log.warning(
                    f"populate: skipping unsupported {_type} {_name}.{zone} record"
                )
                continue
            values[_name][_type].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f"_data_for_{_type}")

                # fix for specific name records
                if _type == "SRV":
                    proto = (
                        records[0]["delegated_zone"]["uri"]
                        .split("/")[-1]
                        .removesuffix(
                            f".{self._get_zone_without_trailling_dot(zone.name)}"
                        )
                    )
                    name = f"{self._get_fqdn(name)}{proto}"
                elif name == ".":
                    name = ""

                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            "populate:   found %s records, exists=%s",
            len(zone.records) - before,
            exists,
        )

        return exists

    def zone_records(self, zone: Zone) -> list[dict[str, Any]]:
        if zone.name not in self._zone_records:
            self._zone_records[zone.name] = self._client.get_records(
                self._get_zone_without_trailling_dot(zone.name)
            )

        return self._zone_records[zone.name]

    def _data_for_multiple(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [record["target"].replace(";", "\\;") for record in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_TXT = _data_for_multiple

    def _data_for_CAA(
        self, _type: str, records: dict[str, Any]
    ) -> list[dict[str, Any]]:
        values = []
        for record in records:
            flags, tag, value = record["target"].split(" ", 2)
            values.append(
                {"flags": int(flags), "tag": tag, "value": value.replace('"', "")}
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_CNAME(self, _type, records):
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "value": self._get_fqdn(records[0]["target"]),
        }

    def _data_for_DS(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            key_tag, algorithm, digest_type, digest = record["target"].split(" ", 3)
            values.append(
                {
                    "algorithm": int(algorithm),
                    "digest": digest,
                    "digest_type": int(digest_type),
                    "key_tag": int(key_tag),
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_MX(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            priority, exchange = record["target"].split(" ", 1)
            values.append(
                {
                    "priority": int(priority),
                    "exchange": self._get_fqdn(exchange),
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_NS(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [self._get_fqdn(record["target"]) for record in records],
        }

    def _data_for_SRV(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        values = []
        for record in records:
            priority, weight, port, target = record["target"].split(" ", 3)
            values.append(
                {
                    "priority": int(priority),
                    "weight": int(weight),
                    "port": int(port),
                    "target": self._get_fqdn(target),
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_SSHFP(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        values = []
        for record in records:
            algorithm, fingerprint_type, fingerprint = record["target"].split(" ", 2)
            values.append(
                {
                    "algorithm": int(algorithm),
                    "fingerprint_type": int(fingerprint_type),
                    "fingerprint": fingerprint,
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_TLSA(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        values = []
        for record in records:
            certificate_usage, selector, matching_type, certificate_association_data = (
                record["target"].split(" ", 3)
            )
            values.append(
                {
                    "certificate_usage": int(certificate_usage),
                    "selector": int(selector),
                    "matching_type": int(matching_type),
                    "certificate_association_data": certificate_association_data,
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _params_for_multiple(self, record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": value.replace("\\;", ";"),
                "ttl": record.ttl,
                "type": record._type,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_NS = _params_for_multiple
    _params_for_TXT = _params_for_multiple

    def _params_for_CAA(self, record: Record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": f'{value.flags} {value.tag} "{value.value}"',
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_CNAME(self, record: Record) -> Iterator[dict[str, Any]]:
        yield {
            "source": self._get_record_name(record.name),
            "target": record.value,
            "ttl": record.ttl,
            "type": record._type,
        }

    def _params_for_DS(self, record: Record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": f"{value.key_tag} {value.algorithm} {value.digest_type} {value.digest}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_MX(self, record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": f"{value.preference} {value.exchange}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_SRV(self, record: Record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": f"{value.priority} {value.weight} {value.port} {value.target}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_SSHFP(self, record: Record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": f"{value.algorithm} {value.fingerprint_type} {value.fingerprint}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_TLSA(self, record: Record) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "source": self._get_record_name(record.name),
                "target": f"{value.certificate_usage} {value.selector} {value.matching_type} {value.certificate_association_data}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _apply_create(self, changes):
        new = changes.new
        params_for = getattr(self, f"_params_for_{new._type}")

        for params in params_for(new):
            self._client.post_record(
                self._get_zone_without_trailling_dot(new.zone.name), params
            )

    def _apply_delete(self, changes):
        existing = changes.existing
        zone = existing.zone

        for record in self.zone_records(zone):
            # fix for specific name records
            name = existing.name
            if existing._type == "SRV":
                name = name.split("._")[0]
            elif name == "":
                name = "."

            if name == record["source"] and existing._type == record["type"]:
                self._client.delete_record(
                    self._get_zone_without_trailling_dot(zone.name), record["id"]
                )

    def _apply_update(self, changes):
        self._apply_delete(changes)
        self._apply_create(changes)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug("_apply: zone=%s, len(changes)=%d", desired.name, len(changes))

        for change in changes:
            class_name = change.__class__.__name__.lower()
            self.log.info(change)
            getattr(self, f"_apply_{class_name}")(change)

        self._zone_records.pop(desired.name, None)
