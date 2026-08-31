#!/usr/bin/env python3
"""Exercises `POST /api/validate` from outside the service.

The endpoint is the middle ground left behind when a full hosted PITTv3 was decided against: the
browser application validates in the page and never posts here, so a script is the client. That
makes this the only thing that drives `orchestrate::validate` end to end, and the only way a
breakpoint in the service's validation path fires without a request hand-assembled in curl.

Certificates travel as base64 because JSON has no bytes. DER and PEM are both accepted -- the
service decodes either -- so files are read as bytes and encoded as they are.

    # what the service holds
    validate_api.py --stores

    # one certificate against a store the service names
    validate_api.py --store-id dod_nipr_prod ee.der

    # against anchors and intermediates carried in the request instead
    validate_api.py --ta root.der --ca intermediate.der ee.der

    # every path for each target, not just the first that validates
    validate_api.py --store-id webpki --validate-all ee.der

    # the whole report rather than a summary
    validate_api.py --store-id fpki --json ee.der

    # take a live host's chain and validate what it presented, in one call
    validate_api.py --peek letsencrypt.org --store-id webpki_tls

    # retrieve one artifact through the relay, without validating anything
    validate_api.py --fetch http://crl.example.com/ca.crl

Run a service to point it at, or name a deployed one with --base:

    cargo run -p pittv3-service -- --bind 127.0.0.1:8080

Exit status is 0 when every target validated, 1 when any did not, and 2 when the request itself
failed -- so a caller can gate on the verdict without reading the report.
"""

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_BASE = "http://127.0.0.1:8080"


def post(base, path, body, timeout):
    """Posts JSON and returns the parsed response.

    A refusal carries an `error` string and a status this script reports rather than translates:
    404 means the route is off (`--no-validation`), and a 4xx from the policy is a decision the
    service made about the request, not a failure to reach it.
    """
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            detail = json.loads(detail).get("error", detail)
        except json.JSONDecodeError:
            pass
        raise SystemExit(f"{path}: HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise SystemExit(f"{path}: could not reach {base}: {e.reason}")


def get(base, path, timeout):
    try:
        with urllib.request.urlopen(f"{base}{path}", timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{path}: HTTP {e.code}")
    except urllib.error.URLError as e:
        raise SystemExit(f"{path}: could not reach {base}: {e.reason}")


def named(paths):
    """Reads each file into the `{name, der}` pair the endpoint takes.

    The name is the client's label and is what appears in the report, so the file name is used --
    it is what the person running this has in hand when reading the results.
    """
    certificates = []
    for path in paths:
        p = Path(path)
        if not p.is_file():
            raise SystemExit(f"{path}: not a file")
        certificates.append(
            {"name": p.name, "der": base64.b64encode(p.read_bytes()).decode()}
        )
    return certificates


def peeked_certificates(base, host, timeout):
    """Takes a host's chain through `/api/tls` and returns it as `NamedCertificate` values.

    The server sends its own certificate first and its issuers after, so the first becomes the
    target and the rest become CA input. Nothing here enforces that order -- a server that does not
    follow it is the kind of finding this exists to surface -- so the names carry the position, and
    a chain that came back in another order shows up as a target that finds no path rather than as
    a silent reordering.
    """
    response = post(base, "/api/tls", {"uri": host}, timeout)
    certificates = response.get("certificates", [])
    if not certificates:
        raise SystemExit(f"{host}: the handshake completed but presented no certificate")

    label = f"{response['host']}:{response['port']}"
    print(
        f"{label} presented {len(certificates)} certificate(s) over "
        f"{response.get('protocol') or 'an unreported protocol'}"
        + (", with a stapled OCSP response" if response.get("stapled_ocsp") else "")
    )
    named_certs = [
        {"name": f"{label}[{i}]", "der": der} for i, der in enumerate(certificates)
    ]
    return named_certs[0], named_certs[1:], response.get("stapled_ocsp")


def verdict(report, accepted):
    """True when every target reached one of the `accepted` statuses.

    Separate from the printing because `--json` prints the report instead of a summary and still
    has to exit on the same reading of it.
    """
    targets = report.get("targets", [])
    return bool(targets) and all(t.get("status") in accepted for t in targets)


def summarize(report):
    """Prints a target-per-line summary.

    A target that yielded no path carries its reason on `error` rather than a path list, so that
    case is printed as what it is instead of as zero valid paths.
    """
    totals = report.get("totals", {})
    print(
        f"{totals.get('targets', 0)} target(s), {totals.get('paths_found', 0)} path(s), "
        f"{totals.get('valid_paths', 0)} valid, {totals.get('invalid_paths', 0)} invalid "
        f"in {report.get('duration_ms', 0)} ms"
    )

    for note in report.get("notes", []):
        print(f"  note: {note}")

    for target in report.get("targets", []):
        status = target.get("status")
        paths = target.get("paths", [])
        valid = sum(
            1 for p in paths if p.get("error") is None and p.get("status") == "Valid"
        )
        if target.get("error"):
            print(f"  {target.get('name')}: {status} -- {target['error']}")
            continue
        print(f"  {target.get('name')}: {status} ({valid}/{len(paths)} path(s) valid)")


def main():
    parser = argparse.ArgumentParser(
        description="Calls POST /api/validate on a running pittv3-service.",
        epilog="Exit status: 0 all targets valid, 1 some not, 2 the request failed.",
    )
    parser.add_argument("targets", nargs="*", help="certificate files to validate")
    parser.add_argument(
        "--base", default=DEFAULT_BASE, help=f"service base URI (default {DEFAULT_BASE})"
    )
    parser.add_argument(
        "--store-id",
        help="identifier of a store the service holds; see --stores for what it offers",
    )
    parser.add_argument(
        "--ta",
        action="append",
        default=[],
        metavar="FILE",
        help="trust anchor to carry in the request, repeatable",
    )
    parser.add_argument(
        "--ca",
        action="append",
        default=[],
        metavar="FILE",
        help="intermediate to carry in the request, repeatable",
    )
    parser.add_argument(
        "--settings",
        metavar="FILE",
        help="JSON CertificationPathSettings for the run; the service sanitizes what it will not honor",
    )
    parser.add_argument(
        "--validate-all",
        action="store_true",
        help="validate every path found rather than stopping at the first that validates",
    )
    parser.add_argument(
        "--allow-undetermined",
        action="store_true",
        help="count ValidExceptRevocationUndetermined as success; for a service run with "
        "--no-revocation-fetch, or a run whose revocation data was not supplied",
    )
    parser.add_argument(
        "--peek",
        metavar="HOST",
        help="take the chain HOST presents over TLS and validate it, instead of reading files; "
        "the certificate the server sends first is the target and the rest are CA input",
    )
    parser.add_argument(
        "--fetch",
        metavar="URI",
        help="retrieve one artifact through the relay and report what came back, then exit",
    )
    parser.add_argument(
        "--stores", action="store_true", help="list the stores the service holds and exit"
    )
    parser.add_argument(
        "--json", action="store_true", help="print the whole report instead of a summary"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="seconds to wait; a run that retrieves can be slow (default 120)",
    )
    args = parser.parse_args()

    base = args.base.rstrip("/")

    if args.stores:
        for store in get(base, "/api/stores", args.timeout):
            # A store carrying trust anchors alone offers no ca_url, and asking for one is a 404
            # rather than an empty artifact -- worth showing here so that is not a surprise.
            halves = "ta+ca" if store.get("ca_url") else "ta only"
            print(
                f"{store['id']:<20} {store.get('label', '')}  "
                f"[{store.get('provenance')}, {halves}]"
            )
        return 0

    if args.fetch:
        got = post(base, "/api/fetch", {"uri": args.fetch}, args.timeout)
        body = base64.b64decode(got["body"])
        print(
            f"{got['status']} {got.get('content_type') or 'no content type'} "
            f"{len(body)} bytes from {got['final_uri']}"
            + (f" (last modified {got['last_modified']})" if got.get("last_modified") else "")
        )
        # A repository's own 4xx is reported, not translated: the relay reached it and this is what
        # it said. Only a refusal to make the request at all comes back as an error.
        return 0 if got["status"] < 400 else 1

    if args.peek and args.targets:
        parser.error("--peek supplies the certificates; do not also name files")
    if not args.peek and not args.targets:
        parser.error(
            "name at least one certificate to validate, or pass --peek, --fetch or --stores"
        )
    if not args.store_id and not args.ta:
        parser.error(
            "a run needs anchors: pass --store-id, or --ta, or both (a store plus extra anchors)"
        )

    if args.peek:
        target, chain, _stapled = peeked_certificates(base, args.peek, args.timeout)
        targets, cas = [target], chain + named(args.ca)
    else:
        targets, cas = named(args.targets), named(args.ca)

    body = {
        "targets": targets,
        "trust_anchors": named(args.ta),
        "cas": cas,
        "validate_all": args.validate_all,
    }
    if args.store_id:
        body["store_id"] = args.store_id
    if args.settings:
        body["settings"] = json.loads(Path(args.settings).read_text())

    report = post(base, "/api/validate", body, args.timeout)

    # The service reports a run that could not start as an error on the report itself, which is not
    # the same as a run whose targets came back invalid.
    if report.get("error"):
        print(f"the run did not complete: {report['error']}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        summarize(report)

    accepted = {"Valid"}
    if args.allow_undetermined:
        accepted.add("ValidExceptRevocationUndetermined")
    return 0 if verdict(report, accepted) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
            sys.exit(2)
        raise
