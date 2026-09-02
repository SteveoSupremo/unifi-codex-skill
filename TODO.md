# TODO

The expanded read-only audit is functional and covered by the current mocked test
suite, but the following work remains before its firewall conclusions should be
treated as comprehensive.

## Firewall policy correctness

- Apply `matchOpposite` semantics when evaluating network, address, and port
  filters. The normalized value is currently retained for evidence but is not used
  by segmentation classification or port-forward correlation.
- Handle missing, null, and malformed policy ordering indexes without aborting the
  audit. Preserve the uncertainty in coverage and evidence when ordering cannot be
  established.
- Confirm how `allowReturnTraffic` affects effective directional segmentation and
  incorporate it where the controller's documented semantics justify doing so.
- Validate combined address-and-port filters and non-`ALLOW`/`BLOCK` actions against
  representative official Integration API payloads.
- Improve reporting for unresolved zone and network identifiers, keeping the result
  `UNKNOWN` when policy applicability cannot be proven.
- Distinguish an officially collected-but-empty policy dataset from an unavailable
  or unsupported dataset throughout findings and segmentation output.

## Posture and exposure analysis

- Add focused tests for unavailable, empty, partial, and malformed VPN, IDS/IPS, and
  UPnP datasets.
- Validate UPnP/runtime-forward reconciliation when equivalent mappings use
  different object identifiers or field representations.
- Expand port-forward correlation tests for inverted filters, address ranges,
  protocol constraints, and combined destination filters.

## Tests and validation

- Add regression tests for every policy edge case above, including conservative
  `UNKNOWN` behavior when evidence is incomplete.
- Test policy ordering ties and missing indexes explicitly.
- Re-run the full mocked suite with:

  ```bash
  python3 -m unittest discover -s tests -v
  ```

- Exercise the audit against sanitized captures from each supported UniFi Network
  version. Never commit raw inventory, audit output, reports, snapshots, credentials,
  or other controller data.
