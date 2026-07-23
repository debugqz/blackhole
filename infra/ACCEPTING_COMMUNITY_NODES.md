# Accepting a community-run bootstrap node

This is the operator-side counterpart to `COMMUNITY_NODE_GUIDE.md`: what
to actually do once someone tells you "I set up my node, here's my
multiaddr." Don't add an address to anything you distribute just because
it was handed to you — verify it first. This codebase has no
registration/authentication protocol for bootstrap peers at all (see
`docs/THREAT_MODEL.md` §3.5), so the only thing standing between "a
plausible-looking string" and "a real, working, non-malicious peer" is
you checking it yourself.

## What a bad or fake entry actually costs

Low, but not zero. A bootstrap node never sees message content or contact
graphs — it only helps Kademlia routing. The realistic risks of adding a
bad entry are:

- **Dead weight**: an offline/unreachable address wastes new peers' first
  connection attempt (they fall through to the next one in the list — see
  `bh-network::supervised::dial_bootstrap_peers`, which dials every
  configured address independently and just logs a warning per failure).
  Annoying, not dangerous.
- **Routing-table influence**: a live-but-malicious node is still subject
  to `routing_admission::RoutingAdmission`'s per-subnet cap and
  `eclipse_resistance`'s HMAC-scored circuit selection (§3.5) — it can't
  unilaterally flood the table or force itself into every circuit. But
  concentrating trust in *many* nodes from the same operator (even if each
  is individually reachable and well-behaved today) narrows the subnet/
  operator diversity the whole mitigation depends on. Prefer breadth
  (different people, different hosting providers/regions) over depth (one
  enthusiastic submitter's ten VPSes).

## Step 1 — confirm it's actually reachable and really a Blackhole peer

Don't just trust that the string parses as a multiaddr. Spin up a
disposable daemon whose *only* configured bootstrap peer is the candidate,
and watch what happens:

```sh
docker run --rm -it \
  -e BLACKHOLE_BOOTSTRAP_PEERS="<the candidate's multiaddr, alone>" \
  -e RUST_LOG=info \
  blackhole-bootstrap-node
```

(Build that image first if you haven't: `docker build -f
infra/bootstrap-node/Dockerfile -t blackhole-bootstrap-node .` from the
repo root — same image `docker-compose.yml`'s own `bootstrap-node` service
builds.)

- If the candidate is unreachable or isn't actually speaking the right
  protocol, `dial_bootstrap_peers` logs `failed to dial bootstrap peer`
  with the address and the underlying error within a few seconds of
  startup. **Reject the entry** — ask the submitter to double check their
  firewall/port-forward against `COMMUNITY_NODE_GUIDE.md`'s "Firewall"
  section, or that the PeerId in the multiaddr they gave you actually
  matches their node's own logged `peer_id`.
- If that warning never appears, the dial succeeded — this is a real,
  reachable Blackhole daemon. There isn't (yet) a diagnostic surface that
  reports "peer count in routing table" (`GET /network/status` reports
  only this disposable daemon's *own* `peer_id`/`alive`/`listen_addrs`,
  not who it's connected to — see `crates/bh-api/src/network.rs`'s own
  module doc), so absence of the dial-failure warning plus `alive: true`
  is the practical signal available today.
- Independently of the above, a plain reachability check costs nothing
  and catches the simplest failure mode (wrong port, address typo'd) even
  faster: `nc -zv <their IP> <their port>`.

## Step 2 — add it to what you actually distribute

There's no registry in this codebase (`README.md`'s bootstrap-node
section says the same for the platform's own node) — "the known bootstrap
peer list" is whatever you're already publishing for your own node(s):
a docs page, a config file shipped with the client, a `NETWORK.md` in this
repo, etc. Append the verified multiaddr there, comma-separated alongside
your own, the same way `systemd/bootstrap-node.env.example` and
`infra/community-node.env.example` both describe. Once it's live for the
first daemon that reads it, note the addition — with date and who
submitted it — wherever you keep that list, so a later "is this still
someone we trust" review has a paper trail.

## Step 3 — treat it as ongoing, not one-time

- **No uptime monitoring exists for this.** If you want to know a listed
  community node has gone dark, you have to check — periodically re-run
  Step 1 against every address you've published, or ask the operator to
  self-report if theirs goes down for good.
- **Removing an address from your published list doesn't revoke it
  retroactively.** Any daemon that already has it configured (baked into
  an old client build, a user's own env override) keeps trying it until
  that daemon's own config changes. Removal only stops *new* recommendations
  from that point forward.
- **If a listed node starts misbehaving** (not just going offline — e.g.
  you have reason to think it's trying to concentrate routing-table
  influence, per the "Routing-table influence" note above): remove it
  from your published list per the above, and consider whether the
  submitter's *other* nodes (if you accepted more than one from the same
  person) deserve the same scrutiny.
