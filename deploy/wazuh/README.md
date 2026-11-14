# Wazuh integration

Two ways to get Wazuh alerts into P4B. Pick one; they produce the same findings.

## A. Pull (default in `docs/LAB.md` phase 4)

`rsync` copies `/var/ossec/logs/alerts/alerts.json` from the `siem` VM every minute
and `p4b ingest wazuh` parses the new lines. Nothing to install on the manager.

## B. Push (real time)

1. Copy the shipper into the manager container/VM and make it executable:

   ```bash
   install -m 0755 custom-p4b.py /var/ossec/integrations/custom-p4b
   ```

   On the Docker-based manager from `docs/LAB.md`:

   ```bash
   docker cp custom-p4b.py wazuh-manager:/var/ossec/integrations/custom-p4b
   docker exec wazuh-manager chmod 750 /var/ossec/integrations/custom-p4b
   docker exec wazuh-manager chown root:wazuh /var/ossec/integrations/custom-p4b
   ```

2. Add an integration block to `/var/ossec/etc/ossec.conf`:

   ```xml
   <integration>
     <name>custom-p4b</name>
     <hook_url>http://192.168.56.10:8080/api/v1/ingest/wazuh</hook_url>
     <level>7</level>
     <alert_format>json</alert_format>
   </integration>
   ```

   The script ignores `hook_url` (it uses `P4B_URL`), but integratord requires the
   element.

3. Give the script the destination and, if `require_auth` is on, a token. Wazuh does
   not pass arbitrary environment variables to integrations, so put them in a wrapper:

   ```bash
   cat >/var/ossec/integrations/custom-p4b <<'EOF'
   #!/bin/sh
   P4B_URL=http://192.168.56.10:8080
   P4B_TOKEN=p4b_xxxxxxxxxxxxxxxx
   export P4B_URL P4B_TOKEN
   exec /usr/bin/python3 /var/ossec/integrations/custom-p4b.py "$@"
   EOF
   chmod 750 /var/ossec/integrations/custom-p4b
   ```

4. Restart the manager and watch:

   ```bash
   docker restart wazuh-manager
   docker logs -f wazuh-manager | grep p4b-shipper
   ```

## Verify

```bash
# from the manager: one alert through the same endpoint
echo '{"rule":{"level":12,"description":"test","id":"999999"},"agent":{"name":"lab"}}' \
  | P4B_URL=http://192.168.56.10:8080 python3 custom-p4b.py
```

Expected: `p4b-shipper: parsed=1 created=1 merged=0`, and the finding appears in
`p4b findings` / the UI within a second.

## Notes

- The endpoint is idempotent: replaying the same alert file increments `count`
  instead of creating duplicates.
- Body limit is `max_body_mb` (64 MB by default). If a backlog is larger, ship it in
  batches rather than raising the limit.
- `min_level` can be set per request (`?min_level=10`); the adapter default is 7.
